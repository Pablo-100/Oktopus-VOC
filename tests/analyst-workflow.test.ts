import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { sql, initDb } from "@/lib/db"
import { raiseAlert } from "@/lib/exposure/vuln-tracking"
import {
  addAlertNote,
  assignAlert,
  bulkTransition,
  alertTimeline,
  transitionAlert,
} from "@/lib/exposure/alert-workflow"

/**
 * The daily mechanics of working a queue: claiming a finding, writing down what
 * you concluded, and acting on forty at once.
 *
 * These exist because a triage tool that forces one click per finding is
 * abandoned at volume, and because an audit trail that records only state
 * changes loses the analyst's reasoning — which is the part that stops the next
 * person repeating the investigation.
 */

const TENANT = "analyst-suite-tenant"
const OTHER = "analyst-suite-other"
const KEY = "ip:203.0.113.77"

async function seed(cve: string, port = 443): Promise<number> {
  // `raiseAlert` derives the fingerprint itself and returns whether a NEW alert
  // was created, so the id is read back rather than assumed.
  await raiseAlert({
    userId: TENANT,
    assetKey: KEY,
    target: "203.0.113.77",
    port,
    cveId: cve,
    kind: "new_exposed_vulnerability",
    severity: "critical",
    riskScore: 90,
    previousRisk: null,
    evidenceTier: "strong",
    payload: {},
  })
  const rows = (await sql`
    SELECT id FROM exposure_alerts
    WHERE user_id = ${TENANT} AND asset_key = ${KEY} AND port = ${port} AND cve_id = ${cve}
    ORDER BY id DESC LIMIT 1
  `) as Array<{ id: string }>
  return Number(rows[0].id)
}

async function cleanup() {
  await sql`DELETE FROM exposure_alert_events WHERE user_id IN (${TENANT}, ${OTHER})`
  await sql`DELETE FROM exposure_alerts WHERE user_id IN (${TENANT}, ${OTHER})`
}

describe.skipIf(!HAS_TEST_DB)("analyst notes", () => {
  beforeAll(async () => { await initDb(); await cleanup() }, 120_000)
  afterAll(cleanup)

  test("a note is appended to the same timeline as state changes", async () => {
    // One timeline, not two. An investigation split across separate logs is not
    // an audit trail.
    const id = await seed("CVE-2021-44228")
    expect((await addAlertNote(id, TENANT, "analyst-1", "Confirmed with vendor; patch lands Tuesday.")).ok).toBe(true)
    const events = await alertTimeline(id, TENANT)
    const note = events.find((e) => e.type === "analyst_note")
    expect(note).toBeTruthy()
    expect(note!.detail).toContain("patch lands Tuesday")
    expect(note!.actor).toBe("analyst-1")
    await cleanup()
  })

  test("an empty or whitespace-only note is refused", async () => {
    const id = await seed("CVE-2021-44228")
    expect((await addAlertNote(id, TENANT, "a", "")).code).toBe("empty")
    expect((await addAlertNote(id, TENANT, "a", "    ")).code).toBe("empty")
    await cleanup()
  })

  test("an oversized note is refused rather than silently truncated", async () => {
    // Truncation would store a note that says something different from what the
    // analyst wrote, which is worse than refusing it.
    const id = await seed("CVE-2021-44228")
    expect((await addAlertNote(id, TENANT, "a", "x".repeat(4001))).code).toBe("too_long")
    await cleanup()
  })

  test("one tenant cannot annotate another tenant's alert", async () => {
    const id = await seed("CVE-2021-44228")
    const r = await addAlertNote(id, OTHER, "intruder", "should not appear")
    expect(r.ok).toBe(false)
    expect(r.code).toBe("not_found")
    expect((await alertTimeline(id, TENANT)).some((e) => e.detail?.includes("should not appear"))).toBe(false)
    await cleanup()
  })
})

describe.skipIf(!HAS_TEST_DB)("assignment", () => {
  beforeAll(async () => { await initDb(); await cleanup() }, 120_000)
  afterAll(cleanup)

  test("claiming records an owner and an auditable event", async () => {
    const id = await seed("CVE-2021-44228")
    expect((await assignAlert(id, TENANT, "analyst-1", "analyst-1")).ok).toBe(true)
    const rows = (await sql`SELECT assigned_to, assigned_at FROM exposure_alerts WHERE id = ${id}`) as Array<{ assigned_to: string | null; assigned_at: string | null }>
    expect(rows[0].assigned_to).toBe("analyst-1")
    expect(rows[0].assigned_at).toBeTruthy()
    expect((await alertTimeline(id, TENANT)).some((e) => e.type === "alert_assigned")).toBe(true)
    await cleanup()
  })

  test("releasing clears the owner and the timestamp", async () => {
    const id = await seed("CVE-2021-44228")
    await assignAlert(id, TENANT, "analyst-1", "analyst-1")
    expect((await assignAlert(id, TENANT, "analyst-1", null)).ok).toBe(true)
    const rows = (await sql`SELECT assigned_to, assigned_at FROM exposure_alerts WHERE id = ${id}`) as Array<{ assigned_to: string | null; assigned_at: string | null }>
    expect(rows[0].assigned_to).toBeNull()
    expect(rows[0].assigned_at).toBeNull()
    expect((await alertTimeline(id, TENANT)).some((e) => e.type === "alert_unassigned")).toBe(true)
    await cleanup()
  })

  test("re-assigning to the same person writes no duplicate event", async () => {
    // A handover log full of no-op entries is a log nobody reads.
    const id = await seed("CVE-2021-44228")
    await assignAlert(id, TENANT, "analyst-1", "analyst-1")
    await assignAlert(id, TENANT, "analyst-1", "analyst-1")
    const assigned = (await alertTimeline(id, TENANT)).filter((e) => e.type === "alert_assigned")
    expect(assigned.length).toBe(1)
    await cleanup()
  })

  test("one tenant cannot claim another tenant's alert", async () => {
    const id = await seed("CVE-2021-44228")
    const r = await assignAlert(id, OTHER, "intruder", "intruder")
    expect(r.ok).toBe(false)
    expect(r.code).toBe("not_found")
    const rows = (await sql`SELECT assigned_to FROM exposure_alerts WHERE id = ${id}`) as Array<{ assigned_to: string | null }>
    expect(rows[0].assigned_to).toBeNull()
    await cleanup()
  })
})

describe.skipIf(!HAS_TEST_DB)("bulk triage", () => {
  beforeAll(async () => { await initDb(); await cleanup() }, 120_000)
  afterAll(cleanup)

  test("one decision applies to every selected alert", async () => {
    const ids = [await seed("CVE-2021-44228", 443), await seed("CVE-2021-45046", 8080), await seed("CVE-2022-22965", 8443)]
    const r = await bulkTransition({ alertIds: ids, userId: TENANT, to: "acknowledged", actor: "analyst-1" })
    expect(r.applied.sort()).toEqual([...ids].sort())
    expect(r.failed.length).toBe(0)
    const rows = (await sql`SELECT state FROM exposure_alerts WHERE user_id = ${TENANT}`) as Array<{ state: string }>
    expect(rows.every((x) => x.state === "acknowledged")).toBe(true)
    await cleanup()
  })

  test("a batch is NOT atomic — one bad alert does not veto the rest", async () => {
    // The whole point: an alert already closed must not block the other
    // thirty-nine from being acknowledged.
    const ok1 = await seed("CVE-2021-44228", 443)
    const ok2 = await seed("CVE-2021-45046", 8080)
    const closed = await seed("CVE-2022-22965", 8443)
    await transitionAlert({ alertId: closed, userId: TENANT, to: "acknowledged", actor: "a", reason: null })
    await transitionAlert({ alertId: closed, userId: TENANT, to: "resolved", actor: "a", reason: null })
    await transitionAlert({ alertId: closed, userId: TENANT, to: "closed", actor: "a", reason: null })

    const r = await bulkTransition({ alertIds: [ok1, ok2, closed], userId: TENANT, to: "acknowledged", actor: "analyst-1" })
    expect(r.applied.sort()).toEqual([ok1, ok2].sort())
    expect(r.failed.length).toBe(1)
    expect(r.failed[0].id).toBe(closed)
    await cleanup()
  })

  test("failures are reported per id, not as a bare count", async () => {
    // "37 of 40 applied" without saying which three is not actionable.
    const good = await seed("CVE-2021-44228")
    const r = await bulkTransition({ alertIds: [good, 999_999_999], userId: TENANT, to: "acknowledged", actor: "a" })
    expect(r.applied).toEqual([good])
    expect(r.failed[0].id).toBe(999_999_999)
    expect(r.failed[0].error).toBeTruthy()
    await cleanup()
  })

  test("a repeated id produces one decision, not two audit events", async () => {
    const id = await seed("CVE-2021-44228")
    const r = await bulkTransition({ alertIds: [id, id, id], userId: TENANT, to: "acknowledged", actor: "a" })
    expect(r.applied).toEqual([id])
    const acks = (await alertTimeline(id, TENANT)).filter((e) => e.type === "alert_acknowledged")
    expect(acks.length).toBe(1)
    await cleanup()
  })

  test("a batch note lands only on the alerts that actually changed", async () => {
    // An explanation attached to something that did not happen is a false
    // audit record.
    const ok = await seed("CVE-2021-44228", 443)
    const r = await bulkTransition({
      alertIds: [ok, 999_999_999], userId: TENANT, to: "acknowledged",
      actor: "analyst-1", note: "Batch triage: internal-only exposure.",
    })
    expect(r.applied).toEqual([ok])
    expect((await alertTimeline(ok, TENANT)).some((e) => e.type === "analyst_note")).toBe(true)
    await cleanup()
  })

  test("another tenant's alerts in the list are refused, not acted on", async () => {
    const mine = await seed("CVE-2021-44228")
    const r = await bulkTransition({ alertIds: [mine], userId: OTHER, to: "closed", actor: "intruder" })
    expect(r.applied.length).toBe(0)
    expect(r.failed[0].code).toBe("not_found")
    const rows = (await sql`SELECT state FROM exposure_alerts WHERE id = ${mine}`) as Array<{ state: string }>
    expect(rows[0].state).toBe("open")
    await cleanup()
  })

  test("suppression in bulk still demands a reason", async () => {
    // The audit trail must not get weaker just because the decision covered
    // forty findings instead of one.
    const id = await seed("CVE-2021-44228")
    const noReason = await bulkTransition({ alertIds: [id], userId: TENANT, to: "suppressed", actor: "a" })
    expect(noReason.applied.length).toBe(0)
    expect(noReason.failed[0].code).toBe("reason_required")

    const withReason = await bulkTransition({ alertIds: [id], userId: TENANT, to: "suppressed", actor: "a", reason: "accepted_risk" })
    expect(withReason.applied).toEqual([id])
    await cleanup()
  })
})
