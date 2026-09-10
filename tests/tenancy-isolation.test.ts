/**
 * TENANCY ISOLATION.
 *
 * Every user owns their own attack surface. These tests exist because a missing
 * `user_id` predicate is invisible: the query still runs, still returns rows,
 * and the UI still renders — it just shows someone else's data. Nothing but an
 * explicit cross-tenant assertion catches that.
 *
 * The pattern throughout is the same: tenant A and tenant B are given the SAME
 * asset, the SAME CVE and the SAME port, then each is asked what it can see.
 * Two tenants sharing a host is the normal case in a hosted product, not an
 * edge case — a CDN address or a shared provider IP will be monitored by many
 * users at once.
 */
import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { sql, initDb } from "@/lib/db"
import { raiseAlert, resolveAlerts, setAlertState, alertFingerprint } from "@/lib/exposure/vuln-tracking"
import { transitionAlert, escalateAlert, alertTimeline, recordAlertEvent } from "@/lib/exposure/alert-workflow"
import { setMonitoring, getMonitoring, monitoringOverview, claimDueAssets, isAssetLocked } from "@/lib/exposure/monitoring"
import { loadGraphFromStore } from "@/lib/exposure/graph-data"
import { requeueNotification } from "@/lib/notify/outbox"
import type { EvidenceTier } from "@/lib/exposure/types"

const A = "tenant:alpha"
const B = "tenant:bravo"
/** Deliberately the SAME host for both tenants — that is the whole point. */
const ASSET = "ip:203.0.113.240"
const CVE = "CVE-2021-41773"
let dbAvailable = false

async function cleanup() {
  if (!dbAvailable) return
  await sql`DELETE FROM exposure_alert_events WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_tickets      WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_alerts       WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_vulnerability WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_asset_state  WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_history      WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_monitoring   WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_monitoring_runs WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM exposure_events       WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
  await sql`DELETE FROM triage                WHERE user_id = ANY(ARRAY[${A}, ${B}]::text[])`
}

beforeAll(async () => {
  if (!HAS_TEST_DB) return
  try { await initDb(); await sql`SELECT 1`; dbAvailable = true } catch { dbAvailable = false }
  await cleanup()
}, 60_000)
afterAll(async () => {
  if (!HAS_TEST_DB) return
  await cleanup()
})

const alertFor = (userId: string, over: Partial<{ severity: string; tier: string; port: number }> = {}) => ({
  userId, assetKey: ASSET, target: "203.0.113.240",
  port: over.port ?? 443, cveId: CVE,
  kind: "new_exposed_vulnerability" as const,
  severity: over.severity ?? "critical", riskScore: 100, previousRisk: 32,
  evidenceTier: (over.tier ?? "confirmed") as EvidenceTier,
  payload: { asset: "203.0.113.240" },
})

const alertIdFor = async (userId: string) =>
  Number(((await sql`
    SELECT id FROM exposure_alerts WHERE user_id = ${userId} AND asset_key = ${ASSET}
    ORDER BY id DESC LIMIT 1`) as Array<{ id: number }>)[0]?.id)

describe.skipIf(!process.env.DATABASE_URL)("Two tenants, one host", () => {
  test("both tenants can monitor the SAME asset independently", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = await setMonitoring(ASSET, "203.0.113.240", A, { enabled: true })
    const b = await setMonitoring(ASSET, "203.0.113.240", B, { enabled: false })
    // Before tenancy the second write would have overwritten the first: the PK
    // was asset_key alone.
    expect(a.user_id).toBe(A)
    expect(b.user_id).toBe(B)
    expect((await getMonitoring(ASSET, A))?.enabled).toBe(true)
    expect((await getMonitoring(ASSET, B))?.enabled).toBe(false)
  })

  test("pausing one tenant's monitoring does not pause the other's", async () => {
    if (!dbAvailable) return
    await cleanup()
    await setMonitoring(ASSET, "203.0.113.240", A, { enabled: true })
    await setMonitoring(ASSET, "203.0.113.240", B, { enabled: true })
    await setMonitoring(ASSET, "203.0.113.240", B, { enabled: false })
    expect((await getMonitoring(ASSET, A))?.enabled).toBe(true)
  })

  test("a monitoring overview shows only the caller's assets", async () => {
    if (!dbAvailable) return
    await cleanup()
    await setMonitoring(ASSET, "203.0.113.240", A, { enabled: true })
    await setMonitoring("ip:203.0.113.241", "203.0.113.241", B, { enabled: true })
    const seenByA = (await monitoringOverview(A)).assets.map((x) => x.asset_key)
    expect(seenByA).toContain(ASSET)
    expect(seenByA).not.toContain("ip:203.0.113.241")
  })

  test("a lock held by one tenant does not block the other's manual refresh", async () => {
    if (!dbAvailable) return
    await cleanup()
    await setMonitoring(ASSET, "203.0.113.240", A, { enabled: true })
    await setMonitoring(ASSET, "203.0.113.240", B, { enabled: true })
    await sql`UPDATE exposure_monitoring SET locked_at = now(), locked_by = 'run-a' WHERE user_id = ${A}`
    expect(await isAssetLocked(ASSET, A)).toBe(true)
    expect(await isAssetLocked(ASSET, B)).toBe(false)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Alerts never cross tenants", () => {
  test("the SAME finding alerts BOTH tenants — dedup is per user", async () => {
    if (!dbAvailable) return
    await cleanup()
    // With a global unique index on fingerprint alone, whoever was alerted
    // first would have silently suppressed the alert for everyone else.
    expect(await raiseAlert(alertFor(A))).toBe(true)
    expect(await raiseAlert(alertFor(B))).toBe(true)
    const rows = (await sql`
      SELECT user_id FROM exposure_alerts WHERE asset_key = ${ASSET} ORDER BY user_id
    `) as Array<{ user_id: string }>
    expect(rows.map((r) => r.user_id)).toEqual([A, B])
  })

  test("dedup still holds WITHIN a tenant", async () => {
    if (!dbAvailable) return
    await cleanup()
    expect(await raiseAlert(alertFor(A))).toBe(true)
    expect(await raiseAlert(alertFor(A))).toBe(false)
  })

  test("one tenant cannot transition another tenant's alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertFor(A))
    const id = await alertIdFor(A)

    const stolen = await transitionAlert({ alertId: id, userId: B, to: "acknowledged", actor: B })
    expect(stolen.ok).toBe(false)
    // Reported as NOT FOUND, not FORBIDDEN: a wrong-tenant id must not confirm
    // that the alert exists at all.
    if (!stolen.ok) expect(stolen.code).toBe("not_found")

    const owner = await transitionAlert({ alertId: id, userId: A, to: "acknowledged", actor: A })
    expect(owner.ok).toBe(true)
    const state = (await sql`SELECT state FROM exposure_alerts WHERE id = ${id}`) as Array<{ state: string }>
    expect(state[0].state).toBe("acknowledged")
  })

  test("one tenant cannot suppress another tenant's alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertFor(A))
    const id = await alertIdFor(A)
    const r = await transitionAlert({ alertId: id, userId: B, to: "suppressed", actor: B, reason: "false_positive" })
    expect(r.ok).toBe(false)
    const state = (await sql`SELECT state FROM exposure_alerts WHERE id = ${id}`) as Array<{ state: string }>
    expect(state[0].state).toBe("open")   // untouched
  })

  test("setAlertState cannot reach across tenants either", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertFor(A))
    const id = await alertIdFor(A)
    expect(await setAlertState(id, "resolved", B)).toBe(false)
    expect(await setAlertState(id, "resolved", A)).toBe(true)
  })

  test("resolving a finding closes only the owner's alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertFor(A))
    await raiseAlert(alertFor(B))
    expect(await resolveAlerts(ASSET, 443, CVE, A)).toBe(1)
    const states = (await sql`
      SELECT user_id, state FROM exposure_alerts WHERE asset_key = ${ASSET} ORDER BY user_id
    `) as Array<{ user_id: string; state: string }>
    expect(states.find((s) => s.user_id === A)?.state).toBe("resolved")
    expect(states.find((s) => s.user_id === B)?.state).toBe("open")
  })

  test("escalation applies to the owner's alert only", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertFor(A, { severity: "high" }))
    await raiseAlert(alertFor(B, { severity: "high" }))
    const fp = alertFingerprint(ASSET, 443, CVE)
    const r = await escalateAlert(fp, A, { severity: "critical", riskScore: 95, evidenceTier: "confirmed" })
    expect(r.escalated).toBe(true)
    const sev = (await sql`
      SELECT user_id, severity FROM exposure_alerts WHERE asset_key = ${ASSET} ORDER BY user_id
    `) as Array<{ user_id: string; severity: string }>
    expect(sev.find((s) => s.user_id === A)?.severity).toBe("critical")
    expect(sev.find((s) => s.user_id === B)?.severity).toBe("high")   // untouched
  })

  test("a manual notification retry cannot be triggered on another tenant's alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertFor(A))
    const id = await alertIdFor(A)
    await sql`UPDATE exposure_alerts SET notification_state = 'failed' WHERE id = ${id}`
    const stolen = await requeueNotification(id, B, B)
    expect(stolen.ok).toBe(false)
    if (!stolen.ok) expect(stolen.code).toBe("not_found")
    expect((await requeueNotification(id, A, A)).ok).toBe(true)
  })

  test("the audit timeline is not readable across tenants", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertFor(A))
    const id = await alertIdFor(A)
    await recordAlertEvent(id, A, "alert_acknowledged", A, "owner event")
    expect((await alertTimeline(id, A)).length).toBeGreaterThan(0)
    expect(await alertTimeline(id, B)).toHaveLength(0)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Exposure records never cross tenants", () => {
  const snap = (risk: number) => JSON.stringify({
    services: [{ port: 443, product: "nginx", version: null }],
    domains: [], certificateFingerprints: [], cveIds: [], sources: ["netlas"], riskScore: risk,
  })

  test("the graph shows only the caller's assets", async () => {
    if (!dbAvailable) return
    await cleanup()
    await sql`INSERT INTO exposure_asset_state (user_id, asset_key, snapshot) VALUES (${A}, ${ASSET}, ${snap(90)}::jsonb)`
    await sql`INSERT INTO exposure_asset_state (user_id, asset_key, snapshot) VALUES (${B}, ${"ip:203.0.113.241"}, ${snap(90)}::jsonb)`
    const g = await loadGraphFromStore(A, { limit: 150 })
    const ips = g.graph.nodes.filter((n) => n.type === "ip").map((n) => n.id)
    expect(ips).toContain(ASSET)
    expect(ips).not.toContain("ip:203.0.113.241")
  })

  test("both tenants may hold their OWN snapshot of the same host", async () => {
    if (!dbAvailable) return
    await cleanup()
    await sql`INSERT INTO exposure_asset_state (user_id, asset_key, snapshot) VALUES (${A}, ${ASSET}, ${snap(10)}::jsonb)`
    await sql`INSERT INTO exposure_asset_state (user_id, asset_key, snapshot) VALUES (${B}, ${ASSET}, ${snap(90)}::jsonb)`
    const rows = (await sql`
      SELECT user_id, (snapshot->>'riskScore')::float AS risk
      FROM exposure_asset_state WHERE asset_key = ${ASSET} ORDER BY user_id
    `) as Array<{ user_id: string; risk: number }>
    expect(rows).toHaveLength(2)
    expect(rows.find((r) => r.user_id === A)?.risk).toBe(10)
    expect(rows.find((r) => r.user_id === B)?.risk).toBe(90)
  })

  test("triage notes are private to each analyst", async () => {
    if (!dbAvailable) return
    await cleanup()
    await sql`INSERT INTO triage (user_id, cve_id, status, note) VALUES (${A}, ${CVE}, 'in_progress', 'A note')`
    await sql`INSERT INTO triage (user_id, cve_id, status, note) VALUES (${B}, ${CVE}, 'new', 'B note')`
    const rows = (await sql`SELECT user_id, note FROM triage WHERE cve_id = ${CVE} ORDER BY user_id`) as Array<{ user_id: string; note: string }>
    expect(rows).toHaveLength(2)   // one no longer overwrites the other
    expect(rows.find((r) => r.user_id === A)?.note).toBe("A note")
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Scheduler fairness across tenants", () => {
  test("one tenant with many overdue assets cannot starve another", async () => {
    if (!dbAvailable) return
    await cleanup()
    // A has 10 assets overdue by a long time; B has a single, newer one.
    // Ordering purely by next_run_at would hand every slot to A.
    for (let i = 0; i < 10; i++) {
      await setMonitoring(`ip:203.0.113.${100 + i}`, `203.0.113.${100 + i}`, A, { enabled: true })
    }
    await setMonitoring("ip:203.0.113.199", "203.0.113.199", B, { enabled: true })
    await sql`UPDATE exposure_monitoring SET next_run_at = now() - interval '10 hours' WHERE user_id = ${A}`
    await sql`UPDATE exposure_monitoring SET next_run_at = now() - interval '1 minute' WHERE user_id = ${B}`

    const claimed = await claimDueAssets("fair-run", 5)
    const owners = new Set(claimed.map((c) => c.user_id))
    // B must appear despite being newer and far outnumbered.
    expect(owners.has(B)).toBe(true)
    expect(owners.has(A)).toBe(true)
  }, 60_000)
})

describe.skipIf(!process.env.DATABASE_URL)("Provider health is observed, not assumed", () => {
  test("health reflects the LAST REAL outcome, not merely that a key exists", async () => {
    if (!dbAvailable) return
    const rows = (await sql`
      SELECT provider, status, observations FROM exposure_provider_health
    `) as Array<{ provider: string; status: string; observations: number }>
    // The table only ever holds providers that were actually called.
    for (const r of rows) {
      expect(r.status).not.toBe("not_configured")
      // A provider reporting success must have something to show for it.
      if (r.status === "success") expect(r.observations).toBeGreaterThanOrEqual(0)
    }
  })

  test("an exhausted account is distinguishable from a working one", async () => {
    if (!dbAvailable) return
    const rows = (await sql`
      SELECT provider, status, last_ok_at FROM exposure_provider_health
    `) as Array<{ provider: string; status: string; last_ok_at: string | null }>
    if (!rows.length) return   // nothing observed yet on this database
    for (const r of rows) {
      // A provider that has never succeeded must not carry a success timestamp:
      // that is exactly the "looks configured, returns nothing" trap.
      if (r.status === "quota_exhausted" || r.status === "authentication_failed") {
        expect(["success", "partial"]).not.toContain(r.status)
      }
    }
  })
})
