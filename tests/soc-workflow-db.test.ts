/**
 * SOC WORKFLOW — persistence, deduplication, escalation, outbox.
 *
 * These need a real database: the dedup guarantee is a partial unique index,
 * the delivery claim is a locking CTE, and the audit trail is an append-only
 * table. Skips cleanly with no database; all rows use a `test:soc5:` prefix.
 *
 * Telegram is exercised through an INJECTED FAKE TRANSPORT. This is adapter
 * validation — no message is delivered to Telegram and none is claimed to be.
 */
import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { sql, initDb } from "@/lib/db"
import { raiseAlert, evaluateAlerts, trackAssetVulnerabilities, alertFingerprint } from "@/lib/exposure/vuln-tracking"
import { transitionAlert, escalateAlert, alertTimeline, recordAlertEvent } from "@/lib/exposure/alert-workflow"
import { runNotificationCycle, syncTicket } from "@/lib/notify/outbox"
import type { TelegramTransport } from "@/lib/notify/telegram-adapter"
import { makeVulnerability } from "@/lib/exposure/normalize"
import type { AlertRow } from "@/lib/notify/types"
import type { ExposureAsset, ProviderName, ProviderOutcome, ProviderStatus, EvidenceTier } from "@/lib/exposure/types"

/**
 * Tenancy fixtures. Every DB suite runs as an explicit tenant so a query that
 * forgets its user filter shows up as a cross-tenant leak rather than passing
 * silently. `OTHER` exists to prove isolation, not just to satisfy a signature.
 */
const TENANT = "test-tenant-a"
const OTHER = "test-tenant-b"


const KEY = "test:soc5:ip:203.0.113.99"
const CVE = "CVE-2021-41773"
const CREDS = { TELEGRAM_BOT_TOKEN: "111222:TESTONLYtokenVALUE", TELEGRAM_CHAT_ID: "-100999" }
let dbAvailable = false

async function cleanup() {
  if (!dbAvailable) return
  // Batched: one statement per table rather than a round trip per alert. The
  // database is remote, so a per-row loop made cleanup the slowest part of the
  // suite and pushed tests past their timeout.
  await sql`DELETE FROM exposure_alert_events WHERE alert_id IN (SELECT id FROM exposure_alerts WHERE asset_key LIKE 'test:soc5:%')`
  await sql`DELETE FROM exposure_tickets      WHERE alert_id IN (SELECT id FROM exposure_alerts WHERE asset_key LIKE 'test:soc5:%')`
  await sql`DELETE FROM exposure_alerts       WHERE asset_key LIKE 'test:soc5:%'`
  await sql`DELETE FROM exposure_vulnerability WHERE asset_key LIKE 'test:soc5:%'`
}

// The schema migration in `initDb()` runs many statements against a REMOTE
// database, so first-run setup can exceed bun's 5s hook default. This is setup
// cost, not an assertion — the timeout is raised rather than the check weakened.
beforeAll(async () => {
  if (!HAS_TEST_DB) return
  try { await initDb(); await sql`SELECT 1`; dbAvailable = true } catch { dbAvailable = false }
  await cleanup()
}, 60_000)
afterAll(async () => {
  if (!HAS_TEST_DB) return
  await cleanup()
})

const withEnv = async (vars: Record<string, string | undefined>, fn: () => Promise<void>) => {
  const saved: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k]
    if (v === undefined) delete process.env[k]; else process.env[k] = v
  }
  try { await fn() } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v
    }
  }
}

function transportReturning(status: number, body = "{}") {
  const calls: string[] = []
  const transport: TelegramTransport = async (_url, init) => {
    calls.push(String(init.body ?? ""))
    return new Response(body, { status })
  }
  return { transport, calls }
}

async function seedAlert(over: Partial<{ severity: string; tier: string; risk: number; cve: string; port: number }> = {}) {
  const port = over.port ?? 443
  const cve = over.cve ?? CVE
  await raiseAlert({
    userId: TENANT, assetKey: KEY, target: "203.0.113.99", port, cveId: cve,
    kind: "new_exposed_vulnerability",
    severity: over.severity ?? "critical",
    riskScore: over.risk ?? 100, previousRisk: 32,
    evidenceTier: (over.tier ?? "confirmed") as EvidenceTier,
    payload: { asset: "203.0.113.99", product: "Apache HTTP Server", version: "2.4.7", providers: ["netlas"], cvss: 10 },
  })
  const rows = (await sql`SELECT * FROM exposure_alerts WHERE asset_key = ${KEY} AND port = ${port} AND cve_id = ${cve} ORDER BY id DESC LIMIT 1`) as AlertRow[]
  return rows[0]
}

function outcome(provider: ProviderName, status: ProviderStatus): ProviderOutcome {
  return { provider, role: "enrichment", status, retryable: false, query: "x", latencyMs: 1, observationCount: 1, fetchedAt: new Date().toISOString() }
}

function asset(cves: string[], tier: EvidenceTier, severity: string, score: number): ExposureAsset {
  const matchType = ({ confirmed: "cve-search", strong: "version", product: "product", pivot: "pivot", weak: "banner" } as const)[tier]
  return {
    id: KEY, ip: "203.0.113.99", domain: null, hostnames: [], domains: [],
    services: [{ port: 443, transport: "tcp", protocol: "http", product: "Apache HTTP Server", vendor: null, version: "2.4.7", banner: null, httpStatus: null, httpTitle: null, httpServer: null, sources: ["netlas"], claims: [] }],
    technologies: [], certificates: [],
    vulnerabilities: cves.map((c) => ({ correlatedPort: 443, ...makeVulnerability({ cveId: c, matchType, sources: ["netlas"] }) })),
    sources: ["netlas"], sourceCount: 1, confidence: "high", provenance: [], raw: [],
    threat: null, enrichmentStatus: "enriched",
    freshness: { fetchedAt: new Date().toISOString(), observedAt: new Date(Date.now() - 3600_000).toISOString(), observationAgeSeconds: 3600, fromCache: false, state: "fresh" },
    exposureRisk: { score, severity, baseRbvm: score, exposureFactor: 1, factors: [], slaHours: 24, drivingCves: cves },
  } as unknown as ExposureAsset
}

describe.skipIf(!process.env.DATABASE_URL)("Alert creation reuses the EXISTING eligibility decision", () => {
  test("a confirmed critical finding creates an alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "critical", 100)
    const t = await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
    const e = await evaluateAlerts(a, t, TENANT, { severity: "medium", score: 32 })
    expect(e.raised).toHaveLength(1)
  })

  test("PRODUCT evidence creates NO alert, however severe the CVE", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "product", "critical", 100)
    const t = await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
    const e = await evaluateAlerts(a, t, TENANT, { severity: null, score: null })
    expect(e.raised).toHaveLength(0)
    expect(e.suppressed).toHaveLength(1)
    const rows = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(rows[0].n).toBe(0)
  })

  test("PIVOT evidence creates no alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "pivot", "critical", 100)
    const t = await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
    expect((await evaluateAlerts(a, t, TENANT, { severity: null, score: null })).raised).toHaveLength(0)
  })

  test("the workflow never changes an evidence tier or a risk score", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert({ tier: "confirmed", severity: "critical", risk: 100 })
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "acknowledged", actor: "tester" })
    await withEnv(CREDS, async () => {
      const { transport } = transportReturning(200)
      await runNotificationCycle({ transport, syncTickets: false })
    })
    const after = (await sql`SELECT evidence_tier, risk_score, severity FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(after[0].evidence_tier).toBe("confirmed")
    expect(after[0].risk_score).toBe(100)
    expect(after[0].severity).toBe("critical")
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Deduplication and escalation", () => {
  test("the same finding across repeated runs does not create a second alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "critical", 100)
    for (let i = 0; i < 3; i++) {
      const t = await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
      await evaluateAlerts(a, t, TENANT, { severity: "critical", score: 100 })
    }
    const rows = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(rows[0].n).toBe(1)
  })

  test("an alert being worked (in_progress) still blocks a duplicate", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "acknowledged", actor: "tester" })
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "in_progress", actor: "tester" })
    // Monitoring runs again while the analyst is working it.
    expect(await raiseAlert({
      userId: TENANT, assetKey: KEY, target: "203.0.113.99", port: 443, cveId: CVE,
      kind: "new_exposed_vulnerability", severity: "critical", riskScore: 100,
      previousRisk: 32, evidenceTier: "confirmed", payload: {},
    })).toBe(false)
    const rows = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(rows[0].n).toBe(1)
  })

  test("SEVERITY escalation updates the live alert and re-queues notification", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert({ severity: "high", risk: 70 })
    await sql`UPDATE exposure_alerts SET notification_state='sent', notified_at=now(), notified_severity='high' WHERE id = ${created.id}`

    const r = await escalateAlert(alertFingerprint(KEY, 443, CVE), TENANT, { severity: "critical", riskScore: 95, evidenceTier: "confirmed" })
    expect(r.escalated).toBe(true)

    const rows = (await sql`SELECT severity, risk_score, notification_state, escalation_count FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].severity).toBe("critical")
    expect(rows[0].notification_state).toBe("pending") // re-queued
    expect(rows[0].escalation_count).toBe(1)
    // One alert, not two.
    const count = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(count[0].n).toBe(1)
  })

  test("EVIDENCE hardening (product -> confirmed) is an escalation", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert({ tier: "strong", severity: "high", risk: 70 })
    const r = await escalateAlert(alertFingerprint(KEY, 443, CVE), TENANT, { severity: "high", riskScore: 70, evidenceTier: "confirmed" })
    expect(r.escalated).toBe(true)
    const rows = (await sql`SELECT evidence_tier FROM exposure_alerts WHERE id = ${created.id}`) as Array<{ evidence_tier: string }>
    expect(rows[0].evidence_tier).toBe("confirmed")
  })

  test("the SAME severity and evidence is NOT an escalation — no re-notification", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert({ severity: "high", risk: 70, tier: "confirmed" })
    await sql`UPDATE exposure_alerts SET notification_state='sent', notified_at=now() WHERE id = ${created.id}`
    const r = await escalateAlert(alertFingerprint(KEY, 443, CVE), TENANT, { severity: "high", riskScore: 70, evidenceTier: "confirmed" })
    expect(r.escalated).toBe(false)
    const rows = (await sql`SELECT notification_state, escalation_count FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].notification_state).toBe("sent")  // still sent, not re-queued
    expect(rows[0].escalation_count).toBe(0)
  })

  test("a DOWNGRADE is not an escalation", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedAlert({ severity: "critical", risk: 100 })
    const r = await escalateAlert(alertFingerprint(KEY, 443, CVE), TENANT, { severity: "high", riskScore: 60, evidenceTier: "confirmed" })
    expect(r.escalated).toBe(false)
  })

  test("escalating a finding with no live alert does nothing", async () => {
    if (!dbAvailable) return
    await cleanup()
    expect((await escalateAlert("test:soc5:nothing|1|CVE-0000-0000", TENANT, { severity: "critical", riskScore: 99, evidenceTier: "confirmed" })).escalated).toBe(false)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Lifecycle persistence and audit trail", () => {
  test("NEW -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> CLOSED, each recorded", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    for (const to of ["acknowledged", "in_progress", "resolved", "closed"] as const) {
      const r = await transitionAlert({ alertId: created.id, userId: TENANT, to, actor: "analyst-1" })
      expect(r.ok).toBe(true)
    }
    const rows = (await sql`SELECT state, acknowledged_at, started_at, resolved_at, closed_at FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].state).toBe("closed")
    for (const stamp of ["acknowledged_at", "started_at", "resolved_at", "closed_at"]) {
      expect(rows[0][stamp]).toBeTruthy()
    }
    const timeline = await alertTimeline(created.id, TENANT)
    const types = timeline.map((e) => e.type)
    expect(types).toContain("alert_created")
    expect(types).toContain("alert_acknowledged")
    expect(types).toContain("alert_started")
    expect(types).toContain("alert_resolved")
    expect(types).toContain("alert_closed")
  })

  test("an invalid transition is rejected and changes nothing", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    const r = await transitionAlert({ alertId: created.id, userId: TENANT, to: "closed", actor: "analyst-1" })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.code).toBe("invalid_transition")
    const rows = (await sql`SELECT state FROM exposure_alerts WHERE id = ${created.id}`) as Array<{ state: string }>
    expect(rows[0].state).toBe("open")
  })

  test("a CLOSED alert cannot be reopened", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "resolved", actor: "a" })
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "closed", actor: "a" })
    for (const to of ["open", "acknowledged", "in_progress"] as const) {
      expect((await transitionAlert({ alertId: created.id, userId: TENANT, to, actor: "a" })).ok).toBe(false)
    }
  })

  test("suppression REQUIRES a valid reason", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    const noReason = await transitionAlert({ alertId: created.id, userId: TENANT, to: "suppressed", actor: "a" })
    expect(noReason.ok).toBe(false)
    if (!noReason.ok) expect(noReason.code).toBe("reason_required")

    const badReason = await transitionAlert({ alertId: created.id, userId: TENANT, to: "suppressed", actor: "a", reason: "because" })
    expect(badReason.ok).toBe(false)

    const ok = await transitionAlert({ alertId: created.id, userId: TENANT, to: "suppressed", actor: "analyst-9", reason: "false_positive" })
    expect(ok.ok).toBe(true)
    const rows = (await sql`SELECT suppressed_reason, suppressed_by FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].suppressed_reason).toBe("false_positive")
    expect(rows[0].suppressed_by).toBe("analyst-9")
  })

  test("suppression does NOT delete the underlying vulnerability", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "critical", 100)
    await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
    const created = await seedAlert()
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "suppressed", actor: "a", reason: "accepted_risk" })
    const vulns = (await sql`SELECT count(*)::int AS n FROM exposure_vulnerability WHERE asset_key = ${KEY} AND status='active'`) as Array<{ n: number }>
    expect(vulns[0].n).toBeGreaterThan(0)
  })

  test("a missing alert reports not_found rather than throwing", async () => {
    if (!dbAvailable) return
    const r = await transitionAlert({ alertId: 999_999_999, userId: TENANT, to: "acknowledged", actor: "a" })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.code).toBe("not_found")
  })

  test("the timeline is deterministically ordered", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    for (const t of ["telegram_queued", "telegram_sent", "ticket_created"] as const) {
      await recordAlertEvent(created.id, TENANT, t, "system")
    }
    const first = (await alertTimeline(created.id, TENANT)).map((e) => `${e.type}:${e.id}`)
    const second = (await alertTimeline(created.id, TENANT)).map((e) => `${e.type}:${e.id}`)
    expect(first).toEqual(second)
    const ids = (await alertTimeline(created.id, TENANT)).map((e) => e.id)
    expect([...ids].sort((x, y) => x - y)).toEqual(ids)
  })

  test("audit metadata never stores a credential", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv(CREDS, async () => {
      await recordAlertEvent(created.id, TENANT, "telegram_failed", "system",
        `failed with token ${CREDS.TELEGRAM_BOT_TOKEN}`, { url: `https://api.telegram.org/bot${CREDS.TELEGRAM_BOT_TOKEN}/sendMessage` })
    })
    const rows = (await sql`SELECT detail, metadata::text AS m FROM exposure_alert_events WHERE alert_id = ${created.id} AND type='telegram_failed'`) as Array<{ detail: string; m: string }>
    const blob = `${rows[0]?.detail ?? ""} ${rows[0]?.m ?? ""}`
    expect(blob).not.toContain(CREDS.TELEGRAM_BOT_TOKEN)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Notification outbox — adapter validation with a fake transport", () => {
  test("a successful delivery is recorded exactly once and does not duplicate the alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, calls } = transportReturning(200)
      const r1 = await runNotificationCycle({ transport, syncTickets: false })
      expect(r1.sent).toBe(1)
      expect(calls).toHaveLength(1)
      // A second cycle has nothing to do: the alert is already 'sent'.
      const r2 = await runNotificationCycle({ transport, syncTickets: false })
      expect(r2.scanned).toBe(0)
      expect(calls).toHaveLength(1)
    })
    const rows = (await sql`SELECT notification_state, notified_at, notified_severity FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].notification_state).toBe("sent")
    expect(rows[0].notified_at).toBeTruthy()
    expect(rows[0].notified_severity).toBe("critical")

    const sentEvents = (await alertTimeline(created.id, TENANT)).filter((e) => e.type === "telegram_sent")
    expect(sentEvents).toHaveLength(1)
    const count = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(count[0].n).toBe(1)
  })

  test("a 429 leaves the alert INTACT and schedules a retry", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = transportReturning(429, JSON.stringify({ description: "Too Many Requests", parameters: { retry_after: 30 } }))
      const r = await runNotificationCycle({ transport, syncTickets: false })
      expect(r.retrying).toBe(1)
      expect(r.sent).toBe(0)
    })
    const rows = (await sql`SELECT state, notification_state, notify_attempts, notify_next_attempt_at, notified_at FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].state).toBe("open")                    // the finding is untouched
    expect(rows[0].notification_state).toBe("retrying")
    expect(rows[0].notify_attempts).toBe(1)
    expect(rows[0].notify_next_attempt_at).toBeTruthy()
    expect(rows[0].notified_at).toBeNull()                // NOT marked delivered
  })

  test("a permanent rejection stops retrying immediately", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = transportReturning(401, JSON.stringify({ description: "Unauthorized" }))
      const r = await runNotificationCycle({ transport, syncTickets: false })
      expect(r.failed).toBe(1)
    })
    const rows = (await sql`SELECT notification_state, notify_next_attempt_at, notify_attempts FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].notification_state).toBe("failed")
    expect(rows[0].notify_next_attempt_at).toBeNull()  // no further attempt scheduled
    expect(rows[0].notify_attempts).toBe(1)            // gave up after one, not five
  })

  test("a retryable failure is capped after MAX_ATTEMPTS", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = transportReturning(503, JSON.stringify({ description: "Service Unavailable" }))
      for (let i = 0; i < 6; i++) {
        await sql`UPDATE exposure_alerts SET notify_next_attempt_at = NULL WHERE id = ${created.id}` // make it due
        await runNotificationCycle({ transport, syncTickets: false })
      }
    })
    const rows = (await sql`SELECT notification_state, notify_attempts FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].notification_state).toBe("failed")
    expect(Number(rows[0].notify_attempts)).toBeLessThanOrEqual(5)
  }, 30_000)

  test("with Telegram unconfigured the alert survives and is marked DISABLED, not failed", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv({ TELEGRAM_BOT_TOKEN: undefined, TELEGRAM_CHAT_ID: undefined }, async () => {
      const r = await runNotificationCycle({ syncTickets: false })
      expect(r.configured).toBe(false)
      expect(r.failed).toBe(0)
    })
    const rows = (await sql`SELECT state, notification_state FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].state).toBe("open")                   // alert intact
    expect(rows[0].notification_state).toBe("disabled")
  })

  test("a SUPPRESSED alert is never delivered", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "suppressed", actor: "a", reason: "maintenance" })
    await withEnv(CREDS, async () => {
      const { transport, calls } = transportReturning(200)
      const r = await runNotificationCycle({ transport, syncTickets: false })
      expect(r.scanned).toBe(0)
      expect(calls).toHaveLength(0)
    })
  })

  // Generous timeout: each seeded alert is several round trips to a remote
  // database, and the worker deliberately paces sends.
  test("the delivery batch is bounded", async () => {
    if (!dbAvailable) return
    await cleanup()
    for (let i = 0; i < 6; i++) await seedAlert({ port: 1000 + i, cve: `CVE-2021-${41000 + i}` })
    await withEnv(CREDS, async () => {
      const { transport } = transportReturning(200)
      const r = await runNotificationCycle({ transport, limit: 2, syncTickets: false })
      expect(r.scanned).toBeLessThanOrEqual(2)
      // The rest stay queued rather than being dropped.
      const pending = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY} AND notification_state = 'pending'`) as Array<{ n: number }>
      expect(pending[0].n).toBeGreaterThan(0)
    })
  }, 30_000)

  test("the stored error never contains the bot token", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = transportReturning(400, JSON.stringify({
        description: `bad request to https://api.telegram.org/bot${CREDS.TELEGRAM_BOT_TOKEN}/sendMessage`,
      }))
      await runNotificationCycle({ transport, syncTickets: false })
    })
    const rows = (await sql`SELECT notify_last_error FROM exposure_alerts WHERE id = ${created.id}`) as Array<{ notify_last_error: string }>
    expect(rows[0].notify_last_error).not.toContain(CREDS.TELEGRAM_BOT_TOKEN)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Ticketing — one work item per finding", () => {
  test("with no provider configured the alert reports ticket state NONE", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv({ TICKETING_PROVIDER: undefined }, async () => {
      expect((await syncTicket(created)).state).toBe("none")
    })
    const rows = (await sql`SELECT ticket_state, ticket_key FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].ticket_state).toBe("none")
    expect(rows[0].ticket_key).toBeNull()   // no ticket is claimed to exist
  })

  test("the internal provider creates a ticket that references the alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv({ TICKETING_PROVIDER: "internal" }, async () => {
      const r = await syncTicket(created)
      expect(r.state).toBe("open")
    })
    const rows = (await sql`SELECT ticket_state, ticket_key, ticket_provider FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].ticket_state).toBe("open")
    expect(String(rows[0].ticket_key)).toStartWith("SOC-")
    const ticket = (await sql`SELECT alert_id, title FROM exposure_tickets WHERE alert_id = ${created.id}`) as Array<Record<string, unknown>>
    expect(ticket[0].alert_id).toBe(created.id)
    expect(String(ticket[0].title)).toContain(CVE)
  })

  test("repeated monitoring UPDATES the existing ticket instead of creating a second", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv({ TICKETING_PROVIDER: "internal" }, async () => {
      await syncTicket(created)
      const withKey = (await sql`SELECT * FROM exposure_alerts WHERE id = ${created.id}`) as AlertRow[]
      const second = await syncTicket(withKey[0])
      expect(second.state).toBe("updated")
    })
    const count = (await sql`SELECT count(*)::int AS n FROM exposure_tickets WHERE alert_id = ${created.id}`) as Array<{ n: number }>
    expect(count[0].n).toBe(1)
  })

  test("a ticket failure does not roll back a successful notification", async () => {
    if (!dbAvailable) return
    await cleanup()
    const created = await seedAlert()
    await withEnv({ ...CREDS, TICKETING_PROVIDER: "internal" }, async () => {
      const { transport } = transportReturning(200)
      await runNotificationCycle({ transport, syncTickets: false })
      // A ticket for an alert that does not exist genuinely fails.
      const failed = await syncTicket({ ...created, id: -1, user_id: TENANT })
      expect(failed.state).toBe("failed")
    })
    const rows = (await sql`SELECT notification_state FROM exposure_alerts WHERE id = ${created.id}`) as Array<Record<string, unknown>>
    expect(rows[0].notification_state).toBe("sent")  // untouched by the ticket failure
    // And the failure created no orphan work item.
    const orphan = (await sql`SELECT count(*)::int AS n FROM exposure_tickets WHERE alert_id <= 0`) as Array<{ n: number }>
    expect(orphan[0].n).toBe(0)
  })
})

describe.skipIf(!HAS_TEST_DB)("cross-tenant isolation", () => {
  test("one tenant cannot transition another tenant's alert", async () => {
    // Seeds its own row: reading whatever happens to be in the table meant an
    // empty result silently turned this into a test that asserted nothing.
    await cleanup()
    const created = await seedAlert()
    const r = await transitionAlert({ alertId: created.id, userId: OTHER, to: "acknowledged", actor: OTHER, reason: null })
    expect(r.ok).toBe(false)
    // "not_found" rather than a distinct "forbidden": a different error would
    // confirm the row exists, which is itself a disclosure.
    if (!r.ok) expect(r.code).toBe("not_found")

    // And the alert really is still untouched.
    const after = (await sql`SELECT state FROM exposure_alerts WHERE id = ${created.id}`) as Array<{ state: string }>
    expect(after[0].state).toBe("open")
    await cleanup()
  }, 30_000)

  test("the timeline of another tenant's alert is empty, not readable", async () => {
    await cleanup()
    const created = await seedAlert()
    await transitionAlert({ alertId: created.id, userId: TENANT, to: "acknowledged", actor: TENANT, reason: null })
    // The owner sees the history; the other tenant sees nothing rather than a
    // redacted version of it.
    expect((await alertTimeline(created.id, TENANT)).length).toBeGreaterThan(0)
    expect((await alertTimeline(created.id, OTHER)).length).toBe(0)
    await cleanup()
  }, 30_000)
})
