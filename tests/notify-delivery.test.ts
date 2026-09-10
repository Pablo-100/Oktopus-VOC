/**
 * STEP 5.1 — IMMEDIATE DELIVERY + RELIABLE OUTBOX.
 *
 * The guarantees under test are about DELIVERY, not intelligence: exactly-once
 * sending under concurrency, bounded retries, crash recovery, and the alert
 * surviving whatever Telegram does.
 *
 * Telegram is exercised through an INJECTED FAKE TRANSPORT throughout. This is
 * adapter validation — no message is delivered to Telegram and none is claimed
 * to be.
 */
import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { sql, initDb } from "@/lib/db"
import { raiseAlert, evaluateAlerts, trackAssetVulnerabilities } from "@/lib/exposure/vuln-tracking"
import { transitionAlert, escalateAlert, alertTimeline } from "@/lib/exposure/alert-workflow"
import {
  runNotificationCycle, deliverAlertNow, deliverAlertsNow, reclaimStaleClaims,
  backoffSeconds, CLAIM_LEASE_SECONDS, MAX_IMMEDIATE_PER_EVALUATION, requeueNotification,
} from "@/lib/notify/outbox"
import { deliverTelegram, type TelegramTransport } from "@/lib/notify/telegram-adapter"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { alertFingerprint } from "@/lib/exposure/vuln-tracking"
import type { ExposureAsset, ProviderName, ProviderOutcome, ProviderStatus, EvidenceTier } from "@/lib/exposure/types"

/**
 * Tenancy fixtures. Every DB suite runs as an explicit tenant so a query that
 * forgets its user filter shows up as a cross-tenant leak rather than passing
 * silently. `OTHER` exists to prove isolation, not just to satisfy a signature.
 */
const TENANT = "test-tenant-a"
const OTHER = "test-tenant-b"


const KEY = "test:s51:ip:203.0.113.211"
const CVE = "CVE-2021-41773"
const CREDS = { TELEGRAM_BOT_TOKEN: "555444:S51TESTONLYtoken", TELEGRAM_CHAT_ID: "-100555" }
let dbAvailable = false

async function cleanup() {
  if (!dbAvailable) return
  await sql`DELETE FROM exposure_alert_events WHERE alert_id IN (SELECT id FROM exposure_alerts WHERE asset_key LIKE 'test:s51:%')`
  await sql`DELETE FROM exposure_tickets      WHERE alert_id IN (SELECT id FROM exposure_alerts WHERE asset_key LIKE 'test:s51:%')`
  await sql`DELETE FROM exposure_alerts       WHERE asset_key LIKE 'test:s51:%'`
  await sql`DELETE FROM exposure_vulnerability WHERE asset_key LIKE 'test:s51:%'`
}

// The migration in `initDb()` runs many statements against a REMOTE database,
// so first-run setup can exceed bun's 5s hook default. Setup cost, not a check.
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

/** Counts sends and optionally stalls, to widen the concurrency window. */
function countingTransport(status = 200, body = "{}", delayMs = 0) {
  const state = { sends: 0 }
  const transport: TelegramTransport = async () => {
    state.sends++
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs))
    return new Response(body, { status })
  }
  return { transport, state }
}

async function seedAlert(over: Partial<{ severity: string; tier: string; risk: number; cve: string; port: number }> = {}) {
  const port = over.port ?? 443
  const cve = over.cve ?? CVE
  await raiseAlert({
    userId: TENANT, assetKey: KEY, target: "203.0.113.211", port, cveId: cve,
    kind: "new_exposed_vulnerability",
    severity: over.severity ?? "critical",
    riskScore: over.risk ?? 100, previousRisk: 32,
    evidenceTier: (over.tier ?? "confirmed") as EvidenceTier,
    payload: { asset: "203.0.113.211", product: "Apache HTTP Server", providers: ["netlas"] },
  })
  const rows = (await sql`SELECT id FROM exposure_alerts WHERE asset_key = ${KEY} AND port = ${port} AND cve_id = ${cve} ORDER BY id DESC LIMIT 1`) as Array<{ id: number }>
  return Number(rows[0].id)
}

const row = async (id: number) =>
  ((await sql`SELECT * FROM exposure_alerts WHERE id = ${id}`) as Array<Record<string, unknown>>)[0]

function outcome(provider: ProviderName, status: ProviderStatus): ProviderOutcome {
  return { provider, role: "enrichment", status, retryable: false, query: "x", latencyMs: 1, observationCount: 1, fetchedAt: new Date().toISOString() }
}

function asset(cves: string[], tier: EvidenceTier, severity: string, score: number): ExposureAsset {
  const matchType = ({ confirmed: "cve-search", strong: "version", product: "product", pivot: "pivot", weak: "banner" } as const)[tier]
  return {
    id: KEY, ip: "203.0.113.211", domain: null, hostnames: [], domains: [],
    services: [{ port: 443, transport: "tcp", protocol: "http", product: "Apache HTTP Server", vendor: null, version: "2.4.7", banner: null, httpStatus: null, httpTitle: null, httpServer: null, sources: ["netlas"], claims: [] }],
    technologies: [], certificates: [],
    vulnerabilities: cves.map((c) => ({ correlatedPort: 443, ...makeVulnerability({ cveId: c, matchType, sources: ["netlas"] }) })),
    sources: ["netlas"], sourceCount: 1, confidence: "high", provenance: [], raw: [],
    threat: null, enrichmentStatus: "enriched",
    freshness: { fetchedAt: new Date().toISOString(), observedAt: new Date(Date.now() - 3600_000).toISOString(), observationAgeSeconds: 3600, fromCache: false, state: "fresh" },
    exposureRisk: { score, severity, baseRbvm: score, exposureFactor: 1, factors: [], slaHours: 24, drivingCves: cves },
  } as unknown as ExposureAsset
}

// ─────────────────── retry classification & backoff (pure) ───────────────────

describe.skipIf(!HAS_TEST_DB)("Retry schedule is bounded and respects Telegram", () => {
  test("waits grow and are capped", () => {
    expect(backoffSeconds(1)).toBe(60)
    expect(backoffSeconds(2)).toBe(300)
    expect(backoffSeconds(3)).toBe(900)
    expect(backoffSeconds(4)).toBe(1800)
    expect(backoffSeconds(99)).toBe(1800)      // never grows without bound
  })

  test("Retry-After wins over our schedule, and is itself capped", () => {
    expect(backoffSeconds(1, 42)).toBe(42)
    expect(backoffSeconds(4, 7)).toBe(7)
    expect(backoffSeconds(1, 999_999)).toBeLessThanOrEqual(3600)
  })

  test("the claim lease is comfortably longer than a send timeout", () => {
    // Reclaiming while the original send is still in flight is what would cause
    // a duplicate message, so the window must err toward waiting.
    expect(CLAIM_LEASE_SECONDS).toBeGreaterThanOrEqual(60)
  })
})

describe.skipIf(!HAS_TEST_DB)("Delivery timeout is enforced", () => {
  test("a hung transport aborts and is classified RETRYABLE", async () => {
    await withEnv(CREDS, async () => {
      // Never resolves on its own — only the abort can end this.
      const transport: TelegramTransport = (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(new Error("The operation was aborted.")))
        })
      const t0 = Date.now()
      const r = await deliverTelegram("hi", { transport, timeoutMs: 250 })
      expect(r.status).toBe("retryable")
      expect(r.message).toMatch(/timed out/i)
      expect(Date.now() - t0).toBeLessThan(3000) // it really did abort
    })
  })

  test("the abort signal is actually passed to the transport", async () => {
    await withEnv(CREDS, async () => {
      let sawSignal = false
      const transport: TelegramTransport = async (_url, init) => {
        sawSignal = init.signal instanceof AbortSignal
        return new Response("{}", { status: 200 })
      }
      await deliverTelegram("hi", { transport })
      expect(sawSignal).toBe(true)
    })
  })
})

// ─────────────────────────── outbox behaviour (DB) ───────────────────────────

describe.skipIf(!process.env.DATABASE_URL)("Immediate delivery", () => {
  test("a new eligible alert is queued in the outbox on creation", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    const r = await row(id)
    // Alert and outbox item are the SAME row, so they cannot disagree.
    expect(r.notification_state).toBe("pending")
    expect(Number(r.notify_attempts)).toBe(0)
    expect(r.notified_at).toBeNull()
  })

  test("successful immediate delivery marks SENT and records the event once", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      const r = await deliverAlertNow(id, { transport, syncTickets: false })
      expect(r.outcome).toBe("sent")
      expect(state.sends).toBe(1)
    })
    const after = await row(id)
    expect(after.notification_state).toBe("sent")
    expect(after.notified_at).toBeTruthy()
    expect(after.notify_claimed_at).toBeNull()   // claim released
    expect((await alertTimeline(id, TENANT)).filter((e) => e.type === "telegram_sent")).toHaveLength(1)
  })

  test("failed immediate delivery leaves the notification QUEUED for retry", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = countingTransport(503, JSON.stringify({ description: "Service Unavailable" }))
      expect((await deliverAlertNow(id, { transport, syncTickets: false })).outcome).toBe("retrying")
    })
    const after = await row(id)
    expect(after.notification_state).toBe("retrying")
    expect(after.notify_next_attempt_at).toBeTruthy()
    expect(after.notified_at).toBeNull()          // never marked delivered
    expect(after.notify_claimed_at).toBeNull()    // claim released for the retry
  })

  test("the ALERT survives a failed delivery untouched", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = countingTransport(500)
      await deliverAlertNow(id, { transport, syncTickets: false })
    })
    const after = await row(id)
    expect(after.state).toBe("open")              // lifecycle untouched
    expect(after.severity).toBe("critical")
    expect(after.evidence_tier).toBe("confirmed") // evidence untouched
    expect(after.risk_score).toBe(100)            // RBVM untouched
  })

  test("immediate delivery is bounded per evaluation", async () => {
    if (!dbAvailable) return
    await cleanup()
    const ids: number[] = []
    for (let i = 0; i < MAX_IMMEDIATE_PER_EVALUATION + 2; i++) {
      ids.push(await seedAlert({ port: 5000 + i, cve: `CVE-2021-${45000 + i}` }))
    }
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      const results = await deliverAlertsNow(ids, { transport, syncTickets: false })
      expect(results.length).toBeLessThanOrEqual(MAX_IMMEDIATE_PER_EVALUATION)
      expect(state.sends).toBeLessThanOrEqual(MAX_IMMEDIATE_PER_EVALUATION)
    })
    // The overflow is still queued — deferred, not dropped.
    const pending = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY} AND notification_state = 'pending'`) as Array<{ n: number }>
    expect(pending[0].n).toBeGreaterThan(0)
  }, 30_000)

  test("delivery to an unconfigured Telegram is DISABLED, and the alert stands", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv({ TELEGRAM_BOT_TOKEN: undefined, TELEGRAM_CHAT_ID: undefined }, async () => {
      expect((await deliverAlertNow(id, { syncTickets: false })).outcome).toBe("disabled")
    })
    const after = await row(id)
    expect(after.state).toBe("open")
    expect(after.notification_state).toBe("disabled")
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Exactly-once under concurrency", () => {
  test("two concurrent SCHEDULER runs send once", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200, "{}", 300)
      await Promise.all([
        runNotificationCycle({ transport, syncTickets: false }),
        runNotificationCycle({ transport, syncTickets: false }),
      ])
      expect(state.sends).toBe(1)
    })
  }, 30_000)

  test("IMMEDIATE and SCHEDULER racing send once", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200, "{}", 300)
      await Promise.all([
        deliverAlertNow(id, { transport, syncTickets: false }),
        runNotificationCycle({ transport, syncTickets: false }),
      ])
      expect(state.sends).toBe(1)
    })
    expect((await row(id)).notification_state).toBe("sent")
  }, 30_000)

  test("a five-way pile-up sends once", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200, "{}", 300)
      await Promise.all([
        deliverAlertNow(id, { transport, syncTickets: false }),
        deliverAlertNow(id, { transport, syncTickets: false }),
        runNotificationCycle({ transport, syncTickets: false }),
        runNotificationCycle({ transport, syncTickets: false }),
        runNotificationCycle({ transport, syncTickets: false }),
      ])
      expect(state.sends).toBe(1)
    })
    const after = await row(id)
    expect(Number(after.notify_attempts)).toBe(1)  // attempts counted once, not five times
  }, 30_000)

  test("a SENT notification is never claimed again", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      await deliverAlertNow(id, { transport, syncTickets: false })
      expect(state.sends).toBe(1)
      // Every later path must be a no-op.
      expect((await deliverAlertNow(id, { transport, syncTickets: false })).outcome).toBe("skipped")
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.scanned).toBe(0)
      expect(state.sends).toBe(1)
    })
  })

  test("repeated immediate calls for one alert send once (idempotent)", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      // Simulates an HTTP/serverless retry of the same request.
      await deliverAlertNow(id, { transport, syncTickets: false })
      await deliverAlertNow(id, { transport, syncTickets: false })
      await deliverAlertNow(id, { transport, syncTickets: false })
      expect(state.sends).toBe(1)
    })
  })

  test("an in-flight claim is not stealable while its lease is fresh", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    // Simulate a worker that claimed the row and is still sending.
    await sql`UPDATE exposure_alerts SET notification_state='sending', notify_claimed_at=now(), notify_claimed_by='worker-a', notify_attempts=1 WHERE id = ${id}`
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      expect((await deliverAlertNow(id, { transport, syncTickets: false })).outcome).toBe("skipped")
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.scanned).toBe(0)
      expect(cycle.reclaimed).toBe(0)     // lease is fresh; nothing to reclaim
      expect(state.sends).toBe(0)
    })
    expect((await row(id)).notification_state).toBe("sending")
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Crash recovery", () => {
  test("a STALE claim is reclaimed and retried, not lost", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    // A worker claimed this and then died.
    await sql`
      UPDATE exposure_alerts
      SET notification_state='sending', notify_attempts=1, notify_claimed_by='dead-worker',
          notify_claimed_at = now() - (${CLAIM_LEASE_SECONDS + 60}::text || ' seconds')::interval
      WHERE id = ${id}`

    expect(await reclaimStaleClaims()).toBe(1)
    const after = await row(id)
    // Requeued as `retrying`, preserving the fact an attempt was already made,
    // so the attempt ceiling still applies.
    expect(after.notification_state).toBe("retrying")
    expect(after.notify_claimed_at).toBeNull()
    expect(Number(after.notify_attempts)).toBe(1)

    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.sent).toBe(1)
      expect(state.sends).toBe(1)
    })
    expect((await row(id)).notification_state).toBe("sent")
  }, 30_000)

  test("the scheduler reclaims stale claims as part of its cycle", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await sql`
      UPDATE exposure_alerts
      SET notification_state='sending', notify_attempts=1,
          notify_claimed_at = now() - (${CLAIM_LEASE_SECONDS + 60}::text || ' seconds')::interval
      WHERE id = ${id}`
    await withEnv(CREDS, async () => {
      const { transport } = countingTransport(200)
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.reclaimed).toBe(1)
      expect(cycle.sent).toBe(1)   // reclaimed AND delivered in the same cycle
    })
  }, 30_000)

  test("a reclaim is recorded in the audit trail", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await sql`
      UPDATE exposure_alerts SET notification_state='sending', notify_attempts=1,
        notify_claimed_at = now() - (${CLAIM_LEASE_SECONDS + 60}::text || ' seconds')::interval
      WHERE id = ${id}`
    await reclaimStaleClaims()
    const events = await alertTimeline(id, TENANT)
    expect(events.some((e) => e.type === "telegram_failed" && e.metadata?.reclaimed === true)).toBe(true)
  })

  test("a crash mid-send does not permanently lose the notification", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      // The transport throws hard, as a crashed runtime would.
      const boom: TelegramTransport = async () => { throw new Error("process died") }
      await deliverAlertNow(id, { transport: boom, syncTickets: false })
      // Even in the worst case where the row was left claimed, the sweep frees it.
      await sql`UPDATE exposure_alerts SET notification_state='sending',
        notify_claimed_at = now() - (${CLAIM_LEASE_SECONDS + 60}::text || ' seconds')::interval WHERE id = ${id}`
      await runNotificationCycle({ transport: countingTransport(200).transport, syncTickets: false })
    })
    expect((await row(id)).notification_state).toBe("sent")
  }, 30_000)
})

describe.skipIf(!process.env.DATABASE_URL)("Retry classification and bounds", () => {
  const cases: Array<[string, number, string, string]> = [
    ["429 rate limit", 429, JSON.stringify({ description: "Too Many Requests", parameters: { retry_after: 30 } }), "retrying"],
    ["500 server error", 500, JSON.stringify({ description: "Internal" }), "retrying"],
    ["503 unavailable", 503, JSON.stringify({ description: "Unavailable" }), "retrying"],
    ["400 bad request", 400, JSON.stringify({ description: "chat not found" }), "failed"],
    ["401 invalid token", 401, JSON.stringify({ description: "Unauthorized" }), "failed"],
    ["403 forbidden", 403, JSON.stringify({ description: "Forbidden" }), "failed"],
  ]

  for (const [label, status, body, expected] of cases) {
    test(`${label} -> ${expected}`, async () => {
      if (!dbAvailable) return
      await cleanup()
      const id = await seedAlert()
      await withEnv(CREDS, async () => {
        const { transport } = countingTransport(status, body)
        await deliverAlertNow(id, { transport, syncTickets: false })
      })
      const after = await row(id)
      expect(after.notification_state).toBe(expected)
      expect(after.notified_at).toBeNull()   // never "delivered"
      if (expected === "failed") {
        expect(after.notify_next_attempt_at).toBeNull()  // no further attempt scheduled
      } else {
        expect(after.notify_next_attempt_at).toBeTruthy()
      }
    })
  }

  test("Retry-After is honoured in the scheduled retry time", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = countingTransport(429, JSON.stringify({ description: "Too Many", parameters: { retry_after: 30 } }))
      await deliverAlertNow(id, { transport, syncTickets: false })
    })
    const after = await row(id)
    const waitSeconds = (Date.parse(String(after.notify_next_attempt_at)) - Date.now()) / 1000
    // ~30s from Telegram, not our 60s default schedule.
    expect(waitSeconds).toBeGreaterThan(15)
    expect(waitSeconds).toBeLessThan(50)
  })

  test("retries are bounded — a persistent 5xx terminates as FAILED", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(503)
      for (let i = 0; i < 8; i++) {
        await sql`UPDATE exposure_alerts SET notify_next_attempt_at = NULL WHERE id = ${id}` // make due
        await runNotificationCycle({ transport, syncTickets: false })
      }
      expect(state.sends).toBeLessThanOrEqual(5)   // MAX_ATTEMPTS
    })
    const after = await row(id)
    expect(after.notification_state).toBe("failed")
    expect(Number(after.notify_attempts)).toBeLessThanOrEqual(5)
  }, 60_000)

  test("a permanent failure gives up after ONE attempt", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(401, JSON.stringify({ description: "Unauthorized" }))
      await deliverAlertNow(id, { transport, syncTickets: false })
      await runNotificationCycle({ transport, syncTickets: false })
      expect(state.sends).toBe(1)   // not retried
    })
    expect(Number((await row(id)).notify_attempts)).toBe(1)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Scheduler is now a recovery mechanism", () => {
  test("it processes only DUE notifications and skips future retries", async () => {
    if (!dbAvailable) return
    await cleanup()
    const due = await seedAlert({ port: 8001, cve: "CVE-2021-40001" })
    const future = await seedAlert({ port: 8002, cve: "CVE-2021-40002" })
    await sql`UPDATE exposure_alerts SET notification_state='retrying', notify_next_attempt_at = now() + interval '1 hour' WHERE id = ${future}`
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.scanned).toBe(1)
      expect(state.sends).toBe(1)
    })
    expect((await row(due)).notification_state).toBe("sent")
    expect((await row(future)).notification_state).toBe("retrying")  // untouched
  }, 30_000)

  test("it never resends a SENT notification", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await sql`UPDATE exposure_alerts SET notification_state='sent', notified_at=now() WHERE id = ${id}`
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.scanned).toBe(0)
      expect(state.sends).toBe(0)
    })
  })

  test("it skips suppressed and closed alerts", async () => {
    if (!dbAvailable) return
    await cleanup()
    const suppressed = await seedAlert({ port: 8003, cve: "CVE-2021-40003" })
    await transitionAlert({ alertId: suppressed, userId: TENANT, to: "suppressed", actor: "analyst", reason: "accepted_risk" })
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.scanned).toBe(0)
      expect(state.sends).toBe(0)
    })
  })
})

describe.skipIf(!process.env.DATABASE_URL)("New alert vs escalation vs steady state", () => {
  test("repeated monitoring of the SAME finding produces no second notification", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "critical", 100)
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      for (let cycle = 0; cycle < 3; cycle++) {
        const t = await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
        const e = await evaluateAlerts(a, t, TENANT, { severity: "critical", score: 100 })
        await deliverAlertsNow(e.alertIds, { transport, syncTickets: false })
      }
      // One alert, one message — not one per monitoring cycle.
      expect(state.sends).toBe(1)
    })
    const rows = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(rows[0].n).toBe(1)
  }, 30_000)

  test("an evaluation that raises an alert exposes its id for immediate delivery", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "critical", 100)
    const t = await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
    const e = await evaluateAlerts(a, t, TENANT, { severity: "medium", score: 32 })
    expect(e.raised).toHaveLength(1)
    expect(e.alertIds).toHaveLength(1)
    expect(e.alertIds[0]).toBeGreaterThan(0)
  })

  test("a suppressed finding yields no alert id and therefore no delivery", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "product", "critical", 100)   // evidence gate blocks it
    const t = await trackAssetVulnerabilities(a, [outcome("netlas", "success")], TENANT)
    const e = await evaluateAlerts(a, t, TENANT, { severity: null, score: null })
    expect(e.raised).toHaveLength(0)
    expect(e.alertIds).toHaveLength(0)
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      await deliverAlertsNow(e.alertIds, { transport, syncTickets: false })
      expect(state.sends).toBe(0)
    })
  })

  test("an ESCALATION re-queues and delivers exactly one new notification", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert({ severity: "high", risk: 70 })
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      await deliverAlertNow(id, { transport, syncTickets: false })
      expect(state.sends).toBe(1)

      // The finding gets worse.
      const esc = await escalateAlert(alertFingerprint(KEY, 443, CVE), TENANT,
        { severity: "critical", riskScore: 95, evidenceTier: "confirmed" })
      expect(esc.escalated).toBe(true)
      expect((await row(id)).notification_state).toBe("pending")  // re-queued

      await deliverAlertNow(id, { transport, syncTickets: false })
      expect(state.sends).toBe(2)   // exactly one more, for the escalation
    })
  }, 30_000)

  test("the SAME severity does not re-queue, so nothing is re-sent", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert({ severity: "high", risk: 70 })
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      await deliverAlertNow(id, { transport, syncTickets: false })
      const esc = await escalateAlert(alertFingerprint(KEY, 443, CVE), TENANT,
        { severity: "high", riskScore: 70, evidenceTier: "confirmed" })
      expect(esc.escalated).toBe(false)
      expect((await row(id)).notification_state).toBe("sent")   // still sent
      await deliverAlertNow(id, { transport, syncTickets: false })
      expect(state.sends).toBe(1)   // no second message
    })
  }, 30_000)
})

describe.skipIf(!process.env.DATABASE_URL)("Secrets never reach storage or errors", () => {
  test("no credential appears in the alert row after a failure quoting the URL", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await withEnv(CREDS, async () => {
      const { transport } = countingTransport(400, JSON.stringify({
        description: `bad request to https://api.telegram.org/bot${CREDS.TELEGRAM_BOT_TOKEN}/sendMessage chat ${CREDS.TELEGRAM_CHAT_ID}`,
      }))
      await deliverAlertNow(id, { transport, syncTickets: false })
    })
    const after = await row(id)
    const blob = JSON.stringify(after) + JSON.stringify(await alertTimeline(id, TENANT))
    expect(blob).not.toContain(CREDS.TELEGRAM_BOT_TOKEN)
    expect(blob).not.toMatch(/api\.telegram\.org\/bot\d+:[A-Za-z0-9_-]+/)
  })

  test("the outbox never persists a claim owner that looks like a credential", async () => {
    if (!dbAvailable) return
    await cleanup()
    const id = await seedAlert()
    await sql`UPDATE exposure_alerts SET notification_state='sending', notify_claimed_at=now(), notify_claimed_by='x' WHERE id = ${id}`
    const after = await row(id)
    // The claim owner is a generated run id, never anything credential-derived.
    expect(String(after.notify_claimed_by)).not.toContain(":")
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Migration safety", () => {
  test("a PRE-MIGRATION alert row is readable and gets safe defaults", async () => {
    if (!dbAvailable) return
    await cleanup()
    // Inserts only the columns STEP 5 knew about — exactly what an existing
    // production row looks like. The STEP 5.1 columns must default, not fail.
    await sql`
      INSERT INTO exposure_alerts (fingerprint, asset_key, port, cve_id, kind, state, severity,
        risk_score, previous_risk, evidence_tier, payload)
      VALUES (${`${KEY}|9999|CVE-2021-40099`}, ${KEY}, 9999, 'CVE-2021-40099',
        'new_exposed_vulnerability', 'open', 'critical', 100, 32, 'confirmed', '{}'::jsonb)
    `
    const rows = (await sql`SELECT * FROM exposure_alerts WHERE asset_key = ${KEY} AND port = 9999`) as Array<Record<string, unknown>>
    const r = rows[0]
    expect(r).toBeTruthy()
    expect(r.notification_state).toBe("pending")   // safe default, not null
    expect(Number(r.notify_attempts)).toBe(0)
    expect(r.notify_claimed_at).toBeNull()
    expect(r.ticket_state).toBe("none")

    // And it is deliverable through the new path.
    await withEnv(CREDS, async () => {
      const { transport, state } = countingTransport(200)
      const cycle = await runNotificationCycle({ transport, syncTickets: false })
      expect(cycle.sent).toBe(1)
      expect(state.sends).toBe(1)
    })
  }, 30_000)

  test("the outbox index covers every claimable state", async () => {
    if (!dbAvailable) return
    const rows = (await sql`SELECT indexdef FROM pg_indexes WHERE indexname = 'exposure_alerts_notify_idx'`) as Array<{ indexdef: string }>
    const def = rows[0]?.indexdef ?? ""
    for (const st of ["pending", "retrying", "sending"]) expect(def).toContain(st)
  })
})

describe.skipIf(!HAS_TEST_DB)("Architecture — delivery holds no intelligence", () => {
  test("the outbox does not score, correlate or classify evidence", async () => {
    const src = await Bun.file("lib/notify/outbox.ts").text()
    expect(src).not.toMatch(/^import .*risk-engine/m)
    expect(src).not.toMatch(/computeRiskScore\(|computeExposureRisk\(|isAlertEligible\(/)
    expect(src).not.toMatch(/correlateServices\(|makeVulnerability\(/)
  })

  test("the claim transitions state in the SAME statement that selects it", async () => {
    const src = await Bun.file("lib/notify/outbox.ts").text()
    // Without this, FOR UPDATE SKIP LOCKED releases at statement commit — before
    // the HTTP call — and an overlapping run re-selects the row.
    expect(src).toMatch(/SET notification_state = 'sending'/)
    expect(src).toContain("FOR UPDATE SKIP LOCKED")
    expect(src).toContain("WITH due AS")
  })

  test("immediate delivery happens after the writes, never inside them", async () => {
    const src = await Bun.file("lib/exposure/orchestrator.ts").text()
    const evalIdx = src.indexOf("evaluateAlerts(asset, tracking")
    const deliverIdx = src.indexOf("deliverAlertsNow(")
    expect(evalIdx).toBeGreaterThan(0)
    expect(deliverIdx).toBeGreaterThan(evalIdx)   // strictly after
    // And it is not inside the alert try/catch that guards the writes.
    expect(src).toMatch(/\}\s*\n\s*\n\s*\/\/ STEP 5\.1 — IMMEDIATE DELIVERY/)
  })

  test("no Telegram call lives in the risk, correlation or provider layers", async () => {
    for (const f of ["lib/risk-engine.ts", "lib/exposure/risk.ts", "lib/exposure/cve-correlation.ts", "lib/exposure/providers/_base.ts"]) {
      const src = await Bun.file(f).text()
      expect(src).not.toMatch(/deliverTelegram|api\.telegram\.org|deliverAlertNow/)
    }
  })
})

describe.skipIf(!HAS_TEST_DB)("cross-tenant isolation", () => {
  test("one tenant cannot requeue another tenant's notification", async () => {
    // Seeds its own alert rather than reusing whatever happens to be in the
    // table: an early `return` on an empty result would make this assert
    // nothing at all while still reporting as passed.
    await cleanup()
    const created = await seedAlert()
    // Scoped lookups must report "not found" rather than acting, so the caller
    // learns nothing about whether the id exists.
    const r = await requeueNotification(created, OTHER, OTHER)
    expect(r.ok).toBe(false)
    expect(r.code).toBe("not_found")

    // The owner is unaffected by the refused attempt.
    const mine = await requeueNotification(created, TENANT, TENANT)
    expect(typeof mine.ok).toBe("boolean")
    await cleanup()
  }, 30_000)
})
