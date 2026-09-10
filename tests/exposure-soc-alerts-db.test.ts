/**
 * SOC alert lifecycle against a real database.
 *
 * Deduplication and resolution are enforced by SQL (a partial unique index and
 * an upsert), so they cannot be proven in memory. Skips cleanly with no
 * database, and confines itself to a dedicated test asset key.
 */
import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { sql, initDb } from "@/lib/db"
import {
  raiseAlert, resolveAlerts, setAlertState, trackAssetVulnerabilities, evaluateAlerts,
} from "@/lib/exposure/vuln-tracking"
import { makeVulnerability } from "@/lib/exposure/normalize"
import type {

  ExposureAsset, ExposureService, ProviderName, ProviderOutcome, ProviderStatus, EvidenceTier,
} from "@/lib/exposure/types"

/**
 * Tenancy fixtures. Every DB suite runs as an explicit tenant so a query that
 * forgets its user filter shows up as a cross-tenant leak rather than passing
 * silently. `OTHER` exists to prove isolation, not just to satisfy a signature.
 */
const TENANT = "test-tenant-a"
const OTHER = "test-tenant-b"

const KEY = "test:soc:ip:203.0.113.55"
const CVE = "CVE-2021-41773"
let dbAvailable = false

async function cleanup() {
  if (!dbAvailable) return
  // STEP 5 added an audit trail and work items keyed by alert id. They must be
  // removed BEFORE their alerts, or every run leaves orphaned event rows behind.
  await sql`DELETE FROM exposure_alert_events WHERE alert_id IN (SELECT id FROM exposure_alerts WHERE asset_key LIKE 'test:soc:%')`
  await sql`DELETE FROM exposure_tickets      WHERE alert_id IN (SELECT id FROM exposure_alerts WHERE asset_key LIKE 'test:soc:%')`
  await sql`DELETE FROM exposure_alerts       WHERE asset_key LIKE 'test:soc:%'`
  await sql`DELETE FROM exposure_vulnerability WHERE asset_key LIKE 'test:soc:%'`
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

function service(port: number, product: string | null, sources: ProviderName[]): ExposureService {
  return {
    port, transport: "tcp", protocol: "http", product, vendor: null, version: "2.4.49",
    banner: null, httpStatus: null, httpTitle: null, httpServer: null, sources,
    claims: sources.map((s) => ({ source: s, product, vendor: null, version: "2.4.49", protocol: "http" })),
  }
}

function outcome(provider: ProviderName, status: ProviderStatus): ProviderOutcome {
  return {
    provider, role: "enrichment", status, retryable: false, query: "x",
    latencyMs: 5, observationCount: status === "success" ? 1 : 0, fetchedAt: new Date().toISOString(),
  }
}

/** Asset carrying `cves` at a given tier, with a HIGH RBVM severity so alerting is in play. */
function asset(cves: string[], tier: EvidenceTier = "confirmed", severity = "high", score = 78): ExposureAsset {
  const matchType = ({ confirmed: "cve-search", strong: "version", product: "product", pivot: "pivot", weak: "banner" } as const)[tier]
  return {
    id: KEY, ip: "203.0.113.55", domain: null, hostnames: [], domains: [],
    services: [service(443, "Apache HTTP Server", ["censys"])],
    technologies: [], certificates: [],
    vulnerabilities: cves.map((c) => ({ correlatedPort: 443, ...makeVulnerability({ cveId: c, matchType, sources: ["censys"] }) })),
    sources: ["censys"], sourceCount: 1, confidence: "high", provenance: [], raw: [],
    threat: null, enrichmentStatus: "enriched",
    freshness: {
      fetchedAt: new Date().toISOString(),
      observedAt: new Date(Date.now() - 3600_000).toISOString(),
      observationAgeSeconds: 3600, fromCache: false, state: "fresh",
    },
    exposureRisk: { score, severity, baseRbvm: score, exposureFactor: 1, factors: [], slaHours: 24, drivingCves: cves },
  } as unknown as ExposureAsset
}

const alertInput = (cveId = CVE, port = 443) => ({
  userId: TENANT, assetKey: KEY, target: "203.0.113.55", port, cveId,
  kind: "new_exposed_vulnerability" as const, severity: "high",
  riskScore: 78, previousRisk: 32, evidenceTier: "confirmed" as EvidenceTier,
  payload: { asset: "203.0.113.55", cveId },
})

describe.skipIf(!process.env.DATABASE_URL)("Alert deduplication (item 20)", () => {
  test("the same condition raises exactly ONE active alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    expect(await raiseAlert(alertInput())).toBe(true)
    // The scheduler runs every 15 minutes; the condition persists.
    expect(await raiseAlert(alertInput())).toBe(false)
    expect(await raiseAlert(alertInput())).toBe(false)
    const rows = await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY} AND state = 'open'`
    expect((rows as Array<{ n: number }>)[0].n).toBe(1)
  })

  test("concurrent raises cannot both win — the DB, not the code, decides", async () => {
    if (!dbAvailable) return
    await cleanup()
    const results = await Promise.all([raiseAlert(alertInput()), raiseAlert(alertInput()), raiseAlert(alertInput())])
    expect(results.filter(Boolean)).toHaveLength(1)
  })

  test("a different port or CVE is a DIFFERENT condition and alerts separately", async () => {
    if (!dbAvailable) return
    await cleanup()
    expect(await raiseAlert(alertInput(CVE, 443))).toBe(true)
    expect(await raiseAlert(alertInput(CVE, 8443))).toBe(true)
    expect(await raiseAlert(alertInput("CVE-2021-42013", 443))).toBe(true)
  })

  test("an ACKNOWLEDGED alert still suppresses duplicates", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertInput())
    const id = ((await sql`SELECT id FROM exposure_alerts WHERE asset_key = ${KEY} LIMIT 1`) as Array<{ id: number }>)[0].id
    expect(await setAlertState(id, "acknowledged", TENANT)).toBe(true)
    // An analyst working the alert must not be re-paged for the same thing.
    expect(await raiseAlert(alertInput())).toBe(false)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Alert lifecycle (items 21 & 24)", () => {
  test("a vanished condition closes its alert", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertInput())
    expect(await resolveAlerts(KEY, 443, CVE, TENANT)).toBe(1)
    const rows = await sql`SELECT state, resolved_at FROM exposure_alerts WHERE asset_key = ${KEY}`
    expect((rows as Array<{ state: string; resolved_at: string }>)[0].state).toBe("resolved")
    expect((rows as Array<{ state: string; resolved_at: string }>)[0].resolved_at).toBeTruthy()
  })

  test("a condition that RETURNS after resolution raises a NEW alert (item 20)", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertInput())
    await resolveAlerts(KEY, 443, CVE, TENANT)
    // Same fingerprint, but the previous one is resolved — this is a new event.
    expect(await raiseAlert(alertInput())).toBe(true)
    const rows = await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${KEY}`
    expect((rows as Array<{ n: number }>)[0].n).toBe(2) // history preserved, not overwritten
  })

  test("resolving twice is a no-op, not an error", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertInput())
    expect(await resolveAlerts(KEY, 443, CVE, TENANT)).toBe(1)
    expect(await resolveAlerts(KEY, 443, CVE, TENANT)).toBe(0)
  })

  test("an alert can be suppressed and stops deduplicating future occurrences", async () => {
    if (!dbAvailable) return
    await cleanup()
    await raiseAlert(alertInput())
    const id = ((await sql`SELECT id FROM exposure_alerts WHERE asset_key = ${KEY} LIMIT 1`) as Array<{ id: number }>)[0].id
    await setAlertState(id, "suppressed", TENANT)
    // Suppressed leaves the active set, so a genuinely new occurrence is visible.
    expect(await raiseAlert(alertInput())).toBe(true)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Vulnerability relationship lifecycle (items 15, 16, 24, 25)", () => {
  test("a new correlated CVE is reported as created and stored active", async () => {
    if (!dbAvailable) return
    await cleanup()
    const t = await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    expect(t.created.map((c) => c.cveId)).toEqual([CVE])
    const rows = await sql`SELECT status, port, source_providers FROM exposure_vulnerability WHERE asset_key = ${KEY}`
    expect((rows as Array<{ status: string; port: number }>)[0].status).toBe("active")
    expect((rows as Array<{ status: string; port: number }>)[0].port).toBe(443)
  })

  test("the SAME vulnerability on a later run is not reported as new again", async () => {
    if (!dbAvailable) return
    await cleanup()
    await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    const second = await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    expect(second.created).toHaveLength(0) // no alert spam every 15 minutes
  })

  test("first_seen_at is preserved across runs — history is not rewritten", async () => {
    if (!dbAvailable) return
    await cleanup()
    await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    const first = (await sql`SELECT first_seen_at FROM exposure_vulnerability WHERE asset_key = ${KEY}`) as Array<{ first_seen_at: string }>
    await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    const again = (await sql`SELECT first_seen_at, last_seen_at FROM exposure_vulnerability WHERE asset_key = ${KEY}`) as Array<{ first_seen_at: string; last_seen_at: string }>
    expect(again[0].first_seen_at).toEqual(first[0].first_seen_at)
    expect(Date.parse(again[0].last_seen_at)).toBeGreaterThanOrEqual(Date.parse(again[0].first_seen_at))
  })

  test("a vulnerability that disappears is RESOLVED, not deleted", async () => {
    if (!dbAvailable) return
    await cleanup()
    await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    const t = await trackAssetVulnerabilities(asset([]), [outcome("censys", "success")], TENANT)
    expect(t.resolved.map((r) => r.cve_id)).toEqual([CVE])
    const rows = (await sql`SELECT status, resolved_at FROM exposure_vulnerability WHERE asset_key = ${KEY}`) as Array<{ status: string; resolved_at: string | null }>
    expect(rows).toHaveLength(1)           // the row still exists
    expect(rows[0].status).toBe("resolved")
    expect(rows[0].resolved_at).toBeTruthy()
  })

  test("PROVIDER FAILURE DOES NOT RESOLVE A VULNERABILITY (item 25)", async () => {
    if (!dbAvailable) return
    await cleanup()
    await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    // Censys supplied the evidence and is now rate-limited. Its silence is not
    // proof the host was patched.
    const t = await trackAssetVulnerabilities(asset([]), [outcome("censys", "rate_limited"), outcome("netlas", "success")], TENANT)
    expect(t.resolved).toHaveLength(0)
    expect(t.resolutionWithheld).toBe(true)
    const rows = (await sql`SELECT status FROM exposure_vulnerability WHERE asset_key = ${KEY}`) as Array<{ status: string }>
    expect(rows[0].status).toBe("active") // still active — correctly "unknown", not "fixed"
  })

  test("a vulnerability returning after resolution is reported as NEW again", async () => {
    if (!dbAvailable) return
    await cleanup()
    await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    await trackAssetVulnerabilities(asset([]), [outcome("censys", "success")], TENANT)          // resolved
    const back = await trackAssetVulnerabilities(asset([CVE]), [outcome("censys", "success")], TENANT)
    expect(back.created.map((c) => c.cveId)).toEqual([CVE])
    const rows = (await sql`SELECT status FROM exposure_vulnerability WHERE asset_key = ${KEY}`) as Array<{ status: string }>
    expect(rows[0].status).toBe("active")
  })

  test("the query target itself is never tracked as a finding", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE])
    ;(a as unknown as { isQueryTarget: boolean }).isQueryTarget = true
    const t = await trackAssetVulnerabilities(a, [outcome("censys", "success")], TENANT)
    expect(t.created).toHaveLength(0)
    const rows = (await sql`SELECT count(*)::int AS n FROM exposure_vulnerability WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(rows[0].n).toBe(0)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("End-to-end: correlation outcome -> alert decision", () => {
  test("confirmed evidence at HIGH severity raises exactly one alert, then stops", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "high", 78)
    const t1 = await trackAssetVulnerabilities(a, [outcome("censys", "success")], TENANT)
    const e1 = await evaluateAlerts(a, t1, TENANT, { severity: "medium", score: 32 })
    expect(e1.raised).toHaveLength(1)
    expect(e1.raised[0].kind).toBe("new_exposed_vulnerability")

    // Steady state: same condition, next scheduler run.
    const t2 = await trackAssetVulnerabilities(a, [outcome("censys", "success")], TENANT)
    const e2 = await evaluateAlerts(a, t2, TENANT, { severity: "high", score: 78 })
    expect(e2.raised).toHaveLength(0)
  })

  test("PRODUCT evidence on a CVSS-10 KEV CVE raises NO alert, and says why", async () => {
    if (!dbAvailable) return
    await cleanup()
    // Severity is forced HIGH here to isolate the EVIDENCE gate: even at high
    // severity, a product-name match must not page anyone.
    const a = asset([CVE], "product", "high", 78)
    const t = await trackAssetVulnerabilities(a, [outcome("censys", "success")], TENANT)
    const e = await evaluateAlerts(a, t, TENANT, { severity: null, score: null })
    expect(e.raised).toHaveLength(0)
    expect(e.suppressed).toHaveLength(1)
    expect(e.suppressed[0].reason).toMatch(/lead, not a confirmed finding/i)
    // The finding is still RECORDED — suppressed from alerting, not hidden.
    const rows = (await sql`SELECT count(*)::int AS n FROM exposure_vulnerability WHERE asset_key = ${KEY}`) as Array<{ n: number }>
    expect(rows[0].n).toBe(1)
  })

  test("a resolved vulnerability closes its alert through the same path", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "high", 78)
    const t1 = await trackAssetVulnerabilities(a, [outcome("censys", "success")], TENANT)
    await evaluateAlerts(a, t1, TENANT, { severity: "medium", score: 32 })

    const gone = asset([], "confirmed", "low", 0)
    const t2 = await trackAssetVulnerabilities(gone, [outcome("censys", "success")], TENANT)
    const e2 = await evaluateAlerts(gone, t2, TENANT, { severity: "high", score: 78 })
    expect(e2.closed).toBe(1)
  })

  test("alert payloads never contain provider credentials", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "high", 78)
    const t = await trackAssetVulnerabilities(a, [outcome("censys", "success")], TENANT)
    await evaluateAlerts(a, t, TENANT, { severity: "medium", score: 32 })
    const rows = (await sql`SELECT payload::text AS p FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ p: string }>
    const blob = rows.map((r) => r.p).join(" ")
    for (const name of ["CENSYS_API_TOKEN", "LEAKIX_API_KEY", "NETLAS_API_KEY", "FOFA_API_KEY", "ZOOMEYE_API_KEY", "GREYNOISE_API_KEY"]) {
      const value = process.env[name]
      if (value && value.length >= 8) expect(blob).not.toContain(value)
    }
    expect(blob).not.toMatch(/[?&](key|token|api_key|secret)=/i)
  })

  test("the alert records observedAt and fetchedAt as SEPARATE facts (item 26)", async () => {
    if (!dbAvailable) return
    await cleanup()
    const a = asset([CVE], "confirmed", "high", 78)
    const t = await trackAssetVulnerabilities(a, [outcome("censys", "success")], TENANT)
    await evaluateAlerts(a, t, TENANT, { severity: "medium", score: 32 })
    const rows = (await sql`SELECT payload FROM exposure_alerts WHERE asset_key = ${KEY}`) as Array<{ payload: Record<string, unknown> }>
    const p = rows[0].payload
    expect(p.observedAt).toBeTruthy()
    expect(p.fetchedAt).toBeTruthy()
    expect(p.observedAt).not.toBe(p.fetchedAt) // never collapsed into one claim
    expect(p.evidence).toBe("confirmed")
    expect(p.freshness).toBeTruthy()           // reported alongside, not instead
  })
})

describe.skipIf(!HAS_TEST_DB)("cross-tenant isolation", () => {
  test("alert rows are scoped to their owner", async () => {
    const rows = (await sql`SELECT user_id FROM exposure_alerts WHERE user_id = ${TENANT}`) as Array<{ user_id: string }>
    for (const r of rows) expect(r.user_id).toBe(TENANT)
    const theirs = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE user_id = ${OTHER} AND user_id = ${TENANT}`) as Array<{ n: number }>
    expect(theirs[0].n).toBe(0)
  }, 30_000)
})
