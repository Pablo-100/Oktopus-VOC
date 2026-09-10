/**
 * EXPOSURE GRAPH — assembly from persisted records, against a real database.
 *
 * Exercises `loadGraphFromStore` (the exact function the route calls) rather
 * than re-implementing its queries in the test, so a change to the real query
 * is caught here instead of being quietly mirrored.
 *
 * Skips cleanly with no database. All rows it writes use a dedicated
 * `test:graph:` prefix and are removed afterwards.
 */
import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { sql, initDb } from "@/lib/db"
import { loadGraphFromStore } from "@/lib/exposure/graph-data"
import type { AssetSnapshot } from "@/lib/exposure/changes"

/**
 * Tenancy fixtures. Every DB suite runs as an explicit tenant so a query that
 * forgets its user filter shows up as a cross-tenant leak rather than passing
 * silently. `OTHER` exists to prove isolation, not just to satisfy a signature.
 */
const TENANT = "test-tenant-a"
const OTHER = "test-tenant-b"


const PREFIX = "test:graph:"
const A = `${PREFIX}ip:104.20.23.154`
const B = `${PREFIX}ip:172.66.147.243`
let dbAvailable = false

async function cleanup() {
  if (!dbAvailable) return
  await sql`DELETE FROM exposure_alerts WHERE asset_key LIKE ${PREFIX + "%"}`
  await sql`DELETE FROM exposure_vulnerability WHERE asset_key LIKE ${PREFIX + "%"}`
  await sql`DELETE FROM exposure_asset_state WHERE asset_key LIKE ${PREFIX + "%"}`
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

async function seedState(assetKey: string, snapshot: AssetSnapshot) {
  await sql`
    INSERT INTO exposure_asset_state (user_id, asset_key, snapshot, updated_at)
    VALUES (${TENANT}, ${assetKey}, ${JSON.stringify(snapshot)}::jsonb, now())
    ON CONFLICT (user_id, asset_key) DO UPDATE SET snapshot = EXCLUDED.snapshot, updated_at = now()
  `
}

async function seedVuln(assetKey: string, port: number, cveId: string, opts: {
  tier?: string; matchType?: string; providers?: string[]; product?: string | null; observedAt?: string
} = {}) {
  await sql`
    INSERT INTO exposure_vulnerability (
      user_id, asset_key, port, cve_id, evidence_tier, confirmed, match_type, source_providers,
      product, version, matched_via, observed_at, fetched_at, risk_score, severity, status
    ) VALUES (
      ${TENANT}, ${assetKey}, ${port}, ${cveId}, ${opts.tier ?? "product"}, false,
      ${opts.matchType ?? "product"}, ${(opts.providers ?? ["netlas"]) as unknown as string[]},
      ${opts.product ?? "Apache HTTP Server"}, '2.4.7', 'test fixture',
      ${opts.observedAt ?? "2026-08-21T00:00:00.000Z"}::timestamptz, now(), 30.9, 'medium', 'active'
    )
    ON CONFLICT (user_id, asset_key, port, cve_id) DO NOTHING
  `
}

/**
 * `loadGraphFromStore` selects the highest-risk assets first, so fixtures use a
 * high default riskScore. With 0 they would sort last and could fall outside
 * the window once the table holds enough real rows — a latent ordering
 * dependency rather than a property worth testing.
 */
const snapshot = (over: Partial<AssetSnapshot> = {}): AssetSnapshot => ({
  services: [], domains: [], certificateFingerprints: [], cveIds: [], sources: [], riskScore: 99, ...over,
})

describe.skipIf(!process.env.DATABASE_URL)("Persisted graph assembly", () => {
  test("with nothing stored the graph is empty and says so", async () => {
    if (!dbAvailable) return
    await cleanup()
    // Scoped to a key that cannot exist, so real data does not affect the assertion.
    const r = await loadGraphFromStore(TENANT, { assetKey: `${PREFIX}nonexistent` })
    expect(r.empty).toBe(true)
    expect(r.graph.nodes).toHaveLength(0)
    expect(r.graph.edges).toHaveLength(0)
  })

  test("a stored asset becomes an IP node carrying its persisted providers and risk", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({
      services: [{ port: 443, product: "Apache HTTP Server", version: "2.4.7" }],
      domains: ["example.com"], sources: ["censys", "netlas"], riskScore: 30.9,
    }))
    const { graph } = await loadGraphFromStore(TENANT, { assetKey: A })
    const ip = graph.nodes.find((n) => n.type === "ip")!
    expect(ip.id).toBe(A)
    expect(ip.metadata.providers).toEqual(["censys", "netlas"])
    expect(ip.metadata.riskScore).toBe(30.9)
    // Severity comes from the RBVM engine's bands, not a second definition.
    expect(ip.metadata.severity).toBe("medium")
  })

  test("multiple IPs behind one domain stay separate nodes joined by RESOLVES_TO", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ domains: ["example.com"], sources: ["censys"] }))
    await seedState(B, snapshot({ domains: ["example.com"], sources: ["leakix"] }))
    const { graph } = await loadGraphFromStore(TENANT, { limit: 150 })
    const mine = graph.nodes.filter((n) => n.type === "ip" && n.id.startsWith(PREFIX))
    // Both fixtures are high-risk, so they are deterministically in the window.
    expect(mine).toHaveLength(2)
    const domainEdges = graph.edges.filter((e) => e.kind === "resolves_to" && e.target.startsWith(PREFIX))
    expect(domainEdges).toHaveLength(2)
    expect(new Set(domainEdges.map((e) => e.source)).size).toBe(1) // one shared domain
  })

  test("a stored vulnerability becomes an AFFECTED_BY edge at its real tier", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({
      services: [{ port: 443, product: "Apache HTTP Server", version: "2.4.7" }], sources: ["netlas"],
    }))
    await seedVuln(A, 443, "CVE-2021-41773", { tier: "product", matchType: "product" })
    const { graph } = await loadGraphFromStore(TENANT, { assetKey: A })
    const edge = graph.edges.find((e) => e.kind === "affected_by")!
    expect(edge.evidenceTier).toBe("product")
    expect(edge.metadata?.confirmed).toBe(false)
    // Anchored at the version, because the stored service has product + version.
    expect(edge.source).toBe("version:apache http server:2.4.7")
  })

  test("the tier is re-derived from match_type, so a corrupted row cannot claim confirmed", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ services: [{ port: 443, product: "nginx", version: null }], sources: ["netlas"] }))
    // A row whose stored tier disagrees with its match_type: the normalizer wins.
    await sql`
      INSERT INTO exposure_vulnerability (user_id, asset_key, port, cve_id, evidence_tier, confirmed, match_type,
        source_providers, product, version, matched_via, risk_score, severity, status)
      VALUES (${TENANT}, ${A}, 443, 'CVE-2021-41773', 'confirmed', true, 'product',
        ARRAY['netlas']::text[], 'nginx', NULL, 'test fixture', 30.9, 'medium', 'active')
      ON CONFLICT (user_id, asset_key, port, cve_id) DO UPDATE SET evidence_tier='confirmed', confirmed=true, match_type='product'
    `
    const { graph } = await loadGraphFromStore(TENANT, { assetKey: A })
    const edge = graph.edges.find((e) => e.kind === "affected_by")!
    expect(edge.evidenceTier).toBe("product")     // NOT the stored 'confirmed'
    expect(edge.metadata?.confirmed).toBe(false)
  })

  test("per-port providers come only from stored rows, never inherited from the asset", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({
      services: [
        { port: 443, product: "Apache HTTP Server", version: "2.4.7" },
        { port: 8080, product: null, version: null },
      ],
      sources: ["censys", "netlas", "leakix"],   // asset-level providers
    }))
    await seedVuln(A, 443, "CVE-2021-41773", { providers: ["netlas"] })
    const { graph } = await loadGraphFromStore(TENANT, { assetKey: A })
    const p443 = graph.nodes.find((n) => n.id === `svc:${A}:443`)!
    const p8080 = graph.nodes.find((n) => n.id === `svc:${A}:8080`)!
    expect(p443.metadata.providers).toEqual(["netlas"])
    // 8080 had no vulnerability row, so it claims NO provider rather than
    // borrowing the asset's three.
    expect(p8080.metadata.providers).toEqual([])
  })

  test("an alert row produces CVE -> TRIGGERED -> ALERT and nothing is generated", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ services: [{ port: 443, product: "nginx", version: null }], sources: ["netlas"] }))
    await seedVuln(A, 443, "CVE-2021-41773", { product: "nginx" })

    const before = await loadGraphFromStore(TENANT, { assetKey: A })
    expect(before.graph.nodes.filter((n) => n.type === "alert")).toHaveLength(0)

    await sql`
      INSERT INTO exposure_alerts (user_id, fingerprint, asset_key, port, cve_id, kind, state, severity,
        risk_score, previous_risk, evidence_tier, payload)
      VALUES (${TENANT}, ${`${A}|443|CVE-2021-41773`}, ${A}, 443, 'CVE-2021-41773',
        'new_exposed_vulnerability', 'open', 'high', 78, 32, 'confirmed', '{}'::jsonb)
    `
    const after = await loadGraphFromStore(TENANT, { assetKey: A })
    expect(after.graph.nodes.filter((n) => n.type === "alert")).toHaveLength(1)
    const t = after.graph.edges.find((e) => e.kind === "triggered")!
    expect(t.source).toBe("cve:CVE-2021-41773")

    // Reading the graph must not have created or altered any alert.
    const count = (await sql`SELECT count(*)::int AS n FROM exposure_alerts WHERE asset_key = ${A}`) as Array<{ n: number }>
    expect(count[0].n).toBe(1)
  })

  test("resolved vulnerabilities are not drawn as current findings", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ services: [{ port: 443, product: "nginx", version: null }], sources: ["netlas"] }))
    await seedVuln(A, 443, "CVE-2021-41773", { product: "nginx" })
    await sql`UPDATE exposure_vulnerability SET status='resolved', resolved_at=now() WHERE user_id=${TENANT} AND asset_key=${A}`
    const { graph } = await loadGraphFromStore(TENANT, { assetKey: A })
    expect(graph.edges.filter((e) => e.kind === "affected_by")).toHaveLength(0)
    expect(graph.nodes.filter((n) => n.type === "cve")).toHaveLength(0)
  })

  test("observation time and retrieval time stay distinct on the assembled node", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ services: [{ port: 443, product: "nginx", version: null }], sources: ["netlas"] }))
    await seedVuln(A, 443, "CVE-2021-41773", { product: "nginx", observedAt: "2026-08-21T00:00:00.000Z" })
    const { graph } = await loadGraphFromStore(TENANT, { assetKey: A })
    const ip = graph.nodes.find((n) => n.type === "ip")!
    expect(ip.metadata.observedAt).toBe("2026-08-21T00:00:00.000Z")
    expect(ip.metadata.fetchedAt).toBeTruthy()
    expect(ip.metadata.observedAt).not.toBe(ip.metadata.fetchedAt)
    // Ten days old under the shared thresholds.
    expect(ip.metadata.freshness).toBe("stale")
  })

  test("no provider timestamp yields UNKNOWN rather than our fetch time", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ sources: ["netlas"] }))
    const { graph } = await loadGraphFromStore(TENANT, { assetKey: A })
    const ip = graph.nodes.find((n) => n.type === "ip")!
    expect(ip.metadata.observedAt).toBeNull()
    expect(ip.metadata.freshness).toBe("unknown")
  })

  test("the response carries no credentials and no raw provider payloads", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({
      services: [{ port: 443, product: "Apache HTTP Server", version: "2.4.7" }],
      domains: ["example.com"], sources: ["censys", "netlas"], riskScore: 30.9,
    }))
    await seedVuln(A, 443, "CVE-2021-41773")
    const blob = JSON.stringify(await loadGraphFromStore(TENANT, { limit: 150 }))

    for (const name of ["CENSYS_API_TOKEN", "LEAKIX_API_KEY", "NETLAS_API_KEY", "FOFA_API_KEY", "ZOOMEYE_API_KEY", "GREYNOISE_API_KEY", "CRON_SECRET", "DATABASE_URL"]) {
      const value = process.env[name]
      if (value && value.length >= 8) expect(blob).not.toContain(value)
    }
    expect(blob).not.toMatch(/Bearer\s/i)
    expect(blob).not.toMatch(/[?&](key|api_key|apikey|token|access_token|secret|email)=/i)
    // `live` is never emitted anywhere in OCTUPUS.
    expect(blob).not.toMatch(/"freshness":"live"/)
  })

  test("reading the graph does not modify any exposure record", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ services: [{ port: 443, product: "nginx", version: null }], sources: ["netlas"] }))
    await seedVuln(A, 443, "CVE-2021-41773", { product: "nginx" })

    const before = await sql`
      SELECT (SELECT count(*)::int FROM exposure_asset_state WHERE asset_key = ${A}) AS s,
             (SELECT count(*)::int FROM exposure_vulnerability WHERE asset_key = ${A}) AS v,
             (SELECT count(*)::int FROM exposure_alerts WHERE asset_key = ${A}) AS a,
             (SELECT max(updated_at) FROM exposure_asset_state WHERE asset_key = ${A}) AS t`
    await loadGraphFromStore(TENANT, { assetKey: A })
    await loadGraphFromStore(TENANT, { limit: 150 })
    const after = await sql`
      SELECT (SELECT count(*)::int FROM exposure_asset_state WHERE asset_key = ${A}) AS s,
             (SELECT count(*)::int FROM exposure_vulnerability WHERE asset_key = ${A}) AS v,
             (SELECT count(*)::int FROM exposure_alerts WHERE asset_key = ${A}) AS a,
             (SELECT max(updated_at) FROM exposure_asset_state WHERE asset_key = ${A}) AS t`
    expect(after).toEqual(before)
  })

  test("the asset limit is enforced server-side and cannot be raised by the caller", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seedState(A, snapshot({ sources: ["netlas"] }))
    const r = await loadGraphFromStore(TENANT, { limit: 99999 })
    // Clamped to the module ceiling rather than honoured.
    expect(r.graph.stats.assetsIncluded).toBeLessThanOrEqual(150)
  })
})

describe.skipIf(!HAS_TEST_DB)("cross-tenant isolation", () => {
  test("a graph never contains another tenant's asset", async () => {
    // The doc comment at the top of this file promises `OTHER` proves
    // isolation. It did not: the constant was declared and never asserted on,
    // so a graph query missing its user filter would have passed here.
    const mine = await loadGraphFromStore(TENANT)
    const theirs = await loadGraphFromStore(OTHER)
    const myIds = new Set(mine.graph.nodes.map((n) => n.id))
    const theirIds = new Set(theirs.graph.nodes.map((n) => n.id))
    for (const id of theirIds) expect(myIds.has(id)).toBe(false)
  }, 30_000)

  test("an unknown tenant sees an empty graph, not everyone's", async () => {
    const g = await loadGraphFromStore("tenant-that-owns-nothing")
    expect(g.graph.nodes.length).toBe(0)
    expect(g.empty).toBe(true)
  }, 30_000)
})
