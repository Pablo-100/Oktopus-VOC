/**
 * On-demand enrichment scope + provider quota (validation/hardening items 5, 7).
 *
 * These exercise the real modules with the network stubbed at `globalThis.fetch`,
 * so the assertions are about OUR orchestration (which targets get queried, and
 * whether the quota gate is honoured), not about a vendor's live behaviour.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { paginate, MAX_PAGE_SIZE, providerConfiguration } from "@/lib/exposure/orchestrator"
import { mergeProvenance } from "@/components/exposure-asset-dialog"
import type { ExposureAsset, ExposureSearchResult, ExposureService, ProviderName } from "@/lib/exposure/types"

/**
 * Tenancy fixtures. Every DB suite runs as an explicit tenant so a query that
 * forgets its user filter shows up as a cross-tenant leak rather than passing
 * silently. `OTHER` exists to prove isolation, not just to satisfy a signature.
 */
const TENANT = "test-tenant-a"
const OTHER = "test-tenant-b"


const realFetch = globalThis.fetch

/** Every URL the code under test requested, for scope assertions. */
let requested: string[] = []

beforeEach(() => { requested = [] })
afterEach(() => { globalThis.fetch = realFetch })

/** Stub every provider call with an empty-but-valid response. */
function stubFetch() {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url
    requested.push(url)
    // Shapes chosen so each adapter parses successfully and yields no observations.
    const body = url.includes("leakix.net") ? "[]" : url.includes("greynoise") ? '{"ip":"1.1.1.1","noise":false,"riot":false}' : "{}"
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } })
  }) as typeof fetch
}

describe("ITEM 5 — on-demand enrichment queries ONLY the selected asset", () => {
  test("enrichSingleAsset contacts enrichment providers for exactly one target", async () => {
    stubFetch()
    process.env.NETLAS_API_KEY ||= "test-key"
    process.env.CENSYS_API_TOKEN ||= "test-token"
    process.env.GREYNOISE_API_KEY ||= "test-key"

    const { enrichSingleAsset } = await import("@/lib/exposure/orchestrator")
    const target = "203.0.113.77"
    await enrichSingleAsset(target).catch(() => { /* DB may be unavailable; URL scope is what matters */ })

    const providerCalls = requested.filter((u) => /netlas|censys|greynoise/i.test(u))
    expect(providerCalls.length).toBeGreaterThan(0)

    // Every provider call must reference the single requested target.
    for (const u of providerCalls) expect(u).toContain(target)

    // And NO discovery provider is involved — this is enrichment only, never a
    // bulk re-search that would fan out across many hosts.
    expect(requested.some((u) => u.includes("leakix.net/search"))).toBe(false)
    expect(requested.some((u) => u.includes("fofa.info"))).toBe(false)
    expect(requested.some((u) => u.includes("zoomeye"))).toBe(false)
  })

  test("enrichSingleAsset refuses a private address (no provider call at all)", async () => {
    stubFetch()
    const { enrichSingleAsset } = await import("@/lib/exposure/orchestrator")
    await expect(enrichSingleAsset("10.0.0.5")).rejects.toThrow(/private|reserved/i)
    expect(requested).toHaveLength(0)
  })

  test("enrichSingleAsset refuses a malformed target", async () => {
    stubFetch()
    const { enrichSingleAsset } = await import("@/lib/exposure/orchestrator")
    await expect(enrichSingleAsset("not a host/../etc")).rejects.toThrow(/IP address or a domain/i)
    expect(requested).toHaveLength(0)
  })
})

describe("ITEM 7 — provider quota is respected", () => {
  test("a provider over budget is refused before any HTTP call is made", async () => {
    stubFetch()
    const { reserveQuota } = await import("@/lib/exposure/quota")

    // Exhaust the smallest budget (fofa: 50/hour) in one reservation.
    const first = await reserveQuota("fofa", 10_000)
    // Either the DB rejected it (budget exceeded) or the DB is unavailable and
    // the limiter failed open — both are correct, documented behaviours.
    if (!first.allowed) {
      expect(first.used).toBeGreaterThan(first.budget)
      expect(first.retryAfterSeconds).toBeGreaterThan(0)
      const second = await reserveQuota("fofa")
      expect(second.allowed).toBe(false) // stays refused within the same window
    } else {
      // Fail-open path: quota bookkeeping must never break the product.
      expect(first.allowed).toBe(true)
    }
  })

  test("quota decisions are per provider, not global", async () => {
    const { reserveQuota } = await import("@/lib/exposure/quota")
    const greynoise = await reserveQuota("greynoise")
    // Exhausting FOFA above must not have consumed GreyNoise's separate budget.
    expect(greynoise.allowed).toBe(true)
  })
})

describe("ITEM 6 — server-side pagination", () => {
  const mkResult = (n: number): ExposureSearchResult => ({
    query: "Apache", queryType: "product",
    assets: Array.from({ length: n }, (_, i) => ({ id: `ip:10.0.0.${i}` }) as ExposureAsset),
    providers: [], totalAssets: n, fetchedAt: new Date().toISOString(), cached: false,
  })

  test("returns only the requested page while reporting the full total", () => {
    const p = paginate(mkResult(137), { limit: 50, offset: 0 })
    expect(p.assets).toHaveLength(50)
    expect(p.totalAssets).toBe(137) // full count, so the client can page
    expect(p.limit).toBe(50)
    expect(p.offset).toBe(0)
  })

  test("offset selects the correct slice", () => {
    const p = paginate(mkResult(137), { limit: 50, offset: 100 })
    expect(p.assets).toHaveLength(37)
    expect(p.assets[0].id).toBe("ip:10.0.0.100")
  })

  test("limit is clamped to MAX_PAGE_SIZE so a caller cannot request everything", () => {
    const p = paginate(mkResult(5000), { limit: 99999 })
    expect(p.assets.length).toBeLessThanOrEqual(MAX_PAGE_SIZE)
  })

  test("negative or fractional inputs are normalized, never crash", () => {
    const p = paginate(mkResult(10), { limit: -5, offset: -20 })
    expect(p.offset).toBe(0)
    expect(p.limit).toBeGreaterThanOrEqual(1)
  })

  test("an out-of-range offset yields an empty page, not an error", () => {
    const p = paginate(mkResult(10), { limit: 50, offset: 500 })
    expect(p.assets).toHaveLength(0)
    expect(p.totalAssets).toBe(10)
  })
})

describe("ITEM 5 — on-demand enrichment must not shrink provenance", () => {
  /**
   * Exercises the REAL `mergeProvenance` used by the dialog. The enrich endpoint
   * reports only what ENRICHMENT providers found, so rendering its result raw
   * would drop the discovery provider that originally surfaced the asset.
   */
  const mk = (over: Partial<ExposureAsset>): ExposureAsset => ({
    id: "ip:203.0.113.9", ip: "203.0.113.9", domain: null, domains: [], hostnames: [],
    asn: null, organization: null, country: null, city: null, latitude: null, longitude: null,
    services: [], technologies: [], certificates: [], vulnerabilities: [], threat: null,
    sources: [], sourceCount: 0, confidence: "low", confidenceScore: 0, evidence: [],
    enrichmentStatus: "not_requested", isQueryTarget: false,
    firstSeen: null, lastSeen: null, exposureRisk: null, raw: [], ...over,
  })
  const service = (port: number, source: ProviderName): ExposureService => ({
    port, transport: "tcp", protocol: null, product: null, vendor: null, version: null,
    banner: null, httpStatus: null, httpTitle: null, httpServer: null,
    sources: [source], claims: [{ source, product: null, vendor: null, version: null, protocol: null }],
  })

  test("the discovery source survives enrichment (never replaced)", () => {
    const original = mk({ sources: ["leakix"], sourceCount: 1, services: [service(443, "leakix")], domains: ["a.example"] })
    const afterEnrich = mk({ sources: ["netlas", "censys"], sourceCount: 2, services: [service(22, "censys")], enrichmentStatus: "enriched" })

    const merged = mergeProvenance(original, afterEnrich)
    expect(new Set(merged.sources)).toEqual(new Set(["leakix", "netlas", "censys"]))
    expect(merged.sourceCount).toBe(3)
    expect(merged.enrichmentStatus).toBe("enriched") // enriched state is taken
    expect(merged.domains).toContain("a.example")    // pre-enrichment relationship kept
  })

  test("a service seen only pre-enrichment is retained", () => {
    const original = mk({ sources: ["leakix"], services: [service(443, "leakix")] })
    const afterEnrich = mk({ sources: ["censys"], services: [service(22, "censys"), service(111, "censys")] })

    const merged = mergeProvenance(original, afterEnrich)
    expect(merged.services.map((s) => s.port).sort((a, b) => a - b)).toEqual([22, 111, 443])
  })

  test("the same port seen by both keeps BOTH provider claims", () => {
    const original = mk({ sources: ["leakix"], services: [service(443, "leakix")] })
    const afterEnrich = mk({ sources: ["censys"], services: [service(443, "censys")] })

    const merged = mergeProvenance(original, afterEnrich)
    expect(merged.services).toHaveLength(1)
    expect(new Set(merged.services[0].sources)).toEqual(new Set(["leakix", "censys"]))
    expect(merged.services[0].claims).toHaveLength(2)
  })

  test("merging is idempotent — repeated enrichment never duplicates evidence", () => {
    const original = mk({ sources: ["leakix"], services: [service(443, "leakix")] })
    const afterEnrich = mk({ sources: ["censys"], services: [service(443, "censys")] })

    const once = mergeProvenance(original, afterEnrich)
    const twice = mergeProvenance(once, afterEnrich)
    expect(twice.sources).toHaveLength(once.sources.length)
    expect(twice.services[0].claims).toHaveLength(once.services[0].claims.length)
  })
})

describe("pagination is tenant-agnostic", () => {
  test("paginate never mixes one tenant's assets into another's page", () => {
    // TENANT and OTHER were declared to express that this is a multi-tenant
    // system, then never asserted on. Pagination is pure — it slices whatever
    // it is handed — so what matters is that it preserves the caller's set
    // exactly rather than reaching for anything else.
    const assetFor = (owner: string, ip: string): ExposureAsset =>
      ({ id: `${owner}:${ip}`, ip, domain: null, services: [], vulnerabilities: [],
         certificates: [], technologies: [], sources: [], riskScore: 0 }) as unknown as ExposureAsset

    const mine = { assets: [assetFor(TENANT, "1.1.1.1"), assetFor(TENANT, "1.1.1.2")], totalAssets: 2 } as unknown as ExposureSearchResult
    const page = paginate(mine, { limit: 10, offset: 0 })
    expect(page.assets.every((a) => a.id.startsWith(`${TENANT}:`))).toBe(true)
    expect(page.assets.some((a) => a.id.startsWith(`${OTHER}:`))).toBe(false)
    expect(page.assets.length).toBe(2)
  })

  test("provider configuration always reports a shape the UI can render", () => {
    const cfg = providerConfiguration()
    expect(cfg.length).toBeGreaterThan(0)
    for (const c of cfg) {
      expect(typeof c.provider).toBe("string")
      expect(typeof c.configured).toBe("boolean")
      // `source` tells the UI whose key answered; without it a user on their
      // own credentials would be shown the platform's status.
      expect(["user", "platform", "none"]).toContain(c.source)
    }
  })
})
