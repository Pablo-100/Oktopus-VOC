/**
 * RISK-SCORING REGRESSION MATRIX (validation/hardening phase).
 *
 * Central invariant under test:
 *
 *   Weaker evidence can NEVER automatically become Critical merely because a
 *   high CVSS / KEV / active-exploitation signal exists somewhere upstream.
 *
 * Upstream severity describes the CVE. It says nothing about whether THIS host
 * actually runs the affected build. Only the evidence tier can establish that,
 * so the tier — not the CVE's severity — gates escalation.
 *
 * Every fixture is built through the production normalizer (`makeVulnerability`),
 * so a test cannot construct an evidence state production could not produce.
 */
import { describe, test, expect } from "bun:test"
import { correlate, scoreConfidence } from "@/lib/exposure/correlate"
import { computeExposureRisk, type CveFacts } from "@/lib/exposure/risk"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { evidenceTierFor } from "@/lib/exposure/types"
import type {
  EvidenceTier, ExposureAsset, ExposureService, ProviderName, ProviderObservation, VulnMatchType,
} from "@/lib/exposure/types"

const CVE = "CVE-2021-44228" // Log4Shell: the most escalation-prone CVE available

/** The worst realistic upstream signal set: CVSS 10, EPSS ~1.0, KEV, public exploit. */
const MAX_UPSTREAM = new Map<string, CveFacts>([
  [CVE, { cveId: CVE, cvss: 10, epss: 0.99999, isKev: true, hasExploit: true }],
])

function svc(port: number, source: ProviderName, product: string | null = null, version: string | null = null): ExposureService {
  return {
    port, transport: "tcp", protocol: "HTTPS", product, vendor: null, version,
    banner: null, httpStatus: null, httpTitle: null, httpServer: null,
    sources: [source],
    claims: [{ source, product, vendor: null, version, protocol: "HTTPS" }],
  }
}

function baseObs(provider: ProviderName, ip: string, vulnerabilities: ExposureAsset["vulnerabilities"] = []): ProviderObservation {
  return {
    provider, ip, domain: null, hostname: null, asn: null, organization: null,
    country: null, city: null, latitude: null, longitude: null,
    services: [], technologies: [], certificates: [], vulnerabilities,
    notes: null, firstSeen: null, lastSeen: null, raw: null,
  }
}

function asset(over: Partial<ExposureAsset> = {}): ExposureAsset {
  return {
    id: "ip:203.0.113.10", ip: "203.0.113.10", domain: null, domains: [], hostnames: [],
    asn: 64500, organization: "Example Org", country: "US", city: null, latitude: null, longitude: null,
    services: [svc(443, "censys", "Apache", "2.4.49")],
    technologies: [], certificates: [], vulnerabilities: [],
    threat: null, sources: ["censys", "netlas", "leakix"], sourceCount: 3,
    confidence: "very_high", confidenceScore: 85, evidence: [],
    enrichmentStatus: "enriched", isQueryTarget: false,
    firstSeen: null, lastSeen: null, exposureRisk: null, raw: [],
    ...over,
  }
}

function withMatch(matchType: VulnMatchType, over: Partial<ExposureAsset> = {}): ExposureAsset {
  return asset({
    vulnerabilities: [makeVulnerability({ cveId: CVE, matchType, sources: ["netlas"], matchedProduct: "Apache" })],
    ...over,
  })
}

// ─────────────────────────────────────────────────────────────────────────────

describe("MATRIX — every evidence class against maximum upstream severity", () => {
  /**
   * Each row is scored against CVSS 10 + EPSS 0.99999 + KEV + public exploit.
   * `mayReachCritical` is whether that row is permitted to reach Critical AT ALL.
   */
  const MATRIX: Array<{ name: string; build: () => ExposureAsset; tier: EvidenceTier; mayReachCritical: boolean }> = [
    { name: "direct CVE evidence (provider queried by CVE id)", build: () => withMatch("cve-search"), tier: "confirmed", mayReachCritical: true },
    { name: "KEV + direct evidence", build: () => withMatch("cve-search"), tier: "confirmed", mayReachCritical: true },
    {
      name: "active exploitation (GreyNoise malicious) + direct evidence",
      build: () => withMatch("cve-search", { threat: { ip: "203.0.113.10", classification: "malicious", noise: true, riot: false, actor: null, lastSeen: null, link: null } }),
      tier: "confirmed", mayReachCritical: true,
    },
    { name: "strong product/version match", build: () => withMatch("version"), tier: "strong", mayReachCritical: true },
    { name: "product-only match", build: () => withMatch("product"), tier: "product", mayReachCritical: false },
    { name: "CPE pivot", build: () => withMatch("pivot"), tier: "pivot", mayReachCritical: false },
    { name: "banner/heuristic match", build: () => withMatch("banner"), tier: "weak", mayReachCritical: false },
    {
      name: "domain-only relationship (no IP)",
      build: () => withMatch("pivot", { id: "domain:example.com", ip: null, domain: "example.com", domains: ["example.com"], services: [] }),
      tier: "pivot", mayReachCritical: false,
    },
    {
      name: "query-target only (zero provider evidence)",
      build: () => withMatch("pivot", { sources: [], sourceCount: 0, isQueryTarget: true, confidence: "low", confidenceScore: 0, services: [] }),
      tier: "pivot", mayReachCritical: false,
    },
    {
      name: "provider disagreement on the service fingerprint",
      build: () => withMatch("product", {
        services: [{
          ...svc(443, "censys", "nginx", "1.24.0"),
          sources: ["censys", "leakix"],
          claims: [
            { source: "censys", product: "nginx", vendor: null, version: "1.24.0", protocol: "HTTPS" },
            { source: "leakix", product: "Apache", vendor: null, version: "2.4.49", protocol: "HTTPS" },
          ],
          conflict: true,
        }],
      }),
      tier: "product", mayReachCritical: false,
    },
    {
      name: "not-enriched asset",
      build: () => withMatch("pivot", { enrichmentStatus: "not_requested", services: [] }),
      tier: "pivot", mayReachCritical: false,
    },
  ]

  for (const row of MATRIX) {
    test(`${row.name} → tier "${row.tier}", ${row.mayReachCritical ? "may" : "must NOT"} reach Critical`, () => {
      const a = row.build()
      expect(a.vulnerabilities[0].evidenceTier).toBe(row.tier)
      const r = computeExposureRisk(a, MAX_UPSTREAM)

      if (row.mayReachCritical) {
        expect(r.severity).toBe("critical")
      } else {
        // THE CENTRAL INVARIANT.
        expect(r.severity).not.toBe("critical")
        expect(r.score).toBeLessThan(75)
      }
    })
  }

  test("strict evidence ordering holds under identical upstream severity", () => {
    const score = (m: VulnMatchType) => computeExposureRisk(withMatch(m), MAX_UPSTREAM).score
    expect(score("pivot")).toBeLessThan(score("banner"))
    expect(score("banner")).toBeLessThan(score("product"))
    expect(score("product")).toBeLessThan(score("version"))
    expect(score("version")).toBeLessThanOrEqual(score("cve-search"))
    // Not merely lower — a different verdict class.
    expect(computeExposureRisk(withMatch("pivot"), MAX_UPSTREAM).severity).not.toBe("critical")
    expect(computeExposureRisk(withMatch("cve-search"), MAX_UPSTREAM).severity).toBe("critical")
  })

  test("KEV and public-exploit escalation are withheld from weak tiers", () => {
    for (const m of ["pivot", "product", "banner"] as VulnMatchType[]) {
      const r = computeExposureRisk(withMatch(m), MAX_UPSTREAM)
      expect(r.factors.some((f) => f.label === "CISA KEV")).toBe(false)
      expect(r.factors.some((f) => f.label === "Public exploit")).toBe(false)
      expect(r.factors.some((f) => f.label === "Potential match only")).toBe(true)
    }
    for (const m of ["cve-search", "version"] as VulnMatchType[]) {
      expect(computeExposureRisk(withMatch(m), MAX_UPSTREAM).factors.some((f) => f.label === "CISA KEV")).toBe(true)
    }
  })

  test("upstream severity alone cannot lift a weak tier to Critical", () => {
    // Same asset, same exposure — only the CVE's upstream severity changes.
    const mild = new Map<string, CveFacts>([[CVE, { cveId: CVE, cvss: 3, epss: 0.01, isKev: false, hasExploit: false }]])
    const pivotMild = computeExposureRisk(withMatch("pivot"), mild)
    const pivotMax = computeExposureRisk(withMatch("pivot"), MAX_UPSTREAM)
    expect(pivotMax.score).toBeGreaterThan(pivotMild.score) // it may rise…
    expect(pivotMax.severity).not.toBe("critical")          // …but never to Critical
  })

  test("every scored asset explains itself — no black-box numbers", () => {
    for (const row of MATRIX) {
      const r = computeExposureRisk(row.build(), MAX_UPSTREAM)
      expect(r.factors.length).toBeGreaterThan(0)
      expect(r.factors.some((f) => f.label === "Base RBVM")).toBe(true)
    }
  })
})

describe("ITEM 2 — query-target observations can never contribute to risk or confidence", () => {
  const queryTarget = (ip: string): ProviderObservation => ({
    provider: null, origin: "query-target", ip, domain: null, hostname: null,
    asn: null, organization: null, country: null, city: null, latitude: null, longitude: null,
    services: [], technologies: [], certificates: [], vulnerabilities: [],
    notes: null, firstSeen: null, lastSeen: null, raw: { should: "not appear" },
  })

  test("zero provider evidence → zero sources, zero confidence, no raw payload", () => {
    const [a] = correlate([queryTarget("203.0.113.99")])
    expect(a.sources).toEqual([])
    expect(a.sourceCount).toBe(0)
    expect(a.confidenceScore).toBe(0)
    expect(a.isQueryTarget).toBe(true)
    expect(a.raw).toEqual([])
  })

  test("a query target never adds a provider to an asset that has real evidence", () => {
    const [a] = correlate([queryTarget("203.0.113.99"), baseObs("censys", "203.0.113.99")])
    expect(a.sources).toEqual(["censys"])
    expect(a.sourceCount).toBe(1)
    expect(a.isQueryTarget).toBe(false)
  })

  test("a query-target asset contributes no risk of its own", () => {
    const [a] = correlate([queryTarget("203.0.113.99")])
    const r = computeExposureRisk(a, MAX_UPSTREAM)
    expect(r.score).toBe(0)
    expect(r.severity).toBe("low")
  })

  test("scoreConfidence refuses to score an asset with no sources", () => {
    expect(scoreConfidence(asset({ sources: [], sourceCount: 0 })).score).toBe(0)
  })
})

describe("ITEM 3 — a pivot can never produce a confirmed vulnerability claim", () => {
  test("the normalizer refuses to mark a pivot as confirmed", () => {
    const v = makeVulnerability({ cveId: CVE, matchType: "pivot", sources: ["leakix"] })
    expect(v.evidenceTier).toBe("pivot")
    expect(v.confirmed).toBe(false)
  })

  test("only a direct CVE-id hit is `confirmed`", () => {
    const cases: Array<[VulnMatchType, boolean]> = [
      ["cve-search", true], ["version", false], ["product", false], ["banner", false], ["pivot", false], ["unknown", false],
    ]
    for (const [m, expected] of cases) {
      expect(makeVulnerability({ cveId: CVE, matchType: m, sources: ["netlas"] }).confirmed).toBe(expected)
    }
  })

  test("evidenceTierFor is the single mapping and stays consistent", () => {
    expect(evidenceTierFor("cve-search")).toBe("confirmed")
    expect(evidenceTierFor("version")).toBe("strong")
    expect(evidenceTierFor("product")).toBe("product")
    expect(evidenceTierFor("pivot")).toBe("pivot")
    expect(evidenceTierFor("banner")).toBe("weak")
    expect(evidenceTierFor(undefined)).toBe("weak")
  })

  test("merging a pivot with a confirmed hit promotes tier AND confirmed together", () => {
    const [a] = correlate([
      baseObs("leakix", "203.0.113.5", [makeVulnerability({ cveId: CVE, matchType: "pivot", sources: ["leakix"] })]),
      baseObs("censys", "203.0.113.5", [makeVulnerability({ cveId: CVE, matchType: "cve-search", sources: ["censys"] })]),
    ])
    const v = a.vulnerabilities[0]
    expect(v.evidenceTier).toBe("confirmed")
    expect(v.confirmed).toBe(true) // must not lag behind matchType
  })

  test("merging never DOWNGRADES a confirmed hit to a pivot", () => {
    const [a] = correlate([
      baseObs("censys", "203.0.113.6", [makeVulnerability({ cveId: CVE, matchType: "cve-search", sources: ["censys"] })]),
      baseObs("leakix", "203.0.113.6", [makeVulnerability({ cveId: CVE, matchType: "pivot", sources: ["leakix"] })]),
    ])
    expect(a.vulnerabilities[0].confirmed).toBe(true)
    expect(a.vulnerabilities[0].evidenceTier).toBe("confirmed")
  })
})

describe("ITEM 7 — not-enriched must not read as a low-confidence judgement", () => {
  test("enrichmentStatus is independent of confidence", () => {
    const a = asset({ enrichmentStatus: "not_requested", sources: ["leakix", "censys", "netlas"], sourceCount: 3 })
    expect(a.enrichmentStatus).toBe("not_requested")
    expect(scoreConfidence(a).level).not.toBe("low") // 3 corroborating sources is not "low confidence"
  })

  test("an un-enriched asset is not penalised in risk for being un-enriched", () => {
    const notEnriched = computeExposureRisk(withMatch("version", { enrichmentStatus: "not_requested" }), MAX_UPSTREAM)
    const enrichedAsset = computeExposureRisk(withMatch("version", { enrichmentStatus: "enriched" }), MAX_UPSTREAM)
    expect(notEnriched.score).toBe(enrichedAsset.score)
  })
})
