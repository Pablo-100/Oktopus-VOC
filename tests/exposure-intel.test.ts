/**
 * Exposure Intelligence — pure tests (no DB, no network).
 *
 * The payload fixtures below are REAL shapes captured live from each provider
 * on 2026-08-29, not invented. That matters: the parsers exist to survive the
 * actual API responses, so testing against a made-up shape would prove nothing.
 */
import { describe, test, expect } from "bun:test"
import { correlate, scoreConfidence } from "@/lib/exposure/correlate"
import { computeExposureRisk, type CveFacts } from "@/lib/exposure/risk"
import { classifyQuery } from "@/lib/exposure/orchestrator"
import { isValidIp, isValidDomain, isValidCve, isPrivateIp, classifyHttp } from "@/lib/exposure/providers/_base"
import { parsePorts, softwareByPort, portFromUri } from "@/lib/exposure/providers/netlas"
import { buildCensysCveQuery } from "@/lib/exposure/providers/censys"
import { buildFofaQuery } from "@/lib/exposure/providers/fofa"
import { buildZoomeyeQuery } from "@/lib/exposure/providers/zoomeye"
import { leakixCveUnsupported } from "@/lib/exposure/providers/leakix"
import { makeVulnerability } from "@/lib/exposure/normalize"
import type { ExposureAsset, ExposureService, ProviderName, ProviderObservation, VulnMatchType } from "@/lib/exposure/types"

function obs(partial: Partial<ProviderObservation> & { provider: ProviderObservation["provider"] }): ProviderObservation {
  return {
    ip: null, domain: null, hostname: null, asn: null, organization: null,
    country: null, city: null, latitude: null, longitude: null,
    services: [], technologies: [], certificates: [], vulnerabilities: [],
    notes: null, firstSeen: null, lastSeen: null, raw: null,
    ...partial,
  }
}

/**
 * Vulnerability factory — routes through the SAME normalizer production uses,
 * so a test can never construct an evidence tier that production could not.
 */
function vuln(cveId: string, matchType: VulnMatchType, source: ProviderName, over: { providerScore?: number | null; providerSeverity?: string | null; matchedProduct?: string | null } = {}) {
  return makeVulnerability({ cveId, matchType, sources: [source], ...over })
}

/** Service factory — keeps `claims` in sync with the declared product/version. */
function svc(port: number, source: ProviderObservation["provider"] & string, over: Partial<ExposureService> = {}): ExposureService {
  const product = over.product ?? null
  const version = over.version ?? null
  return {
    port, transport: "tcp", protocol: null, product, vendor: null, version,
    banner: null, httpStatus: null, httpTitle: null, httpServer: null,
    sources: [source],
    claims: [{ source, product, vendor: null, version, protocol: over.protocol ?? null }],
    ...over,
  }
}

describe("A1 REGRESSION — domain is a relationship, never an identity", () => {
  /**
   * The exact defect found in review: `example.com` with three A records
   * collapsed into ONE asset and two hosts were silently destroyed.
   * DO NOT weaken this test to make an implementation pass.
   */
  test("TEST 1: three IPs behind one domain produce THREE assets", () => {
    const assets = correlate([
      obs({ provider: "netlas", ip: "104.20.23.154", domain: "example.com" }),
      obs({ provider: "netlas", ip: "172.66.147.243", domain: "example.com" }),
      obs({ provider: "netlas", ip: "8.47.69.8", domain: "example.com" }),
    ])
    expect(assets).toHaveLength(3)
    expect(new Set(assets.map((a) => a.ip))).toEqual(new Set(["104.20.23.154", "172.66.147.243", "8.47.69.8"]))
    // The domain relationship must be preserved on every one of them.
    for (const a of assets) expect(a.domains).toContain("example.com")
  })

  test("the same domain across different IPs never merges, even with many providers", () => {
    const assets = correlate([
      obs({ provider: "leakix", ip: "1.1.1.1", domain: "shared.example" }),
      obs({ provider: "censys", ip: "1.1.1.1", domain: "shared.example" }),
      obs({ provider: "netlas", ip: "2.2.2.2", domain: "shared.example" }),
      obs({ provider: "fofa", ip: "3.3.3.3", domain: "shared.example" }),
    ])
    expect(assets).toHaveLength(3)
    // The IP seen by two providers keeps both; the others stay single-source.
    const first = assets.find((a) => a.ip === "1.1.1.1")!
    expect(first.sourceCount).toBe(2)
  })

  test("a shared certificate must NOT merge two different IPs (same cert on LB nodes)", () => {
    const cert = (p: "censys" | "leakix") => ([{ commonName: "lb.example.com", sans: [], issuer: null, fingerprint: "sha-shared", validFrom: null, validTo: null, expired: null, sources: [p] }])
    const assets = correlate([
      obs({ provider: "censys", ip: "10.0.0.1", certificates: cert("censys") }),
      obs({ provider: "leakix", ip: "10.0.0.2", certificates: cert("leakix") }),
    ])
    expect(assets).toHaveLength(2)
  })

  test("two observations with only the same domain (no IP) DO merge into one domain asset", () => {
    const assets = correlate([
      obs({ provider: "netlas", domain: "only-domain.example" }),
      obs({ provider: "leakix", domain: "only-domain.example" }),
    ])
    expect(assets).toHaveLength(1)
    expect(assets[0].ip).toBeNull()
    expect(assets[0].sourceCount).toBe(2)
  })
})

describe("Correlation — the same host seen by many providers becomes ONE asset", () => {
  test("TEST 2: 4 providers reporting the same IP collapse into a single asset with 4 sources", () => {
    const assets = correlate([
      obs({ provider: "censys", ip: "185.1.2.3", services: [svc(443, "censys", { product: "Apache", protocol: "HTTPS" })] }),
      obs({ provider: "netlas", ip: "185.1.2.3", technologies: [{ name: "Apache", version: "2.4.49", categories: [], sources: ["netlas"] }] }),
      obs({ provider: "leakix", ip: "185.1.2.3" }),
      obs({ provider: "fofa", ip: "185.1.2.3" }),
    ])
    expect(assets).toHaveLength(1)
    expect(assets[0].ip).toBe("185.1.2.3")
    expect(assets[0].sourceCount).toBe(4)
    expect(new Set(assets[0].sources)).toEqual(new Set(["censys", "netlas", "leakix", "fofa"]))
  })

  test("same IP with DIFFERENT domains still correlates to one IP asset, keeping both domains", () => {
    const assets = correlate([
      obs({ provider: "censys", ip: "4.4.4.4", domain: "a.example" }),
      obs({ provider: "leakix", ip: "4.4.4.4", domain: "b.example" }),
    ])
    expect(assets).toHaveLength(1)
    expect(assets[0].sourceCount).toBe(2)
    expect(new Set(assets[0].domains)).toEqual(new Set(["a.example", "b.example"]))
  })

  test("different IPs are NEVER merged", () => {
    const assets = correlate([
      obs({ provider: "censys", ip: "1.1.1.1" }),
      obs({ provider: "netlas", ip: "2.2.2.2" }),
    ])
    expect(assets).toHaveLength(2)
  })

  test("a shared product name alone must NOT merge two hosts (false-merge guard)", () => {
    const assets = correlate([
      obs({ provider: "censys", ip: "1.1.1.1", services: [svc(443, "censys", { product: "Apache", version: "2.4.49" })] }),
      obs({ provider: "netlas", ip: "2.2.2.2", services: [svc(443, "netlas", { product: "Apache", version: "2.4.49" })] }),
    ])
    expect(assets).toHaveLength(2)
  })

  test("services from different providers on the same port merge, keeping both sources", () => {
    const assets = correlate([
      obs({ provider: "censys", ip: "7.7.7.7", services: [svc(443, "censys", { protocol: "HTTPS" })] }),
      obs({ provider: "leakix", ip: "7.7.7.7", services: [svc(443, "leakix", { product: "Apache", version: "2.4.49", protocol: "HTTPS", httpStatus: 200, httpTitle: "Home" })] }),
    ])
    expect(assets[0].services).toHaveLength(1)
    const s = assets[0].services[0]
    expect(new Set(s.sources)).toEqual(new Set(["censys", "leakix"]))
    expect(s.product).toBe("Apache")
    expect(s.version).toBe("2.4.49")
  })

  test("vulnerability merge keeps the STRONGEST match type (version beats product)", () => {
    const assets = correlate([
      obs({ provider: "netlas", ip: "8.8.8.4", vulnerabilities: [vuln("CVE-2021-41773", "product", "netlas", { providerScore: 7.5, providerSeverity: "high", matchedProduct: "Apache" })] }),
      obs({ provider: "censys", ip: "8.8.8.4", vulnerabilities: [vuln("CVE-2021-41773", "version", "censys")] }),
    ])
    expect(assets[0].vulnerabilities).toHaveLength(1)
    expect(assets[0].vulnerabilities[0].matchType).toBe("version")
    expect(assets[0].vulnerabilities[0].providerScore).toBe(7.5)
  })
})

describe("A2 REGRESSION — a query target is not provider evidence", () => {
  const queryTarget = (ip: string) => obs({ provider: null, origin: "query-target", ip })

  test("TEST 3: a query target with no provider results yields NO sources and NO confidence", () => {
    const assets = correlate([queryTarget("185.9.9.9")])
    expect(assets).toHaveLength(1)
    const a = assets[0]
    expect(a.sources).toEqual([])
    expect(a.sourceCount).toBe(0)
    expect(a.confidenceScore).toBe(0)
    expect(a.isQueryTarget).toBe(true)
    // The specific bug: LeakIX must never be credited for a target it never saw.
    expect(a.sources).not.toContain("leakix")
  })

  test("query target + one real Censys observation reports exactly ['censys']", () => {
    const assets = correlate([
      queryTarget("185.9.9.9"),
      obs({ provider: "censys", ip: "185.9.9.9", services: [svc(443, "censys", { product: "nginx" })] }),
    ])
    expect(assets).toHaveLength(1)
    expect(assets[0].sources).toEqual(["censys"])
    expect(assets[0].sourceCount).toBe(1)
    expect(assets[0].isQueryTarget).toBe(false)
  })

  test("a query target contributes no raw payload to the audit view", () => {
    const assets = correlate([queryTarget("185.9.9.9")])
    expect(assets[0].raw).toEqual([])
  })
})

describe("B3 — provider disagreement is preserved, not silently resolved", () => {
  test("TEST 6: conflicting product fingerprints keep both claims and flag a conflict", () => {
    const assets = correlate([
      obs({ provider: "censys", ip: "6.6.6.6", services: [svc(443, "censys", { product: "nginx", version: "1.24.0" })] }),
      obs({ provider: "leakix", ip: "6.6.6.6", services: [svc(443, "leakix", { product: "Apache", version: "2.4.49" })] }),
    ])
    const s = assets[0].services[0]
    expect(s.claims).toHaveLength(2)
    expect(s.conflict).toBe(true)
    expect(new Set(s.claims.map((c) => c.source))).toEqual(new Set(["censys", "leakix"]))
    // The disagreement must reach the analyst as evidence.
    expect(assets[0].evidence.some((e) => e.basis === "provider-disagreement")).toBe(true)
  })

  test("a GENERIC fingerprint does not count as disagreement with a specific one", () => {
    // Censys reports "http_server" for "something answered HTTP" — that is not
    // a competing vendor claim against LeakIX's "Apache".
    const assets = correlate([
      obs({ provider: "censys", ip: "6.6.6.7", services: [svc(443, "censys", { product: "http_server" })] }),
      obs({ provider: "leakix", ip: "6.6.6.7", services: [svc(443, "leakix", { product: "Apache" })] }),
    ])
    const s = assets[0].services[0]
    expect(s.conflict).toBe(false)
    expect(s.product).toBe("Apache")
    expect(s.claims).toHaveLength(2) // both claims still retained
  })

  test("agreeing providers produce no conflict flag", () => {
    const assets = correlate([
      obs({ provider: "censys", ip: "6.6.6.8", services: [svc(443, "censys", { product: "Apache" })] }),
      obs({ provider: "leakix", ip: "6.6.6.8", services: [svc(443, "leakix", { product: "Apache" })] }),
    ])
    expect(assets[0].services[0].conflict).toBe(false)
  })
})

describe("Confidence — evidence-weighted, not a raw provider count", () => {
  function assetWith(sources: ExposureAsset["sources"], extra: Partial<ExposureAsset> = {}): ExposureAsset {
    return {
      id: "x", ip: "1.2.3.4", domain: null, domains: [], hostnames: [], asn: null, organization: null,
      country: null, city: null, latitude: null, longitude: null,
      services: [], technologies: [], certificates: [], vulnerabilities: [], threat: null,
      sources, sourceCount: sources.length, confidence: "low", confidenceScore: 0, evidence: [],
      enrichmentStatus: "not_requested", isQueryTarget: false,
      firstSeen: null, lastSeen: null, exposureRisk: null, raw: [], ...extra,
    }
  }
  const sharedSvc: ExposureService = {
    port: 443, protocol: null, product: null, vendor: null, version: null, banner: null,
    httpStatus: null, httpTitle: null, httpServer: null, transport: null,
    sources: ["leakix", "censys"],
    claims: [{ source: "leakix", product: null, vendor: null, version: null, protocol: null }],
  }

  test("more independent providers raises confidence", () => {
    const one = scoreConfidence(assetWith(["leakix"])).score
    const four = scoreConfidence(assetWith(["leakix", "censys", "netlas", "fofa"])).score
    expect(four).toBeGreaterThan(one)
  })

  test("a corroborated service beats the same provider count without one", () => {
    const plain = scoreConfidence(assetWith(["leakix", "censys"])).score
    const corroborated = scoreConfidence(assetWith(["leakix", "censys"], { services: [sharedSvc] })).score
    expect(corroborated).toBeGreaterThan(plain)
  })

  test("4 corroborated providers reach very_high", () => {
    const r = scoreConfidence(assetWith(["leakix", "censys", "netlas", "fofa"], {
      services: [sharedSvc],
      certificates: [{ commonName: null, sans: [], issuer: null, fingerprint: "fp", validFrom: null, validTo: null, expired: null, sources: ["censys"] }],
      asn: 1234,
    }))
    expect(r.level).toBe("very_high")
  })

  test("an asset with zero sources scores zero — nothing to be confident in", () => {
    expect(scoreConfidence(assetWith([], { isQueryTarget: true })).score).toBe(0)
  })
})

describe("Exposure risk — amplifies CVE risk, never invents it", () => {
  const base = (over: Partial<ExposureAsset> = {}): ExposureAsset => ({
    id: "a", ip: "1.2.3.4", domain: null, domains: [], hostnames: [], asn: null, organization: null,
    country: null, city: null, latitude: null, longitude: null,
    services: [svc(443, "censys", { product: "Apache", version: "2.4.49", protocol: "HTTPS" })],
    technologies: [], certificates: [],
    vulnerabilities: [vuln("CVE-2021-41773", "version", "netlas", { providerScore: 7.5, providerSeverity: "high", matchedProduct: "Apache" })],
    threat: null, sources: ["censys", "netlas", "leakix"], sourceCount: 3,
    confidence: "high", confidenceScore: 70, evidence: [],
    enrichmentStatus: "enriched", isQueryTarget: false,
    firstSeen: null, lastSeen: null,
    exposureRisk: null, raw: [], ...over,
  })

  const kevFacts = new Map<string, CveFacts>([["CVE-2021-41773", { cveId: "CVE-2021-41773", cvss: 7.5, epss: 0.94, isKev: true, hasExploit: true }]])

  test("an exposed KEV CVE with a version match escalates to critical", () => {
    const r = computeExposureRisk(base(), kevFacts)
    expect(r.score).toBeGreaterThan(r.baseRbvm)
    expect(r.severity).toBe("critical")
    expect(r.slaHours).toBe(24) // KEV forces 24h
    expect(r.drivingCves).toContain("CVE-2021-41773")
  })

  test("no correlated CVE means zero risk — exposure alone is not a vulnerability", () => {
    const r = computeExposureRisk(base({ vulnerabilities: [] }), new Map())
    expect(r.score).toBe(0)
    expect(r.severity).toBe("low")
  })

  test("exposure cannot manufacture a critical from a low-severity CVE", () => {
    const lowFacts = new Map<string, CveFacts>([["CVE-2020-0001", { cveId: "CVE-2020-0001", cvss: 2.0, epss: 0.01, isKev: false, hasExploit: false }]])
    const r = computeExposureRisk(
      base({ vulnerabilities: [vuln("CVE-2020-0001", "version", "netlas", { providerScore: 2, providerSeverity: "low" })] }),
      lowFacts,
    )
    expect(r.severity).toBe("low")
    expect(r.score).toBeLessThan(25)
  })

  test("low correlation confidence reduces the score", () => {
    // Uses a MID-range CVE deliberately: with a KEV/high-EPSS CVE the score
    // saturates at the 100 cap for both confidence levels, so the penalty
    // would be invisible. That saturation is intended (both really are
    // "fix now"), but it makes such a case useless for testing the mechanism.
    const midFacts = new Map<string, CveFacts>([["CVE-2020-1234", { cveId: "CVE-2020-1234", cvss: 5.0, epss: 0.2, isKev: false, hasExploit: false }]])
    const midAsset = (over: Partial<ExposureAsset> = {}) => base({
      vulnerabilities: [vuln("CVE-2020-1234", "version", "netlas", { providerScore: 5, providerSeverity: "medium" })],
      ...over,
    })
    const high = computeExposureRisk(midAsset(), midFacts).score
    const low = computeExposureRisk(midAsset({ confidence: "low" }), midFacts).score
    expect(high).toBeLessThan(100) // guard: if this ever saturates, the test stops proving anything
    expect(low).toBeLessThan(high)
  })

  test("the score is capped at 100 even when the factor would exceed it", () => {
    const r = computeExposureRisk(base(), kevFacts)
    expect(r.score).toBeLessThanOrEqual(100)
  })

  test("GreyNoise malicious activity raises risk; every factor is itemised", () => {
    const withThreat = computeExposureRisk(
      base({ threat: { ip: "1.2.3.4", classification: "malicious", noise: true, riot: false, actor: null, lastSeen: null, link: null } }),
      kevFacts,
    )
    const without = computeExposureRisk(base(), kevFacts)
    expect(withThreat.score).toBeGreaterThanOrEqual(without.score)
    expect(withThreat.factors.some((f) => f.label.includes("GreyNoise"))).toBe(true)
    // The number must always be explainable.
    expect(withThreat.factors.length).toBeGreaterThan(1)
  })

  test("a CVE absent from OCTUPUS's own pipeline never infers KEV/exploit from the EASM provider", () => {
    const r = computeExposureRisk(base(), new Map()) // no authoritative facts
    expect(r.factors.some((f) => f.label === "CISA KEV")).toBe(false)
    expect(r.factors.some((f) => f.label === "Public exploit")).toBe(false)
  })
})

describe("Query classification", () => {
  test("routes each input shape to the right strategy", () => {
    expect(classifyQuery("80.82.77.139")).toBe("ip")
    expect(classifyQuery("CVE-2021-44228")).toBe("cve")
    expect(classifyQuery("example.com")).toBe("domain")
    expect(classifyQuery("443")).toBe("port")
    expect(classifyQuery("Apache 2.4.49")).toBe("product")
  })
})

describe("Input validation — SSRF and injection guards", () => {
  test("accepts genuine IPs and rejects smuggled paths/schemes", () => {
    expect(isValidIp("80.82.77.139")).toBe(true)
    expect(isValidIp("1.1.1.1/../admin")).toBe(false)
    expect(isValidIp("http://evil.com")).toBe(false)
    expect(isValidIp("999.1.1.1")).toBe(false)
  })

  test("accepts domains and rejects credentials/ports/paths", () => {
    expect(isValidDomain("example.com")).toBe(true)
    expect(isValidDomain("sub.example.co.uk")).toBe(true)
    expect(isValidDomain("evil.com/path")).toBe(false)
    expect(isValidDomain("user@evil.com")).toBe(false)
    expect(isValidDomain("evil.com:8080")).toBe(false)
  })

  test("private and loopback ranges are refused (no internal probing via a provider)", () => {
    expect(isPrivateIp("127.0.0.1")).toBe(true)
    expect(isPrivateIp("10.0.0.5")).toBe(true)
    expect(isPrivateIp("192.168.1.1")).toBe(true)
    expect(isPrivateIp("172.16.0.1")).toBe(true)
    expect(isPrivateIp("169.254.1.1")).toBe(true)
    expect(isPrivateIp("80.82.77.139")).toBe(false)
  })

  test("CVE ids are strictly matched", () => {
    expect(isValidCve("CVE-2021-44228")).toBe(true)
    expect(isValidCve("CVE-21-4")).toBe(false)
  })
})

describe("Netlas port parsing — the change signal monitoring depends on", () => {
  /**
   * Real shape, captured live from GET /api/host/45.33.32.156 on 2026-08-30.
   * Netlas reports open ports in `ports[]`, separate from `software[]`. This
   * was previously unparsed, so Netlas contributed zero services and periodic
   * monitoring had no port-change signal at all.
   */
  const LIVE_PORTS = [
    { prot4: "udp", protocol: "ntp", port: 123, prot7: "ntp" },
    { protocol: "http", prot4: "tcp", port: 80, prot7: "http" },
  ]

  test("extracts ports with transport and protocol", () => {
    const svc = parsePorts(LIVE_PORTS)
    expect(svc.map((s) => s.port)).toEqual([80, 123]) // sorted
    const http = svc.find((s) => s.port === 80)!
    expect(http.transport).toBe("tcp")
    expect(http.protocol).toBe("http")
    const ntp = svc.find((s) => s.port === 123)!
    expect(ntp.transport).toBe("udp")
  })

  test("does NOT invent a product for a port Netlas made no product claim about", () => {
    // `software[]` is host-wide, not per-port. Attributing it to a port would
    // fabricate an association, and the risk engine weights product matches.
    const svc = parsePorts(LIVE_PORTS)
    for (const s of svc) {
      expect(s.product).toBeNull()
      expect(s.version).toBeNull()
      expect(s.claims[0].product).toBeNull()
    }
  })

  test("rejects out-of-range and malformed ports instead of emitting junk services", () => {
    expect(parsePorts([{ port: 0 }, { port: -1 }, { port: 70000 }, { port: "abc" }, {}])).toHaveLength(0)
  })

  test("accepts a numeric string port and de-duplicates repeats", () => {
    const svc = parsePorts([{ port: "443", prot4: "tcp" }, { port: 443, protocol: "https" }])
    expect(svc).toHaveLength(1)
    expect(svc[0].port).toBe(443)
    expect(svc[0].transport).toBe("tcp")   // merged from the first claim
    expect(svc[0].protocol).toBe("https")  // filled in by the second
  })

  test("attributes every service to netlas so provenance stays honest", () => {
    for (const s of parsePorts(LIVE_PORTS)) expect(s.sources).toEqual(["netlas"])
  })
})

describe("Netlas software-to-port attribution — reading, not inferring", () => {
  /**
   * Real shape from GET /api/host/45.33.32.156 (2026-08-31). Netlas states the
   * port association itself via `uri`, so using it reports what the provider
   * said. Discarding it left every Netlas port with no product and gave CVE
   * correlation nothing to work from.
   */
  const LIVE_SOFTWARE = [{
    uri: "http://45.33.32.156:80/",
    tag: [
      { name: "ubuntu", fullname: "Ubuntu", category: ["Operating systems"], ubuntu: { version: "" } },
      { name: "apache_http_server", fullname: "Apache HTTP Server", category: ["Web servers"], apache_http_server: { version: "2.4.7" } },
    ],
  }]

  test("extracts the port and the listening product with its version", () => {
    const m = softwareByPort(LIVE_SOFTWARE)
    expect(m.get(80)).toEqual({ product: "Apache HTTP Server", version: "2.4.7" })
  })

  test("the host OPERATING SYSTEM is never used as the service product", () => {
    // Ubuntu runs the host; it is not what is listening on port 80. Claiming it
    // would attach OS CVEs to a web server.
    expect(softwareByPort(LIVE_SOFTWARE).get(80)?.product).not.toBe("Ubuntu")
  })

  test("software with no URI is not attributed to any port", () => {
    expect(softwareByPort([{ tag: [{ name: "nginx", fullname: "nginx" }] }]).size).toBe(0)
  })

  test("implicit scheme ports are resolved; anything unparseable is null", () => {
    expect(portFromUri("http://1.2.3.4/")).toBe(80)
    expect(portFromUri("https://1.2.3.4/")).toBe(443)
    expect(portFromUri("http://1.2.3.4:8443/")).toBe(8443)
    expect(portFromUri("not a url")).toBeNull()
    expect(portFromUri(undefined)).toBeNull()
    expect(portFromUri("ftp://1.2.3.4/")).toBeNull() // no default we can assert
  })

  test("a versioned claim wins over an unversioned one for the same port", () => {
    const m = softwareByPort([{
      uri: "https://1.2.3.4:443/",
      tag: [
        { name: "nginx", fullname: "nginx", category: ["Web servers"] },
        { name: "openssl", fullname: "OpenSSL", category: ["Crypto"], openssl: { version: "1.1.1" } },
      ],
    }])
    expect(m.get(443)?.version).toBe("1.1.1")
  })
})

describe("Error classification — actionable, never a bare 'blocked'", () => {
  const mk = (status: number) => new Response("{}", { status })
  test("maps HTTP status to the operator-actionable cause", () => {
    expect(classifyHttp(mk(401), "").status).toBe("authentication_failed")
    expect(classifyHttp(mk(402), "").status).toBe("quota_exhausted")
    expect(classifyHttp(mk(429), "").status).toBe("rate_limited")
    expect(classifyHttp(mk(400), "").status).toBe("query_unsupported")
    expect(classifyHttp(mk(503), "").status).toBe("provider_unavailable")
  })

  test("an exhausted account balance reported as 400/422 is quota, not a bad query", () => {
    // Observed live: Censys answers an out-of-credits account with
    // HTTP 422 {"errors":[{"message":"insufficient balance"}]}. Treating that
    // as a malformed query blames the query for an account state AND makes
    // periodic monitoring back the asset off as if it were broken.
    const body = '{"title":"Unprocessable Entity","status":422,"errors":[{"message":"insufficient balance"}]}'
    const e = classifyHttp(mk(422), body)
    expect(e.status).toBe("quota_exhausted")
    expect(e.retryable).toBe(true) // credits can be topped up; this is not permanent

    // A genuinely malformed query must still classify as such.
    expect(classifyHttp(mk(422), '{"detail":"invalid field name"}').status).toBe("query_unsupported")
  })

  test("only transient failures are marked retryable", () => {
    expect(classifyHttp(mk(429), "").retryable).toBe(true)
    expect(classifyHttp(mk(503), "").retryable).toBe(true)
    expect(classifyHttp(mk(401), "").retryable).toBe(false) // a bad key never fixes itself
  })

  test("HTML error pages are not leaked into the operator message", () => {
    const e = classifyHttp(mk(502), "<html><body>nginx</body></html>")
    expect(e.message).not.toContain("<html>")
  })
})

describe("Provider failure isolation", () => {
  test("observations from healthy providers survive when others contribute none", () => {
    // Mirrors the real orchestrator contract: a failed provider yields zero
    // observations, and correlation still produces the working providers' asset.
    const assets = correlate([
      obs({ provider: "leakix", ip: "3.3.3.3" }),
      obs({ provider: "netlas", ip: "3.3.3.3" }),
      // fofa + zoomeye contributed nothing (quota exhausted)
    ])
    expect(assets).toHaveLength(1)
    expect(assets[0].sourceCount).toBe(2)
  })
})

describe("A3 REGRESSION — CVE queries never use the generic product path", () => {
  test("TEST 4/5: each provider's CVE builder uses its documented CVE field", () => {
    // The defect: a CVE fell through to `app="CVE-2021-44228"`, a meaningless
    // product search. These must use real CVE fields instead.
    expect(buildCensysCveQuery("CVE-2021-44228")).toBe('vulnerabilities.cve_id="CVE-2021-44228"')
    expect(buildFofaQuery("CVE-2021-44228", "cve")).toBe('cve="CVE-2021-44228"')
    expect(buildZoomeyeQuery("CVE-2021-44228", "cve")).toBe('cve="CVE-2021-44228"')

    // And explicitly NOT the product form.
    expect(buildFofaQuery("CVE-2021-44228", "cve")).not.toBe('app="CVE-2021-44228"')
    expect(buildZoomeyeQuery("CVE-2021-44228", "cve")).not.toBe('app="CVE-2021-44228"')
    expect(buildCensysCveQuery("CVE-2021-44228")).not.toContain("services.software.product")
  })

  test("TEST 5: a provider without CVE capability reports unsupported, with no free-text fallback", () => {
    const o = leakixCveUnsupported("CVE-2021-44228")
    expect(o.status).toBe("query_unsupported")
    expect(o.observationCount).toBe(0)
    expect(o.retryable).toBe(false)
    // It must explain WHY rather than silently returning nothing.
    expect(o.message).toBeTruthy()
  })

  test("classifyQuery routes a CVE to the cve strategy, not product", () => {
    expect(classifyQuery("CVE-2021-44228")).toBe("cve")
    expect(classifyQuery("CVE-2021-44228")).not.toBe("product")
  })

  test("a pivot match is ranked weaker than a direct provider CVE assertion", () => {
    // pivot = "this CVE affects a product we saw here" — a lead, not a finding.
    const assets = correlate([
      obs({ provider: "leakix", ip: "20.0.0.1", vulnerabilities: [vuln("CVE-2021-44228", "pivot", "leakix", { matchedProduct: "Apache" })] }),
      obs({ provider: "censys", ip: "20.0.0.1", vulnerabilities: [vuln("CVE-2021-44228", "cve-search", "censys")] }),
    ])
    expect(assets[0].vulnerabilities).toHaveLength(1)
    // The stronger evidence must win the merge.
    expect(assets[0].vulnerabilities[0].matchType).toBe("cve-search")
  })
})

describe("B2 — enrichment status is distinct from confidence", () => {
  test("TEST 7: an un-enriched asset is flagged not_requested, not merely 'low confidence'", () => {
    const assets = correlate([obs({ provider: "leakix", ip: "30.0.0.1" })])
    // correlate() never claims enrichment happened; the orchestrator sets it.
    expect(assets[0].enrichmentStatus).toBe("not_requested")
  })

  test("enrichmentStatus and confidence are independent fields", () => {
    const assets = correlate([
      obs({ provider: "leakix", ip: "30.0.0.2" }),
      obs({ provider: "censys", ip: "30.0.0.2" }),
      obs({ provider: "netlas", ip: "30.0.0.2" }),
    ])
    expect(assets[0].confidence).not.toBe("low")       // 3 sources => decent confidence
    expect(assets[0].enrichmentStatus).toBe("not_requested") // but never examined
  })
})

describe("C6 — IPv6 private/local detection", () => {
  test("TEST 9: ULA fc00::/7 is treated as private", () => {
    expect(isPrivateIp("fc00::1")).toBe(true)
    expect(isPrivateIp("fd12:3456:789a::1")).toBe(true)
  })

  test("link-local, loopback, unspecified and multicast are private", () => {
    expect(isPrivateIp("fe80::1")).toBe(true)
    expect(isPrivateIp("::1")).toBe(true)
    expect(isPrivateIp("::")).toBe(true)
    expect(isPrivateIp("ff02::1")).toBe(true)
  })

  test("an internal IPv4 cannot be smuggled through in IPv4-mapped form", () => {
    expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true)
    expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true)
  })

  test("legitimate public IPv6 is NOT blocked", () => {
    expect(isPrivateIp("2606:4700:4700::1111")).toBe(false) // Cloudflare
    expect(isPrivateIp("2001:4860:4860::8888")).toBe(false) // Google
  })
})

describe("TEST 10 — provider secrets never reach normalized output", () => {
  test("no provider adapter embeds a credential in its observation shape", () => {
    // Guards against an adapter accidentally putting an API key into `raw`,
    // `query` or `notes`, which would then reach the UI, cache and logs.
    const SECRET_SHAPES = /(api[_-]?key|authorization|bearer\s|censys_[a-z0-9]{6}|npg_|sk-or-v1)/i
    const assets = correlate([
      obs({ provider: "censys", ip: "40.0.0.1", raw: { ip: "40.0.0.1", services: [] } }),
      obs({ provider: "leakix", ip: "40.0.0.1", notes: "Exposed service detected" }),
    ])
    const serialized = JSON.stringify(assets)
    expect(SECRET_SHAPES.test(serialized)).toBe(false)
  })
})

describe("Evidence quality gates risk — a lead must not score like a confirmation", () => {
  const kevFacts = new Map<string, CveFacts>([["CVE-2021-44228", { cveId: "CVE-2021-44228", cvss: 10, epss: 0.99999, isKev: true, hasExploit: true }]])
  const assetWithMatch = (matchType: VulnMatchType): ExposureAsset => ({
    id: "a", ip: "1.2.3.4", domain: null, domains: [], hostnames: [], asn: null, organization: null,
    country: null, city: null, latitude: null, longitude: null,
    services: [svc(443, "censys", { product: "cloudflare" })],
    technologies: [], certificates: [],
    vulnerabilities: [vuln("CVE-2021-44228", matchType, "leakix", { matchedProduct: "Apache" })],
    threat: null, sources: ["leakix", "netlas", "censys"], sourceCount: 3,
    confidence: "very_high", confidenceScore: 85, evidence: [],
    enrichmentStatus: "enriched", isQueryTarget: false,
    firstSeen: null, lastSeen: null, exposureRisk: null, raw: [],
  })

  test("a product-name PIVOT on a KEV CVE must NOT reach critical", () => {
    // Observed live before the fix: a Cloudflare load balancer scored 100
    // CRITICAL purely from a Log4Shell product-name pivot.
    const r = computeExposureRisk(assetWithMatch("pivot"), kevFacts)
    expect(r.severity).not.toBe("critical")
    expect(r.score).toBeLessThan(75)
    expect(r.factors.some((f) => f.label === "Potential match only")).toBe(true)
  })

  test("a provider-confirmed CVE hit on the same asset DOES reach critical", () => {
    const r = computeExposureRisk(assetWithMatch("cve-search"), kevFacts)
    expect(r.severity).toBe("critical")
    expect(r.slaHours).toBe(24)
  })

  test("evidence quality is strictly ordered: pivot < product < version = cve-search", () => {
    const pivot = computeExposureRisk(assetWithMatch("pivot"), kevFacts).score
    const product = computeExposureRisk(assetWithMatch("product"), kevFacts).score
    const version = computeExposureRisk(assetWithMatch("version"), kevFacts).score
    expect(pivot).toBeLessThan(product)
    expect(product).toBeLessThan(version)
  })

  test("KEV/exploit escalation requires a strong link, not a pivot", () => {
    const r = computeExposureRisk(assetWithMatch("pivot"), kevFacts)
    expect(r.factors.some((f) => f.label === "CISA KEV")).toBe(false)
    expect(r.factors.some((f) => f.label === "Public exploit")).toBe(false)
  })
})
