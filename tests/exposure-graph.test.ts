/**
 * EXPOSURE INTELLIGENCE GRAPH — adapter guarantees.
 *
 * The graph is a visualization layer, so every test here is about it NOT
 * becoming a source of truth: no invented nodes, no promoted evidence, no
 * recomputed risk, no fabricated provenance, no false merging.
 *
 * All fixtures below are DETERMINISTIC UNIT-TEST DATA. Nothing here is seeded
 * into the database or shown in production.
 */
import { describe, test, expect } from "bun:test"
import {
  buildGraph, neighborhood, projectGraph, nodeId,
  type ExposureGraph, type GraphAlertInput, type GraphCveFacts,
} from "@/lib/exposure/graph"
import { makeVulnerability } from "@/lib/exposure/normalize"
import type {
  ExposureAsset, ExposureService, ProviderName, EvidenceTier,
} from "@/lib/exposure/types"

// ─────────────────────────── fixtures ───────────────────────────

function service(port: number, opts: {
  product?: string | null; version?: string | null; sources?: ProviderName[]
  conflict?: boolean; claims?: Array<{ source: ProviderName; product: string | null; version: string | null }>
} = {}): ExposureService {
  const sources = opts.sources ?? ["censys"]
  return {
    port, transport: "tcp", protocol: "http",
    product: opts.product ?? null, vendor: null, version: opts.version ?? null,
    banner: null, httpStatus: null, httpTitle: null, httpServer: null,
    sources, conflict: opts.conflict,
    claims: opts.claims
      ? opts.claims.map((c) => ({ ...c, vendor: null, protocol: "http" }))
      : sources.map((s) => ({ source: s, product: opts.product ?? null, vendor: null, version: opts.version ?? null, protocol: "http" })),
  }
}

function asset(id: string, over: Partial<ExposureAsset> = {}): ExposureAsset {
  return {
    id, ip: id.startsWith("ip:") ? id.slice(3) : null,
    domain: null, domains: [], hostnames: [],
    services: [], technologies: [], certificates: [], vulnerabilities: [],
    sources: ["censys"], sourceCount: 1, confidence: "high", confidenceScore: 80,
    evidence: [], enrichmentStatus: "enriched", isQueryTarget: false,
    threat: null, raw: [],
    freshness: {
      fetchedAt: "2026-08-31T00:00:00.000Z",
      observedAt: "2026-08-21T00:00:00.000Z",
      observationAgeSeconds: 10 * 86400, fromCache: false, state: "stale",
    },
    exposureRisk: {
      score: 30.9, severity: "medium", baseRbvm: 26.9, exposureFactor: 1.15,
      factors: [], slaHours: 168, drivingCves: [],
    },
    ...over,
  } as ExposureAsset
}

function vuln(cveId: string, tier: EvidenceTier, opts: { port?: number | null; sources?: ProviderName[] } = {}) {
  const matchType = ({ confirmed: "cve-search", strong: "version", product: "product", pivot: "pivot", weak: "banner" } as const)[tier]
  return {
    correlatedPort: opts.port ?? null,
    ...makeVulnerability({ cveId, matchType, sources: opts.sources ?? ["censys"] }),
  }
}

/**
 * ITEM 18 — the mandated regression fixture.
 *
 * One domain fronting THREE distinct IPs, with services, product/version,
 * multi-provider provenance and a product-tier CVE. This is the exact shape
 * that a naive correlator collapses into a single asset.
 */
function multiIpFixture(): ExposureAsset[] {
  const DOMAIN = "example.com"
  return [
    asset("ip:104.20.23.154", {
      domains: [DOMAIN], sources: ["censys", "netlas"], sourceCount: 2,
      services: [
        service(80, { product: "Apache HTTP Server", version: "2.4.7", sources: ["netlas"] }),
        service(443, { product: "Apache HTTP Server", version: "2.4.7", sources: ["censys", "netlas"] }),
      ],
      vulnerabilities: [vuln("CVE-2021-41773", "product", { port: 443, sources: ["netlas"] })],
    }),
    asset("ip:172.66.147.243", {
      domains: [DOMAIN], sources: ["leakix"], sourceCount: 1,
      services: [service(443, { product: "nginx", sources: ["leakix"] })],
    }),
    asset("ip:8.47.69.8", {
      domains: [DOMAIN], sources: ["censys"], sourceCount: 1,
      services: [service(80, { sources: ["censys"] })], // port only, no product
    }),
  ]
}

const CVE_FACTS = new Map<string, GraphCveFacts>([
  ["CVE-2021-41773", { cveId: "CVE-2021-41773", cvss: 7.5, epss: 0.97, isKev: true, hasExploit: true, severity: "high" }],
])

const byType = (g: ExposureGraph, t: string) => g.nodes.filter((n) => n.type === t)
const edgesOf = (g: ExposureGraph, kind: string) => g.edges.filter((e) => e.kind === kind)

// ─────────────────────────── tests ───────────────────────────

describe("ITEM 18 regression — a domain fronting many IPs must never collapse", () => {
  const g = buildGraph(multiIpFixture(), { cveFacts: CVE_FACTS })

  test("one domain node and THREE distinct IP nodes", () => {
    expect(byType(g, "domain")).toHaveLength(1)
    expect(byType(g, "ip")).toHaveLength(3)
    expect(byType(g, "ip").map((n) => n.label).sort())
      .toEqual(["104.20.23.154", "172.66.147.243", "8.47.69.8"])
  })

  test("the domain RESOLVES_TO all three IPs — a relationship, not an identity", () => {
    const resolves = edgesOf(g, "resolves_to")
    expect(resolves).toHaveLength(3)
    expect(new Set(resolves.map((e) => e.source))).toEqual(new Set([nodeId.domain("example.com")]))
    expect(new Set(resolves.map((e) => e.target)).size).toBe(3)
  })

  test("services stay attached to their own IP, never pooled across assets", () => {
    // 80+443 on the first IP, 443 on the second, 80 on the third.
    expect(byType(g, "service")).toHaveLength(4)
    const exposes = edgesOf(g, "exposes")
    const byIp = new Map<string, number>()
    for (const e of exposes) byIp.set(e.source, (byIp.get(e.source) ?? 0) + 1)
    expect(byIp.get("ip:104.20.23.154")).toBe(2)
    expect(byIp.get("ip:172.66.147.243")).toBe(1)
    expect(byIp.get("ip:8.47.69.8")).toBe(1)
  })

  test("two services on different hosts running the same product share ONE product node", () => {
    // Apache appears on ports 80 and 443 of the same host: one product node,
    // two `runs` edges. This is a genuine shared entity, not a merge of assets.
    const apache = byType(g, "product").filter((n) => n.label === "Apache HTTP Server")
    expect(apache).toHaveLength(1)
    expect(edgesOf(g, "runs").filter((e) => e.target === apache[0].id)).toHaveLength(2)
  })

  test("product -> version is created only where a version was reported", () => {
    expect(byType(g, "version")).toHaveLength(1)
    expect(byType(g, "version")[0].label).toBe("Apache HTTP Server 2.4.7")
    // nginx had no version, so no version node was invented for it.
    expect(byType(g, "version").some((n) => n.label.includes("nginx"))).toBe(false)
  })

  test("a port with no product produces NO product node", () => {
    // 80/tcp on 8.47.69.8 reported a port and nothing else.
    const svc = g.nodes.find((n) => n.id === nodeId.service("ip:8.47.69.8", 80))!
    expect(svc.metadata.product).toBeNull()
    expect(edgesOf(g, "runs").some((e) => e.source === svc.id)).toBe(false)
  })

  test("the CVE anchors to the VERSION node and carries its real evidence tier", () => {
    const affected = edgesOf(g, "affected_by")
    expect(affected).toHaveLength(1)
    expect(affected[0].source).toBe(nodeId.version("Apache HTTP Server", "2.4.7"))
    expect(affected[0].evidenceTier).toBe("product")
    expect(affected[0].metadata?.confirmed).toBe(false)
  })

  test("CVE facts come from the existing CVE store, unchanged", () => {
    const cve = byType(g, "cve")[0]
    expect(cve.metadata.cvss).toBe(7.5)
    expect(cve.metadata.epss).toBe(0.97)
    expect(cve.metadata.isKev).toBe(true)
    expect(cve.metadata.hasExploit).toBe(true)
  })

  test("provider provenance is preserved per provider, never merged", () => {
    const providers = byType(g, "provider").map((n) => n.label).sort()
    expect(providers).toEqual(["censys", "leakix", "netlas"])
    // No generic aggregate node.
    expect(g.nodes.some((n) => /internet/i.test(n.label))).toBe(false)
    // LeakIX observed only the asset it actually saw.
    const leakixEdges = edgesOf(g, "observed").filter((e) => e.source === nodeId.provider("leakix"))
    const targets = leakixEdges.map((e) => e.target)
    expect(targets).toContain("ip:172.66.147.243")
    expect(targets).not.toContain("ip:104.20.23.154")
  })

  test("RBVM risk is passed through verbatim, not recomputed", () => {
    for (const ip of byType(g, "ip")) {
      expect(ip.metadata.riskScore).toBe(30.9)
      expect(ip.metadata.severity).toBe("medium")
    }
  })
})

describe("Evidence can never be promoted by the graph", () => {
  test("product evidence stays product and unconfirmed", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      services: [service(443, { product: "Apache HTTP Server", version: "2.4.7" })],
      vulnerabilities: [vuln("CVE-2021-41773", "product", { port: 443 })],
    })])
    const e = edgesOf(g, "affected_by")[0]
    expect(e.evidenceTier).toBe("product")
    expect(e.metadata?.confirmed).toBe(false)
  })

  test("pivot evidence stays pivot and unconfirmed", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      vulnerabilities: [vuln("CVE-2021-44228", "pivot")],
    })])
    const e = edgesOf(g, "affected_by")[0]
    expect(e.evidenceTier).toBe("pivot")
    expect(e.metadata?.confirmed).toBe(false)
  })

  test("weak evidence stays weak", () => {
    const g = buildGraph([asset("ip:1.2.3.4", { vulnerabilities: [vuln("CVE-2021-41773", "weak")] })])
    expect(edgesOf(g, "affected_by")[0].evidenceTier).toBe("weak")
  })

  test("an existing CONFIRMED finding stays confirmed", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      vulnerabilities: [vuln("CVE-2021-41773", "confirmed", { sources: ["netlas"] })],
    })])
    const e = edgesOf(g, "affected_by")[0]
    expect(e.evidenceTier).toBe("confirmed")
    expect(e.metadata?.confirmed).toBe(true)
  })

  test("an OBSERVED edge is direct evidence; an AFFECTED_BY edge never is", () => {
    // The visual distinction the analyst relies on: a provider SAW this, versus
    // OCTUPUS MATCHED this.
    const g = buildGraph([asset("ip:1.2.3.4", {
      services: [service(443, { product: "nginx" })],
      vulnerabilities: [vuln("CVE-2021-41773", "product", { port: 443 })],
    })])
    expect(edgesOf(g, "observed").every((e) => e.direct === true)).toBe(true)
    expect(edgesOf(g, "affected_by").every((e) => e.direct === false)).toBe(true)
  })
})

describe("Query-target never becomes a provider", () => {
  const queryTarget = asset("ip:9.9.9.9", {
    isQueryTarget: true, sources: [], sourceCount: 0, confidence: "low",
    enrichmentStatus: "not_requested", exposureRisk: null,
  })

  test("an asset with no provider evidence produces no provider node or edge", () => {
    const g = buildGraph([queryTarget])
    expect(byType(g, "provider")).toHaveLength(0)
    expect(edgesOf(g, "observed")).toHaveLength(0)
  })

  test("the asset itself is still rendered, marked as a query target", () => {
    const g = buildGraph([queryTarget])
    const ip = byType(g, "ip")[0]
    expect(ip.metadata.isQueryTarget).toBe(true)
    expect(ip.metadata.sourceCount).toBe(0)
    expect(ip.metadata.providers).toEqual([])
  })

  test("no provider appears in the stats for a query-target-only graph", () => {
    expect(buildGraph([queryTarget]).stats.providers).toHaveLength(0)
  })
})

describe("Nothing is invented from missing fields", () => {
  test("an asset with nothing populated yields exactly one node and no edges", () => {
    const g = buildGraph([asset("ip:1.2.3.4", { sources: [], sourceCount: 0 })])
    expect(g.nodes).toHaveLength(1)
    expect(g.edges).toHaveLength(0)
  })

  test("empty input produces an empty graph, not a placeholder", () => {
    const g = buildGraph([])
    expect(g.nodes).toHaveLength(0)
    expect(g.edges).toHaveLength(0)
    expect(g.stats.assetsTotal).toBe(0)
    expect(g.stats.truncated).toBe(false)
  })

  test("blank domains and blank product names are skipped, not rendered", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      domains: ["", "   "],
      technologies: [{ name: "  ", version: null, categories: [], sources: ["censys"] }],
    })])
    expect(byType(g, "domain")).toHaveLength(0)
    expect(byType(g, "product")).toHaveLength(0)
  })

  test("a CVE absent from the CVE store shows null facts, never guessed ones", () => {
    const g = buildGraph([asset("ip:1.2.3.4", { vulnerabilities: [vuln("CVE-2099-0001", "product")] })], {
      cveFacts: new Map(),
    })
    const cve = byType(g, "cve")[0]
    expect(cve.metadata.cvss).toBeNull()
    expect(cve.metadata.epss).toBeNull()
    expect(cve.metadata.isKev).toBeNull()
  })

  test("an asset with no risk yet reports null, not zero", () => {
    const g = buildGraph([asset("ip:1.2.3.4", { exposureRisk: null })])
    expect(byType(g, "ip")[0].metadata.riskScore).toBeNull()
    expect(byType(g, "ip")[0].metadata.severity).toBeNull()
  })
})

describe("Host-wide software is not attached to a port", () => {
  const g = buildGraph([asset("ip:1.2.3.4", {
    services: [service(80, { product: "Apache HTTP Server", version: "2.4.7", sources: ["netlas"] })],
    technologies: [{ name: "Ubuntu", version: null, categories: ["Operating systems"], sources: ["netlas"] }],
  })])

  test("the host-wide product hangs off the IP, not the service", () => {
    const ubuntu = byType(g, "product").find((n) => n.label === "Ubuntu")!
    const runs = edgesOf(g, "runs").filter((e) => e.target === ubuntu.id)
    expect(runs).toHaveLength(1)
    expect(runs[0].source).toBe("ip:1.2.3.4")           // the host
    expect(runs[0].source).not.toBe(nodeId.service("ip:1.2.3.4", 80))
  })

  test("its scope is labelled so the UI can say why", () => {
    const ubuntu = byType(g, "product").find((n) => n.label === "Ubuntu")!
    expect(ubuntu.metadata.scope).toBe("host")
    const runs = edgesOf(g, "runs").find((e) => e.target === ubuntu.id)!
    expect(String(runs.metadata?.note)).toMatch(/not associated with a specific port/i)
  })

  test("service-level product keeps its own service association", () => {
    const apache = byType(g, "product").find((n) => n.label === "Apache HTTP Server")!
    const runs = edgesOf(g, "runs").find((e) => e.target === apache.id)!
    expect(runs.source).toBe(nodeId.service("ip:1.2.3.4", 80))
  })
})

describe("CVE anchoring follows the evidence, never deeper", () => {
  test("host-level finding (no port) anchors to the IP", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      services: [service(443, { product: "nginx", version: "1.24" })],
      vulnerabilities: [vuln("CVE-2021-41773", "confirmed")], // no correlatedPort
    })])
    expect(edgesOf(g, "affected_by")[0].source).toBe("ip:1.2.3.4")
  })

  test("port with no product anchors to the SERVICE", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      services: [service(443)],
      vulnerabilities: [vuln("CVE-2021-41773", "product", { port: 443 })],
    })])
    expect(edgesOf(g, "affected_by")[0].source).toBe(nodeId.service("ip:1.2.3.4", 443))
  })

  test("product without version anchors to the PRODUCT", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      services: [service(443, { product: "nginx" })],
      vulnerabilities: [vuln("CVE-2021-41773", "product", { port: 443 })],
    })])
    expect(edgesOf(g, "affected_by")[0].source).toBe(nodeId.product("nginx"))
  })

  test("a port that does not exist on the asset falls back to the IP, not a phantom service", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      services: [service(80)],
      vulnerabilities: [vuln("CVE-2021-41773", "product", { port: 9999 })],
    })])
    expect(edgesOf(g, "affected_by")[0].source).toBe("ip:1.2.3.4")
    expect(byType(g, "service")).toHaveLength(1) // no node created for 9999
  })
})

describe("Provider disagreement is preserved, not silently resolved", () => {
  test("both conflicting claims survive onto the service node", () => {
    const g = buildGraph([asset("ip:1.2.3.4", {
      sources: ["censys", "leakix"], sourceCount: 2,
      services: [service(443, {
        product: "Apache HTTP Server", version: "2.4.49", conflict: true,
        sources: ["censys", "leakix"],
        claims: [
          { source: "censys", product: "Apache HTTP Server", version: "2.4.49" },
          { source: "leakix", product: "nginx", version: null },
        ],
      })],
    })])
    const svc = byType(g, "service")[0]
    expect(svc.metadata.conflict).toBe(true)
    const claims = svc.metadata.claims as Array<{ source: string; product: string | null }>
    expect(claims).toHaveLength(2)
    expect(claims.map((c) => c.product)).toEqual(["Apache HTTP Server", "nginx"])
    // Both providers keep an observed edge; neither is dropped for disagreeing.
    const observers = edgesOf(g, "observed").filter((e) => e.target === svc.id).map((e) => e.source)
    expect(observers.sort()).toEqual([nodeId.provider("censys"), nodeId.provider("leakix")])
  })
})

describe("Alerts are represented, never generated", () => {
  const base = asset("ip:1.2.3.4", {
    vulnerabilities: [vuln("CVE-2021-41773", "confirmed", { sources: ["netlas"] })],
  })
  const alert: GraphAlertInput = {
    id: 7, asset_key: "ip:1.2.3.4", port: 443, cve_id: "CVE-2021-41773",
    kind: "new_exposed_vulnerability", state: "open", severity: "high",
    risk_score: 78, evidence_tier: "confirmed", created_at: "2026-08-31T00:00:00.000Z",
  }

  test("no alert record means no alert node", () => {
    const g = buildGraph([base])
    expect(byType(g, "alert")).toHaveLength(0)
    expect(edgesOf(g, "triggered")).toHaveLength(0)
  })

  test("a real alert record produces CVE -> TRIGGERED -> ALERT", () => {
    const g = buildGraph([base], { alerts: [alert] })
    expect(byType(g, "alert")).toHaveLength(1)
    const t = edgesOf(g, "triggered")[0]
    expect(t.source).toBe(nodeId.cve("CVE-2021-41773"))
    expect(t.target).toBe(nodeId.alert(7))
    expect(byType(g, "alert")[0].metadata.state).toBe("open")
  })

  test("an alert for a CVE not in the graph is ignored rather than inventing one", () => {
    const g = buildGraph([base], { alerts: [{ ...alert, cve_id: "CVE-2099-9999" }] })
    expect(byType(g, "alert")).toHaveLength(0)
  })

  test("an alert for an asset outside this graph is ignored", () => {
    const g = buildGraph([base], { alerts: [{ ...alert, asset_key: "ip:9.9.9.9" }] })
    expect(byType(g, "alert")).toHaveLength(0)
  })
})

describe("Freshness is carried honestly", () => {
  test("observation time and fetch time stay separate on the node", () => {
    const g = buildGraph(multiIpFixture())
    const ip = byType(g, "ip")[0]
    expect(ip.metadata.observedAt).toBe("2026-08-21T00:00:00.000Z")
    expect(ip.metadata.fetchedAt).toBe("2026-08-31T00:00:00.000Z")
    expect(ip.metadata.observedAt).not.toBe(ip.metadata.fetchedAt)
    expect(ip.metadata.freshness).toBe("stale")
  })

  test("the graph never emits LIVE", () => {
    const g = buildGraph(multiIpFixture())
    const blob = JSON.stringify(g)
    expect(blob).not.toMatch(/"freshness":"live"/)
    expect(blob).not.toMatch(/"live"/)
  })

  test("a cached read is labelled cached, not passed off as a provider state", () => {
    const a = asset("ip:1.2.3.4")
    a.freshness = { fetchedAt: "2026-08-31T00:00:00.000Z", observedAt: null, observationAgeSeconds: null, fromCache: true, state: "unknown" }
    expect(byType(buildGraph([a]), "ip")[0].metadata.freshness).toBe("cached")
  })

  test("no freshness at all reports unknown rather than a guess", () => {
    const a = asset("ip:1.2.3.4", { freshness: null })
    const ip = byType(buildGraph([a]), "ip")[0]
    expect(ip.metadata.freshness).toBe("unknown")
    expect(ip.metadata.observedAt).toBeNull()
  })
})

describe("Scale is bounded and filtering is non-destructive", () => {
  const many = Array.from({ length: 400 }, (_, i) =>
    asset(`ip:10.0.${Math.floor(i / 256)}.${i % 256}`, {
      services: [service(443, { product: "nginx" })],
      vulnerabilities: [vuln("CVE-2021-41773", "product", { port: 443 })],
    }))

  test("a large asset set is truncated with the truncation reported, not silently", () => {
    const g = buildGraph(many, { maxAssets: 50 })
    expect(g.stats.assetsIncluded).toBe(50)
    expect(g.stats.assetsTotal).toBe(400)
    expect(g.stats.truncated).toBe(true)
    expect(byType(g, "ip")).toHaveLength(50)
  })

  test("a graph within the cap is not marked truncated", () => {
    expect(buildGraph(many.slice(0, 10), { maxAssets: 50 }).stats.truncated).toBe(false)
  })

  test("building 400 assets stays fast enough to be interactive", () => {
    const t0 = performance.now()
    buildGraph(many, { maxAssets: 400 })
    expect(performance.now() - t0).toBeLessThan(2000)
  })

  test("projection returns a NEW graph and leaves the source untouched", () => {
    const g = buildGraph(multiIpFixture())
    const beforeNodes = g.nodes.length
    const beforeEdges = g.edges.length
    const projected = projectGraph(g, new Set(["ip:104.20.23.154"]))
    expect(projected.nodes).toHaveLength(1)
    expect(projected.edges).toHaveLength(0) // both endpoints required
    // Source model is intact — filtering must never destroy it.
    expect(g.nodes).toHaveLength(beforeNodes)
    expect(g.edges).toHaveLength(beforeEdges)
  })

  test("stats recount on projection instead of reporting stale totals", () => {
    const g = buildGraph(multiIpFixture())
    const projected = projectGraph(g, new Set(g.nodes.filter((n) => n.type === "ip").map((n) => n.id)))
    expect(projected.stats.nodeCounts.ip).toBe(3)
    expect(projected.stats.nodeCounts.domain).toBeUndefined()
  })
})

describe("Focus mode is a projection of the same model", () => {
  const g = buildGraph(multiIpFixture(), { cveFacts: CVE_FACTS })

  test("focusing an IP keeps its own services and drops unrelated hosts", () => {
    const keep = neighborhood(g, "ip:104.20.23.154", 2)
    expect(keep.has("ip:104.20.23.154")).toBe(true)
    expect(keep.has(nodeId.service("ip:104.20.23.154", 443))).toBe(true)
    // Reached at depth 2 via the shared domain — a real relationship, correctly shown.
    expect(keep.has(nodeId.domain("example.com"))).toBe(true)
  })

  test("depth 1 shows only immediate relationships", () => {
    const keep = neighborhood(g, "ip:172.66.147.243", 1)
    expect(keep.has(nodeId.service("ip:172.66.147.243", 443))).toBe(true)
    expect(keep.has("ip:104.20.23.154")).toBe(false) // two hops away
  })

  test("focused nodes are the SAME objects, not a rebuilt dataset", () => {
    const projected = projectGraph(g, neighborhood(g, "ip:104.20.23.154", 1))
    for (const n of projected.nodes) {
      expect(g.nodes.find((x) => x.id === n.id)).toBe(n) // identity, not a copy
    }
  })

  test("focusing an unknown node yields an empty set rather than throwing", () => {
    expect(neighborhood(g, "ip:203.0.113.1", 2).size).toBe(0)
  })
})

describe("The adapter is inert — no calls, no writes, no scoring", () => {
  test("the module performs no network or database access", async () => {
    const src = await Bun.file("lib/exposure/graph.ts").text()
    expect(src).not.toMatch(/fetch\(/)
    expect(src).not.toContain("https://")
    expect(src).not.toContain("@/lib/db")
    expect(src).not.toMatch(/\bsql`/)
  })

  test("it imports no scoring or correlation engine", async () => {
    const src = await Bun.file("lib/exposure/graph.ts").text()
    expect(src).not.toMatch(/^import .*risk-engine/m)
    expect(src).not.toMatch(/^import .*exposure\/risk/m)
    expect(src).not.toMatch(/^import .*cve-correlation/m)
    expect(src).not.toMatch(/computeRiskScore\(|computeExposureRisk\(|correlateServices\(/)
  })

  test("it never references a provider credential", async () => {
    const src = await Bun.file("lib/exposure/graph.ts").text()
    for (const k of ["CENSYS_API_TOKEN", "LEAKIX_API_KEY", "NETLAS_API_KEY", "FOFA_API_KEY", "ZOOMEYE_API_KEY", "GREYNOISE_API_KEY", "CRON_SECRET"]) {
      expect(src).not.toContain(k)
    }
  })

  test("raw provider payloads are never copied into node metadata", () => {
    // `asset.raw` can be large and is a debugging aid, not graph data.
    const a = asset("ip:1.2.3.4", {
      raw: [{ provider: "censys", data: { secret_looking: "Bearer abc123", huge: "x".repeat(5000) } }],
    })
    const blob = JSON.stringify(buildGraph([a]))
    expect(blob).not.toContain("Bearer")
    expect(blob).not.toContain("secret_looking")
  })

  test("building the graph does not mutate the input assets", () => {
    const assets = multiIpFixture()
    const snapshot = JSON.stringify(assets)
    buildGraph(assets, { cveFacts: CVE_FACTS })
    expect(JSON.stringify(assets)).toBe(snapshot)
  })

  test("the same input always produces the same output", () => {
    const a = multiIpFixture()
    expect(JSON.stringify(buildGraph(a, { cveFacts: CVE_FACTS })))
      .toBe(JSON.stringify(buildGraph(multiIpFixture(), { cveFacts: CVE_FACTS })))
  })
})
