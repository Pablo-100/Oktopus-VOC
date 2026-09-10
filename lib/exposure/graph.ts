/**
 * EXPOSURE INTELLIGENCE GRAPH — pure adapter.
 *
 * Transforms records OCTUPUS already holds into nodes and edges. It is a
 * PRESENTATION layer and deliberately powerless:
 *
 *   - no provider requests, no fetch, no external calls
 *   - no CVE correlation (that is `lib/exposure/cve-correlation.ts`)
 *   - no risk scoring (that is `lib/risk-engine.ts` via `computeExposureRisk`)
 *   - no evidence promotion (tiers are copied, never recomputed)
 *   - no writes of any kind
 *
 * Given the same input it returns the same output, so it is fully testable
 * without a database or a network.
 *
 * ── WHY A NODE EXISTS ────────────────────────────────────────────────────────
 * Every node is backed by a field that is actually populated. A type existing
 * in the union is not a reason to render one: an asset with no certificates
 * produces no certificate node, and a service whose product is null produces no
 * product node rather than a node labelled "unknown".
 *
 * ── WHERE A CVE ATTACHES ─────────────────────────────────────────────────────
 * A CVE is linked to the MOST SPECIFIC element its evidence supports, never
 * deeper:
 *   version known    -> VERSION node
 *   product only     -> PRODUCT node
 *   port only        -> SERVICE node
 *   host-level       -> IP node
 * A host-wide software reading (`asset.technologies`) is attached to the IP and
 * never to a port, because no source associated it with one.
 */
import type {
  ExposureAsset, ExposureService, ExposureCertificate, ExposureTechnology,
  ExposureVulnerability, EvidenceTier, ProviderName, Freshness, ConfidenceLevel,
  EnrichmentStatus, ThreatContext,
} from "@/lib/exposure/types"

/**
 * What the adapter actually reads.
 *
 * Structural rather than `ExposureAsset` so both callers can satisfy it
 * honestly: a live correlated asset assigns directly, while the persisted path
 * supplies only the fields the database really stores — instead of being forced
 * to invent `baseRbvm`, `exposureFactor` or `factors` just to satisfy a type.
 */
export interface GraphAssetInput {
  id: string
  ip?: string | null
  domain?: string | null
  domains: string[]
  asn?: number | null
  organization?: string | null
  country?: string | null
  services: ExposureService[]
  technologies: ExposureTechnology[]
  certificates: ExposureCertificate[]
  vulnerabilities: ExposureVulnerability[]
  sources: ProviderName[]
  sourceCount: number
  confidence: ConfidenceLevel
  enrichmentStatus: EnrichmentStatus
  isQueryTarget: boolean
  threat?: ThreatContext | null
  freshness?: Freshness | null
  providerFreshness?: Array<{ provider: ProviderName; freshness: Freshness }>
  /** Only the risk fields the graph displays. Never recomputed here. */
  exposureRisk?: { score: number; severity: string; slaHours?: number } | null
}

/** A full correlated asset is a valid graph input; this makes that explicit. */
export type { ExposureAsset }

export type GraphNodeType =
  | "domain" | "ip" | "service" | "product" | "version"
  | "cve" | "provider" | "certificate" | "alert"

/**
 * Edge kinds carry meaning an analyst reads directly.
 *
 * `observed` is DIRECT evidence — a provider saw this. `affected_by` is a
 * MATCH, whose strength is carried in `evidenceTier`. Keeping them as separate
 * kinds is what stops the graph implying a correlation was an observation.
 */
export type GraphEdgeKind =
  | "resolves_to"      // domain -> ip
  | "exposes"          // ip -> service
  | "runs"             // service -> product, or ip -> product for host-wide software
  | "has_version"      // product -> version
  | "affected_by"      // service/product/version/ip -> cve   (carries evidenceTier)
  | "triggered"        // cve -> alert
  | "observed"         // provider -> ip/service/certificate  (DIRECT evidence)
  | "associated_with"  // certificate -> domain/ip

export interface GraphNode {
  id: string
  type: GraphNodeType
  label: string
  metadata: Record<string, unknown>
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  kind: GraphEdgeKind
  /** Present only on `affected_by`. Copied from the vulnerability, never derived. */
  evidenceTier?: EvidenceTier | null
  /** True only for `observed` — a provider directly reported this. */
  direct?: boolean
  metadata?: Record<string, unknown>
}

export interface GraphStats {
  /** Node counts by type, for legend and filter chips. Real counts only. */
  nodeCounts: Record<string, number>
  /** Providers ACTUALLY represented, so no filter is offered for an absent one. */
  providers: Array<{ provider: ProviderName; nodes: number }>
  /** Evidence tiers actually present among `affected_by` edges. */
  evidenceTiers: Array<{ tier: EvidenceTier; edges: number }>
  /** Risk severities actually present among IP nodes. */
  severities: Array<{ severity: string; nodes: number }>
  truncated: boolean
  assetsIncluded: number
  assetsTotal: number
}

export interface ExposureGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  stats: GraphStats
}

/** Alert records, as stored by STEP 3. Only fields the graph displays. */
export interface GraphAlertInput {
  id: number
  asset_key: string
  port: number
  cve_id: string
  kind: string
  state: string
  severity: string
  risk_score: number | null
  evidence_tier: string
  created_at: string
}

/** Authoritative CVE facts, read from the existing `cves` table by the caller. */
export interface GraphCveFacts {
  cveId: string
  cvss: number | null
  epss: number | null
  isKev: boolean
  hasExploit: boolean
  severity?: string | null
  /** RBVM risk already computed by the existing pipeline. Never recomputed here. */
  riskScore?: number | null
}

export interface BuildGraphOptions {
  alerts?: GraphAlertInput[]
  cveFacts?: Map<string, GraphCveFacts>
  /**
   * Hard ceiling on assets folded into one graph. A graph beyond a few hundred
   * nodes stops being an investigation tool and becomes a hairball, and the
   * browser pays for every element. Callers page; this is the backstop.
   */
  maxAssets?: number
}

const DEFAULT_MAX_ASSETS = 150

/** Stable, collision-free ids. Prefixes double as the node type. */
export const nodeId = {
  domain: (d: string) => `domain:${d.trim().toLowerCase()}`,
  ip: (assetId: string) => assetId,
  service: (assetId: string, port: number) => `svc:${assetId}:${port}`,
  product: (name: string) => `product:${name.trim().toLowerCase()}`,
  version: (name: string, version: string) => `version:${name.trim().toLowerCase()}:${version.trim().toLowerCase()}`,
  cve: (id: string) => `cve:${id.toUpperCase()}`,
  provider: (p: string) => `provider:${p}`,
  certificate: (fp: string) => `cert:${fp.trim().toLowerCase()}`,
  alert: (id: number) => `alert:${id}`,
}

/** Freshness reduced to what the graph shows. `live` is never produced upstream. */
function freshnessMeta(f: Freshness | null | undefined): Record<string, unknown> {
  if (!f) return { freshness: "unknown", observedAt: null, fetchedAt: null }
  return {
    // `fromCache` is surfaced separately from the state: a cached read is a
    // statement about OUR retrieval, not about the provider's observation.
    freshness: f.fromCache ? "cached" : f.state,
    observedAt: f.observedAt,
    fetchedAt: f.fetchedAt,
    observationAgeSeconds: f.observationAgeSeconds,
  }
}

/**
 * Node the CVE evidence justifies attaching to.
 *
 * Deliberately conservative: without a port there is no service context, so the
 * finding stays on the host. Inventing a port here would be exactly the
 * fabrication the evidence model exists to prevent.
 */
function cveAnchor(asset: GraphAssetInput, v: ExposureVulnerability): string {
  const port = v.correlatedPort ?? null
  if (port == null) return nodeId.ip(asset.id)

  const svc = asset.services.find((s) => s.port === port)
  if (!svc) return nodeId.ip(asset.id)
  if (svc.product && svc.version) return nodeId.version(svc.product, svc.version)
  if (svc.product) return nodeId.product(svc.product)
  return nodeId.service(asset.id, port)
}

/**
 * Build the graph model.
 *
 * The FULL bounded model is produced in one pass. Focus mode and progressive
 * expansion are projections of this same model in the UI (never a second
 * dataset), so what an analyst expands is always consistent with what they
 * filtered.
 */
export function buildGraph(assets: GraphAssetInput[], opts: BuildGraphOptions = {}): ExposureGraph {
  const maxAssets = Math.max(1, opts.maxAssets ?? DEFAULT_MAX_ASSETS)
  const included = assets.slice(0, maxAssets)
  const truncated = assets.length > included.length

  const nodes = new Map<string, GraphNode>()
  const edges = new Map<string, GraphEdge>()

  const addNode = (n: GraphNode) => {
    const existing = nodes.get(n.id)
    if (!existing) { nodes.set(n.id, n); return n }
    // Merge metadata additively — a product seen on two assets keeps both.
    existing.metadata = { ...existing.metadata, ...n.metadata }
    return existing
  }
  const addEdge = (e: Omit<GraphEdge, "id">) => {
    const id = `${e.source}->${e.target}:${e.kind}`
    if (!edges.has(id)) edges.set(id, { id, ...e })
    return edges.get(id)!
  }

  /** Provider provenance. Individual attribution — never merged into "Internet". */
  const providerNodeCounts = new Map<ProviderName, number>()
  const observe = (provider: ProviderName, targetId: string, freshness?: Freshness | null) => {
    const pid = nodeId.provider(provider)
    addNode({ id: pid, type: "provider", label: provider, metadata: { provider } })
    addEdge({
      source: pid, target: targetId, kind: "observed", direct: true,
      metadata: freshness ? freshnessMeta(freshness) : undefined,
    })
    providerNodeCounts.set(provider, (providerNodeCounts.get(provider) ?? 0) + 1)
  }

  for (const asset of included) {
    // A query-target asset carries no provider evidence at all. It is still a
    // real thing the analyst searched for, so it is rendered — but it can never
    // gain a provider edge, because `sources` is empty by construction
    // (correlate.ts only records sources for observations with a provider).
    const ipNodeId = nodeId.ip(asset.id)
    const risk = asset.exposureRisk ?? null

    addNode({
      id: ipNodeId,
      type: "ip",
      label: asset.ip ?? asset.domain ?? asset.id,
      metadata: {
        assetKey: asset.id,
        ip: asset.ip ?? null,
        organization: asset.organization ?? null,
        country: asset.country ?? null,
        asn: asset.asn ?? null,
        // Risk is COPIED from the existing RBVM result. Never recomputed.
        riskScore: risk?.score ?? null,
        severity: risk?.severity ?? null,
        slaHours: risk?.slaHours ?? null,
        confidence: asset.confidence,
        enrichmentStatus: asset.enrichmentStatus,
        isQueryTarget: asset.isQueryTarget,
        sourceCount: asset.sourceCount,
        providers: [...asset.sources],
        serviceCount: asset.services.length,
        vulnerabilityCount: asset.vulnerabilities.length,
        threat: asset.threat
          ? { classification: asset.threat.classification ?? null, noise: asset.threat.noise, riot: asset.threat.riot }
          : null,
        ...freshnessMeta(asset.freshness),
        providerFreshness: (asset.providerFreshness ?? []).map((p) => ({
          provider: p.provider,
          freshness: p.freshness.fromCache ? "cached" : p.freshness.state,
          observedAt: p.freshness.observedAt,
        })),
      },
    })

    // ── Provider provenance at asset level ──
    // Per-provider freshness where it exists, so "which source is stale" is
    // answerable from the edge itself.
    const freshByProvider = new Map((asset.providerFreshness ?? []).map((p) => [p.provider, p.freshness]))
    for (const p of asset.sources) observe(p, ipNodeId, freshByProvider.get(p) ?? null)

    // ── Domains: a RELATIONSHIP, never an identity ──
    // Three IPs behind one domain stay three IP nodes joined to one domain node.
    for (const d of asset.domains) {
      if (!d?.trim()) continue
      const did = nodeId.domain(d)
      addNode({ id: did, type: "domain", label: d, metadata: { domain: d } })
      addEdge({ source: did, target: ipNodeId, kind: "resolves_to" })
    }

    // ── Services ──
    for (const svc of asset.services) {
      const sid = nodeId.service(asset.id, svc.port)
      addNode({
        id: sid,
        type: "service",
        label: `${svc.port}/${svc.transport ?? "tcp"}`,
        metadata: {
          assetKey: asset.id,
          port: svc.port,
          transport: svc.transport ?? null,
          protocol: svc.protocol ?? null,
          product: svc.product ?? null,
          version: svc.version ?? null,
          httpStatus: svc.httpStatus ?? null,
          httpTitle: svc.httpTitle ?? null,
          providers: [...svc.sources],
          // Provider disagreement is preserved, never silently resolved: both
          // claims travel with the node.
          conflict: Boolean(svc.conflict),
          claims: svc.claims.map((c) => ({
            source: c.source, product: c.product ?? null, version: c.version ?? null,
          })),
        },
      })
      addEdge({ source: ipNodeId, target: sid, kind: "exposes" })
      for (const p of svc.sources) observe(p, sid, freshByProvider.get(p) ?? null)

      // Product / version, only when the service actually reported them.
      if (svc.product) {
        const pid = nodeId.product(svc.product)
        addNode({ id: pid, type: "product", label: svc.product, metadata: { product: svc.product, scope: "service" } })
        addEdge({ source: sid, target: pid, kind: "runs" })

        if (svc.version) {
          const vid = nodeId.version(svc.product, svc.version)
          addNode({
            id: vid, type: "version", label: `${svc.product} ${svc.version}`,
            metadata: { product: svc.product, version: svc.version },
          })
          addEdge({ source: pid, target: vid, kind: "has_version" })
        }
      }
    }

    // ── Host-wide software ──
    // Attached to the IP, NOT to a port: nothing associated it with a service,
    // and inventing that association is precisely what the evidence model
    // forbids. Marked `scope: "host"` so the UI can say so.
    for (const tech of asset.technologies) {
      if (!tech.name?.trim()) continue
      const pid = nodeId.product(tech.name)
      addNode({
        id: pid, type: "product", label: tech.name,
        metadata: { product: tech.name, scope: "host", categories: tech.categories },
      })
      addEdge({
        source: ipNodeId, target: pid, kind: "runs",
        metadata: { scope: "host", note: "Reported for the host, not associated with a specific port." },
      })
      for (const p of tech.sources) observe(p, pid, freshByProvider.get(p) ?? null)
    }

    // ── Certificates ──
    for (const [i, cert] of asset.certificates.entries()) {
      const fp = cert.fingerprint?.trim()
      // Without a fingerprint the certificate has no cross-asset identity, so
      // it is scoped to this asset rather than merged with anything else.
      const cid = fp ? nodeId.certificate(fp) : `cert:${asset.id}:${i}`
      addNode({
        id: cid, type: "certificate",
        label: cert.commonName || fp?.slice(0, 16) || "certificate",
        metadata: {
          commonName: cert.commonName ?? null,
          issuer: cert.issuer ?? null,
          fingerprint: fp ?? null,
          validFrom: cert.validFrom ?? null,
          validTo: cert.validTo ?? null,
          expired: cert.expired ?? null,
          sans: cert.sans,
          providers: [...cert.sources],
        },
      })
      addEdge({ source: cid, target: ipNodeId, kind: "associated_with" })
      for (const san of cert.sans) {
        const did = nodeId.domain(san)
        if (nodes.has(did)) addEdge({ source: cid, target: did, kind: "associated_with" })
      }
      for (const p of cert.sources) observe(p, cid, freshByProvider.get(p) ?? null)
    }

    // ── Vulnerabilities ──
    for (const v of asset.vulnerabilities) {
      const cid = nodeId.cve(v.cveId)
      const facts = opts.cveFacts?.get(v.cveId.toUpperCase())
      addNode({
        id: cid, type: "cve", label: v.cveId,
        metadata: {
          cveId: v.cveId,
          // Authoritative facts from the existing CVE store. Absent rather than
          // guessed when the CVE is not in the database.
          cvss: facts?.cvss ?? null,
          epss: facts?.epss ?? null,
          isKev: facts?.isKev ?? null,
          hasExploit: facts?.hasExploit ?? null,
          cveSeverity: facts?.severity ?? null,
          // Provider's own score, kept distinct from the authoritative CVSS.
          providerScore: v.providerScore ?? null,
        },
      })
      addEdge({
        source: cveAnchor(asset, v),
        target: cid,
        kind: "affected_by",
        // Copied verbatim. The graph has no path to promote a tier.
        evidenceTier: v.evidenceTier,
        direct: false,
        metadata: {
          confirmed: v.confirmed,
          matchType: v.matchType ?? null,
          matchedProduct: v.matchedProduct ?? null,
          providers: [...v.sources],
          assetKey: asset.id,
          port: v.correlatedPort ?? null,
        },
      })
      for (const p of v.sources) observe(p, cid, freshByProvider.get(p) ?? null)
    }
  }

  // ── Alerts ──
  // Represented, never generated. An alert node exists only because a row
  // exists, and only when its CVE is already in the graph.
  const assetIds = new Set(included.map((a) => a.id))
  for (const alert of opts.alerts ?? []) {
    if (!assetIds.has(alert.asset_key)) continue
    const cid = nodeId.cve(alert.cve_id)
    if (!nodes.has(cid)) continue
    const aid = nodeId.alert(alert.id)
    addNode({
      id: aid, type: "alert", label: `${alert.severity?.toUpperCase() ?? "ALERT"} · ${alert.cve_id}`,
      metadata: {
        alertId: alert.id,
        state: alert.state,
        kind: alert.kind,
        severity: alert.severity,
        riskScore: alert.risk_score,
        evidenceTier: alert.evidence_tier,
        createdAt: alert.created_at,
        assetKey: alert.asset_key,
        port: alert.port,
      },
    })
    addEdge({ source: cid, target: aid, kind: "triggered" })
  }

  // ── Stats: derived from what was actually built ──
  const nodeList = [...nodes.values()]
  const edgeList = [...edges.values()]

  const nodeCounts: Record<string, number> = {}
  for (const n of nodeList) nodeCounts[n.type] = (nodeCounts[n.type] ?? 0) + 1

  const evidenceCounts = new Map<EvidenceTier, number>()
  for (const e of edgeList) {
    if (e.kind !== "affected_by" || !e.evidenceTier) continue
    evidenceCounts.set(e.evidenceTier, (evidenceCounts.get(e.evidenceTier) ?? 0) + 1)
  }

  const severityCounts = new Map<string, number>()
  for (const n of nodeList) {
    if (n.type !== "ip") continue
    const sev = n.metadata.severity
    if (typeof sev === "string") severityCounts.set(sev, (severityCounts.get(sev) ?? 0) + 1)
  }

  return {
    nodes: nodeList,
    edges: edgeList,
    stats: {
      nodeCounts,
      // Only providers genuinely present — no filter is offered for an absent one.
      providers: [...providerNodeCounts.entries()].map(([provider, n]) => ({ provider, nodes: n })),
      evidenceTiers: [...evidenceCounts.entries()].map(([tier, n]) => ({ tier, edges: n })),
      severities: [...severityCounts.entries()].map(([severity, n]) => ({ severity, nodes: n })),
      truncated,
      assetsIncluded: included.length,
      assetsTotal: assets.length,
    },
  }
}

// ───────────────────────── projections (item 12) ─────────────────────────

/**
 * Nodes reachable from `rootId` within `depth` hops, ignoring edge direction.
 *
 * Focus mode is a PROJECTION of the graph above, not a second dataset: the same
 * node objects come back, so anything an analyst filtered stays filtered.
 */
export function neighborhood(graph: ExposureGraph, rootId: string, depth = 2): Set<string> {
  const keep = new Set<string>()
  if (!graph.nodes.some((n) => n.id === rootId)) return keep

  const adjacency = new Map<string, string[]>()
  const connect = (from: string, to: string) => {
    const list = adjacency.get(from)
    if (list) list.push(to)
    else adjacency.set(from, [to])
  }
  for (const e of graph.edges) {
    // Undirected for traversal: an analyst focusing an IP expects to see the
    // domain pointing AT it and the provider that observed it, not just the
    // things it points to.
    connect(e.source, e.target)
    connect(e.target, e.source)
  }

  let frontier = [rootId]
  keep.add(rootId)
  for (let d = 0; d < depth; d++) {
    const next: string[] = []
    for (const id of frontier) {
      for (const nb of adjacency.get(id) ?? []) {
        if (keep.has(nb)) continue
        keep.add(nb)
        next.push(nb)
      }
    }
    if (!next.length) break
    frontier = next
  }
  return keep
}

/**
 * Restrict a graph to a set of node ids, dropping edges that lose an endpoint.
 *
 * Returns a NEW graph and never touches the input — filtering must not mutate
 * the source model, or repeated filtering would progressively destroy it.
 */
export function projectGraph(graph: ExposureGraph, keep: Set<string>): ExposureGraph {
  const nodes = graph.nodes.filter((n) => keep.has(n.id))
  const edges = graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target))
  const nodeCounts: Record<string, number> = {}
  for (const n of nodes) nodeCounts[n.type] = (nodeCounts[n.type] ?? 0) + 1
  return { nodes, edges, stats: { ...graph.stats, nodeCounts } }
}
