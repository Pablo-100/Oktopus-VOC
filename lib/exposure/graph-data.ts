import { sql, initDb } from "@/lib/db"
import { riskLevel } from "@/lib/risk-engine"
import { buildGraph, type ExposureGraph, type GraphAssetInput, type GraphAlertInput, type GraphCveFacts } from "@/lib/exposure/graph"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { makeFreshness } from "@/lib/exposure/types"
import type {
  ExposureService, ExposureCertificate, ExposureVulnerability, ProviderName, VulnMatchType, Freshness,
} from "@/lib/exposure/types"
import type { AssetSnapshot } from "@/lib/exposure/changes"

/**
 * EXPOSURE GRAPH — assembly from the persisted attack surface.
 *
 * Read-only. It assembles the graph from records OCTUPUS already holds
 * (`exposure_asset_state`, `exposure_vulnerability`, `exposure_alerts`, `cves`)
 * and runs the same pure adapter the client uses for live search results.
 *
 * It contacts NO provider. Expanding a node in the UI is a projection of data
 * already returned here, so exploring the graph can never spend provider quota.
 *
 * ── DELIBERATE FIDELITY LIMITS OF THE PERSISTED PATH ─────────────────────────
 * The stored snapshot is a compact change-detection record, not a full asset.
 * Rather than invent the difference, this endpoint omits what is not stored:
 *
 *   - Per-service provider attribution exists only where a vulnerability row
 *     recorded it (`exposure_vulnerability.source_providers`). Elsewhere,
 *     provenance is attached at asset level, which is what `snapshot.sources`
 *     actually supports.
 *   - Certificates are stored as FINGERPRINTS only, so certificate nodes carry
 *     no common name, issuer or SANs and no provider attribution.
 *   - `technologies` (host-wide software) is not snapshotted, so the persisted
 *     graph has no host-scope product nodes.
 *
 * A live search graph, built client-side from the correlated assets, carries
 * all of the above. Both use the same adapter.
 */
/** Upper bound so one request can never assemble an unusable graph. */
const MAX_ASSETS = 150

interface StateRow { asset_key: string; snapshot: AssetSnapshot; updated_at: string }
interface VulnRow {
  asset_key: string; port: number; cve_id: string; evidence_tier: string
  confirmed: boolean; match_type: string | null; source_providers: ProviderName[]
  product: string | null; version: string | null
  observed_at: string | null; fetched_at: string | null
  risk_score: number | null; severity: string | null; status: string
}

/**
 * Assemble the graph from persisted records.
 *
 * Separated from the route so it can be tested against a real database without
 * standing up auth — the route is then only authentication plus this call.
 */
export async function loadGraphFromStore(
  userId: string,
  opts: { assetKey?: string | null; limit?: number } = {},
): Promise<{ graph: ExposureGraph; empty: boolean }> {
  await initDb()
  const only = opts.assetKey?.trim() || null
  const limit = Number.isFinite(opts.limit) && (opts.limit ?? 0) > 0
  ? Math.min(Math.floor(opts.limit!), MAX_ASSETS)
  : MAX_ASSETS

  // ── Assets ──
  // Every read is tenant-scoped: the graph is an investigation view of the
  // caller's OWN surface, never a window onto another user's assets.
  const states = (only
    ? await sql`
        SELECT asset_key, snapshot, updated_at FROM exposure_asset_state
        WHERE user_id = ${userId} AND asset_key = ${only}`
    : await sql`
        SELECT asset_key, snapshot, updated_at FROM exposure_asset_state
        WHERE user_id = ${userId}
        ORDER BY (snapshot->>'riskScore')::float DESC NULLS LAST, updated_at DESC
        LIMIT ${limit}`) as StateRow[]

  // An empty graph is a real answer, not an error: nothing has been enriched
  // or monitored yet.
  if (!states.length) return { graph: buildGraph([]), empty: true }

  const assetKeys = states.map((s) => s.asset_key)

  // ── Vulnerability relationships (STEP 3 records) ──
  const vulns = (await sql`
    SELECT asset_key, port, cve_id, evidence_tier, confirmed, match_type, source_providers,
           product, version, observed_at, fetched_at, risk_score, severity, status
    FROM exposure_vulnerability
    WHERE user_id = ${userId} AND asset_key = ANY(${assetKeys}::text[]) AND status = 'active'
  `) as VulnRow[]

  // ── Authoritative CVE facts from the EXISTING store ──
  const cveIds = [...new Set(vulns.map((v) => v.cve_id))]
  const cveFacts = new Map<string, GraphCveFacts>()
  if (cveIds.length) {
    const rows = (await sql`
      SELECT cve_id, cvss, epss, is_kev, has_exploit, severity, risk_score
      FROM cves WHERE cve_id = ANY(${cveIds}::text[])
    `) as Array<{ cve_id: string; cvss: number | null; epss: number | null; is_kev: boolean; has_exploit: boolean; severity: string | null; risk_score: number | null }>
    for (const r of rows) {
      cveFacts.set(r.cve_id.toUpperCase(), {
        cveId: r.cve_id, cvss: r.cvss, epss: r.epss,
        isKev: r.is_kev, hasExploit: r.has_exploit,
        severity: r.severity, riskScore: r.risk_score,
      })
    }
  }

  // ── Alerts (represented, never generated here) ──
  const alerts = (await sql`
    SELECT id, asset_key, port, cve_id, kind, state, severity, risk_score, evidence_tier, created_at
    FROM exposure_alerts
    WHERE user_id = ${userId} AND asset_key = ANY(${assetKeys}::text[])
      AND state IN ('open','acknowledged','in_progress')
    ORDER BY created_at DESC LIMIT 200
  `) as GraphAlertInput[]

  // ── Reconstruct graph inputs from what is genuinely stored ──
  const vulnsByAsset = new Map<string, VulnRow[]>()
  for (const v of vulns) {
    const list = vulnsByAsset.get(v.asset_key) ?? []
    list.push(v)
    vulnsByAsset.set(v.asset_key, list)
  }

  const assets: GraphAssetInput[] = states.map((state) => {
    const snap = state.snapshot
    const rows = vulnsByAsset.get(state.asset_key) ?? []

    // Per-port provider attribution, ONLY where a vulnerability row recorded
    // it. Ports without such a row keep an empty source list rather than
    // inheriting the asset's providers, which would fabricate attribution.
    const providersByPort = new Map<number, Set<ProviderName>>()
    for (const r of rows) {
      if (r.port <= 0) continue
      const set = providersByPort.get(r.port) ?? new Set<ProviderName>()
      for (const p of r.source_providers ?? []) set.add(p)
      providersByPort.set(r.port, set)
    }

    const services: ExposureService[] = (snap.services ?? []).map((s) => {
      const sources = [...(providersByPort.get(s.port) ?? [])]
      return {
        port: s.port, transport: "tcp", protocol: null,
        product: s.product, vendor: null, version: s.version,
        banner: null, httpStatus: null, httpTitle: null, httpServer: null,
        sources,
        claims: sources.map((src) => ({ source: src, product: s.product, vendor: null, version: s.version, protocol: null })),
      }
    })

    // Fingerprints are all the snapshot keeps — no CN, issuer, SANs or
    // provider, so none are asserted.
    const certificates: ExposureCertificate[] = (snap.certificateFingerprints ?? []).map((fp) => ({
      commonName: null, sans: [], issuer: null, fingerprint: fp,
      validFrom: null, validTo: null, expired: null, sources: [],
    }))

    const vulnerabilities: ExposureVulnerability[] = rows.map((r) => ({
      correlatedPort: r.port > 0 ? r.port : null,
      // Rebuilt through the SAME normalizer the rest of OCTUPUS uses, so the
      // tier/`confirmed` pair is derived rather than trusted from the row.
      ...makeVulnerability({
        cveId: r.cve_id,
        matchType: (r.match_type ?? "unknown") as VulnMatchType,
        sources: r.source_providers ?? [],
        matchedProduct: r.product,
      }),
    }))

    const score = typeof snap.riskScore === "number" ? snap.riskScore : null
    const isIp = state.asset_key.startsWith("ip:")

    return {
      id: state.asset_key,
      ip: isIp ? state.asset_key.slice(3) : null,
      domain: state.asset_key.startsWith("domain:") ? state.asset_key.slice(7) : null,
      domains: snap.domains ?? [],
      services, technologies: [], certificates, vulnerabilities,
      sources: snap.sources ?? [],
      sourceCount: (snap.sources ?? []).length,
      confidence: "high",
      enrichmentStatus: "enriched",
      isQueryTarget: false,
      threat: null,
      // Freshness of the RELATIONSHIP records: `observed_at` is the provider's
      // own timestamp and `fetched_at` is ours. They are never collapsed, and
      // no state is claimed when neither is stored.
      freshness: freshnessFrom(rows, state.updated_at),
      exposureRisk: score == null ? null : {
        score,
        // The band comes from the RBVM engine's own thresholds — not
        // re-declared here.
        severity: riskLevel(score).tone,
      },
    }
  })

  return { graph: buildGraph(assets, { alerts, cveFacts, maxAssets: limit }), empty: false }
}

/**
 * Freshness for a persisted asset, from the newest provider observation across
 * its stored relationships.
 *
 * Delegates to `makeFreshness`, which owns the FRESH/RECENT/STALE thresholds —
 * re-deriving them here would let the graph and the rest of the app disagree
 * about what "stale" means. When no provider timestamp is stored the state is
 * `unknown`, never backfilled with our fetch time.
 */
function freshnessFrom(rows: VulnRow[], updatedAt: string): Freshness {
  const newest = (values: Array<string | null>) => {
  const valid = values.filter((t): t is string => Boolean(t) && Number.isFinite(Date.parse(t!))).sort()
  return valid.length ? valid[valid.length - 1] : null
  }
  const observedAt = newest(rows.map((r) => r.observed_at))
  const fetchedAt = newest(rows.map((r) => r.fetched_at)) ?? updatedAt
  return makeFreshness(observedAt, { fetchedAt: new Date(fetchedAt).toISOString() })
}
