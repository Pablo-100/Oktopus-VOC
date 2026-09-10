/**
 * Exposure change detection.
 *
 * Compares a newly observed asset against the last-known snapshot and emits
 * normalized change events. Only NORMALIZED change information is stored —
 * never the raw provider payloads, which are large and already stripped from
 * the cache for the same reason.
 *
 * Risk is NOT recomputed here. Change detection reports what moved; the
 * existing RBVM engine (via `computeExposureRisk`) remains the only thing that
 * turns that into a score.
 */
import type { ExposureAsset, ProviderName } from "@/lib/exposure/types"

export type ChangeKind =
  | "service_added" | "service_removed"
  | "product_changed" | "version_changed"
  | "domain_added" | "domain_removed"
  | "certificate_changed"
  | "vulnerability_added" | "vulnerability_removed"
  | "provider_appeared" | "provider_disappeared"
  | "risk_changed"

export interface ExposureChange {
  kind: ChangeKind
  /** Short analyst-facing description, e.g. "443/tcp nginx 1.24". */
  detail: string
  before?: string | null
  after?: string | null
}

/**
 * Minimal snapshot of an asset — everything change detection needs and nothing
 * else. Deliberately small so history rows stay cheap to store.
 */
export interface AssetSnapshot {
  services: Array<{ port: number; product: string | null; version: string | null }>
  domains: string[]
  certificateFingerprints: string[]
  cveIds: string[]
  sources: ProviderName[]
  riskScore: number
}

export function snapshotOf(asset: ExposureAsset): AssetSnapshot {
  return {
    services: asset.services
      .map((s) => ({ port: s.port, product: s.product ?? null, version: s.version ?? null }))
      .sort((a, b) => a.port - b.port),
    domains: [...asset.domains].sort(),
    certificateFingerprints: asset.certificates.map((c) => c.fingerprint).filter((f): f is string => Boolean(f)).sort(),
    cveIds: [...new Set(asset.vulnerabilities.map((v) => v.cveId))].sort(),
    sources: [...asset.sources].sort(),
    riskScore: asset.exposureRisk?.score ?? 0,
  }
}

function describeService(s: { port: number; product: string | null; version: string | null }): string {
  const label = [s.product, s.version].filter(Boolean).join(" ")
  return label ? `${s.port}/tcp ${label}` : `${s.port}/tcp`
}

/**
 * Diff two snapshots. `previous` null means this is the first observation —
 * that is NOT a wall of "everything is new" events, it produces no changes at
 * all, because nothing actually changed.
 */
export function detectChanges(previous: AssetSnapshot | null, current: AssetSnapshot): ExposureChange[] {
  if (!previous) return []
  const changes: ExposureChange[] = []

  // ── Services ──
  const prevByPort = new Map(previous.services.map((s) => [s.port, s]))
  const currByPort = new Map(current.services.map((s) => [s.port, s]))

  for (const [port, s] of currByPort) {
    if (!prevByPort.has(port)) {
      changes.push({ kind: "service_added", detail: describeService(s), after: describeService(s) })
      continue
    }
    const before = prevByPort.get(port)!
    if ((before.product ?? "") !== (s.product ?? "")) {
      changes.push({
        kind: "product_changed",
        detail: `${port}/tcp product ${before.product ?? "unknown"} → ${s.product ?? "unknown"}`,
        before: before.product, after: s.product,
      })
    } else if ((before.version ?? "") !== (s.version ?? "")) {
      // Only report a version change when the product itself is stable —
      // otherwise the product change above already covers it.
      changes.push({
        kind: "version_changed",
        detail: `${port}/tcp ${s.product ?? ""} ${before.version ?? "unknown"} → ${s.version ?? "unknown"}`.trim(),
        before: before.version, after: s.version,
      })
    }
  }
  for (const [port, s] of prevByPort) {
    if (!currByPort.has(port)) {
      changes.push({ kind: "service_removed", detail: describeService(s), before: describeService(s) })
    }
  }

  // ── Domains ──
  for (const d of current.domains) if (!previous.domains.includes(d)) changes.push({ kind: "domain_added", detail: d, after: d })
  for (const d of previous.domains) if (!current.domains.includes(d)) changes.push({ kind: "domain_removed", detail: d, before: d })

  // ── Certificates ──
  const certAdded = current.certificateFingerprints.filter((f) => !previous.certificateFingerprints.includes(f))
  const certRemoved = previous.certificateFingerprints.filter((f) => !current.certificateFingerprints.includes(f))
  if (certAdded.length || certRemoved.length) {
    changes.push({
      kind: "certificate_changed",
      detail: `${certAdded.length} new / ${certRemoved.length} gone`,
      before: certRemoved[0]?.slice(0, 16) ?? null,
      after: certAdded[0]?.slice(0, 16) ?? null,
    })
  }

  // ── Vulnerabilities ──
  for (const c of current.cveIds) if (!previous.cveIds.includes(c)) changes.push({ kind: "vulnerability_added", detail: c, after: c })
  for (const c of previous.cveIds) if (!current.cveIds.includes(c)) changes.push({ kind: "vulnerability_removed", detail: c, before: c })

  // ── Providers ──
  for (const p of current.sources) if (!previous.sources.includes(p)) changes.push({ kind: "provider_appeared", detail: p, after: p })
  for (const p of previous.sources) if (!current.sources.includes(p)) changes.push({ kind: "provider_disappeared", detail: p, before: p })

  // ── Risk ──
  // Reported only, never computed here — the RBVM engine owns the number.
  if (previous.riskScore !== current.riskScore) {
    changes.push({
      kind: "risk_changed",
      detail: `Risk ${previous.riskScore} → ${current.riskScore}`,
      before: String(previous.riskScore), after: String(current.riskScore),
    })
  }

  return changes
}

/** Changes worth surfacing prominently — an attack surface that GREW. */
export function isEscalation(change: ExposureChange): boolean {
  return change.kind === "service_added"
    || change.kind === "vulnerability_added"
    || (change.kind === "risk_changed" && Number(change.after) > Number(change.before))
}
