"use client"

import { useCallback, useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { TONE_CLASS } from "@/lib/risk-engine"
import { cn } from "@/lib/utils"
import type { ExposureAsset, Freshness, FreshnessState, ProviderName } from "@/lib/exposure/types"
import type { ExposureChange } from "@/lib/exposure/changes"

const CONFIDENCE_CLASS: Record<string, string> = {
  very_high: "bg-emerald-600 text-white",
  high: "bg-sky-600 text-white",
  medium: "bg-amber-500 text-black",
  low: "bg-zinc-600 text-white",
}
const CONFIDENCE_LABEL: Record<string, string> = {
  very_high: "Very high", high: "High", medium: "Medium", low: "Low",
}
const ALL_PROVIDERS: ProviderName[] = ["censys", "leakix", "netlas", "fofa", "zoomeye", "greynoise"]

/**
 * CVE↔asset evidence strength, surfaced verbatim to the analyst. The
 * distinction matters operationally: a `pivot` must not be actioned as if a
 * provider had confirmed the host is vulnerable.
 */
const MATCH_LABEL: Record<string, string> = {
  "cve-search": "Provider-confirmed",
  version: "Version confirmed",
  banner: "Banner inferred",
  product: "Product name only",
  pivot: "Potential (product match)",
  unknown: "Unknown",
}
const MATCH_HELP: Record<string, string> = {
  "cve-search": "A provider was queried by CVE id and returned this host — the strongest available evidence.",
  version: "The affected product VERSION was fingerprinted on this host.",
  banner: "Inferred from a service banner.",
  product: "The product name matched, but not the version — the host may not be on an affected build.",
  pivot: "Derived locally: this CVE affects a product seen on this host. POTENTIAL exposure only — not confirmation.",
  unknown: "Match basis not reported by the provider.",
}
const MATCH_CLASS: Record<string, string> = {
  "cve-search": "bg-red-600 text-white",
  version: "bg-orange-600 text-white",
  banner: "",
  product: "",
  pivot: "border-amber-500/60 text-amber-300",
  unknown: "",
}
const PROVIDER_LABEL: Record<string, string> = {
  censys: "Censys", leakix: "LeakIX", netlas: "Netlas", fofa: "FOFA", zoomeye: "ZoomEye", greynoise: "GreyNoise",
}

/**
 * Freshness badges. Deliberately no "LIVE" — no configured provider performs an
 * on-demand scan, so claiming live would be false. States describe the age of
 * the PROVIDER'S OBSERVATION, not when OCTUPUS fetched it.
 */
const FRESHNESS_UI: Record<FreshnessState, { label: string; cls: string; help: string }> = {
  live: { label: "LIVE", cls: "bg-emerald-600 text-white", help: "Observed on demand at query time." },
  fresh: { label: "FRESH", cls: "bg-emerald-600 text-white", help: "The provider observed this host within the last 24 hours." },
  recent: { label: "RECENT", cls: "bg-sky-600 text-white", help: "The provider observed this host within the last 7 days." },
  stale: { label: "STALE", cls: "bg-amber-500 text-black", help: "The provider's most recent observation is over a week old — the host may have changed since." },
  unknown: { label: "UNKNOWN", cls: "bg-zinc-600 text-white", help: "This provider supplies no observation timestamp, so the age of the data cannot be determined." },
}

/** Compact humanized age, e.g. "3 days ago". */
function humanAge(seconds: number | null): string {
  if (seconds == null) return "unknown"
  if (seconds < 90) return "just now"
  const m = Math.floor(seconds / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h} h ago`
  return `${Math.floor(h / 24)} days ago`
}

function FreshnessBadge({ freshness }: { freshness: Freshness | null | undefined }) {
  if (!freshness) return null
  const ui = FRESHNESS_UI[freshness.state]
  return <Badge className={ui.cls} title={ui.help}>{freshness.fromCache ? "CACHED" : ui.label}</Badge>
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h4>
      {children}
    </div>
  )
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-muted-foreground">{children}</p>
}

/**
 * Union the provenance of the pre-enrichment asset with the on-demand
 * enrichment result.
 *
 * Deliberately narrow: it unions SOURCES and SERVICES (both are genuine
 * observations of the same host from this session) and otherwise takes the
 * enriched values, which are strictly richer. It does NOT attempt to redo
 * correlation client-side — merging observations is the server's job; this only
 * prevents the display from under-reporting evidence we already had.
 */
export function mergeProvenance(original: ExposureAsset, enrichedAsset: ExposureAsset): ExposureAsset {
  const sources = [...new Set([...original.sources, ...enrichedAsset.sources])]
  const services = [...enrichedAsset.services]
  for (const s of original.services) {
    const hit = services.find((x) => x.port === s.port)
    if (!hit) { services.push(s); continue }
    for (const src of s.sources) if (!hit.sources.includes(src)) hit.sources.push(src)
    for (const c of s.claims) if (!hit.claims.some((x) => x.source === c.source)) hit.claims.push(c)
  }
  return {
    ...enrichedAsset,
    sources,
    sourceCount: sources.length,
    services,
    domains: [...new Set([...original.domains, ...enrichedAsset.domains])],
    hostnames: [...new Set([...original.hostnames, ...enrichedAsset.hostnames])],
  }
}

/**
 * Evidence tiers, shown as their own dimension.
 *
 * Kept separate from SEVERITY everywhere: severity says how dangerous the CVE
 * is, evidence says how sure we are this host actually runs it. A `product`
 * match on a CVSS-10 KEV bug is still only a lead.
 */
const TIER_UI: Record<string, { label: string; cls: string; hint: string }> = {
  confirmed: { label: "Confirmed", cls: "bg-emerald-600 text-white", hint: "A provider returned this host when queried for this CVE." },
  strong: { label: "Strong", cls: "bg-sky-600 text-white", hint: "The affected VERSION was fingerprinted here." },
  product: { label: "Product", cls: "bg-amber-500 text-black", hint: "Product NAME matched only — the version is unproven. A lead, not a finding." },
  weak: { label: "Weak", cls: "bg-zinc-600 text-white", hint: "Banner or heuristic inference only." },
  pivot: { label: "Pivot", cls: "bg-zinc-700 text-white", hint: "Derived locally from CVE→product; this host was never reported as affected." },
}
const TIER_RANK: Record<string, number> = { confirmed: 5, strong: 4, product: 3, weak: 2, pivot: 1 }

/** Strongest evidence tier present in a set of vulnerabilities. */
function strongestTier(vulns: Array<{ evidenceTier?: string }>): string | null {
  let best: string | null = null
  for (const v of vulns) {
    const t = v.evidenceTier ?? "weak"
    if (!best || (TIER_RANK[t] ?? 0) > (TIER_RANK[best] ?? 0)) best = t
  }
  return best
}

/** Monitoring state for THIS asset, as stored by the scheduler. */
interface MonitoringRow {
  asset_key: string
  target: string
  enabled: boolean
  interval_seconds: number
  last_attempt_at: string | null
  last_success_at: string | null
  next_run_at: string
  last_status: string | null
  last_error: string | null
  consecutive_failures: number
}

const INTERVAL_OPTIONS: Array<{ value: number; label: string }> = [
  { value: 3600, label: "Hourly" },
  { value: 6 * 3600, label: "Every 6 hours" },
  { value: 24 * 3600, label: "Daily" },
  { value: 7 * 24 * 3600, label: "Weekly" },
]

const MONITOR_STATUS_LABEL: Record<string, string> = {
  success: "Success", partial: "Partial", quota_deferred: "Deferred",
  no_provider: "No provider", failed: "Failed",
}

function whenRelative(iso: string | null): string {
  if (!iso) return "never"
  const diff = Date.now() - Date.parse(iso)
  const m = Math.round(Math.abs(diff) / 60000)
  if (m < 1) return "just now"
  const u = m < 60 ? `${m}m` : m < 1440 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`
  return diff >= 0 ? `${u} ago` : `in ${u}`
}

export function ExposureAssetDialog({
  asset: incoming, open, onOpenChange,
}: { asset: ExposureAsset | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [showRaw, setShowRaw] = useState(false)
  // Locally-enriched replacement for the asset passed in, so an on-demand
  // enrichment updates this dialog without re-running the whole search.
  //
  // `enrichedFor` scopes the result to the asset it was fetched for. Deriving
  // staleness this way (rather than resetting state in an effect) avoids a
  // cascading render and keeps the component effect-free.
  const [enriched, setEnriched] = useState<{ forId: string; asset: ExposureAsset } | null>(null)
  const [enriching, setEnriching] = useState(false)
  const [enrichError, setEnrichError] = useState<{ forId: string; message: string } | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [changeResult, setChangeResult] = useState<{ forId: string; changes: ExposureChange[] } | null>(null)
  // Monitoring state is scoped to the asset it was fetched for, the same way
  // `enriched` is — so opening a different asset never shows the previous
  // asset's schedule while the new one loads.
  const [monitorState, setMonitorState] = useState<{ forId: string; row: MonitoringRow | null } | null>(null)
  const [monitorBusy, setMonitorBusy] = useState(false)

  const incomingId = incoming?.id ?? null
  const activeEnriched = enriched && enriched.forId === incomingId ? enriched.asset : null
  const activeError = enrichError && enrichError.forId === incomingId ? enrichError.message : null
  const changes = changeResult && changeResult.forId === incomingId ? changeResult.changes : null
  const monitoring = monitorState && monitorState.forId === incomingId ? monitorState.row : null
  const monitorLoaded = monitorState?.forId === incomingId

  const loadMonitoring = useCallback(async (assetId: string): Promise<MonitoringRow | null> => {
    const r = await fetch(`/api/exposure/monitoring?assetKey=${encodeURIComponent(assetId)}`)
    if (!r.ok) return null
    return ((await r.json()) as { monitoring: MonitoringRow | null }).monitoring
  }, [])

  // Fetch the schedule for whichever asset is open. State is written only from
  // the async callback, never synchronously in the effect body.
  useEffect(() => {
    if (!open || !incomingId) return
    let cancelled = false
    loadMonitoring(incomingId)
      .then((row) => { if (!cancelled) setMonitorState({ forId: incomingId, row }) })
      .catch(() => { if (!cancelled) setMonitorState({ forId: incomingId, row: null }) })
    return () => { cancelled = true }
  }, [open, incomingId, loadMonitoring])

  // The enrich endpoint reports what the ENRICHMENT providers found for this
  // host; it does not re-run discovery, so on its own it would DROP the
  // discovery provider that originally surfaced the asset (e.g. LeakIX) and
  // under-report provenance. Both observations are real and from this same
  // session, so the source lists are unioned rather than replaced — evidence
  // must accumulate, never silently shrink.
  const asset = activeEnriched && incoming ? mergeProvenance(incoming, activeEnriched) : activeEnriched ?? incoming
  if (!asset) return null

  const risk = asset.exposureRisk
  const tone = risk?.severity ?? "low"
  const enrichTarget = asset.ip ?? asset.domain ?? null

  /** Refresh = re-query providers AND diff against the last stored snapshot. */
  async function runRefresh() {
    if (!enrichTarget || !incomingId) return
    setRefreshing(true)
    setEnrichError(null)
    try {
      const r = await fetch("/api/exposure/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: enrichTarget }),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.error || "Refresh failed")
      if (d.asset) setEnriched({ forId: incomingId, asset: d.asset as ExposureAsset })
      setChangeResult({ forId: incomingId, changes: (d.changes ?? []) as ExposureChange[] })
    } catch (e) {
      setEnrichError({ forId: incomingId, message: e instanceof Error ? e.message : String(e) })
    } finally {
      setRefreshing(false)
    }
  }

  /**
   * Enable / pause / re-schedule monitoring for this asset. Explicit opt-in —
   * viewing an asset never schedules it.
   */
  async function setMonitoringFor(enabled: boolean, intervalSeconds: number) {
    if (!enrichTarget || !incomingId) return
    setMonitorBusy(true)
    try {
      const r = await fetch("/api/exposure/monitoring", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ assetKey: incomingId, target: enrichTarget, enabled, intervalSeconds }),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.error || "Could not update monitoring")
      setMonitorState({ forId: incomingId, row: d.monitoring as MonitoringRow })
    } catch (e) {
      setEnrichError({ forId: incomingId, message: e instanceof Error ? e.message : String(e) })
    } finally {
      setMonitorBusy(false)
    }
  }

  async function runEnrichment() {
    if (!enrichTarget || !incomingId) return
    setEnriching(true)
    setEnrichError(null)
    try {
      const r = await fetch("/api/exposure/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: enrichTarget }),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.error || "Enrichment failed")
      if (d.asset) setEnriched({ forId: incomingId, asset: d.asset as ExposureAsset })
      else setEnrichError({ forId: incomingId, message: "No provider returned data for this asset." })
    } catch (e) {
      setEnrichError({ forId: incomingId, message: e instanceof Error ? e.message : String(e) })
    } finally {
      setEnriching(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {/* Width must use the `!` override: the base DialogContent ships
          `sm:max-w-sm`, which otherwise wins and renders this cramped.
          Matches the pattern in cve-detail-dialog / zero-day-detail-dialog. */}
      <DialogContent className="max-h-[92vh] w-[95vw] max-w-[calc(100%-2rem)] overflow-y-auto leading-relaxed sm:!max-w-5xl sm:p-8">
        <DialogHeader>
          <DialogTitle className="flex flex-wrap items-center gap-3 font-mono text-lg">
            {asset.ip ?? asset.domain ?? asset.id}
            {risk && risk.score > 0 && (
              <Badge className={cn("border", TONE_CLASS[tone])}>Exposure risk {risk.score}</Badge>
            )}
            {/* A2/B2: never imply evidence or a confidence judgement that does not exist. */}
            {asset.sourceCount === 0 ? (
              <Badge variant="outline">Search target — no provider evidence</Badge>
            ) : asset.enrichmentStatus === "not_requested" ? (
              <Badge variant="outline" title="Deep enrichment was not run for this asset. This is not a confidence judgement.">
                Not enriched · {asset.sourceCount}/{ALL_PROVIDERS.length} sources
              </Badge>
            ) : (
              <Badge className={CONFIDENCE_CLASS[asset.confidence]}>
                Confidence: {CONFIDENCE_LABEL[asset.confidence]} ({asset.sourceCount}/{ALL_PROVIDERS.length} sources)
              </Badge>
            )}
          </DialogTitle>
        </DialogHeader>

        <Tabs defaultValue="overview">
          <TabsList className="flex-wrap">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="services">Services ({asset.services.length})</TabsTrigger>
            <TabsTrigger value="vulns">Vulnerabilities ({asset.vulnerabilities.length})</TabsTrigger>
            <TabsTrigger value="certs">Certificates ({asset.certificates.length})</TabsTrigger>
            <TabsTrigger value="evidence">Evidence</TabsTrigger>
            <TabsTrigger value="raw">Raw</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4 pt-3">
            {/* Item 5: on-demand enrichment for THIS asset only. Shown when the
                per-search budget skipped it, or when a previous attempt failed. */}
            {(asset.enrichmentStatus === "not_requested" || asset.enrichmentStatus === "failed") && enrichTarget && (
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-white/5 p-3">
                <div className="text-sm">
                  <p className="font-medium">
                    Enrichment status:{" "}
                    <span className="text-muted-foreground">
                      {asset.enrichmentStatus === "failed" ? "Failed" : "Not enriched"}
                    </span>
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {asset.enrichmentStatus === "failed"
                      ? "Every enrichment provider failed for this asset. Retrying is safe."
                      : "Deep enrichment was not run for this asset. This is not a confidence judgement."}
                  </p>
                </div>
                <Button size="sm" onClick={runEnrichment} disabled={enriching}>
                  {enriching ? "Enriching…" : "Enrich asset"}
                </Button>
              </div>
            )}
            {activeEnriched && (
              <p className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-2 text-xs text-emerald-300">
                Enriched just now — services, technologies and CVE matches below reflect this asset only.
              </p>
            )}
            {activeError && (
              <p className="rounded-lg border border-red-500/40 bg-red-500/10 p-2 text-xs text-red-300">⚠️ {activeError}</p>
            )}

            <div className="grid gap-4 sm:grid-cols-2">
              <Section title="Network">
                <dl className="space-y-1 text-sm">
                  {asset.ip && <div className="flex gap-2"><dt className="w-28 text-muted-foreground">IP</dt><dd className="font-mono">{asset.ip}</dd></div>}
                  {/* A1: domains are a relationship — an asset can carry several, and
                      several assets can share one. Show them all. */}
                  {asset.domains.length > 0 && (
                    <div className="flex gap-2">
                      <dt className="w-28 text-muted-foreground">{asset.domains.length > 1 ? "Domains" : "Domain"}</dt>
                      <dd className="font-mono">{asset.domains.join(", ")}</dd>
                    </div>
                  )}
                  {asset.asn != null && <div className="flex gap-2"><dt className="w-28 text-muted-foreground">ASN</dt><dd>AS{asset.asn}</dd></div>}
                  {asset.organization && <div className="flex gap-2"><dt className="w-28 text-muted-foreground">Organization</dt><dd>{asset.organization}</dd></div>}
                  {(asset.country || asset.city) && <div className="flex gap-2"><dt className="w-28 text-muted-foreground">Location</dt><dd>{[asset.city, asset.country].filter(Boolean).join(", ")}</dd></div>}
                  {asset.hostnames.length > 0 && <div className="flex gap-2"><dt className="w-28 text-muted-foreground">Hostnames</dt><dd className="font-mono text-xs">{asset.hostnames.slice(0, 4).join(", ")}</dd></div>}
                </dl>
              </Section>

              {/* Item 3/9: fetchedAt and observedAt are DIFFERENT facts and are
                  never collapsed into one "live" claim. */}
              <Section title="Freshness">
                <div className="space-y-2 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <FreshnessBadge freshness={asset.freshness} />
                    {asset.freshness?.fromCache && (
                      <span className="text-xs text-muted-foreground">served from cache</span>
                    )}
                  </div>
                  <dl className="space-y-1 text-xs">
                    <div className="flex gap-2">
                      <dt className="w-40 text-muted-foreground">Retrieved by OCTUPUS</dt>
                      <dd>{asset.freshness ? new Date(asset.freshness.fetchedAt).toLocaleString("en-US") : "—"}</dd>
                    </div>
                    <div className="flex gap-2">
                      <dt className="w-40 text-muted-foreground">Provider observation</dt>
                      <dd>
                        {asset.freshness?.observedAt
                          ? <>{new Date(asset.freshness.observedAt).toLocaleString("en-US")} <span className="text-muted-foreground">({humanAge(asset.freshness.observationAgeSeconds)})</span></>
                          : <span className="text-muted-foreground">not supplied by any provider</span>}
                      </dd>
                    </div>
                  </dl>
                  {asset.providerFreshness && asset.providerFreshness.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {asset.providerFreshness.map((p) => (
                        <div key={p.provider} className="flex items-center gap-2 text-xs">
                          <span className="w-20 text-muted-foreground">{PROVIDER_LABEL[p.provider] ?? p.provider}</span>
                          <FreshnessBadge freshness={p.freshness} />
                          <span className="text-muted-foreground">
                            {p.freshness.observedAt ? `observed ${humanAge(p.freshness.observationAgeSeconds)}` : "no timestamp"}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  {enrichTarget && (
                    <div className="pt-1">
                      <Button size="sm" variant="outline" onClick={runRefresh} disabled={refreshing || enriching}>
                        {refreshing ? "Refreshing…" : "Refresh now"}
                      </Button>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        Re-queries providers for their latest indexed observation and records any changes. It cannot make a provider re-scan the host — none offer that.
                      </p>
                    </div>
                  )}
                  {changes && changes.length > 0 && (
                    <div className="mt-2 rounded border border-amber-500/40 bg-amber-500/10 p-2">
                      <p className="mb-1 text-xs font-semibold text-amber-300">Changes detected</p>
                      <ul className="space-y-0.5 text-xs text-muted-foreground">
                        {changes.map((c, i) => <li key={i}><span className="font-mono">{c.kind}</span> — {c.detail}</li>)}
                      </ul>
                    </div>
                  )}
                  {changes && changes.length === 0 && (
                    <p className="mt-2 text-xs text-muted-foreground">Refreshed — no changes since the last observation.</p>
                  )}
                </div>
              </Section>

              {/* Item 18: periodic monitoring for THIS asset. Opt-in only —
                  opening an asset must never schedule provider calls. */}
              {enrichTarget && (
                <Section title="Monitoring">
                  <div className="space-y-2 text-sm">
                    {!monitorLoaded ? (
                      <p className="text-xs text-muted-foreground">Loading schedule…</p>
                    ) : (
                      <>
                        <div className="flex flex-wrap items-center gap-2">
                          {monitoring?.enabled
                            ? <Badge className="bg-emerald-500/15 text-emerald-300">Monitored</Badge>
                            : <Badge variant="outline" className="text-muted-foreground">
                                {monitoring ? "Paused" : "Not monitored"}
                              </Badge>}
                          {monitoring?.last_status && (
                            <span className="text-xs text-muted-foreground">
                              last run: {MONITOR_STATUS_LABEL[monitoring.last_status] ?? monitoring.last_status}
                            </span>
                          )}
                          {(monitoring?.consecutive_failures ?? 0) > 0 && (
                            <span className="text-xs text-red-300">
                              {monitoring?.consecutive_failures} consecutive failure(s)
                            </span>
                          )}
                        </div>

                        {monitoring && (
                          <dl className="space-y-1 text-xs">
                            <div className="flex gap-2">
                              <dt className="w-40 text-muted-foreground">Interval</dt>
                              <dd>{INTERVAL_OPTIONS.find((o) => o.value === monitoring.interval_seconds)?.label
                                ?? `Every ${Math.round(monitoring.interval_seconds / 60)}m`}</dd>
                            </div>
                            <div className="flex gap-2">
                              <dt className="w-40 text-muted-foreground">Last checked</dt>
                              <dd>{whenRelative(monitoring.last_attempt_at)}</dd>
                            </div>
                            <div className="flex gap-2">
                              <dt className="w-40 text-muted-foreground">Last successful check</dt>
                              <dd>{whenRelative(monitoring.last_success_at)}</dd>
                            </div>
                            <div className="flex gap-2">
                              <dt className="w-40 text-muted-foreground">Next check</dt>
                              <dd>{monitoring.enabled ? whenRelative(monitoring.next_run_at) : "— (paused)"}</dd>
                            </div>
                          </dl>
                        )}

                        <div className="flex flex-wrap items-center gap-2 pt-1">
                          {monitoring?.enabled ? (
                            <Button size="sm" variant="outline" disabled={monitorBusy}
                              onClick={() => void setMonitoringFor(false, monitoring.interval_seconds)}>
                              {monitorBusy ? "…" : "Pause monitoring"}
                            </Button>
                          ) : (
                            <Button size="sm" variant="outline" disabled={monitorBusy}
                              onClick={() => void setMonitoringFor(true, monitoring?.interval_seconds ?? 6 * 3600)}>
                              {monitorBusy ? "…" : monitoring ? "Resume monitoring" : "Monitor this asset"}
                            </Button>
                          )}
                          <select
                            className="rounded-md border border-border bg-transparent px-2 py-1 text-xs"
                            value={monitoring?.interval_seconds ?? 6 * 3600}
                            disabled={monitorBusy}
                            onChange={(e) => void setMonitoringFor(monitoring?.enabled ?? false, Number(e.target.value))}
                          >
                            {INTERVAL_OPTIONS.map((o) => (
                              <option key={o.value} value={o.value} className="bg-background">{o.label}</option>
                            ))}
                          </select>
                        </div>

                        <p className="text-[11px] text-muted-foreground">
                          Periodic, not real-time: each scheduled run re-queries providers for their latest indexed
                          observation and records any differences as change events. Provider quota is shared across all
                          monitored assets, so longer intervals scale further.
                        </p>
                      </>
                    )}
                  </div>
                </Section>
              )}

              <Section title="Threat signals">
                <div className="flex flex-wrap gap-2">
                  {/* Deliberately distinct signals — EPSS/KEV come from the CVE
                      pipeline, GreyNoise is IP activity. Never merged. */}
                  {asset.threat?.classification === "malicious" && <Badge className="bg-red-600 text-white">GreyNoise: malicious</Badge>}
                  {asset.threat?.classification === "benign" && <Badge className="bg-emerald-600 text-white">GreyNoise: benign{asset.threat.actor ? ` (${asset.threat.actor})` : ""}</Badge>}
                  {asset.threat?.classification === "not_observed" && <Badge variant="outline">Not observed scanning</Badge>}
                  {asset.threat?.noise && <Badge className="bg-amber-500 text-black">Observed scanning the internet</Badge>}
                  {asset.threat?.riot && <Badge variant="secondary">Known benign service (RIOT)</Badge>}
                  {asset.services.length > 0 && <Badge className="bg-orange-600 text-white">Internet exposed</Badge>}
                  {!asset.threat && <Empty>No GreyNoise data for this asset.</Empty>}
                </div>
                {asset.threat?.link && (
                  <a href={asset.threat.link} target="_blank" rel="noopener noreferrer" className="mt-2 inline-block text-xs underline decoration-dotted">
                    View on GreyNoise →
                  </a>
                )}
              </Section>
            </div>

            {risk && risk.score > 0 && (
              <Section title="Exposure risk breakdown">
                <div className="rounded-lg border border-border bg-white/5 p-3 text-sm">
                  <p className="mb-2">
                    Base RBVM <b>{risk.baseRbvm}</b> × exposure factor <b>{risk.exposureFactor}</b> = <b className="text-foreground">{risk.score}</b>
                    <span className="ml-2 text-muted-foreground">· SLA {risk.slaHours}h</span>
                  </p>
                  <ul className="space-y-1 text-xs text-muted-foreground">
                    {risk.factors.map((f, i) => (
                      <li key={i}>
                        <span className={cn("font-mono", f.delta < 0 ? "text-emerald-400" : "text-amber-400")}>
                          {f.delta > 0 && f.label !== "Base RBVM" ? "+" : ""}{f.delta}
                        </span>{" "}
                        <b className="text-foreground">{f.label}</b> — {f.detail}
                      </li>
                    ))}
                  </ul>
                </div>
              </Section>
            )}

            <Section title="Technologies">
              {asset.technologies.length ? (
                <div className="flex flex-wrap gap-1">
                  {asset.technologies.map((t) => (
                    <Badge key={t.name} variant="secondary" title={`Source: ${t.sources.join(", ")}`}>
                      {t.name}{t.version ? ` ${t.version}` : ""}
                    </Badge>
                  ))}
                </div>
              ) : <Empty>No technologies fingerprinted.</Empty>}
            </Section>

            <Section title="Provider confirmation">
              <div className="flex flex-wrap gap-2">
                {ALL_PROVIDERS.map((p) => (
                  <Badge key={p} variant={asset.sources.includes(p) ? "default" : "outline"} className={cn(!asset.sources.includes(p) && "opacity-40")}>
                    {asset.sources.includes(p) ? "✓" : "—"} {PROVIDER_LABEL[p]}
                  </Badge>
                ))}
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                {asset.firstSeen && `First seen ${new Date(asset.firstSeen).toLocaleString("en-US")}. `}
                {asset.lastSeen && `Last observed ${new Date(asset.lastSeen).toLocaleString("en-US")}.`}
              </p>
            </Section>
          </TabsContent>

          <TabsContent value="services" className="pt-3">
            {asset.services.length ? (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow><TableHead>Port</TableHead><TableHead>Protocol</TableHead><TableHead>Product</TableHead><TableHead>Version</TableHead><TableHead>Vulnerabilities</TableHead><TableHead>HTTP</TableHead><TableHead>Sources</TableHead></TableRow>
                  </TableHeader>
                  <TableBody>
                    {asset.services.sort((a, b) => a.port - b.port).map((s) => (
                      <TableRow key={`${s.port}-${s.protocol}`}>
                        <TableCell className="font-mono">{s.port}/{s.transport ?? "tcp"}</TableCell>
                        <TableCell>{s.protocol ?? "—"}</TableCell>
                        <TableCell>
                          {s.product ?? "—"}
                          {/* B3: conflicting fingerprints are surfaced, never silently resolved. */}
                          {s.conflict && (
                            <Badge
                              className="ml-2 bg-amber-500 text-black"
                              title={s.claims.map((c) => `${PROVIDER_LABEL[c.source] ?? c.source}: ${c.product ?? "?"}${c.version ? " " + c.version : ""}`).join("  |  ")}
                            >
                              ⚠ Provider disagreement
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{s.version ?? "—"}</TableCell>
                        <TableCell className="text-xs">
                          {/* CVEs correlated THROUGH this port, with the
                              strongest evidence backing any of them. */}
                          {(() => {
                            const onPort = asset.vulnerabilities.filter((v) => v.correlatedPort === s.port)
                            if (!onPort.length) return <span className="text-muted-foreground">none</span>
                            const tier = strongestTier(onPort) ?? "weak"
                            const ui = TIER_UI[tier] ?? TIER_UI.weak
                            return (
                              <span className="flex items-center gap-1.5 whitespace-nowrap">
                                <span className="tabular-nums">{onPort.length}</span>
                                <Badge className={cn("text-[10px]", ui.cls)} title={ui.hint}>{ui.label}</Badge>
                              </span>
                            )
                          })()}
                        </TableCell>
                        <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                          {s.httpStatus ? `${s.httpStatus} ` : ""}{s.httpTitle ?? s.httpServer ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs">{s.sources.map((x) => PROVIDER_LABEL[x]).join(", ")}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : <Empty>No services observed.</Empty>}
          </TabsContent>

          <TabsContent value="vulns" className="pt-3">
            {asset.vulnerabilities.length ? (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow><TableHead>CVE</TableHead><TableHead>Service</TableHead><TableHead>Evidence</TableHead><TableHead>Provider score</TableHead><TableHead>Match quality</TableHead><TableHead>Matched product</TableHead><TableHead>Sources</TableHead></TableRow>
                  </TableHeader>
                  <TableBody>
                    {asset.vulnerabilities.map((v) => (
                      <TableRow key={v.cveId}>
                        <TableCell className="font-mono">
                          <a href={`https://nvd.nist.gov/vuln/detail/${v.cveId}`} target="_blank" rel="noopener noreferrer" className="underline decoration-dotted">{v.cveId}</a>
                        </TableCell>
                        <TableCell className="whitespace-nowrap font-mono text-xs">
                          {v.correlatedPort ? `${v.correlatedPort}/tcp` : <span className="text-muted-foreground">host-level</span>}
                        </TableCell>
                        <TableCell>
                          {(() => {
                            const ui = TIER_UI[v.evidenceTier ?? "weak"] ?? TIER_UI.weak
                            return <Badge className={cn("text-[10px]", ui.cls)} title={ui.hint}>{ui.label}</Badge>
                          })()}
                        </TableCell>
                        <TableCell>{v.providerScore ?? "—"}</TableCell>
                        <TableCell>
                          {/* Match quality is decision-relevant and must not be flattened:
                              a locally-derived `pivot` is a LEAD, a `cve-search` hit is a
                              provider directly asserting this host is affected. */}
                          <Badge
                            className={cn(MATCH_CLASS[v.matchType ?? "unknown"])}
                            variant={v.matchType === "version" || v.matchType === "cve-search" ? "default" : "outline"}
                            title={MATCH_HELP[v.matchType ?? "unknown"]}
                          >
                            {MATCH_LABEL[v.matchType ?? "unknown"]}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs">{v.matchedProduct ?? "—"}</TableCell>
                        <TableCell className="text-xs">{v.sources.map((x) => PROVIDER_LABEL[x]).join(", ")}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <p className="mt-2 text-xs text-muted-foreground">
                  Authoritative CVSS / EPSS / KEV for these CVEs come from OCTUPUS&apos;s own NVD pipeline, not from the exposure provider.
                </p>
              </div>
            ) : <Empty>No vulnerabilities correlated to this asset.</Empty>}
          </TabsContent>

          <TabsContent value="certs" className="pt-3">
            {asset.certificates.length ? (
              <div className="space-y-3">
                {asset.certificates.map((c, i) => (
                  <div key={i} className="rounded-lg border border-border bg-white/5 p-3 text-sm">
                    <p className="font-medium">{c.commonName ?? "(no common name)"}</p>
                    {c.issuer && <p className="text-xs text-muted-foreground">Issuer: {c.issuer}</p>}
                    {c.fingerprint && <p className="break-all font-mono text-xs text-muted-foreground">SHA-256: {c.fingerprint}</p>}
                    {(c.validFrom || c.validTo) && (
                      <p className="text-xs text-muted-foreground">
                        Valid {c.validFrom ? new Date(c.validFrom).toLocaleDateString("en-US") : "?"} → {c.validTo ? new Date(c.validTo).toLocaleDateString("en-US") : "?"}
                        {c.expired === true && <Badge className="ml-2 bg-red-600 text-white">Expired</Badge>}
                      </p>
                    )}
                    {c.sans.length > 0 && <p className="mt-1 text-xs"><span className="text-muted-foreground">SANs:</span> {c.sans.slice(0, 12).join(", ")}{c.sans.length > 12 ? ` +${c.sans.length - 12} more` : ""}</p>}
                    <p className="mt-1 text-xs text-muted-foreground">Sources: {c.sources.map((x) => PROVIDER_LABEL[x]).join(", ")}</p>
                  </div>
                ))}
              </div>
            ) : <Empty>No certificates observed.</Empty>}
          </TabsContent>

          <TabsContent value="evidence" className="space-y-3 pt-3">
            <Section title="Why these observations were merged into one asset">
              {asset.evidence.length ? (
                <ul className="space-y-2 text-sm">
                  {asset.evidence.map((e, i) => (
                    <li key={i} className="rounded border border-border bg-white/5 p-2">
                      <Badge variant="outline" className="mr-2 font-mono text-[10px]">{e.basis}</Badge>
                      {e.detail}
                    </li>
                  ))}
                </ul>
              ) : <Empty>Single-source observation — nothing to correlate.</Empty>}
            </Section>
            <Section title="Confidence">
              <p className="text-sm">
                <b>{CONFIDENCE_LABEL[asset.confidence]}</b> ({asset.confidenceScore}/100) from {asset.sourceCount} independent provider{asset.sourceCount === 1 ? "" : "s"}.
              </p>
            </Section>
          </TabsContent>

          <TabsContent value="raw" className="pt-3">
            <button onClick={() => setShowRaw((v) => !v)} className="mb-2 rounded border border-border px-3 py-1 text-sm hover:bg-accent">
              {showRaw ? "Hide" : "Show"} raw provider intelligence
            </button>
            {showRaw && (
              <div className="space-y-3">
                {asset.raw.map((r, i) => (
                  <div key={i}>
                    <p className="mb-1 text-xs font-semibold uppercase text-muted-foreground">{PROVIDER_LABEL[r.provider]}</p>
                    <pre className="max-h-64 overflow-auto rounded border border-border bg-black/40 p-2 text-[11px]">{JSON.stringify(r.data, null, 2)}</pre>
                  </div>
                ))}
                {!asset.raw.length && <Empty>No raw payloads retained for this asset.</Empty>}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
