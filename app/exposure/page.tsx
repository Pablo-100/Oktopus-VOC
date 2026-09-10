"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { TONE_CLASS } from "@/lib/risk-engine"
import { cn } from "@/lib/utils"
import { ExposureAssetDialog } from "@/components/exposure-asset-dialog"
import { ExposureMonitoringPanel } from "@/components/exposure-monitoring-panel"
import { ExposureAlertsPanel } from "@/components/exposure-alerts-panel"
import { ExposureGraphPanel } from "@/components/exposure-graph-panel"
import type { ExposureAsset, ExposureSearchResult, ProviderOutcome, ProviderStatus } from "@/lib/exposure/types"

const PROVIDER_LABEL: Record<string, string> = {
  censys: "Censys", leakix: "LeakIX", netlas: "Netlas", fofa: "FOFA", zoomeye: "ZoomEye", greynoise: "GreyNoise",
}

/** Provider status -> operator-facing meaning. Never a bare "Blocked". */
const STATUS_UI: Record<ProviderStatus, { label: string; cls: string }> = {
  success: { label: "Operational", cls: "bg-emerald-500/15 text-emerald-300" },
  partial: { label: "Partial", cls: "bg-sky-500/15 text-sky-300" },
  not_configured: { label: "Not configured", cls: "bg-white/5 text-muted-foreground" },
  authentication_failed: { label: "Auth failed", cls: "bg-red-500/15 text-red-300" },
  rate_limited: { label: "Rate limited", cls: "bg-amber-500/15 text-amber-300" },
  quota_exhausted: { label: "Quota exhausted", cls: "bg-amber-500/15 text-amber-300" },
  plan_limitation: { label: "Plan limitation", cls: "bg-violet-500/15 text-violet-300" },
  query_unsupported: { label: "Query unsupported", cls: "bg-violet-500/15 text-violet-300" },
  provider_unavailable: { label: "Unavailable", cls: "bg-red-500/15 text-red-300" },
  timeout: { label: "Timeout", cls: "bg-amber-500/15 text-amber-300" },
}

const CONFIDENCE_CLASS: Record<string, string> = {
  very_high: "bg-emerald-600 text-white", high: "bg-sky-600 text-white",
  medium: "bg-amber-500 text-black", low: "bg-zinc-600 text-white",
}

/**
 * Freshness of the PROVIDER'S OBSERVATION. There is intentionally no "LIVE"
 * value in use — no configured provider scans on demand, so the app must never
 * imply it is looking at the internet right now.
 */
const FRESHNESS_LABEL: Record<string, string> = {
  live: "LIVE", fresh: "FRESH", recent: "RECENT", stale: "STALE", unknown: "UNKNOWN", cached: "CACHED",
}
const FRESHNESS_CLASS: Record<string, string> = {
  live: "bg-emerald-600 text-white",
  fresh: "bg-emerald-600 text-white",
  recent: "bg-sky-600 text-white",
  stale: "bg-amber-500 text-black",
  unknown: "bg-zinc-600 text-white",
  cached: "bg-amber-500/80 text-black",
}
const CONFIDENCE_LABEL: Record<string, string> = { very_high: "Very high", high: "High", medium: "Medium", low: "Low" }

/**
 * Evidence tiers, kept visually distinct from RISK. Severity says how bad the
 * CVE is; evidence says how sure we are the asset really runs it.
 */
const EVIDENCE_BADGE: Record<string, { label: string; cls: string; hint: string }> = {
  confirmed: { label: "Confirmed", cls: "bg-emerald-600 text-white", hint: "A provider returned this host when queried for the CVE." },
  strong: { label: "Strong", cls: "bg-sky-600 text-white", hint: "An affected VERSION was fingerprinted on this host." },
  product: { label: "Product", cls: "bg-amber-500 text-black", hint: "Product NAME matched only — version unproven. A lead, not a finding." },
  weak: { label: "Weak", cls: "bg-zinc-600 text-white", hint: "Banner or heuristic inference only." },
  pivot: { label: "Pivot", cls: "bg-zinc-700 text-white", hint: "Local CVE→product pivot; never reported as affected." },
}
const EVIDENCE_RANK: Record<string, number> = { confirmed: 5, strong: 4, product: 3, weak: 2, pivot: 1 }

function strongestTier(vulns: Array<{ evidenceTier?: string }>): string | null {
  let best: string | null = null
  for (const v of vulns) {
    const t = v.evidenceTier ?? "weak"
    if (!best || (EVIDENCE_RANK[t] ?? 0) > (EVIDENCE_RANK[best] ?? 0)) best = t
  }
  return best
}

const EXAMPLES = ["Apache", "nginx", "80.82.77.139", "example.com", "CVE-2021-44228"]
const DEFAULT_QUERY = "Apache"
/** Server-side page size — must stay <= MAX_PAGE_SIZE in lib/exposure/orchestrator.ts. */
const PAGE_SIZE = 50

type Tab = "assets" | "services" | "vulnerabilities" | "certificates" | "providers" | "monitoring" | "alerts" | "graph"

function ago(d: Date | null): string {
  if (!d) return "—"
  const s = Math.floor((Date.now() - d.getTime()) / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  return m === 1 ? "1 min ago" : `${m} min ago`
}

/**
 * Provider health strip.
 *
 * Shown above every tab because a partial result set is otherwise
 * indistinguishable from a quiet internet. "Configured" only means a key is
 * present — it says nothing about the account behind it, so a provider whose
 * credits are spent looked healthy while contributing nothing. This reports
 * the LAST OBSERVED outcome instead.
 */
function ProviderStrip() {
  const [rows, setRows] = useState<Array<{
    provider: string; configured: boolean
    health: { status: string; message: string | null; lastOkAt: string | null } | null
  }> | null>(null)

  const load = useCallback(async () => {
    const res = await fetch("/api/exposure/status")
    if (!res.ok) throw new Error(String(res.status))
    return (await res.json()) as { providers: typeof rows }
  }, [])

  useEffect(() => {
    let cancelled = false
    load().then((d) => { if (!cancelled) setRows(d.providers ?? []) }).catch(() => { /* strip is optional */ })
    return () => { cancelled = true }
  }, [load])

  if (!rows?.length) return null

  const label = (r: NonNullable<typeof rows>[number]) => {
    if (!r.configured) return { text: "no key", cls: "bg-white/5 text-muted-foreground", why: "No API key configured for this provider." }
    const st = r.health?.status
    if (!st) return { text: "untested", cls: "bg-white/5 text-muted-foreground", why: "Configured, but not called yet — no observed result." }
    if (st === "success" || st === "partial") return { text: "working", cls: "bg-emerald-500/15 text-emerald-300", why: r.health?.message ?? "Returned data on the last call." }
    if (st === "quota_exhausted") return { text: "no credits", cls: "bg-amber-500/15 text-amber-300", why: r.health?.message ?? "The provider account has no remaining credits." }
    if (st === "rate_limited") return { text: "rate limited", cls: "bg-amber-500/15 text-amber-300", why: r.health?.message ?? "Temporarily rate limited." }
    if (st === "authentication_failed") return { text: "bad key", cls: "bg-red-500/15 text-red-300", why: r.health?.message ?? "Credentials rejected." }
    return { text: st.replace(/_/g, " "), cls: "bg-red-500/15 text-red-300", why: r.health?.message ?? "" }
  }

  const degraded = rows.filter((r) => r.configured && r.health && !["success", "partial"].includes(r.health.status))

  return (
    <div className="mb-4 rounded-lg border border-border bg-white/5 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Providers</span>
        {rows.map((r) => {
          const l = label(r)
          return (
            <span key={r.provider} className={cn("rounded-full px-2 py-0.5 text-[11px]", l.cls)} title={l.why}>
              {r.provider} · {l.text}
            </span>
          )
        })}
      </div>
      {degraded.length > 0 && (
        <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
          <b className="text-amber-300">Results are partial.</b>{" "}
          {degraded.map((d) => d.provider).join(", ")} {degraded.length === 1 ? "is" : "are"} not returning data, so this
          view shows only what the remaining providers observed. This is a provider-account state, not a fault in the
          search — top up or replace those credentials to widen coverage.
        </p>
      )}
    </div>
  )
}

function ProviderHealth({ providers }: { providers: ProviderOutcome[] }) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Provider</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead>
            <TableHead>Calls</TableHead><TableHead>Success</TableHead><TableHead>Failed</TableHead>
            <TableHead>Avg latency</TableHead><TableHead>Observations</TableHead><TableHead>Detail</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {providers.map((p) => {
            const ui = STATUS_UI[p.status]
            // C3: real call accounting — a row can summarize many per-host calls,
            // so a single host's query must not be shown as THE provider query.
            const calls = p.calls ?? 1
            const ok = p.successCalls ?? (p.status === "success" || p.status === "partial" ? 1 : 0)
            const failed = p.failedCalls ?? calls - ok
            return (
              <TableRow key={p.provider}>
                <TableCell className="font-medium">{PROVIDER_LABEL[p.provider] ?? p.provider}</TableCell>
                <TableCell><Badge variant="outline" className="text-[10px] uppercase">{p.role}</Badge></TableCell>
                <TableCell><span className={cn("rounded-full px-2 py-0.5 text-xs", ui.cls)}>● {ui.label}</span></TableCell>
                <TableCell className="font-mono text-xs tabular-nums">{calls}</TableCell>
                <TableCell className="font-mono text-xs tabular-nums text-emerald-400">{ok}</TableCell>
                <TableCell className={cn("font-mono text-xs tabular-nums", failed > 0 && "text-amber-400")}>{failed}</TableCell>
                <TableCell className="font-mono text-xs tabular-nums">{p.latencyMs}ms</TableCell>
                <TableCell className="font-mono text-xs tabular-nums">{p.observationCount}</TableCell>
                <TableCell className="max-w-[380px] text-xs text-muted-foreground">
                  {p.message ?? <span className="font-mono">{p.query}</span>}
                  {p.retryable && p.status !== "success" && p.status !== "partial" && <Badge variant="outline" className="ml-2 text-[10px]">retryable</Badge>}
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

export default function ExposurePage() {
  const [query, setQuery] = useState("")
  const [result, setResult] = useState<ExposureSearchResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [checkedAt, setCheckedAt] = useState<Date | null>(null)
  const [tab, setTab] = useState<Tab>(() => {
    // The graph links to ?tab=alerts&alert=<id>; honour it so a click from the
    // investigation view lands on the workflow rather than the asset table.
    if (typeof window === "undefined") return "assets"
    const requested = new URLSearchParams(window.location.search).get("tab")
    const known: Tab[] = ["assets", "services", "vulnerabilities", "certificates", "providers", "monitoring", "alerts", "graph"]
    return (known as string[]).includes(requested ?? "") ? (requested as Tab) : "assets"
  })
  const [selected, setSelected] = useState<ExposureAsset | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [minRisk, setMinRisk] = useState(0)
  const [vulnOnly, setVulnOnly] = useState(false)
  const [page, setPage] = useState(0)
  /** The query the current result belongs to — used to page without re-typing. */
  const [activeQuery, setActiveQuery] = useState<string>(DEFAULT_QUERY)

  // C5: the server slices; the browser only ever receives one page.
  const doFetch = useCallback(async (q: string, offset = 0): Promise<ExposureSearchResult> => {
    const r = await fetch(`/api/exposure/search?q=${encodeURIComponent(q)}&limit=${PAGE_SIZE}&offset=${offset}`)
    const d = await r.json()
    if (!r.ok) throw new Error(d.error || "Search failed")
    return d as ExposureSearchResult
  }, [])

  /** User-initiated search — safe to flip loading synchronously here (not inside an effect). */
  const run = useCallback(async (term: string, offset = 0) => {
    const q = term.trim()
    if (!q) return
    setLoading(true)
    setError(null)
    try {
      setResult(await doFetch(q, offset))
      setActiveQuery(q)
      setPage(Math.floor(offset / PAGE_SIZE))
      setCheckedAt(new Date())
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [doFetch])

  /** Fetch a different page of the CURRENT query — served from cache, no provider calls. */
  const goToPage = useCallback((p: number) => {
    if (!activeQuery) return
    run(activeQuery, p * PAGE_SIZE)
  }, [activeQuery, run])

  // Load a real query on mount — an empty console is indistinguishable from a
  // broken one. State is only set from async callbacks (never synchronously in
  // the effect body); `loading` already starts true, so no pre-set is needed.
  useEffect(() => {
    let cancelled = false
    doFetch(DEFAULT_QUERY)
      .then((d) => { if (!cancelled) { setResult(d); setCheckedAt(new Date()) } })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [doFetch])

  // Memoised, not a bare `??`. The fallback allocates a NEW empty array on every
  // render, so five downstream useMemo hooks that depend on `assets` saw a
  // changed dependency each time and recomputed on every render — which is
  // precisely what those hooks exist to avoid.
  const assets = useMemo(() => result?.assets ?? [], [result])

  const metrics = useMemo(() => {
    const services = assets.reduce((n, a) => n + a.services.length, 0)
    const domains = new Set<string>()
    assets.forEach((a) => { if (a.domain) domains.add(a.domain); a.hostnames.forEach((h) => domains.add(h)) })
    const certs = assets.reduce((n, a) => n + a.certificates.length, 0)
    const vulnAssets = assets.filter((a) => a.vulnerabilities.length > 0).length
    const critical = assets.filter((a) => a.exposureRisk?.severity === "critical").length
    const high = assets.filter((a) => a.exposureRisk?.severity === "high").length
    const threats = assets.filter((a) => a.threat?.noise || a.threat?.classification === "malicious").length
    return { assets: assets.length, services, domains: domains.size, certs, vulnAssets, critical, high, threats }
  }, [assets])

  const filtered = useMemo(() => assets.filter((a) => {
    if (vulnOnly && a.vulnerabilities.length === 0) return false
    if (minRisk > 0 && (a.exposureRisk?.score ?? 0) < minRisk) return false
    return true
  }), [assets, minRisk, vulnOnly])

  // C5: `assets` is already ONE server-provided page; `totalAssets` is the full
  // correlated count. Filters apply within the current page only — that is an
  // honest limitation of filtering a paginated set, surfaced in the footer.
  const totalPages = Math.max(1, Math.ceil((result?.totalAssets ?? 0) / PAGE_SIZE))
  const pageSafe = Math.min(page, totalPages - 1)
  const pageRows = filtered

  const allServices = useMemo(
    () => assets.flatMap((a) => a.services.map((s) => ({ asset: a, service: s }))).sort((x, y) => x.service.port - y.service.port),
    [assets],
  )
  const allVulns = useMemo(() => {
    const rows: Array<{ asset: ExposureAsset; cveId: string; matchType?: string; score?: number | null }> = []
    for (const a of assets) for (const v of a.vulnerabilities) rows.push({ asset: a, cveId: v.cveId, matchType: v.matchType, score: v.providerScore })
    return rows.sort((x, y) => (y.score ?? 0) - (x.score ?? 0))
  }, [assets])
  const allCerts = useMemo(
    () => assets.flatMap((a) => a.certificates.map((c) => ({ asset: a, cert: c }))),
    [assets],
  )

  function openAsset(a: ExposureAsset) { setSelected(a); setDialogOpen(true) }

  const TABS: Array<{ id: Tab; label: string; count: number | null }> = [
    { id: "assets", label: "Assets", count: metrics.assets },
    { id: "services", label: "Services", count: metrics.services },
    { id: "vulnerabilities", label: "Vulnerabilities", count: allVulns.length },
    { id: "certificates", label: "Certificates", count: metrics.certs },
    { id: "providers", label: "Providers", count: result?.providers.length ?? 0 },
    // Monitoring is schedule state, not a slice of the current search result,
    // so it deliberately has no result-derived count.
    { id: "monitoring", label: "Monitoring", count: null },
    // SOC alerts are pipeline state, not a slice of the current search.
    { id: "alerts", label: "SOC Alerts", count: null },
    // The graph reads the persisted surface, not the current search result.
    { id: "graph", label: "Graph", count: null },
  ]

  return (
    <main className="mx-auto max-w-[1700px] px-4 py-8">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:flex-wrap md:items-end md:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Exposure Intelligence</h1>
          <p className="text-sm text-muted-foreground sm:text-base">
            External attack surface correlated across six providers, enriched with the CVE/RBVM engine.
          </p>
        </div>
        <form className="flex w-full flex-col gap-2 sm:flex-row sm:items-center md:w-auto" onSubmit={(e) => { e.preventDefault(); run(query) }}>
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="IP, domain, product, CVE or port…" className="w-full min-w-0 sm:w-72" />
          <Button type="submit" disabled={loading || !query.trim()}>{loading ? "Searching…" : "Search"}</Button>
        </form>
      </div>

      <details className="group mb-4 rounded-lg border border-border bg-white/5 p-3 open:pb-4">
        <summary className="cursor-pointer text-sm font-medium text-foreground">❔ What is Exposure Intelligence?</summary>
        <div className="mt-3 space-y-2 text-sm leading-relaxed text-muted-foreground">
          <p>Providers are used for <b>different jobs, not interchangeably</b>. <b>Discovery</b> (LeakIX, FOFA, ZoomEye) finds candidate hosts from a query. <b>Enrichment</b> (Censys, Netlas) then deepens each host with services, technologies, certificates and CVE matches. <b>GreyNoise</b> adds internet threat activity for the IP.</p>
          <p>Observations from every provider are normalized and <b>correlated into one asset per real host</b> — merged only on strong identifiers (exact IP, domain, certificate fingerprint), never on a shared product name. Confidence reflects how much independent evidence supports the merge.</p>
          <p><b>EPSS</b>, <b>CISA KEV</b>, <b>exploit availability</b> and <b>GreyNoise activity</b> are kept as separate signals — GreyNoise is IP activity intelligence, not an exploit-probability score.</p>
        </div>
      </details>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Try:</span>
        {EXAMPLES.map((ex) => (
          <Button key={ex} size="sm" variant="outline" className="rounded-full font-mono text-xs" onClick={() => { setQuery(ex); run(ex) }}>{ex}</Button>
        ))}
      </div>

      {result && (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">Query: <span className="font-mono">{result.query}</span></span>
          <Badge variant="outline" className="text-[10px] uppercase">{result.queryType}</Badge>
          {/* Item 8: precise terminology. "Retrieved" is OUR fetch; it is not a
              claim about when providers observed anything. */}
          <span>· retrieved {ago(checkedAt)}</span>
          {result.cached && (
            <span className="rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-300" title="Served from OCTUPUS's cache — no provider was contacted for this response.">
              Cached{result.cachedAt ? ` · updated ${ago(new Date(result.cachedAt))}` : ""}
            </span>
          )}
          <span className="rounded-full bg-white/5 px-2 py-0.5">
            {result.providers.filter((p) => p.status === "success" || p.status === "partial").length}/{result.providers.length} providers returned data
          </span>
        </div>
      )}

      {error && <Card className="mb-4 border-red-500/50 bg-red-500/10 p-3 text-sm">⚠️ {error}</Card>}

      {/* Metrics — all computed from the real correlated result set. */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
        {[
          { label: "Assets", value: metrics.assets, cls: "neon-text" },
          { label: "Services", value: metrics.services, cls: "text-foreground" },
          { label: "Domains", value: metrics.domains, cls: "text-foreground" },
          { label: "Certificates", value: metrics.certs, cls: "text-foreground" },
          { label: "Vulnerable", value: metrics.vulnAssets, cls: "text-amber-400" },
          { label: "Critical", value: metrics.critical, cls: "text-red-400" },
          { label: "High", value: metrics.high, cls: "text-orange-400" },
          { label: "Threat signals", value: metrics.threats, cls: "text-violet-400" },
        ].map((m) => (
          <Card key={m.label} className="glass accent-top p-3">
            <div className="eyebrow text-[10px]">{m.label}</div>
            <div className={cn("mt-1 text-2xl font-bold", m.cls)}>{loading ? "…" : m.value}</div>
          </Card>
        ))}
      </div>

      <ProviderStrip />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {TABS.map((t) => (
          <Button key={t.id} size="sm" variant={tab === t.id ? "default" : "outline"} className="rounded-full" onClick={() => setTab(t.id)}>
            {t.label}{t.count !== null && <span className="ml-1 opacity-70">{t.count}</span>}
          </Button>
        ))}
        {tab === "assets" && (
          <div className="ml-auto flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              Min risk <span className="text-foreground">{minRisk}</span>
              <input type="range" min={0} max={100} step={5} value={minRisk} onChange={(e) => setMinRisk(+e.target.value)} className="w-28 accent-violet-500" />
            </label>
            <Button size="sm" variant={vulnOnly ? "default" : "outline"} className="rounded-full" onClick={() => setVulnOnly((v) => !v)}>
              Vulnerable only
            </Button>
          </div>
        )}
      </div>

      {/* Monitoring is schedule state, independent of the current search: it is
          rendered outside the results card so a search in flight neither blanks
          it nor traps it in the results scroll container. */}
      {tab === "monitoring" ? (
        <ExposureMonitoringPanel />
      ) : tab === "alerts" ? (
        <ExposureAlertsPanel />
      ) : tab === "graph" ? (
        <ExposureGraphPanel />
      ) : (
      <Card className="glass overflow-hidden">
        <div className="max-h-[65vh] overflow-auto">
          {loading ? (
            <p className="py-16 text-center text-sm text-muted-foreground">Querying providers, correlating results…</p>
          ) : tab === "providers" ? (
            <ProviderHealth providers={result?.providers ?? []} />
          ) : tab === "assets" ? (
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>Asset</TableHead><TableHead>Risk</TableHead><TableHead>Confidence</TableHead>
                  <TableHead>Freshness</TableHead>
                  <TableHead>Sources</TableHead><TableHead>Services</TableHead><TableHead>CVEs</TableHead>
                  <TableHead>Organization</TableHead><TableHead>Country</TableHead><TableHead>Threat</TableHead><TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageRows.length === 0 ? (
                  <TableRow><TableCell colSpan={11} className="py-10 text-center text-muted-foreground">No assets matched.</TableCell></TableRow>
                ) : pageRows.map((a) => (
                  <TableRow key={a.id} className="cursor-pointer" onClick={() => openAsset(a)}>
                    <TableCell className="whitespace-nowrap font-mono text-xs">{a.ip ?? a.domain ?? a.id}</TableCell>
                    <TableCell>
                      {a.exposureRisk && a.exposureRisk.score > 0
                        ? <Badge className={cn("border", TONE_CLASS[a.exposureRisk.severity])}>{a.exposureRisk.score}</Badge>
                        : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell>
                      {/* B2: "never examined" is NOT "weak evidence" — show it as its own state. */}
                      {a.enrichmentStatus === "not_requested"
                        ? <Badge variant="outline" title="Deep enrichment was not run for this asset (per-search budget). This is not a confidence judgement.">Not enriched</Badge>
                        : <Badge className={CONFIDENCE_CLASS[a.confidence]}>{CONFIDENCE_LABEL[a.confidence]}</Badge>}
                    </TableCell>
                        <TableCell>
                      {/* Freshness reflects the PROVIDER's observation age, not
                          our retrieval time — the two are different facts. */}
                      {a.freshness
                        ? <Badge
                            className={FRESHNESS_CLASS[a.freshness.fromCache ? "cached" : a.freshness.state]}
                            title={a.freshness.observedAt
                              ? `Provider observed ${new Date(a.freshness.observedAt).toLocaleString("en-US")}; OCTUPUS retrieved ${new Date(a.freshness.fetchedAt).toLocaleString("en-US")}`
                              : "No provider supplied an observation timestamp for this asset."}
                          >
                            {a.freshness.fromCache ? "CACHED" : FRESHNESS_LABEL[a.freshness.state]}
                          </Badge>
                        : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs">
                      {/* A2: an asset with no provider evidence must never display a provider name. */}
                      {a.sourceCount === 0
                        ? <span className="text-muted-foreground" title="This asset appears only because you searched for it. No provider reported it.">Search target — no provider evidence</span>
                        : <>{a.sources.map((s) => PROVIDER_LABEL[s]).join(", ")} <span className="text-muted-foreground">({a.sourceCount})</span></>}
                    </TableCell>
                    <TableCell className="tabular-nums">{a.services.length}</TableCell>
                    <TableCell className="whitespace-nowrap tabular-nums">
                      {/* A CVE COUNT on its own is misleading: 25 product-name
                          leads and 1 confirmed hit look identical. The strongest
                          evidence backing any of them is shown alongside. */}
                      {a.vulnerabilities.length ? (
                        <span className="flex items-center gap-1.5">
                          {a.vulnerabilities.length}
                          {(() => {
                            const tier = strongestTier(a.vulnerabilities)
                            const ui = tier ? EVIDENCE_BADGE[tier] : null
                            return ui ? <Badge className={cn("text-[10px]", ui.cls)} title={ui.hint}>{ui.label}</Badge> : null
                          })()}
                        </span>
                      ) : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="max-w-[180px] truncate text-xs text-muted-foreground">{a.organization ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{a.country ?? "—"}</TableCell>
                    <TableCell>
                      {a.threat?.classification === "malicious" ? <Badge className="bg-red-600 text-white">malicious</Badge>
                        : a.threat?.noise ? <Badge className="bg-amber-500 text-black">scanning</Badge>
                        : a.threat?.classification === "benign" ? <Badge variant="secondary">benign</Badge>
                        : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell><span className="text-muted-foreground">›</span></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : tab === "services" ? (
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow><TableHead>Asset</TableHead><TableHead>Port</TableHead><TableHead>Protocol</TableHead><TableHead>Product</TableHead><TableHead>Version</TableHead><TableHead>HTTP</TableHead><TableHead>Sources</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {allServices.length === 0 ? (
                  <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">No services observed.</TableCell></TableRow>
                ) : allServices.map(({ asset, service }, i) => (
                  <TableRow key={`${asset.id}-${service.port}-${i}`} className="cursor-pointer" onClick={() => openAsset(asset)}>
                    <TableCell className="whitespace-nowrap font-mono text-xs">{asset.ip ?? asset.domain}</TableCell>
                    <TableCell className="font-mono">{service.port}/{service.transport ?? "tcp"}</TableCell>
                    <TableCell>{service.protocol ?? "—"}</TableCell>
                    <TableCell>{service.product ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{service.version ?? "—"}</TableCell>
                    <TableCell className="max-w-[240px] truncate text-xs text-muted-foreground">{service.httpStatus ? `${service.httpStatus} ` : ""}{service.httpTitle ?? service.httpServer ?? "—"}</TableCell>
                    <TableCell className="text-xs">{service.sources.map((s) => PROVIDER_LABEL[s]).join(", ")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : tab === "vulnerabilities" ? (
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow><TableHead>CVE</TableHead><TableHead>Asset</TableHead><TableHead>Provider score</TableHead><TableHead>Match quality</TableHead><TableHead>Exposure risk</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {allVulns.length === 0 ? (
                  <TableRow><TableCell colSpan={5} className="py-10 text-center text-muted-foreground">No vulnerabilities correlated to these assets.</TableCell></TableRow>
                ) : allVulns.map((v, i) => (
                  <TableRow key={`${v.cveId}-${i}`} className="cursor-pointer" onClick={() => openAsset(v.asset)}>
                    <TableCell className="font-mono text-xs">{v.cveId}</TableCell>
                    <TableCell className="font-mono text-xs">{v.asset.ip ?? v.asset.domain}</TableCell>
                    <TableCell>{v.score ?? "—"}</TableCell>
                    <TableCell><Badge variant={v.matchType === "version" ? "default" : "outline"}>{v.matchType === "version" ? "Version confirmed" : v.matchType === "product" ? "Product name only" : v.matchType ?? "unknown"}</Badge></TableCell>
                    <TableCell>{v.asset.exposureRisk && v.asset.exposureRisk.score > 0 ? <Badge className={cn("border", TONE_CLASS[v.asset.exposureRisk.severity])}>{v.asset.exposureRisk.score}</Badge> : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow><TableHead>Common name</TableHead><TableHead>Asset</TableHead><TableHead>Issuer</TableHead><TableHead>Valid to</TableHead><TableHead>SANs</TableHead><TableHead>Sources</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {allCerts.length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="py-10 text-center text-muted-foreground">No certificates observed.</TableCell></TableRow>
                ) : allCerts.map(({ asset, cert }, i) => (
                  <TableRow key={`${asset.id}-cert-${i}`} className="cursor-pointer" onClick={() => openAsset(asset)}>
                    <TableCell className="max-w-[220px] truncate text-xs">{cert.commonName ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{asset.ip ?? asset.domain}</TableCell>
                    <TableCell className="max-w-[180px] truncate text-xs text-muted-foreground">{cert.issuer ?? "—"}</TableCell>
                    <TableCell className="text-xs">
                      {cert.validTo ? new Date(cert.validTo).toLocaleDateString("en-US") : "—"}
                      {cert.expired === true && <Badge className="ml-2 bg-red-600 text-white">Expired</Badge>}
                    </TableCell>
                    <TableCell className="tabular-nums">{cert.sans.length}</TableCell>
                    <TableCell className="text-xs">{cert.sources.map((s) => PROVIDER_LABEL[s]).join(", ")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      </Card>
      )}

      {/* C5: server-side pagination — each button refetches one page. */}
      {tab === "assets" && (result?.totalAssets ?? 0) > 0 && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm">
          <span className="text-muted-foreground">
            <b className="text-foreground">{pageSafe * PAGE_SIZE + 1}–{Math.min(pageSafe * PAGE_SIZE + assets.length, result?.totalAssets ?? 0)}</b> of {result?.totalAssets ?? 0} assets
            {filtered.length !== assets.length && <span className="text-xs"> · {filtered.length} shown after filters (this page only)</span>}
            <span className="text-xs"> · page {pageSafe + 1}/{totalPages}</span>
          </span>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="outline" disabled={loading || pageSafe <= 0} onClick={() => goToPage(0)}>« First</Button>
            <Button size="sm" variant="outline" disabled={loading || pageSafe <= 0} onClick={() => goToPage(pageSafe - 1)}>‹ Previous</Button>
            <Button size="sm" variant="outline" disabled={loading || pageSafe >= totalPages - 1} onClick={() => goToPage(pageSafe + 1)}>Next ›</Button>
            <Button size="sm" variant="outline" disabled={loading || pageSafe >= totalPages - 1} onClick={() => goToPage(totalPages - 1)}>Last »</Button>
          </div>
        </div>
      )}

      <ExposureAssetDialog asset={selected} open={dialogOpen} onOpenChange={setDialogOpen} />
    </main>
  )
}
