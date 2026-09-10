"use client"

import { useEffect, useMemo, useState } from "react"
import { loadZeroDays } from "@/lib/data"
import { riskLevel, TONE_CLASS } from "@/lib/risk-engine"
import type { ZeroDay } from "@/lib/types"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"
import { ZeroDayDetailDialog } from "@/components/zero-day-detail-dialog"
import { NoDataYet, NoMatches } from "@/components/empty-state"

const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" }
const KIND_LABEL: Record<string, string> = { reserved: "Reserved", prepub_exploited: "Exploited pre-publication", advisory: "Advisory without CVE" }
const KIND_ICON: Record<string, string> = { reserved: "🕐", prepub_exploited: "🔥", advisory: "🧩" }
const EXPLOIT_COLOR: Record<string, string> = { "kev-confirmed": "bg-red-600 text-white", "source-reported": "bg-orange-500 text-white", "poc-published": "bg-amber-500 text-black", none: "bg-muted text-muted-foreground" }

function extractCvss(cvss: unknown): string {
  if (cvss == null) return "—"
  if (typeof cvss === "number") return String(cvss)
  if (typeof cvss === "object" && "score" in cvss) return String((cvss as { score: number }).score)
  return "—"
}

function rowKey(z: ZeroDay, idx: number): string {
  return `${z.id ?? "no-id"}|${z.source ?? "no-source"}|${z.kind ?? "no-kind"}|${idx}`
}

type Kind = "reserved" | "prepub_exploited" | "advisory" | "resolved"
type Preset = "all" | "exploited" | "advisory" | "resolved"

function RiskBadge({ score, onClick }: { score: number; onClick?: () => void }) {
  const info = riskLevel(score)
  return <Badge onClick={onClick} className={cn("cursor-pointer border", TONE_CLASS[info.tone])} title={`${info.level} — click for the explanation`}>{score}</Badge>
}

function ExploitBadge({ state }: { state: string | null }) {
  if (!state || state === "none") return <span className="text-muted-foreground">—</span>
  const label = state === "kev-confirmed" ? "KEV confirmed" : state === "source-reported" ? "Source-reported" : state === "poc-published" ? "PoC published" : state
  return <Badge className={EXPLOIT_COLOR[state] || "bg-muted text-muted-foreground"}>{label}</Badge>
}

export default function ZeroDaysPage() {
  const [items, setItems] = useState<ZeroDay[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const [preset, setPreset] = useState<Preset>("all")
  const [kindFilter, setKindFilter] = useState<Kind | "all">("all")
  // The Source dropdown had no state and no filter behind it: choosing a source
  // only reset pagination, so the control looked functional and changed nothing.
  const [sourceFilter, setSourceFilter] = useState<string>("")
  const [activeOnly, setActiveOnly] = useState(true)
  const [selected, setSelected] = useState<ZeroDay | null>(null)
  const [tab, setTab] = useState("overview")
  const [open, setOpen] = useState(false)
  const [page, setPage] = useState(0)
  const pageSize = 50
  const [auto, setAuto] = useState(true)
  const [lastSync, setLastSync] = useState<Date | null>(null)

  async function load(opts: { kind?: string; search?: string; active?: string } = {}, background = false) {
    if (background) setRefreshing(true); else setLoading(true)
    setError(null)
    try {
      const data = await loadZeroDays(opts)
      setItems(data); setLastSync(new Date())
    } catch (e) { setError((e as Error).message) }
    finally { setLoading(false); setRefreshing(false) }
  }

  // Runs once, deliberately. This is the initial fetch; every later change to
  // preset/activeOnly/search is applied client-side by the `filtered` memo, so
  // adding them here would re-hit the API on each keystroke for no new data.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load({ kind: preset === "resolved" ? "resolved" : activeOnly ? "true" : undefined, search: search.trim() || undefined }) }, [])
  useEffect(() => {
    if (!auto) return
    const id = setInterval(() => load({ kind: preset === "resolved" ? "resolved" : activeOnly ? "true" : undefined, search: search.trim() || undefined }, true), 60000)
    return () => clearInterval(id)
  }, [auto, search, preset, activeOnly])

  // See the dashboard: the clock must not be read during render, or the
  // server's HTML and the client's first paint disagree.
  const [nowMs, setNowMs] = useState<number | null>(null)
  useEffect(() => {
    setNowMs(Date.now())
    const id = setInterval(() => setNowMs(Date.now()), 30_000)
    return () => clearInterval(id)
  }, [])

  function ago(d: Date | null) {
    if (!d) return "—"
    if (nowMs === null) return "—"
    const s = Math.floor((nowMs - d.getTime()) / 1000)
    if (s < 60) return `${s}s ago`
    const m = Math.floor(s / 60)
    return m === 1 ? "1 min ago" : `${m} min ago`
  }

  function openItem(z: ZeroDay) { setSelected(z); setTab("overview"); setOpen(true) }

  const kpis = useMemo(() => {
    const stamps = items
      .map((z) => (z.firstSeenAt ? Date.parse(z.firstSeenAt) : NaN))
      .filter((t) => Number.isFinite(t))
    const newestAt = stamps.length ? new Date(Math.max(...stamps)) : null
    const days = newestAt && nowMs !== null ? Math.floor((nowMs - newestAt.getTime()) / 864e5) : null
    return {
      total: items.length,
      exploited: items.filter((z) => z.kind === "prepub_exploited").length,
      advisory: items.filter((z) => z.kind === "advisory").length,
      resolved: items.filter((z) => z.becameCve).length,
      newestAt,
      newestLabel: days === null ? "—" : days <= 0 ? "today" : days === 1 ? "1d" : `${days}d`,
    }
  }, [items, nowMs])

  const filtered = useMemo(() => items.filter((z) => {
    if (preset === "exploited" && z.kind !== "prepub_exploited") return false
    if (preset === "advisory" && z.kind !== "advisory") return false
    if (preset === "resolved" && !z.becameCve) return false
    if (activeOnly && z.becameCve) return false
    // Both dropdowns are now actually consulted. `kindFilter` was written by its
    // own onChange and read by nothing, so the Kind control was as inert as the
    // Source one.
    if (kindFilter !== "all") {
      if (kindFilter === "resolved") { if (!z.becameCve) return false }
      else if (z.kind !== kindFilter) return false
    }
    if (sourceFilter && z.source !== sourceFilter) return false
    return true
  }), [items, preset, activeOnly, kindFilter, sourceFilter])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const pageSafe = Math.min(page, totalPages - 1)
  const pageRows = filtered.slice(pageSafe * pageSize, (pageSafe + 1) * pageSize)

  function exportCsv() {
    const head = "ID,Kind,Source,Product,Exploit,CVSS,EPSS,Risk,Severity,First seen,Status\n"
    const rows = filtered.map((z) => `${z.id},${z.kind},${z.source},${z.product ?? "-"},${z.exploitState ?? "-"},${z.cvss ?? "-"},${z.epss != null ? (z.epss * 100).toFixed(1) + "%" : "-"},${z.riskScore},${z.severity},${z.firstSeenAt},${z.becameCve ? "Became CVE" : "Active"}`).join("\n")
    const blob = new Blob([head + rows], { type: "text/csv;charset=utf-8;" })
    const a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = `octupus_0day_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: "application/json;charset=utf-8;" })
    const a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = `octupus_0day_${new Date().toISOString().slice(0, 10)}.json`
    a.click()
  }

  const presets: { id: Preset; label: string }[] = [
    { id: "all", label: "All" }, { id: "exploited", label: "🔥 Exploited in the wild" },
    { id: "advisory", label: "🧩 No CVE" },
    { id: "resolved", label: "✅ Became CVE" },
  ]

  return (
    <main className="mx-auto max-w-[1700px] px-4 py-8">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:flex-wrap md:items-end md:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">0-Days · Pre-CVE Tracker</h1>
          <p className="text-sm text-muted-foreground sm:text-base">Reserved vulnerabilities · Exploited before publication · Advisories without a CVE — free, public, updated every 5 minutes.</p>
        </div>
        <form className="flex w-full flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center md:w-auto" onSubmit={(e) => { e.preventDefault(); load({ kind: preset === "resolved" ? "resolved" : activeOnly ? "true" : undefined, search: search.trim() || undefined }) }}>
          <Input placeholder="Search (title, CVE, GHSA, product)…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full min-w-0 sm:w-56" />
          <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap [&_button]:w-full sm:[&_button]:w-auto">
            <Button type="submit" disabled={refreshing}>{refreshing ? "…" : "Search"}</Button>
            <Button type="button" variant="outline" onClick={() => { setSearch(""); load({ kind: preset === "resolved" ? "resolved" : activeOnly ? "true" : undefined }) }}>Refresh</Button>
            <Button type="button" variant={auto ? "default" : "outline"} onClick={() => setAuto((a) => !a)} title="Auto-refresh every 60s">{auto ? "⏸ Auto" : "▶ Auto"}</Button>
          </div>
        </form>
      </div>

      <details className="group mb-4 rounded-lg border border-border bg-white/5 p-3 open:pb-4">
        <summary className="cursor-pointer text-sm font-medium text-foreground">❔ New here? What is a &ldquo;0-day&rdquo;?</summary>
        <div className="mt-3 space-y-2 text-sm leading-relaxed text-muted-foreground">
          <p>Every publicly known software flaw normally gets a <b>CVE number</b> (like <code>CVE-2026-12345</code>) the moment it&apos;s disclosed, so defenders know it exists and can patch it. A <b>0-day</b> is a flaw attackers found and started exploiting <i>before</i> that ever happened — there was zero days of warning.</p>
          <p>This page tracks two related situations: flaws confirmed exploited before their CVE was published (the real, urgent kind), and security advisories published without a CVE number at all. Reserved-but-undetailed CVE IDs are deliberately not tracked — NVD does not index them, and the source previously used for it was reporting years-old published CVEs as if they were fresh 0-days. Click any row to see a plain-language explanation of exactly what it means and whether you should worry about it.</p>
        </div>
      </details>

      <p className="mb-4 text-xs text-muted-foreground">Sources: CISA KEV (exploited before CVE publication) · GitHub Advisories (no CVE assigned) · Google Project Zero (in-the-wild 0-day tracker) · security news (BleepingComputer, The Hacker News) — see <a href="/sources" className="underline decoration-dotted hover:text-foreground">Data Sources &amp; Attribution</a></p>

      {/* Freshness bar */}
      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span className="font-medium text-foreground">Last sync: {lastSync ? lastSync.toLocaleTimeString("en-US") : "—"}</span>
        <span>· {ago(lastSync)}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5">Total {items.length}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5">🔥 {kpis.exploited}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5">🧩 {kpis.advisory}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5">✅ {kpis.resolved}</span>
        {refreshing && <span className="inline-flex items-center gap-1 rounded-full bg-cyan-500/15 px-2 py-0.5 text-cyan-300"><span className="h-1.5 w-1.5 animate-ping rounded-full bg-cyan-400" /> refreshing…</span>}
      </div>

      {/* KPIs */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Card className="glass glow-hover accent-top p-4">
          <div className="eyebrow">Total 0-day</div>
          <div className="mt-1 text-4xl font-bold neon-text">{kpis.total}</div>
        </Card>
        <Card className={cn("glass glow-hover accent-top p-4", kpis.exploited > 0 && "kev-pulse")}>
          <div className="eyebrow text-red-300">🔥 Exploited in the wild</div>
          <div className="mt-1 text-4xl font-bold text-red-400">{kpis.exploited}</div>
        </Card>
        <Card className="glass glow-hover accent-top p-4">
          <div className="eyebrow text-amber-300">🕐 Newest finding</div>
          <div className="mt-1 text-4xl font-bold text-amber-400">{kpis.newestLabel}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">
            {kpis.newestAt ? kpis.newestAt.toLocaleString() : "no dated findings"}
          </div>
        </Card>
        <Card className="glass glow-hover accent-top p-4">
          <div className="eyebrow text-cyan-300">🧩 GHSA advisories</div>
          <div className="mt-1 text-4xl font-bold text-cyan-400">{kpis.advisory}</div>
        </Card>
        <Card className="glass glow-hover accent-top p-4">
          <div className="eyebrow text-emerald-300">✅ Became CVE</div>
          <div className="mt-1 text-4xl font-bold text-emerald-400">{kpis.resolved}</div>
        </Card>
      </div>

      {/* Presets */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-sm text-muted-foreground">Quick filters:</span>
        {presets.map((p) => <Button key={p.id} size="sm" variant={preset === p.id ? "default" : "outline"} onClick={() => { setPreset(p.id); setPage(0) }} className="rounded-full">{p.label}</Button>)}
        <Button size="sm" variant={activeOnly ? "default" : "outline"} onClick={() => { setActiveOnly((a) => !a); setPage(0) }} className="rounded-full">{activeOnly ? "✅ Active only" : "📜 All (incl. resolved)"}</Button>
      </div>

      {/* Advanced filters */}
      <Card className="glass mb-4 p-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <label className="text-xs text-muted-foreground">Kind</label>
            <select value={kindFilter} onChange={(e) => { setKindFilter(e.target.value as Kind); setPage(0) }} className="mt-1 w-full rounded-md border border-border bg-background px-2 py-2 text-sm">
              <option value="all">All</option>
              <option value="prepub_exploited">Exploited pre-publication</option>
              <option value="advisory">Advisory without CVE</option>
              <option value="resolved">Became CVE</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Source</label>
            <select value={sourceFilter} onChange={(e) => { setSourceFilter(e.target.value); setPage(0) }} className="mt-1 w-full rounded-md border border-border bg-background px-2 py-2 text-sm">
              <option value="">All</option>
              <option value="kev">CISA KEV (pre-publication)</option>
              <option value="github">GitHub Advisories</option>
              <option value="p0">Google Project Zero</option>
              <option value="news">Security news</option>
            </select>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-6">
          <div className="ml-auto flex gap-2">
            <Button variant="outline" size="sm" onClick={exportCsv}>⬇ CSV</Button>
            <Button variant="outline" size="sm" onClick={exportJson}>⬇ JSON</Button>
          </div>
        </div>
      </Card>

      {error && <Card className="mb-4 border-red-500/50 bg-red-500/10 p-3 text-sm">⚠️ {error} — Try again in 1 min.</Card>}

      {/* Table */}
      <Card className="glass overflow-hidden">
        <div className="max-h-[70vh] overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-card">
              <TableRow>
                <TableHead>ID</TableHead><TableHead>Kind</TableHead><TableHead>Source</TableHead>
                <TableHead>Product</TableHead><TableHead>Exploitation</TableHead>
                <TableHead>CVSS</TableHead><TableHead>EPSS</TableHead>
                <TableHead>Risk</TableHead><TableHead>Severity</TableHead>
                <TableHead>First seen</TableHead><TableHead>Status</TableHead><TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow><TableCell colSpan={12} className="py-10 text-center text-muted-foreground">Loading 0-days…</TableCell></TableRow>
              ) : filtered.length === 0 ? (
                items.length === 0
                  ? <NoDataYet what="0-day intelligence" syncPath="/api/cron/zero-days" colSpan={12} />
                  : <NoMatches what="0-day" colSpan={12} />
              ) : pageRows.map((z, idx) => (
                <TableRow key={rowKey(z, idx)} className="cursor-pointer" onClick={() => openItem(z)}>
                  <TableCell className="whitespace-nowrap font-mono text-xs">{z.id}</TableCell>
                  <TableCell><Badge variant="secondary" className="mr-1">{KIND_ICON[z.kind]} {KIND_LABEL[z.kind]}</Badge></TableCell>
                  <TableCell><Badge variant="outline" className="text-[10px]">{z.source}</Badge></TableCell>
                  <TableCell className="max-w-[180px] truncate text-sm text-muted-foreground">{z.product ?? "—"}</TableCell>
                  <TableCell><ExploitBadge state={z.exploitState} /></TableCell>
                  <TableCell>{extractCvss(z.cvss)}</TableCell>
                  <TableCell>{z.epss != null ? (z.epss * 100).toFixed(1) + "%" : "—"}</TableCell>
                  <TableCell onClick={(e) => { e.stopPropagation(); openItem(z) }}><RiskBadge score={z.riskScore} /></TableCell>
                  <TableCell><Badge className={cn("border", TONE_CLASS[z.severity as keyof typeof TONE_CLASS] || "border-border")}>{SEV_LABEL[z.severity] || z.severity}</Badge></TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{z.firstSeenAt ? new Date(z.firstSeenAt).toLocaleDateString("en-US") : "—"}</TableCell>
                  <TableCell className="whitespace-nowrap">{z.becameCve ? <Badge variant="secondary" className="text-emerald-400 border-emerald-500/40">✅ Became CVE</Badge> : <Badge variant="outline">🟢 Active</Badge>}</TableCell>
                  <TableCell><span className="text-muted-foreground">›</span></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </Card>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm">
        <span className="text-muted-foreground"><b className="text-foreground">{filtered.length}</b> 0-day · page {pageSafe + 1}/{totalPages} <span className="text-xs">(50/page)</span></span>
        <div className="flex items-center gap-1">
          <Button size="sm" variant="outline" disabled={pageSafe <= 0} onClick={() => setPage(0)}>« First</Button>
          <Button size="sm" variant="outline" disabled={pageSafe <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>‹ Previous</Button>
          <Button size="sm" variant="outline" disabled={pageSafe >= totalPages - 1} onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}>Next ›</Button>
          <Button size="sm" variant="outline" disabled={pageSafe >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>Last »</Button>
        </div>
      </div>

      <ZeroDayDetailDialog item={selected} open={open} onOpenChange={setOpen} initialTab={tab} onTabChange={setTab} />
    </main>
  )
}