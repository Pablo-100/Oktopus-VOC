"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { loadCves } from "@/lib/data"
import { riskLevel, TONE_CLASS } from "@/lib/risk-engine"
import type { Vuln, RiskTone } from "@/lib/types"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"
import { threatFor } from "@/lib/threat"
import { CveDetailDialog } from "@/components/cve-detail-dialog"
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, PieChart, Pie, Cell, Legend, LabelList,
} from "recharts"

const TG_AUTO_KEY = "octopus.tgAuto"   // alertes Telegram auto activées ? (préférence UI locale)

function tgContext(v: Vuln) {
  const t = threatFor(v)
  const advisory = v.references.find((r) => r.tags.includes("Vendor Advisory") || r.tags.includes("Patch"))?.url ?? null
  return {
    cve_id: v.cveId, severity: v.severity, risk_score: v.riskScore, risk_level: v.riskLevel,
    cvss: v.cvssV3 !== "-" ? v.cvssV3 : v.cvssV2,
    epss: v.epss != null ? (v.epss * 100).toFixed(1) + "%" : null,
    kev: v.isKev, exploit: v.hasExploit, cwe: v.cwes,
    capec: t.capec.map(([id]) => id), attack: t.attack.map(([id]) => id),
    description: v.description, advisory,
  }
}

const AXIS = "#93a1bd"
const IMPACT = [{ label: "Aucun", color: "#475569" }, { label: "Faible", color: "#eab308" }, { label: "Élevé", color: "#e11d48" }]
const SEV_LABEL: Record<string, string> = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" }
const SEV_COLORS: Record<string, string> = { critical: "#e11d48", high: "#f97316", medium: "#eab308", low: "#22c55e" }
const TTD = {
  contentStyle: { background: "rgba(11,16,34,0.95)", border: "1px solid rgba(139,92,246,0.45)", borderRadius: "10px", color: "#e7ecf5" },
  labelStyle: { color: "#c4b5fd", fontWeight: 600 }, itemStyle: { color: "#e7ecf5" }, cursor: { fill: "rgba(139,92,246,0.08)" },
}

type Preset = "all" | "critical" | "kev" | "exploit" | "high-risk" | "parc"

const TRIAGE: Record<string, string> = {
  new: "Nouveau", in_progress: "En cours", resolved: "Traité", false_positive: "Faux positif", accepted: "Risque accepté",
}

function RiskBadge({ score, onClick }: { score: number | null; onClick?: () => void }) {
  if (score == null) return <span className="text-muted-foreground">—</span>
  const info = riskLevel(score)
  return <Badge onClick={onClick} className={cn("cursor-pointer border", TONE_CLASS[info.tone])} title={`${info.level} — cliquer pour l'explication`}>{score}</Badge>
}

function toneOf(score: number | null): RiskTone | null {
  if (score == null) return null
  if (score >= 75) return "critical"; if (score >= 50) return "high"; if (score >= 25) return "medium"; return "low"
}

export default function DashboardPage() {
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [loading, setLoading] = useState(true)      // 1er chargement uniquement
  const [refreshing, setRefreshing] = useState(false) // refresh en arrière-plan
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const [preset, setPreset] = useState<Preset>("all")
  const [tone, setTone] = useState<RiskTone | null>(null)
  const [selected, setSelected] = useState<Vuln | null>(null)
  const [tab, setTab] = useState("ov")
  const [open, setOpen] = useState(false)
  // Filtres avancés
  const [riskMin, setRiskMin] = useState(0)
  const [sev, setSev] = useState("all")
  const [vec, setVec] = useState("all")
  const [cwe, setCwe] = useState("")
  const [kevOnly, setKevOnly] = useState(false)
  const [exploitOnly, setExploitOnly] = useState(false)
  // Pagination
  const [page, setPage] = useState(0)
  const pageSize = 50
  // Auto-refresh + fraîcheur (activé par défaut)
  const [auto, setAuto] = useState(true)
  const [lastSync, setLastSync] = useState<Date | null>(null)
  const [, tick] = useState(0)
  // Alertes Telegram automatiques (High/Critical, dé-doublonnées)
  const [tgAuto, setTgAuto] = useState(false)
  const [tgInfo, setTgInfo] = useState<string>("")
  useEffect(() => { setTgAuto(localStorage.getItem(TG_AUTO_KEY) === "1") }, [])
  function toggleTgAuto() {
    setTgAuto((prev) => { const next = !prev; localStorage.setItem(TG_AUTO_KEY, next ? "1" : "0"); return next })
  }

  // Envoie au bot les nouvelles CVE High/Critical — dédup PARTAGÉ côté serveur (base)
  async function autoSendTelegram(list: Vuln[]) {
    if (localStorage.getItem(TG_AUTO_KEY) !== "1") return
    let sentSet = new Set<string>()
    try { const r = await fetch("/api/telegram"); if (r.ok) { const d = await r.json(); sentSet = new Set<string>(d.sent || []) } } catch { /* ignore */ }
    const candidates = list
      .filter((v) => (v.severity === "critical" || v.severity === "high") && !sentSet.has(v.cveId))
      .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
      .slice(0, 20)
    if (!candidates.length) return // aucune nouvelle -> aucun envoi
    let ok = 0
    for (const v of candidates) {
      try {
        const r = await fetch("/api/telegram", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ context: tgContext(v) }) })
        const d = await r.json().catch(() => ({}))
        if (r.ok && !d.skipped) { ok++; await new Promise((res) => setTimeout(res, 1200)) }
      } catch { /* ignore */ }
    }
    if (ok) setTgInfo(`📤 ${ok} nouvelle(s) alerte(s) envoyée(s)`)
  }
  // Triage PARTAGÉ (base Neon) — plus de localStorage, tous les analystes voient le même état
  const [triage, setTriage] = useState<Record<string, string>>({})
  useEffect(() => {
    fetch("/api/triage").then((r) => r.json()).then((d) => {
      const m: Record<string, string> = {}
      for (const [k, v] of Object.entries(d.triage || {})) m[k] = (v as { status: string }).status
      setTriage(m)
    }).catch(() => { /* base indisponible -> triage vide */ })
  }, [])
  function setStatus(cve: string, status: string) {
    setTriage((prev) => { const next = { ...prev }; if (!status || status === "new") delete next[cve]; else next[cve] = status; return next })
    fetch("/api/triage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cve_id: cve, status }) }).catch(() => { /* ignore */ })
  }

  // Inventaire d'actifs (Neon) -> risque contextualisé « Mon parc »
  const [assets, setAssets] = useState<{ vendor?: string; product?: string }[]>([])
  const loadAssets = useCallback(() => {
    fetch("/api/assets").then((r) => r.json()).then((d) => setAssets(d.assets || [])).catch(() => { /* ignore */ })
  }, [])
  useEffect(() => {
    loadAssets()
    // Re-synchronise les actifs quand on revient sur l'onglet/fenêtre (après édition sur /assets)
    const onFocus = () => loadAssets()
    const onVisible = () => { if (document.visibilityState === "visible") loadAssets() }
    window.addEventListener("focus", onFocus)
    document.addEventListener("visibilitychange", onVisible)
    return () => { window.removeEventListener("focus", onFocus); document.removeEventListener("visibilitychange", onVisible) }
  }, [loadAssets])
  const watchVendors = useMemo(() => new Set(assets.map((a) => (a.vendor || "").toLowerCase()).filter(Boolean)), [assets])
  const watchProducts = useMemo(() => new Set(assets.map((a) => (a.product || "").toLowerCase()).filter(Boolean)), [assets])
  function inParc(v: Vuln) {
    return v.vendors.some((x) => watchVendors.has(x.toLowerCase())) || v.products.some((x) => watchProducts.has(x.toLowerCase()))
  }

  // background = true -> NE PAS vider le tableau (refresh en arrière-plan, l'utilisateur garde sa place)
  async function load(keyword = "", background = false) {
    if (background) setRefreshing(true); else setLoading(true)
    setError(null)
    try {
      const data = await loadCves(keyword)
      setVulns(data); setLastSync(new Date())
      autoSendTelegram(data) // envoi auto au bot (si activé)
    }
    catch (e) { setError((e as Error).message) } // en cas d'échec : on garde les anciennes données
    finally { setLoading(false); setRefreshing(false) }
  }
  useEffect(() => { load() }, []) // 1er chargement seulement -> écran de chargement
  // Boucle 60s si auto-refresh OU alertes Telegram auto sont activés (toujours en arrière-plan)
  useEffect(() => {
    if (!auto && !tgAuto) return
    const id = setInterval(() => { load(search.trim(), true); loadAssets() }, 60000)
    return () => clearInterval(id)
  }, [auto, tgAuto, search, loadAssets])
  useEffect(() => {
    const id = setInterval(() => tick((t) => t + 1), 1000) // décompte vivant
    return () => clearInterval(id)
  }, [])
  function ago(d: Date | null) {
    if (!d) return "—"
    const s = Math.floor((Date.now() - d.getTime()) / 1000)
    if (s < 60) return `il y a ${s}s`
    const m = Math.floor(s / 60)
    return m === 1 ? "il y a 1 min" : `il y a ${m} min`
  }

  function openCve(cveOrVuln: string | Vuln, initialTab = "ov") {
    const v = typeof cveOrVuln === "string" ? vulns.find((x) => x.cveId === cveOrVuln) ?? null : cveOrVuln
    if (v) { setSelected(v); setTab(initialTab); setOpen(true) }
  }

  const kpis = useMemo(() => ({
    total: vulns.length,
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    kev: vulns.filter((v) => v.isKev).length,
  }), [vulns])

  const heat = useMemo(() => {
    const b = { critical: 0, high: 0, medium: 0, low: 0 } as Record<RiskTone, number>
    vulns.forEach((v) => { const t = toneOf(v.riskScore); if (t) b[t]++ })
    return b
  }, [vulns])

  const top10 = useMemo(() => [...vulns].filter((v) => v.riskScore != null).sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0)).slice(0, 10), [vulns])

  const feed = useMemo(() => {
    const ev: { icon: string; text: string; cve: string; d: number }[] = []
    vulns.forEach((v) => {
      const d = v.sortDate?.getTime() ?? 0
      if (v.isKev) ev.push({ icon: "🚨", text: `${v.cveId} ajouté au CISA KEV`, cve: v.cveId, d })
      else if (v.hasExploit) ev.push({ icon: "💥", text: `Exploit public pour ${v.cveId}`, cve: v.cveId, d })
      else if (v.severity === "critical") ev.push({ icon: "🔥", text: `CVE critique ${v.cveId} (Risk ${v.riskScore ?? "-"})`, cve: v.cveId, d })
    })
    return ev.sort((a, b) => b.d - a.d).slice(0, 15)
  }, [vulns])

  const insights = useMemo(() => {
    const cvss = Array.from({ length: 10 }, (_, i) => ({ band: `${i}-${i + 1}`, n: 0 }))
    const sc = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>
    const imp = (k: "impactC" | "impactI" | "impactA") => {
      const o = { NONE: 0, LOW: 0, HIGH: 0 } as Record<string, number>
      vulns.forEach((v) => { const x = v[k]; if (x in o) o[x]++ })
      return [{ name: "Aucun", value: o.NONE }, { name: "Faible", value: o.LOW }, { name: "Élevé", value: o.HIGH }]
    }
    vulns.forEach((v) => {
      const s = v.cvssV3 !== "-" ? Number(v.cvssV3) : v.cvssV2 !== "-" ? Number(v.cvssV2) : 0
      if (s) cvss[Math.min(Math.floor(s), 9)].n++
      sc[v.severity]++
    })
    return {
      cvss,
      sev: [{ name: "critical", value: sc.critical }, { name: "high", value: sc.high }, { name: "medium", value: sc.medium }, { name: "low", value: sc.low }],
      impC: imp("impactC"), impI: imp("impactI"), impA: imp("impactA"),
    }
  }, [vulns])

  const cweNum = cwe.replace(/\D/g, "")
  const filtered = useMemo(() => vulns.filter((v) => {
    if (preset === "critical" && v.severity !== "critical") return false
    if (preset === "kev" && !v.isKev) return false
    if (preset === "exploit" && !v.hasExploit) return false
    if (preset === "high-risk" && (v.riskScore ?? 0) < 70) return false
    if (preset === "parc" && !inParc(v)) return false
    if (tone && toneOf(v.riskScore) !== tone) return false
    if (sev !== "all" && v.severity !== sev) return false
    if (vec !== "all" && (v.attackVector || "").toUpperCase() !== vec) return false
    if (kevOnly && !v.isKev) return false
    if (exploitOnly && !v.hasExploit) return false
    if (riskMin > 0 && (v.riskScore ?? 0) < riskMin) return false
    if (cweNum && !v.cwes.some((c) => c.replace(/\D/g, "") === cweNum)) return false
    return true
  }), [vulns, preset, tone, sev, vec, kevOnly, exploitOnly, riskMin, cweNum])

  // Pagination : on remet en page 1 quand un filtre change
  useEffect(() => { setPage(0) }, [preset, tone, sev, vec, cwe, kevOnly, exploitOnly, riskMin])
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const pageSafe = Math.min(page, totalPages - 1)
  const pageRows = filtered.slice(pageSafe * pageSize, (pageSafe + 1) * pageSize)

  function exportCsv() {
    const head = "CVE,CVSS,EPSS,KEV,Risk,Severite,CWE,Vecteur,Date,Statut\n"
    const rows = filtered.map((v) => {
      const epss = v.epss != null ? (v.epss * 100).toFixed(1) + "%" : "-"
      const cvss = v.cvssV3 !== "-" ? v.cvssV3 : v.cvssV2
      const st = TRIAGE[triage[v.cveId]] || "Nouveau"
      return `${v.cveId},${cvss},${epss},${v.isKev ? "YES" : "no"},${v.riskScore ?? "-"},${v.severity},${v.cwes.join(" | ") || "-"},${v.attackVector},${v.publishedDate},${st}`
    }).join("\n")
    const blob = new Blob([head + rows], { type: "text/csv;charset=utf-8;" })
    const a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = `octupus_cve_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: "application/json;charset=utf-8;" })
    const a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = `octupus_cve_${new Date().toISOString().slice(0, 10)}.json`
    a.click()
  }

  const presets: { id: Preset; label: string }[] = [
    { id: "all", label: "Tout" }, { id: "critical", label: "🔥 Critiques" },
    { id: "kev", label: "🔴 KEV" }, { id: "exploit", label: "💥 Exploit" }, { id: "high-risk", label: "⚡ Risque ≥ 70" },
    { id: "parc", label: "⭐ Mon parc" },
  ]

  // Métriques VOC
  const triageStats = useMemo(() => {
    const s = { in_progress: 0, resolved: 0 } as Record<string, number>
    Object.values(triage).forEach((st) => { if (s[st] != null) s[st]++ })
    return s
  }, [triage])
  const slaOverdue = useMemo(() => {
    const map: Record<string, number> = { critical: 1, high: 3, medium: 7, low: 30 }
    return vulns.filter((v) => {
      const st = triage[v.cveId] || "new"
      if (["resolved", "accepted", "false_positive"].includes(st)) return false
      if (!v.sortDate) return false
      const days = v.isKev ? 1 : (map[v.severity] ?? 30)
      return Date.now() > v.sortDate.getTime() + days * 86400000
    }).length
  }, [vulns, triage])
  const tiles: { tone: RiskTone; label: string; range: string }[] = [
    { tone: "critical", label: "Critique", range: "75-100" }, { tone: "high", label: "Élevé", range: "50-74" },
    { tone: "medium", label: "Moyen", range: "25-49" }, { tone: "low", label: "Faible", range: "0-24" },
  ]

  return (
    <main className="mx-auto max-w-[1700px] px-4 py-8">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:flex-wrap md:items-end md:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">CVE Dashboard</h1>
          <p className="text-sm text-muted-foreground sm:text-base">Priorisation par le risque réel (RBVM · CVSS · EPSS · KEV)</p>
        </div>
        <form className="flex w-full flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center md:w-auto" onSubmit={(e) => { e.preventDefault(); load(search.trim(), true) }}>
          <Input placeholder="Rechercher (ex. apache)…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full min-w-0 sm:w-56" />
          <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap [&_button]:w-full sm:[&_button]:w-auto">
            <Button type="submit" disabled={refreshing}>{refreshing ? "…" : "Rechercher"}</Button>
            <Button type="button" variant="outline" onClick={() => { setSearch(""); load("", true) }}>Actualiser</Button>
            <Button type="button" variant={auto ? "default" : "outline"} onClick={() => setAuto((a) => !a)} title="Auto-actualisation 60s">{auto ? "⏸ Auto" : "▶ Auto"}</Button>
            <Button type="button" variant={tgAuto ? "default" : "outline"} onClick={toggleTgAuto} title="Envoi auto des CVE High/Critical au bot Telegram (toutes les 60s)">
              {tgAuto ? "🔔 Telegram ON" : "🔕 Telegram OFF"}
            </Button>
          </div>
        </form>
      </div>
      {tgAuto && <p className="mb-3 text-xs text-cyan-400">🔔 Alertes Telegram auto activées — les nouvelles CVE High/Critical partent au bot toutes les 60s (max 20/cycle, sans doublon). {tgInfo}</p>}

      {/* Barre de fraîcheur */}
      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span className="font-medium text-foreground">Dernière synchro : {lastSync ? lastSync.toLocaleTimeString("fr-FR") : "—"}</span>
        <span>· {ago(lastSync)}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5">✅ NVD {vulns.length}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5">EPSS {vulns.filter((v) => v.epss != null).length}</span>
        <span className="rounded-full bg-white/5 px-2 py-0.5">🔴 KEV {kpis.kev}</span>
        {refreshing && <span className="inline-flex items-center gap-1 rounded-full bg-cyan-500/15 px-2 py-0.5 text-cyan-300"><span className="h-1.5 w-1.5 animate-ping rounded-full bg-cyan-400" /> actualisation en arrière-plan…</span>}
      </div>

      {/* Métriques VOC (base Neon) */}
      <div className="mb-5 flex flex-wrap gap-2 text-xs">
        <span className="rounded-full border border-border bg-white/5 px-3 py-1">🗂 En cours : <b>{triageStats.in_progress}</b></span>
        <span className="rounded-full border border-border bg-white/5 px-3 py-1">✅ Traité : <b>{triageStats.resolved}</b></span>
        <span className={cn("rounded-full border px-3 py-1", slaOverdue > 0 ? "border-red-500/40 bg-red-500/15 text-red-300" : "border-border bg-white/5")}>⏰ SLA dépassé : <b>{slaOverdue}</b></span>
        <a href="/assets" className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-cyan-300 hover:bg-cyan-500/20">⭐ Actifs surveillés : <b>{assets.length}</b> · gérer →</a>
      </div>

      {/* KPIs */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Card className="glass glow-hover accent-top p-4">
          <div className="eyebrow">Total CVE</div>
          <div className="mt-1 text-4xl font-bold neon-text">{kpis.total}</div>
        </Card>
        <Card className="glass glow-hover accent-top p-4">
          <div className="eyebrow text-muted-foreground">Critiques</div>
          <div className="mt-1 text-4xl font-bold text-foreground">{kpis.critical}</div>
        </Card>
        <Card className="glass glow-hover accent-top p-4">
          <div className="eyebrow text-red-300">Élevées</div>
          <div className="mt-1 text-4xl font-bold text-red-400">{kpis.high}</div>
        </Card>
        <Card className={cn("glass glow-hover accent-top p-4", kpis.kev > 0 && "kev-pulse")}>
          <div className="eyebrow text-red-300">🔴 KEV actifs</div>
          <div className="mt-1 text-4xl font-bold text-red-400">{kpis.kev}</div>
        </Card>
      </div>

      {/* Heatmap + Top10 + Feed */}
      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <Card className="glass p-4 lg:col-span-1">
          <h3 className="mb-3 font-semibold">Heatmap de risque</h3>
          <div className="grid grid-cols-2 gap-2">
            {tiles.map((t) => (
              <button key={t.tone} onClick={() => setTone(tone === t.tone ? null : t.tone)} className={cn("rounded-xl border p-3 text-left transition", TONE_CLASS[t.tone], tone === t.tone && "ring-2 ring-white")}>
                <div className="text-sm font-semibold">{t.label}</div>
                <div className="text-2xl font-bold">{heat[t.tone]}</div>
                <div className="text-xs opacity-80">{t.range}</div>
              </button>
            ))}
          </div>
        </Card>
        <Card className="glass p-4">
          <h3 className="mb-3 font-semibold">🏆 Top 10 à traiter</h3>
          <ol className="space-y-1 text-sm">
            {top10.map((v) => { const info = riskLevel(v.riskScore); return (
              <li key={v.cveId}><button onClick={() => openCve(v)} className="flex w-full items-center justify-between rounded px-1 py-0.5 hover:bg-accent">
                <span className="font-mono text-xs">{v.cveId}{v.isKev && " 🔴"}</span><Badge className={cn("border", TONE_CLASS[info.tone])}>{v.riskScore}</Badge>
              </button></li>) })}
            {!top10.length && <li className="text-muted-foreground">—</li>}
          </ol>
        </Card>
        <Card className="glass p-4">
          <h3 className="mb-3 font-semibold">📡 Threat Feed</h3>
          <ul className="space-y-1 text-sm">
            {feed.map((e, i) => <li key={i}><button onClick={() => openCve(e.cve)} className="flex w-full gap-2 rounded px-1 py-0.5 text-left hover:bg-accent"><span>{e.icon}</span><span className="truncate">{e.text}</span></button></li>)}
            {!feed.length && <li className="text-muted-foreground">Aucun événement notable.</li>}
          </ul>
        </Card>
      </div>

      {/* Insights visuels */}
      <Card className="glass mb-6 p-5">
        <h3 className="font-semibold">Insights visuels</h3>
        <p className="mb-4 text-xs text-muted-foreground">Vue d&apos;ensemble du lot chargé — valeurs affichées, détail au survol.</p>
        <div className="grid gap-6 lg:grid-cols-2">
          <div>
            <p className="mb-1 text-sm font-medium">Distribution des scores CVSS</p>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={insights.cvss} margin={{ top: 18, right: 10, left: -12, bottom: 0 }}>
                  <CartesianGrid stroke="rgba(148,163,184,0.15)" vertical={false} />
                  <XAxis dataKey="band" fontSize={11} stroke={AXIS} tickLine={false} />
                  <YAxis allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
                  <Tooltip {...TTD} />
                  <Bar dataKey="n" fill="#8b5cf6" radius={[4, 4, 0, 0]}><LabelList dataKey="n" position="top" fontSize={10} fill={AXIS} /></Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div>
            <p className="mb-1 text-sm font-medium">Répartition par sévérité</p>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={insights.sev.map((e) => ({ name: SEV_LABEL[e.name], value: e.value, k: e.name }))} dataKey="value" nameKey="name" innerRadius={58} outerRadius={100} paddingAngle={2}
                       label={({ percent }) => ((percent ?? 0) > 0.03 ? `${((percent ?? 0) * 100).toFixed(0)}%` : "")} labelLine={false}>
                    {insights.sev.map((e) => <Cell key={e.name} fill={SEV_COLORS[e.name]} stroke="rgba(0,0,0,0.25)" />)}
                  </Pie>
                  <Legend wrapperStyle={{ fontSize: 12, color: AXIS }} />
                  <Tooltip {...TTD} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <p className="mb-1 mt-4 text-sm font-medium">Types d&apos;impact</p>
        <p className="mb-2 text-xs text-muted-foreground">Répartition Aucun / Faible / Élevé pour chaque dimension (CVSS)</p>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {[{ t: "Confidentialité", d: insights.impC }, { t: "Intégrité", d: insights.impI }, { t: "Disponibilité", d: insights.impA }].map((im) => (
            <div key={im.t} className="text-center">
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={im.d} dataKey="value" nameKey="name" innerRadius={38} outerRadius={68} paddingAngle={2}>
                      {im.d.map((e, i) => <Cell key={i} fill={IMPACT[i].color} stroke="rgba(0,0,0,0.25)" />)}
                    </Pie>
                    <Tooltip {...TTD} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <p className="text-sm font-medium">{im.t}</p>
            </div>
          ))}
        </div>
        <div className="mt-2 flex justify-center gap-4 text-xs text-muted-foreground">
          {IMPACT.map((x) => <span key={x.label} className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full" style={{ background: x.color }} /> {x.label}</span>)}
        </div>
      </Card>

      {/* Presets */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-sm text-muted-foreground">Filtres rapides :</span>
        {presets.map((p) => <Button key={p.id} size="sm" variant={preset === p.id ? "default" : "outline"} onClick={() => setPreset(p.id)} className="rounded-full">{p.label}</Button>)}
        {tone && <Button size="sm" variant="ghost" onClick={() => setTone(null)}>✖ risque: {tone}</Button>}
      </div>

      {/* Filtres avancés */}
      <Card className="glass mb-4 p-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <Label className="text-xs text-muted-foreground">Risk Score min : <span className="text-foreground">{riskMin}</span></Label>
            <input type="range" min={0} max={100} step={5} value={riskMin} onChange={(e) => setRiskMin(+e.target.value)} className="mt-2 w-full accent-violet-500" />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground">Sévérité</Label>
            <select value={sev} onChange={(e) => setSev(e.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-2 py-2 text-sm">
              <option value="all">Toutes</option><option value="critical">Critique</option><option value="high">Élevée</option><option value="medium">Moyenne</option><option value="low">Faible</option>
            </select>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground">Vecteur d&apos;attaque</Label>
            <select value={vec} onChange={(e) => setVec(e.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-2 py-2 text-sm">
              <option value="all">Tous</option><option value="NETWORK">Réseau</option><option value="ADJACENT_NETWORK">Adjacent</option><option value="LOCAL">Local</option><option value="PHYSICAL">Physique</option>
            </select>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground">CWE (n°)</Label>
            <Input value={cwe} onChange={(e) => setCwe(e.target.value)} placeholder="79, 89, 22…" className="mt-1" />
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-6">
          <div className="flex items-center gap-2"><Switch id="kevOnly" checked={kevOnly} onCheckedChange={setKevOnly} /><Label htmlFor="kevOnly">🔴 KEV uniquement</Label></div>
          <div className="flex items-center gap-2"><Switch id="expOnly" checked={exploitOnly} onCheckedChange={setExploitOnly} /><Label htmlFor="expOnly">💥 Exploit connu</Label></div>
          <div className="ml-auto flex gap-2">
            <Button variant="outline" size="sm" onClick={exportCsv}>⬇ CSV</Button>
            <Button variant="outline" size="sm" onClick={exportJson}>⬇ JSON</Button>
          </div>
        </div>
      </Card>

      {error && <Card className="mb-4 border-red-500/50 bg-red-500/10 p-3 text-sm">⚠️ {error} — NVD limite parfois (5/30s sans clé). Réessaie dans 1 min.</Card>}

      {/* Table */}
      <Card className="glass overflow-hidden">
        <div className="max-h-[70vh] overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-card">
              <TableRow>
                <TableHead>CVE ID</TableHead><TableHead>Description</TableHead><TableHead>CVSS</TableHead>
                <TableHead>EPSS</TableHead><TableHead>KEV</TableHead><TableHead>Risk</TableHead><TableHead>Sévérité</TableHead>
                <TableHead>CWE</TableHead><TableHead>Vecteur</TableHead><TableHead>Complexité</TableHead>
                <TableHead>Date</TableHead><TableHead>Statut</TableHead><TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow><TableCell colSpan={13} className="py-10 text-center text-muted-foreground">Chargement des CVE…</TableCell></TableRow>
              ) : filtered.length === 0 ? (
                <TableRow><TableCell colSpan={13} className="py-10 text-center text-muted-foreground">Aucune CVE ne correspond.</TableCell></TableRow>
              ) : pageRows.map((v) => (
                <TableRow key={v.cveId} className="cursor-pointer" onClick={() => openCve(v)}>
                  <TableCell className="whitespace-nowrap font-mono text-xs">{v.cveId}{v.hasExploit && " 💥"}{inParc(v) && <span title="Affecte un actif de votre parc"> ⭐</span>}</TableCell>
                  <TableCell className="max-w-[280px] truncate text-sm text-muted-foreground" title={v.description}>{v.description}</TableCell>
                  <TableCell>{v.cvssV3 !== "-" ? v.cvssV3 : v.cvssV2}</TableCell>
                  <TableCell>{v.epss != null ? (v.epss * 100).toFixed(1) + "%" : "—"}</TableCell>
                  <TableCell>{v.isKev ? <Badge className="bg-red-600 text-white">KEV</Badge> : <span className="text-muted-foreground">—</span>}</TableCell>
                  <TableCell onClick={(e) => { e.stopPropagation(); openCve(v, "risk") }}><RiskBadge score={v.riskScore} /></TableCell>
                  <TableCell><Badge className={cn("border", TONE_CLASS[v.severity])}>{v.severity}</Badge></TableCell>
                  <TableCell className="whitespace-nowrap text-xs" onClick={(e) => e.stopPropagation()}>
                    {v.cwes.length ? v.cwes.slice(0, 2).map((c) => <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.replace(/\D/g, "")}.html`} target="_blank" rel="noopener noreferrer" className="mr-1 underline decoration-dotted">{c}</a>) : <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="max-w-[180px] truncate font-mono text-[11px] text-muted-foreground" title={v.vector}>{v.attackVector}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{v.complexity}</TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{v.publishedDate}</TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <select value={triage[v.cveId] || "new"} onChange={(e) => setStatus(v.cveId, e.target.value)} className="rounded border border-border bg-background px-1 py-1 text-xs">
                      {Object.entries(TRIAGE).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
                    </select>
                  </TableCell>
                  <TableCell><span className="text-muted-foreground">›</span></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </Card>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm">
        <span className="text-muted-foreground"><b className="text-foreground">{filtered.length}</b> CVE · page {pageSafe + 1}/{totalPages} <span className="text-xs">(50/page)</span></span>
        <div className="flex items-center gap-1">
          <Button size="sm" variant="outline" disabled={pageSafe <= 0} onClick={() => setPage(0)}>« Début</Button>
          <Button size="sm" variant="outline" disabled={pageSafe <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>‹ Précédent</Button>
          <Button size="sm" variant="outline" disabled={pageSafe >= totalPages - 1} onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}>Suivant ›</Button>
          <Button size="sm" variant="outline" disabled={pageSafe >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>Fin »</Button>
        </div>
      </div>

      <CveDetailDialog vuln={selected} all={vulns} open={open} onOpenChange={setOpen} onOpenCve={(cve) => openCve(cve)} initialTab={tab} />
    </main>
  )
}
