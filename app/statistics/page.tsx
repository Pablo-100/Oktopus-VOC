"use client"

import { useEffect, useMemo, useState, type ComponentProps } from "react"
import { loadCves } from "@/lib/data"
import type { Vuln } from "@/lib/types"
import { CWE_INFO } from "@/lib/cwe-info"
import { Card } from "@/components/ui/card"
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid,
  PieChart, Pie, Cell, LineChart, Line, Legend, LabelList,
} from "recharts"

const GRID = "rgba(148,163,184,0.15)"
const AXIS = "#93a1bd"
// Palette sévérité (ordinale), avec libellés FR — identité jamais par la couleur seule (légende + labels)
const SEV = [
  { key: "critical", label: "Critique", color: "#e11d48" },
  { key: "high", label: "Élevée", color: "#f97316" },
  { key: "medium", label: "Moyenne", color: "#eab308" },
  { key: "low", label: "Faible", color: "#22c55e" },
]
const IMPACT = [
  { label: "Aucun", color: "#475569" },
  { label: "Faible", color: "#eab308" },
  { label: "Élevé", color: "#e11d48" },
]
const legendStyle = { fontSize: 12, color: "#93a1bd" }
const TT: ComponentProps<typeof Tooltip> = {
  contentStyle: { background: "rgba(11,16,34,0.95)", border: "1px solid rgba(139,92,246,0.45)", borderRadius: "10px", color: "#e7ecf5", boxShadow: "0 10px 30px rgba(0,0,0,0.5)", padding: "10px 12px" },
  labelStyle: { color: "#c4b5fd", fontWeight: 600, marginBottom: 4 },
  itemStyle: { color: "#e7ecf5" },
  cursor: { fill: "rgba(139,92,246,0.10)" },
  formatter: (v) => [v as number, "CVE"],
}

function ChartCard({ title, subtitle, children, tall }: { title: string; subtitle?: string; children: React.ReactNode; tall?: boolean }) {
  return (
    <Card className="glass p-5">
      <h3 className="font-semibold">{title}</h3>
      <p className="mb-3 text-xs text-muted-foreground">{subtitle ?? ""}</p>
      <div className={tall ? "h-[440px]" : "h-80"}>
        <ResponsiveContainer width="100%" height="100%">{children as React.ReactElement}</ResponsiveContainer>
      </div>
    </Card>
  )
}

export default function StatisticsPage() {
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadCves("").then(setVulns).catch((e) => setError((e as Error).message)).finally(() => setLoading(false))
  }, [])

  const agg = useMemo(() => {
    const severity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    const cvss = Array.from({ length: 10 }, (_, i) => ({ band: `${i}-${i + 1}`, n: 0 }))
    const epss = Array.from({ length: 10 }, (_, i) => ({ band: `${i * 10}-${i * 10 + 10}`, n: 0 }))
    const cwe: Record<string, number> = {}
    const vendor: Record<string, number> = {}
    const product: Record<string, number> = {}
    const perDay: Record<string, number> = {}
    let sum = 0, cnt = 0, kev = 0
    vulns.forEach((v) => {
      severity[v.severity]++
      const s = v.cvssV3 !== "-" ? Number(v.cvssV3) : v.cvssV2 !== "-" ? Number(v.cvssV2) : 0
      if (s) { cvss[Math.min(Math.floor(s), 9)].n++; sum += s; cnt++ }
      if (v.epss != null) epss[Math.min(Math.floor(v.epss * 10), 9)].n++
      v.cwes.forEach((c) => (cwe[c] = (cwe[c] || 0) + 1))
      v.vendors.forEach((x) => (vendor[x] = (vendor[x] || 0) + 1))
      v.products.forEach((x) => (product[x] = (product[x] || 0) + 1))
      if (v.sortDate) { const d = v.sortDate.toISOString().slice(0, 10); perDay[d] = (perDay[d] || 0) + 1 }
      if (v.isKev) kev++
    })
    const top = (o: Record<string, number>) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, n]) => ({ name, n }))
    const days = Object.keys(perDay).sort().map((d) => ({ day: d.slice(5), n: perDay[d] }))
    return {
      total: vulns.length, critical: severity.critical, kev, avg: cnt ? (sum / cnt).toFixed(1) : "0",
      sevData: SEV.map((s) => ({ name: s.label, value: severity[s.key], color: s.color })),
      cvss, epss, days, topVendor: top(vendor), topProduct: top(product),
      topCwe: top(cwe).map((c) => {
        const info = CWE_INFO[c.name.replace(/\D/g, "")]
        const short = info ? (info.name.length > 24 ? info.name.slice(0, 24) + "…" : info.name) : ""
        return { ...c, label: short ? `${c.name} — ${short}` : c.name }
      }),
    }
  }, [vulns])

  // CVE par année (NVD totalResults, mis en cache 24h)
  const [byYear, setByYear] = useState<{ year: string; n: number }[]>([])
  useEffect(() => {
    const KEY = "octopus.cveByYear"
    try {
      const c = JSON.parse(localStorage.getItem(KEY) || "null")
      if (c && Date.now() - c.ts < 864e5 && c.data?.length) { setByYear(c.data); return }
    } catch { /* ignore */ }
    let cancelled = false
    ;(async () => {
      const nowY = new Date().getFullYear()
      const out: { year: string; n: number }[] = []
      for (let y = nowY - 7; y <= nowY; y++) {
        try {
          const p = new URLSearchParams({ pubStartDate: `${y}-01-01T00:00:00.000`, pubEndDate: `${y}-12-31T23:59:59.999`, resultsPerPage: "1" })
          const r = await fetch(`/api/nvd?${p.toString()}`)
          if (r.ok) { const j = await r.json(); out.push({ year: String(y), n: j.totalResults || 0 }) }
        } catch { /* ignore */ }
        await new Promise((res) => setTimeout(res, 1500)) // proxy + clé -> plus rapide
      }
      if (!cancelled && out.length) {
        setByYear(out)
        try { localStorage.setItem(KEY, JSON.stringify({ ts: Date.now(), data: out })) } catch { /* ignore */ }
      }
    })()
    return () => { cancelled = true }
  }, [])

  if (loading) return <main className="mx-auto max-w-6xl px-4 py-16 text-center text-muted-foreground">Chargement des statistiques…</main>
  if (error) return <main className="mx-auto max-w-6xl px-4 py-16"><Card className="border-red-500/50 bg-red-500/10 p-4">⚠️ {error}</Card></main>

  return (
    <main className="mx-auto max-w-[1600px] px-6 py-8">
      <h1 className="text-3xl font-bold tracking-tight">Statistiques</h1>
      <p className="mb-6 text-muted-foreground">Analytics sur le lot de CVE chargé (fenêtre récente NVD).</p>

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Card className="glass p-4"><div className="text-xs uppercase text-muted-foreground">Total CVE</div><div className="text-3xl font-bold">{agg.total}</div></Card>
        <Card className="bg-zinc-900 p-4 text-white"><div className="text-xs uppercase opacity-80">Critiques</div><div className="text-3xl font-bold">{agg.critical}</div></Card>
        <Card className="glass p-4"><div className="text-xs uppercase text-muted-foreground">CVSS moyen</div><div className="text-3xl font-bold">{agg.avg}</div></Card>
        <Card className="glass p-4"><div className="text-xs uppercase text-muted-foreground">🔴 KEV</div><div className="text-3xl font-bold">{agg.kev}</div></Card>
      </div>

      <div className="mb-4">
        <ChartCard title="CVE publiées par jour" subtitle="Volume quotidien sur la fenêtre chargée — survole un point pour le détail">
          <LineChart data={agg.days} margin={{ top: 10, right: 20, left: -12, bottom: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis dataKey="day" fontSize={11} stroke={AXIS} tickLine={false} />
            <YAxis allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <Tooltip {...TT} />
            <Line dataKey="n" name="CVE" stroke="#22d3ee" strokeWidth={2.5} dot={{ r: 3, fill: "#22d3ee" }} activeDot={{ r: 6 }} />
          </LineChart>
        </ChartCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard title="Répartition par sévérité" subtitle="Part de chaque niveau de gravité — % sur les tranches, total au survol">
          <PieChart>
            <Pie data={agg.sevData} dataKey="value" nameKey="name" innerRadius={70} outerRadius={118} paddingAngle={2}
                 label={({ percent }) => ((percent ?? 0) > 0.03 ? `${((percent ?? 0) * 100).toFixed(0)}%` : "")} labelLine={false}>
              {agg.sevData.map((e) => <Cell key={e.name} fill={e.color} stroke="rgba(0,0,0,0.25)" />)}
            </Pie>
            <Legend wrapperStyle={legendStyle} />
            <Tooltip {...TT} />
          </PieChart>
        </ChartCard>
        <ChartCard title="Distribution des scores CVSS" subtitle="Nombre de CVE par tranche de score technique (0 → 10)">
          <BarChart data={agg.cvss} margin={{ top: 18, right: 10, left: -12, bottom: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis dataKey="band" fontSize={11} stroke={AXIS} tickLine={false} />
            <YAxis allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <Tooltip {...TT} />
            <Bar dataKey="n" fill="#8b5cf6" radius={[4, 4, 0, 0]}><LabelList dataKey="n" position="top" fontSize={10} fill={AXIS} /></Bar>
          </BarChart>
        </ChartCard>
        <ChartCard title="Distribution EPSS" subtitle="Probabilité d'exploitation à 30 j, par tranche de %">
          <BarChart data={agg.epss} margin={{ top: 18, right: 10, left: -12, bottom: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis dataKey="band" fontSize={11} stroke={AXIS} tickLine={false} />
            <YAxis allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <Tooltip {...TT} />
            <Bar dataKey="n" fill="#22c55e" radius={[4, 4, 0, 0]}><LabelList dataKey="n" position="top" fontSize={10} fill={AXIS} /></Bar>
          </BarChart>
        </ChartCard>
        <ChartCard title="Top 10 faiblesses (CWE)" subtitle="Types de vulnérabilité les plus fréquents (nom au survol)" tall>
          <BarChart data={agg.topCwe} layout="vertical" margin={{ left: 8, right: 34, top: 4, bottom: 4 }}>
            <CartesianGrid stroke={GRID} horizontal={false} />
            <XAxis type="number" allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <YAxis type="category" dataKey="label" width={200} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <Tooltip {...TT} />
            <Bar dataKey="n" fill="#fb7185" radius={[0, 4, 4, 0]}><LabelList dataKey="n" position="right" fontSize={10} fill={AXIS} /></Bar>
          </BarChart>
        </ChartCard>
        <ChartCard title="Top 10 éditeurs" subtitle="Éditeurs les plus touchés (CPE)">
          <BarChart data={agg.topVendor} layout="vertical" margin={{ left: 8, right: 34, top: 4, bottom: 4 }}>
            <CartesianGrid stroke={GRID} horizontal={false} />
            <XAxis type="number" allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <YAxis type="category" dataKey="name" width={110} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <Tooltip {...TT} />
            <Bar dataKey="n" fill="#8b5cf6" radius={[0, 4, 4, 0]}><LabelList dataKey="n" position="right" fontSize={10} fill={AXIS} /></Bar>
          </BarChart>
        </ChartCard>
        <ChartCard title="Top 10 produits" subtitle="Produits les plus touchés (CPE)">
          <BarChart data={agg.topProduct} layout="vertical" margin={{ left: 8, right: 34, top: 4, bottom: 4 }}>
            <CartesianGrid stroke={GRID} horizontal={false} />
            <XAxis type="number" allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <YAxis type="category" dataKey="name" width={110} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
            <Tooltip {...TT} />
            <Bar dataKey="n" fill="#22d3ee" radius={[0, 4, 4, 0]}><LabelList dataKey="n" position="right" fontSize={10} fill={AXIS} /></Bar>
          </BarChart>
        </ChartCard>
        <Card className="glass p-5">
          <h3 className="font-semibold">CVE par année (NVD)</h3>
          <p className="mb-3 text-xs text-muted-foreground">Total publié par an (source NVD, mis en cache 24 h)</p>
          <div className="h-80">
            {byYear.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={byYear} margin={{ top: 18, right: 10, left: -6, bottom: 0 }}>
                  <CartesianGrid stroke={GRID} vertical={false} />
                  <XAxis dataKey="year" fontSize={11} stroke={AXIS} tickLine={false} />
                  <YAxis allowDecimals={false} fontSize={11} stroke={AXIS} tickLine={false} axisLine={false} />
                  <Tooltip {...TT} />
                  <Bar dataKey="n" fill="#fbbf24" radius={[4, 4, 0, 0]}><LabelList dataKey="n" position="top" fontSize={10} fill={AXIS} /></Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-center text-sm text-muted-foreground">Chargement des totaux annuels… (~40 s, mis en cache 24 h)</div>
            )}
          </div>
        </Card>
      </div>
    </main>
  )
}
