"use client"

import { useEffect, useState } from "react"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"

type Asset = { id: number; name: string; vendor?: string; product?: string; criticality: string; owner?: string }

const CRIT_CLASS: Record<string, string> = {
  critical: "bg-red-600 text-white", high: "bg-amber-500 text-black", medium: "bg-sky-600 text-white", low: "bg-emerald-600 text-white",
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [form, setForm] = useState({ name: "", vendor: "", product: "", criticality: "medium", owner: "" })

  async function refresh() {
    try {
      const r = await fetch("/api/assets"); const d = await r.json()
      if (!r.ok) throw new Error(d.error || "Erreur")
      setAssets(d.assets || [])
    } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }
  useEffect(() => { refresh() }, [])

  async function add(e: React.FormEvent) {
    e.preventDefault()
    if (!form.name.trim()) return
    setErr(null)
    try {
      const r = await fetch("/api/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) })
      const d = await r.json(); if (!r.ok) throw new Error(d.error || "Erreur")
      setForm({ name: "", vendor: "", product: "", criticality: "medium", owner: "" })
      refresh()
    } catch (e) { setErr((e as Error).message) }
  }
  async function del(id: number) {
    await fetch(`/api/assets?id=${id}`, { method: "DELETE" }).catch(() => {})
    refresh()
  }

  return (
    <main className="mx-auto max-w-5xl px-4 py-8">
      <h1 className="text-3xl font-bold tracking-tight">Inventaire d&apos;actifs</h1>
      <p className="mb-6 text-muted-foreground">Déclare tes éditeurs / produits surveillés : les CVE qui les concernent sont marquées <b>⭐ Mon parc</b> sur le dashboard (risque contextualisé).</p>

      <Card className="glass mb-6 p-5">
        <form onSubmit={add} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
          <Input placeholder="Nom (ex. Serveur web prod)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="lg:col-span-2" />
          <Input placeholder="Éditeur (ex. apache)" value={form.vendor} onChange={(e) => setForm({ ...form, vendor: e.target.value })} />
          <Input placeholder="Produit (ex. http_server)" value={form.product} onChange={(e) => setForm({ ...form, product: e.target.value })} />
          <select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })} className="rounded-md border border-border bg-background px-2 py-2 text-sm">
            <option value="critical">Critique</option><option value="high">Élevée</option><option value="medium">Moyenne</option><option value="low">Faible</option>
          </select>
          <Button type="submit">+ Ajouter</Button>
        </form>
        <p className="mt-2 text-xs text-muted-foreground">L&apos;éditeur/produit doit correspondre au CPE NVD (minuscules, ex. <code>microsoft</code>, <code>windows</code>).</p>
      </Card>

      {err && <Card className="mb-4 border-red-500/50 bg-red-500/10 p-3 text-sm">⚠️ {err} — la base Neon est-elle configurée (DATABASE_URL) et le serveur redémarré ?</Card>}

      <Card className="glass overflow-hidden">
        {loading ? (
          <p className="p-6 text-center text-muted-foreground">Chargement…</p>
        ) : assets.length === 0 ? (
          <p className="p-6 text-center text-muted-foreground">Aucun actif. Ajoute ton premier ci-dessus.</p>
        ) : (
          <ul className="divide-y divide-border">
            {assets.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-3 p-3">
                <div>
                  <div className="font-medium">{a.name} <Badge className={CRIT_CLASS[a.criticality] || "bg-secondary"}>{a.criticality}</Badge></div>
                  <div className="text-xs text-muted-foreground">{[a.vendor, a.product].filter(Boolean).join(" · ") || "—"}{a.owner ? ` · ${a.owner}` : ""}</div>
                </div>
                <Button variant="ghost" size="sm" onClick={() => del(a.id)} className="text-red-400 hover:text-red-300">Supprimer</Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </main>
  )
}
