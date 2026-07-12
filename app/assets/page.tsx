"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { FacetPicker, type Facet } from "@/components/facet-picker"
import { toast } from "sonner"

type Asset = { id: number; name: string; vendor?: string; product?: string; criticality: string; owner?: string }

const CRIT_CLASS: Record<string, string> = {
  critical: "bg-red-600 text-white", high: "bg-amber-500 text-black", medium: "bg-sky-600 text-white", low: "bg-emerald-600 text-white",
}
const CRIT_LABEL: Record<string, string> = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" }

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)

  // Sélecteur guidé (facettes de la base)
  const [vendors, setVendors] = useState<Facet[]>([])
  const [products, setProducts] = useState<Facet[]>([])
  const [selVendors, setSelVendors] = useState<Set<string>>(new Set())
  const [selProducts, setSelProducts] = useState<Set<string>>(new Set())
  const [crit, setCrit] = useState("medium")
  const [adding, setAdding] = useState(false)

  // Ajout manuel (CPE exact)
  const [manual, setManual] = useState({ name: "", vendor: "", product: "", criticality: "medium" })

  async function refresh() {
    try {
      const r = await fetch("/api/assets"); const d = await r.json()
      if (!r.ok) throw new Error(d.error || "Erreur")
      setAssets(d.assets || [])
    } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }
  useEffect(() => { refresh() }, [])
  useEffect(() => {
    fetch("/api/facets").then((r) => r.json()).then((d) => { setVendors(d.vendors || []); setProducts(d.products || []) }).catch(() => {})
  }, [])

  function toggle(set: Set<string>, setter: (s: Set<string>) => void, name: string) {
    const next = new Set(set); next.has(name) ? next.delete(name) : next.add(name); setter(next)
  }

  async function addStack() {
    const items = [
      ...[...selVendors].map((v) => ({ name: v, vendor: v, criticality: crit })),
      ...[...selProducts].map((p) => ({ name: p, product: p, criticality: crit })),
    ]
    if (!items.length) return
    setAdding(true); setErr(null)
    try {
      for (const it of items) {
        await fetch("/api/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(it) })
      }
      setSelVendors(new Set()); setSelProducts(new Set())
      toast.success(`${items.length} élément(s) ajouté(s) à ton parc`)
      refresh()
    } catch (e) { setErr((e as Error).message) } finally { setAdding(false) }
  }

  async function addManual(e: React.FormEvent) {
    e.preventDefault()
    if (!manual.name.trim()) return
    setErr(null)
    try {
      const r = await fetch("/api/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(manual) })
      const d = await r.json(); if (!r.ok) throw new Error(d.error || "Erreur")
      setManual({ name: "", vendor: "", product: "", criticality: "medium" })
      refresh()
    } catch (e) { setErr((e as Error).message) }
  }
  async function del(id: number) { await fetch(`/api/assets?id=${id}`, { method: "DELETE" }).catch(() => {}); refresh() }

  const selectedCount = selVendors.size + selProducts.size

  return (
    <main className="mx-auto max-w-5xl px-4 py-8">
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Mon parc</h1>
          <p className="text-sm text-muted-foreground sm:text-base">Déclare ta stack (éditeurs, produits, technos). Les CVE qui te concernent seront filtrables via <b>⭐ Mon parc</b>.</p>
        </div>
        <Link href="/dashboard?preset=parc" className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-600 to-pink-500 px-4 py-2 text-sm font-semibold text-white">
          ⭐ Voir les CVE de mon parc
        </Link>
      </div>

      {/* Sélecteur guidé */}
      <Card className="glass mb-6 p-5">
        <h2 className="mb-1 text-lg font-semibold">Construis ton parc</h2>
        <p className="mb-4 text-sm text-muted-foreground">Coche les éditeurs et produits que tu utilises — la liste vient directement des CVE en base (aucune faute de frappe possible).</p>

        <div className="grid gap-5 sm:grid-cols-2">
          <FacetPicker label="Éditeurs" placeholder="Rechercher un éditeur (ex. microsoft, apache)…" options={vendors} selected={selVendors} onToggle={(n) => toggle(selVendors, setSelVendors, n)} />
          <FacetPicker label="Produits / Technologies" placeholder="Rechercher un produit (ex. windows, openssl)…" options={products} selected={selProducts} onToggle={(n) => toggle(selProducts, setSelProducts, n)} />
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="text-sm text-muted-foreground">Criticité :</label>
          <select value={crit} onChange={(e) => setCrit(e.target.value)} className="rounded-md border border-border bg-background px-2 py-2 text-sm">
            <option value="critical">Critique</option><option value="high">Élevée</option><option value="medium">Moyenne</option><option value="low">Faible</option>
          </select>
          <Button onClick={addStack} disabled={adding || selectedCount === 0} className="ml-auto">
            {adding ? "Ajout…" : `+ Ajouter à mon parc${selectedCount ? ` (${selectedCount})` : ""}`}
          </Button>
        </div>
      </Card>

      {err && <Card className="mb-4 border-red-500/50 bg-red-500/10 p-3 text-sm">⚠️ {err}</Card>}

      {/* Liste du parc */}
      <Card className="glass mb-6 overflow-hidden">
        <div className="border-b border-border p-3 text-sm font-medium">Mon parc <span className="text-muted-foreground">({assets.length})</span></div>
        {loading ? (
          <p className="p-6 text-center text-muted-foreground">Chargement…</p>
        ) : assets.length === 0 ? (
          <p className="p-6 text-center text-muted-foreground">Parc vide. Coche tes éditeurs/produits ci-dessus.</p>
        ) : (
          <ul className="divide-y divide-border">
            {assets.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-3 p-3">
                <div className="min-w-0">
                  <div className="truncate font-medium">{a.name} <Badge className={CRIT_CLASS[a.criticality] || "bg-secondary"}>{CRIT_LABEL[a.criticality] || a.criticality}</Badge></div>
                  <div className="truncate text-xs text-muted-foreground">{[a.vendor, a.product].filter(Boolean).join(" · ") || "—"}</div>
                </div>
                <Button variant="ghost" size="sm" onClick={() => del(a.id)} className="text-red-400 hover:text-red-300">Supprimer</Button>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {/* Ajout manuel (avancé) */}
      <details className="rounded-xl border border-border bg-background/40 p-4">
        <summary className="cursor-pointer text-sm font-medium text-muted-foreground">Ajout manuel (CPE exact) — avancé</summary>
        <form onSubmit={addManual} className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <Input placeholder="Nom (ex. Serveur web prod)" value={manual.name} onChange={(e) => setManual({ ...manual, name: e.target.value })} className="lg:col-span-2" />
          <Input placeholder="Éditeur (ex. apache)" value={manual.vendor} onChange={(e) => setManual({ ...manual, vendor: e.target.value })} />
          <Input placeholder="Produit (ex. http server)" value={manual.product} onChange={(e) => setManual({ ...manual, product: e.target.value })} />
          <Button type="submit">+ Ajouter</Button>
        </form>
        <p className="mt-2 text-xs text-muted-foreground">Format CPE NVD en minuscules (ex. <code>microsoft</code>, <code>windows</code>). Préfère le sélecteur ci-dessus.</p>
      </details>
    </main>
  )
}
