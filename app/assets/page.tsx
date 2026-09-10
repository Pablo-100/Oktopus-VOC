"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { FacetPicker, type Facet } from "@/components/facet-picker"
import { toast } from "sonner"

type Impact = { total: number; critical: number; kev: number; maxRisk: number }
type Asset = { id: number; name: string; vendor?: string; product?: string; criticality: string; owner?: string; impact?: Impact }
/** Software the platform observed on the user's own hosts, mapped to CVE vocabulary. */
type Suggestion = { observed: string; hosts: number; match: string | null; cveCount: number; criticalCount: number; kevCount: number }

const CRIT_CLASS: Record<string, string> = {
  critical: "bg-red-600 text-white", high: "bg-amber-500 text-black", medium: "bg-sky-600 text-white", low: "bg-emerald-600 text-white",
}
const CRIT_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" }

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

  // Suggestions from the exposure side. Optional: the page is fully usable
  // without them, so a failure here is silent rather than blocking.
  const [suggestions, setSuggestions] = useState<Suggestion[]>([])
  const [addingSuggestion, setAddingSuggestion] = useState<string | null>(null)

  async function addSuggestion(sg: Suggestion) {
    if (!sg.match) return
    setAddingSuggestion(sg.observed)
    setErr(null)
    try {
      const r = await fetch("/api/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: sg.observed, product: sg.match, criticality: "medium" }),
      })
      const d = (await r.json().catch(() => ({}))) as { error?: string }
      if (!r.ok) { setErr(d.error ?? "Could not add."); return }
      toast.success(`${sg.observed} added — ${sg.cveCount} CVEs now tracked against it.`)
      setSuggestions((prev) => prev.filter((x) => x.observed !== sg.observed))
      refresh()
    } finally { setAddingSuggestion(null) }
  }

  async function refresh() {
    try {
      const r = await fetch("/api/assets"); const d = await r.json()
      if (!r.ok) throw new Error(d.error || "Error")
      setAssets(d.assets || [])
    } catch (e) { setErr((e as Error).message) } finally { setLoading(false) }
  }
  useEffect(() => { refresh() }, [])
  useEffect(() => {
    // Best-effort: suggestions enrich the page, they are not required by it.
    fetch("/api/assets/suggestions")
      .then((r) => (r.ok ? r.json() : { suggestions: [] }))
      .then((d) => setSuggestions(d.suggestions ?? []))
      .catch(() => { /* the picker below still works */ })
  }, [])
  useEffect(() => {
    fetch("/api/facets").then((r) => r.json()).then((d) => { setVendors(d.vendors || []); setProducts(d.products || []) }).catch(() => {})
  }, [])

  function toggle(set: Set<string>, setter: (s: Set<string>) => void, name: string) {
    const next = new Set(set)
    if (next.has(name)) next.delete(name)
    else next.add(name)
    setter(next)
  }

  async function addStack() {
    const items = [
      ...[...selVendors].map((v) => ({ name: v, vendor: v, criticality: crit })),
      ...[...selProducts].map((p) => ({ name: p, product: p, criticality: crit })),
    ]
    if (!items.length) return
    setAdding(true); setErr(null)
    try {
      // Each write is checked. Previously the loop discarded every response and
      // then reported the full count as added, so a rejected request — a
      // validation error, or the per-minute rate limit on a large selection —
      // produced a success message for items that were never stored.
      let added = 0
      const failures: string[] = []
      for (const it of items) {
        try {
          const r = await fetch("/api/assets", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(it),
          })
          if (r.ok) { added++; continue }
          const d = (await r.json().catch(() => ({}))) as { error?: string }
          failures.push(d.error ?? `${it.name ?? "item"}: HTTP ${r.status}`)
        } catch {
          failures.push(`${it.name ?? "item"}: network error`)
        }
      }
      setSelVendors(new Set()); setSelProducts(new Set())
      if (added) toast.success(`${added} item(s) added to your asset inventory`)
      if (failures.length) {
        // Named rather than counted: "3 failed" leaves the user with no idea
        // which of their selection is missing.
        setErr(`${failures.length} item(s) could not be added — ${failures.slice(0, 3).join("; ")}${failures.length > 3 ? "…" : ""}`)
      }
      refresh()
    } catch (e) { setErr((e as Error).message) } finally { setAdding(false) }
  }

  async function addManual(e: React.FormEvent) {
    e.preventDefault()
    if (!manual.name.trim()) return
    setErr(null)
    try {
      const r = await fetch("/api/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(manual) })
      const d = await r.json(); if (!r.ok) throw new Error(d.error || "Error")
      setManual({ name: "", vendor: "", product: "", criticality: "medium" })
      refresh()
    } catch (e) { setErr((e as Error).message) }
  }
  async function del(id: number) {
    setErr(null)
    try {
      const r = await fetch(`/api/assets?id=${id}`, { method: "DELETE" })
      // The catch-all previously hid every failure, so a delete that the server
      // refused looked identical to one it accepted until the row reappeared.
      if (!r.ok) {
        const d = (await r.json().catch(() => ({}))) as { error?: string }
        setErr(d.error ?? `Could not delete this asset (HTTP ${r.status}).`)
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not delete this asset.")
    }
    refresh()
  }

  const selectedCount = selVendors.size + selProducts.size

  return (
    <main className="mx-auto max-w-5xl px-4 py-8">
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">My Assets</h1>
          <p className="text-sm text-muted-foreground sm:text-base">Declare your stack (vendors, products, technologies). CVEs that affect you become filterable via <b>⭐ My assets</b>.</p>
        </div>
        <Link href="/dashboard?preset=parc" className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-600 to-pink-500 px-4 py-2 text-sm font-semibold text-white">
          ⭐ View CVEs affecting my assets
        </Link>
      </div>

      {suggestions.length > 0 && (
        <Card className="glass mb-6 border-primary/30 p-5">
          <h2 className="mb-1 text-lg font-semibold">Detected on your infrastructure</h2>
          <p className="mb-4 text-sm leading-relaxed text-muted-foreground">
            These are running on hosts you monitor, reported by the exposure providers — you do not have to remember
            them. Each is matched to the CVE vocabulary and the counts below are what you would actually start
            tracking, so you can judge the match before accepting it.
          </p>
          <ul className="grid gap-2">
            {suggestions.map((sg) => (
              <li key={sg.observed} className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-white/5 p-3">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">
                    {sg.observed}
                    <span className="ml-2 text-xs text-muted-foreground">
                      on {sg.hosts} host{sg.hosts === 1 ? "" : "s"}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    matches <code className="text-foreground">{sg.match}</code> · {sg.cveCount} CVEs
                    {sg.criticalCount > 0 && <span className="text-red-300"> · {sg.criticalCount} critical</span>}
                    {sg.kevCount > 0 && <span className="text-amber-300"> · {sg.kevCount} exploited in the wild</span>}
                  </div>
                </div>
                <Button size="sm" onClick={() => void addSuggestion(sg)} disabled={addingSuggestion === sg.observed}>
                  {addingSuggestion === sg.observed ? "Adding…" : "Track this"}
                </Button>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {/* Guided picker */}
      <Card className="glass mb-6 p-5">
        <h2 className="mb-1 text-lg font-semibold">Build your inventory</h2>
        <p className="mb-4 text-sm text-muted-foreground">Check the vendors and products you use — the list comes straight from the CVEs in the database (no typos possible).</p>

        <div className="grid gap-5 sm:grid-cols-2">
          <FacetPicker label="Vendors" placeholder="Search a vendor (e.g. microsoft, apache)…" options={vendors} selected={selVendors} onToggle={(n) => toggle(selVendors, setSelVendors, n)} />
          <FacetPicker label="Products / Technologies" placeholder="Search a product (e.g. windows, openssl)…" options={products} selected={selProducts} onToggle={(n) => toggle(selProducts, setSelProducts, n)} />
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="text-sm text-muted-foreground">Criticality:</label>
          <select value={crit} onChange={(e) => setCrit(e.target.value)} className="rounded-md border border-border bg-background px-2 py-2 text-sm">
            <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <Button onClick={addStack} disabled={adding || selectedCount === 0} className="ml-auto">
            {adding ? "Adding…" : `+ Add to my assets${selectedCount ? ` (${selectedCount})` : ""}`}
          </Button>
        </div>
      </Card>

      {err && <Card className="mb-4 border-red-500/50 bg-red-500/10 p-3 text-sm">⚠️ {err}</Card>}

      {/* Asset list */}
      <Card className="glass mb-6 overflow-hidden">
        <div className="border-b border-border p-3 text-sm font-medium">My assets <span className="text-muted-foreground">({assets.length})</span></div>
        {loading ? (
          <p className="p-6 text-center text-muted-foreground">Loading…</p>
        ) : assets.length === 0 ? (
          <p className="p-6 text-center text-muted-foreground">No assets yet. Check your vendors/products above.</p>
        ) : (
          <ul className="divide-y divide-border">
            {assets.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-3 p-3">
                <div className="min-w-0">
                  <div className="truncate font-medium">{a.name} <Badge className={CRIT_CLASS[a.criticality] || "bg-secondary"}>{CRIT_LABEL[a.criticality] || a.criticality}</Badge></div>
                  <div className="truncate text-xs text-muted-foreground">{[a.vendor, a.product].filter(Boolean).join(" · ") || "—"}</div>
                  {/* The answer this page exists to give. Declaring a stack and
                      then having to leave to find out whether it matters is the
                      gap that made the inventory feel pointless. */}
                  {a.impact && (
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                      {a.impact.total === 0 ? (
                        <span className="text-muted-foreground">No CVE in the database matches this yet.</span>
                      ) : (
                        <>
                          <Link href={`/dashboard?preset=parc`} className="text-primary hover:underline">
                            {a.impact.total} CVEs
                          </Link>
                          {a.impact.critical > 0 && <span className="text-red-300">{a.impact.critical} critical</span>}
                          {a.impact.kev > 0 && (
                            <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-amber-300" title="Confirmed exploited in the wild">
                              {a.impact.kev} exploited
                            </span>
                          )}
                          <span className="text-muted-foreground">top risk {a.impact.maxRisk}</span>
                        </>
                      )}
                    </div>
                  )}
                </div>
                <Button variant="ghost" size="sm" onClick={() => del(a.id)} className="text-red-400 hover:text-red-300">Delete</Button>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {/* Manual add (advanced) */}
      <details className="rounded-xl border border-border bg-background/40 p-4">
        <summary className="cursor-pointer text-sm font-medium text-muted-foreground">Manual add (exact CPE) — advanced</summary>
        <form onSubmit={addManual} className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <Input placeholder="Name (e.g. Prod web server)" value={manual.name} onChange={(e) => setManual({ ...manual, name: e.target.value })} className="lg:col-span-2" />
          <Input placeholder="Vendor (e.g. apache)" value={manual.vendor} onChange={(e) => setManual({ ...manual, vendor: e.target.value })} />
          <Input placeholder="Product (e.g. http server)" value={manual.product} onChange={(e) => setManual({ ...manual, product: e.target.value })} />
          <Button type="submit">+ Add</Button>
        </form>
        <p className="mt-2 text-xs text-muted-foreground">Lowercase NVD CPE format (e.g. <code>microsoft</code>, <code>windows</code>). Prefer the picker above.</p>
      </details>
    </main>
  )
}
