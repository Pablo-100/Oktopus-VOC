"use client"

import { useState } from "react"
import { toast } from "sonner"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { riskLevel, TONE_CLASS } from "@/lib/risk-engine"
import type { Vuln } from "@/lib/types"
import { cn } from "@/lib/utils"

const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" }
const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-500 text-black",
  low: "bg-green-600 text-white",
}

type ImportResult = { imported: boolean; error?: string }

function ImportButton({ cveId, onImported }: { cveId: string; onImported?: () => void }) {
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  return (
    <Button
      size="xs"
      variant={done ? "outline" : "default"}
      disabled={busy || done}
      onClick={async () => {
        setBusy(true)
        try {
          const res = await fetch("/api/cves/import", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cveId }),
          })
          const r = (await res.json().catch(() => ({}))) as ImportResult
          if (res.status === 429) { toast.error(r.error || "Too many requests — wait a minute."); return }
          if (!res.ok) { toast.error(r.error || `Import failed (${res.status})`); return }
          if (r.imported) { setDone(true); toast.success("CVE imported into your dataset."); onImported?.() }
          else toast.info("Already in your dataset.")
        } catch {
          toast.error("Import failed — try again.")
        } finally { setBusy(false) }
      }}
    >
      {done ? "Imported ✓" : busy ? "…" : "Import"}
    </Button>
  )
}

function CveRow({ cve, source, onImported }: { cve: Vuln; source?: string; onImported?: () => void }) {
  const info = riskLevel(cve.riskScore)
  const sev = SEV_COLORS[cve.severity] || "bg-muted text-muted-foreground"
  return (
    <div className="flex items-start gap-3 rounded-lg border border-border bg-white/5 p-2.5">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-xs font-medium">{cve.cveId}</span>
          <Badge className={cn("border", TONE_CLASS[info.tone])}>{cve.riskScore ?? "—"}</Badge>
          <Badge className={sev}>{SEV_LABEL[cve.severity] ?? cve.severity}</Badge>
          {cve.isKev && <Badge className="bg-red-600 text-white">KEV</Badge>}
          {cve.hasExploit && <Badge className="bg-orange-500 text-white">Exploit</Badge>}
          {source && <Badge variant="outline">{source === "db" ? "Database" : "Archive"}</Badge>}
        </div>
        <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{cve.description}</p>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {cve.publishedDate} · CVSS {cve.cvssV3 !== "-" ? cve.cvssV3 : cve.cvssV2}
          {cve.vendors.length > 0 && <> · {cve.vendors.slice(0, 3).join(", ")}</>}
        </p>
      </div>
      <ImportButton cveId={cve.cveId} onImported={onImported} />
    </div>
  )
}

/**
 * Recherche de CVE ANCIENNES dans l'archive NVD (Tiers A/B), SANS saturer la base :
 *  - Par ID        → GET  /api/cve-lookup?id=   (base d'abord, sinon archive enrichie à la volée)
 *  - Par mot-clé   → GET  /api/cve-search?q=    (keywordSearch NVD, fenêtres temporelles)
 * L'import (POST /api/cves/import) reste une action EXPLICITE de l'analyste.
 */
export function ArchiveSearchDialog({ onImported }: { onImported?: () => void }) {
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState("id")

  // Lookup par ID (Tier A)
  const [idQuery, setIdQuery] = useState("")
  const [lookup, setLookup] = useState<Vuln | null>(null)
  const [lookSource, setLookSource] = useState<"db" | "archive" | null>(null)
  const [lookErr, setLookErr] = useState<string | null>(null)
  const [lookBusy, setLookBusy] = useState(false)

  // Recherche par mot-clé (Tier B)
  const [q, setQ] = useState("")
  const [rows, setRows] = useState<Vuln[]>([])
  const [qErr, setQErr] = useState<string | null>(null)
  const [qBusy, setQBusy] = useState(false)

  async function runLookup(e: React.FormEvent) {
    e.preventDefault()
    const idT = idQuery.trim().toUpperCase()
    if (!/^CVE-\d{4}-\d{4,}$/.test(idT)) { setLookErr("Expected format: CVE-YYYY-NNNN"); setLookup(null); return }
    setLookBusy(true); setLookErr(null); setLookup(null); setLookSource(null)
    try {
      const res = await fetch(`/api/cve-lookup?id=${encodeURIComponent(idT)}`)
      const j = await res.json().catch(() => ({}))
      if (res.status === 429) { setLookErr(j.error || "Too many requests — wait a minute."); return }
      if (!res.ok) { setLookErr(j.error || `Lookup failed (${res.status})`); return }
      setLookup(j.cve); setLookSource(j.source === "db" ? "db" : "archive")
    } catch {
      setLookErr("Network error — try again.")
    } finally { setLookBusy(false) }
  }

  async function runSearch(e: React.FormEvent) {
    e.preventDefault()
    const qT = q.trim()
    if (qT.length < 3) { setQErr("3 characters minimum."); return }
    setQBusy(true); setQErr(null); setRows([])
    try {
      const res = await fetch(`/api/cve-search?q=${encodeURIComponent(qT)}`)
      const j = await res.json().catch(() => ({}))
      if (res.status === 429) { setQErr(j.error || "Too many requests — try again in a minute."); return }
      if (!res.ok) { setQErr(j.error || `Search failed (${res.status})`); return }
      setRows(j.cves ?? [])
    } catch {
      setQErr("Network error — try again.")
    } finally { setQBusy(false) }
  }

  const shown = rows.slice(0, 50)

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button type="button" variant="outline">Archive</Button>} />
      <DialogContent className="max-h-[85vh] w-[95vw] max-w-2xl overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="text-lg">Search the NVD archive</DialogTitle>
        </DialogHeader>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList className="w-full">
            <TabsTrigger value="id" className="flex-1">By ID</TabsTrigger>
            <TabsTrigger value="kw" className="flex-1">By keyword</TabsTrigger>
          </TabsList>

          <TabsContent value="id" className="mt-3 space-y-3">
            <form onSubmit={runLookup} className="flex gap-2">
              <Input placeholder="CVE-1999-0001" value={idQuery} onChange={(e) => setIdQuery(e.target.value)} className="font-mono" />
              <Button type="submit" disabled={lookBusy}>{lookBusy ? "…" : "Search"}</Button>
            </form>
            {lookErr && <p className="text-sm text-red-400">{lookErr}</p>}
            {lookup && <CveRow cve={lookup} source={lookSource ?? undefined} onImported={onImported} />}
          </TabsContent>

          <TabsContent value="kw" className="mt-3 space-y-3">
            <form onSubmit={runSearch} className="flex gap-2">
              <Input placeholder="e.g. libcurl, openssl, log4j…" value={q} onChange={(e) => setQ(e.target.value)} />
              <Button type="submit" disabled={qBusy}>{qBusy ? "…" : "Search"}</Button>
            </form>
            {qErr && <p className="text-sm text-red-400">{qErr}</p>}
            {!qBusy && !qErr && rows.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {rows.length} result{rows.length > 1 ? "s" : ""}
                {rows.length > 50 ? " — showing first 50" : ""}
              </p>
            )}
            {!qBusy && !qErr && rows.length === 0 && <p className="text-sm text-muted-foreground">No results.</p>}
            <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
              {shown.map((c) => <CveRow key={c.cveId} cve={c} onImported={onImported} />)}
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}