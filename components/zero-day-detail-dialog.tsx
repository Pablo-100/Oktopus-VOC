"use client"

import { useEffect, useState } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { TONE_CLASS } from "@/lib/risk-engine"
import type { ZeroDay } from "@/lib/types"
import { cn } from "@/lib/utils"
import { ExposurePanel } from "./exposure-panel"
import { ExploitationActivityPanel } from "./exploitation-activity-panel"

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

function ExploitBadge({ state }: { state: string | null }) {
  if (!state || state === "none") return <span className="text-muted-foreground">—</span>
  const label = state === "kev-confirmed" ? "KEV confirmed" : state === "source-reported" ? "Source-reported" : state === "poc-published" ? "PoC published" : state
  return <Badge className={EXPLOIT_COLOR[state] || "bg-muted text-muted-foreground"}>{label}</Badge>
}

export function ZeroDayDetailDialog({ item, open, onOpenChange, initialTab, onTabChange }: { item: ZeroDay | null; open: boolean; onOpenChange: (o: boolean) => void; initialTab?: string; onTabChange: (t: string) => void }) {
  const [tab, setTab] = useState(initialTab || "overview")
  useEffect(() => { setTab(initialTab || "overview") }, [initialTab])

  if (!item) return null
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] w-[95vw] max-w-[calc(100%-2rem)] overflow-y-auto text-[15px] leading-relaxed sm:!max-w-4xl sm:p-8">
        <DialogHeader>
          <DialogTitle className="flex flex-wrap items-center gap-2 text-2xl">
            {item.id}
            {item.kind === "prepub_exploited" && <Badge className="bg-red-600 text-white">🔥 Exploited pre-publication</Badge>}
            {item.kind === "reserved" && <Badge className="bg-amber-500 text-black">🕐 Reserved</Badge>}
            {item.kind === "advisory" && <Badge className="bg-cyan-600 text-white">🧩 Advisory without CVE</Badge>}
            {item.becameCve && <Badge className="bg-emerald-600 text-white">✅ Became CVE</Badge>}
            {item.isKev && <Badge className="bg-red-600 text-white">🔴 KEV</Badge>}
            <span className="ml-auto mr-6 flex items-center gap-2">
              <a href={item.cveId ? `https://nvd.nist.gov/vuln/detail/${item.cveId}` : item.permalink ?? "#"} target="_blank" rel="noopener noreferrer"
                className="rounded-full border border-primary/40 bg-primary/10 px-3 py-1 text-sm font-medium text-primary transition hover:bg-primary/20">
                {item.cveId ? "NVD ↗" : item.permalink ? "Source ↗" : "—"}
              </a>
              {item.ghsaId && <a href={`https://github.com/advisories/${item.ghsaId}`} target="_blank" rel="noopener noreferrer" className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20">GitHub Advisory ↗</a>}
            </span>
          </DialogTitle>
        </DialogHeader>
        <Tabs value={tab} onValueChange={(v) => { setTab(v); onTabChange(v) }}>
          <TabsList className="!h-auto flex w-full flex-wrap justify-start gap-1 p-1">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="signals">Signals</TabsTrigger>
            <TabsTrigger value="lifecycle">Lifecycle</TabsTrigger>
            <TabsTrigger value="raw">Raw JSON</TabsTrigger>
          </TabsList>
          <TabsContent value="overview" className="space-y-4 text-base">
            {item.plainSummary && (
              <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-4">
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-cyan-400">In plain terms</p>
                <p className="leading-7">{item.plainSummary}</p>
              </div>
            )}
            {item.description && item.description !== item.plainSummary && (
              <details className="rounded-lg border border-border bg-muted/20 p-4">
                <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-muted-foreground">Technical details</summary>
                <p className="mt-2 whitespace-pre-line text-sm leading-relaxed text-muted-foreground">{item.description}</p>
              </details>
            )}
            {!item.plainSummary && !item.description && <p className="leading-7 text-muted-foreground">No description available.</p>}
            <div className="grid gap-2 sm:grid-cols-3">
              <div><b>Kind</b><br />{KIND_ICON[item.kind]} {KIND_LABEL[item.kind]}</div>
              <div><b>Source</b><br />{item.source}</div>
              <div><b>Product</b><br />{item.product ?? "—"}</div>
            </div>
            <div><b>Exploitation</b><br /><ExploitBadge state={item.exploitState} /></div>
            <div><b>Verification</b><br />{item.verification === "partial" ? "Partial (reserved/pending NVD)" : item.verification === "verified" ? "Verified" : "—"}</div>
            <ExposurePanel product={item.product} />
            <ExploitationActivityPanel cveId={item.cveId} />
            <div>
              <b>References</b><br />
              {item.references.filter(Boolean).length ? (
                <ul className="space-y-1 mt-1">
                  {item.references.filter(Boolean).map((r, i) => <li key={i}><a href={r} target="_blank" rel="noopener noreferrer" className="underline decoration-dotted text-sm">{r}</a></li>)}
                </ul>
              ) : "—"}
            </div>
          </TabsContent>
          <TabsContent value="signals" className="space-y-4 text-sm">
            <div className="grid gap-2 sm:grid-cols-2">
              <div><b>Exploit State</b><br /><ExploitBadge state={item.exploitState} /></div>
              <div><b>Verification</b><br />{item.verification ?? "—"}</div>
              <div><b>CISA KEV</b><br />{item.isKev ? "Yes" : "No"}</div>
              <div><b>CVSS</b><br />{extractCvss(item.cvss)}</div>
              <div><b>EPSS</b><br />{item.epss != null ? (item.epss * 100).toFixed(1) + "%" : "—"}</div>
              <div><b>Risk Score</b><br />{item.riskScore}/100</div>
              <div><b>Severity</b><br /><Badge className={cn("border", TONE_CLASS[item.severity as keyof typeof TONE_CLASS] || "border-border")}>{SEV_LABEL[item.severity] || item.severity}</Badge></div>
            </div>
            <div><b>Raw references</b><br />{item.references.length ? item.references.map((r, i) => <div key={i} className="text-xs"><a href={r} target="_blank" rel="noopener noreferrer" className="underline decoration-dotted">{r}</a></div>) : "—"}</div>
          </TabsContent>
          <TabsContent value="lifecycle" className="space-y-4 text-sm">
            <div className="grid gap-2 sm:grid-cols-2">
              <div><b>First seen</b><br />{item.firstSeenAt ? new Date(item.firstSeenAt).toLocaleString("en-US") : "—"}</div>
              <div><b>Last seen</b><br />{item.lastSeenAt ? new Date(item.lastSeenAt).toLocaleString("en-US") : "—"}</div>
              <div><b>Became CVE</b><br />{item.becameCve ? "Yes" : "No"}</div>
              <div><b>Resolved on</b><br />{item.resolvedAt ? new Date(item.resolvedAt).toLocaleString("en-US") : "—"}</div>
            </div>
            {item.becameCve && item.cveId && (
              <div className="mt-4 p-3 rounded-md border border-border bg-muted/30">
                <p className="font-semibold">This vulnerability has been assigned an official CVE identifier.</p>
                <a href={`/dashboard?search=${item.cveId}`} className="underline decoration-dotted text-cyan-400 hover:text-cyan-300">View in the CVE Dashboard →</a>
              </div>
            )}
          </TabsContent>
          <TabsContent value="raw" className="text-sm">
            <pre className="rounded-md border border-border bg-muted/30 p-4 overflow-auto text-xs max-h-96">{JSON.stringify(item.data, null, 2)}</pre>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}