"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { threatFor } from "@/lib/threat"
import type { Vuln } from "@/lib/types"

/** Mini rendu Markdown -> éléments React (titres ###, gras **, listes -). */
function renderMarkdown(md: string) {
  const lines = md.split("\n")
  const out: React.ReactNode[] = []
  let list: string[] = []
  const flush = (k: number) => {
    if (list.length) {
      out.push(<ul key={"ul" + k} className="ml-5 list-disc space-y-1">{list.map((li, i) => <li key={i} dangerouslySetInnerHTML={{ __html: inline(li) }} />)}</ul>)
      list = []
    }
  }
  const inline = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`(.+?)`/g, "<code>$1</code>")
  lines.forEach((raw, i) => {
    const t = raw.trim()
    if (/^#{2,4}\s/.test(t)) { flush(i); out.push(<h4 key={i} className="mt-3 font-semibold text-cyan-400">{t.replace(/^#+\s/, "")}</h4>) }
    else if (/^[-*]\s/.test(t)) { list.push(t.replace(/^[-*]\s/, "")) }
    else if (t === "") { flush(i) }
    else { flush(i); out.push(<p key={i} dangerouslySetInnerHTML={{ __html: inline(t) }} />) }
  })
  flush(9999)
  return out
}

export function AiAnalysis({ vuln }: { vuln: Vuln }) {
  const [loading, setLoading] = useState(false)
  const [md, setMd] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  async function run() {
    setLoading(true); setErr(null)
    const t = threatFor(vuln)
    const context = {
      cve_id: vuln.cveId, description: vuln.description,
      cvss_v3: vuln.cvssV3, cvss_v2: vuln.cvssV2, severity: vuln.severity, vector: vuln.vector,
      epss: vuln.epss != null ? +(vuln.epss * 100).toFixed(1) + "%" : null,
      cisa_kev: vuln.isKev, exploit_connu: vuln.hasExploit, risk_score_rbvm: vuln.riskScore,
      cwe: vuln.cwes, capec: t.capec.map(([id, n]) => `${id} (${n})`), mitre_attack: t.attack.map(([id, n]) => `${id} (${n})`),
      editeurs: vuln.vendors, produits: vuln.products,
      references: vuln.references.slice(0, 10),
    }
    try {
      const r = await fetch("/api/ai", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ context }) })
      const data = await r.json()
      if (!r.ok) throw new Error(data.error || "Échec")
      setMd(data.text)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <Button size="sm" onClick={run} disabled={loading}>{loading ? "Analyse en cours…" : "🤖 Générer l'analyse IA"}</Button>
      {err && <p className="mt-3 rounded-md border border-red-500/40 bg-red-500/10 p-2 text-sm">⚠️ {err}</p>}
      {md && (
        <div className="mt-3 space-y-1 rounded-lg border border-border bg-primary/5 p-4 text-sm leading-relaxed">
          {renderMarkdown(md)}
          <p className="pt-2 text-xs text-muted-foreground">🤖 Généré par IA à partir des seules données de la CVE — à vérifier.</p>
        </div>
      )}
    </div>
  )
}
