"use client"

import { useEffect, useRef } from "react"
import cytoscape from "cytoscape"
import { THREAT_MAP } from "@/lib/threat-map"
import { digits, exploitSource, hostOf } from "@/lib/threat"
import type { Vuln } from "@/lib/types"

const COLORS: Record<string, string> = {
  cve: "#8b5cf6", vendor: "#22d3ee", product: "#0ea5e9", cwe: "#fbbf24",
  capec: "#38bdf8", attack: "#6366f1", kev: "#ef4444", exploit: "#f59e0b", advisory: "#22c55e",
}

function elements(v: Vuln): cytoscape.ElementDefinition[] {
  const nodes: cytoscape.ElementDefinition[] = []
  const edges: cytoscape.ElementDefinition[] = []
  const add = (id: string, label: string, type: string, url = "") => nodes.push({ data: { id, label, type, url } })
  const link = (a: string, b: string) => edges.push({ data: { source: a, target: b } })

  add("cve", v.cveId, "cve", `https://nvd.nist.gov/vuln/detail/${v.cveId}`)
  v.vendors.slice(0, 6).forEach((x, i) => { add("ven" + i, x, "vendor"); link("ven" + i, "cve") })
  v.products.slice(0, 6).forEach((x, i) => { add("pro" + i, x, "product"); link("cve", "pro" + i) })
  v.cwes.forEach((c, i) => {
    const id = "cwe" + i
    add(id, c, "cwe", `https://cwe.mitre.org/data/definitions/${digits(c)}.html`)
    link("cve", id)
    const e = THREAT_MAP[digits(c)]
    if (e) {
      e.capec.forEach((x, j) => { const cid = `cap${i}_${j}`; add(cid, x.id, "capec", `https://capec.mitre.org/data/definitions/${digits(x.id)}.html`); link(id, cid) })
      e.attack.forEach((x, j) => { const aid = `att${i}_${j}`; const p = x.id.includes(".") ? `${x.id.split(".")[0]}/${x.id.split(".")[1]}` : x.id; add(aid, x.id, "attack", `https://attack.mitre.org/techniques/${p}/`); link(id, aid) })
    }
  })
  if (v.isKev) { add("kev", "CISA KEV", "kev", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"); link("cve", "kev") }
  v.references.filter((r) => r.tags.includes("Exploit")).slice(0, 4).forEach((r, i) => { add("exp" + i, exploitSource(r.url), "exploit", r.url); link("cve", "exp" + i) })
  v.references.filter((r) => r.tags.includes("Vendor Advisory") || r.tags.includes("Patch")).slice(0, 4).forEach((r, i) => { add("adv" + i, hostOf(r.url), "advisory", r.url); link("cve", "adv" + i) })
  return [...nodes, ...edges]
}

export function ThreatGraph({ vuln }: { vuln: Vuln }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!ref.current) return
    const cy = cytoscape({
      container: ref.current,
      elements: elements(vuln),
      style: [
        { selector: "node", style: { "background-color": (e: cytoscape.NodeSingular) => COLORS[e.data("type")] || "#94a3b8", label: "data(label)", color: "#e7ecf5", "font-size": "10px", "text-valign": "center", "text-halign": "center", "text-outline-width": 2, "text-outline-color": "#0b1022", shape: "round-rectangle", width: "label", height: "label", padding: "8px" } },
        { selector: 'node[type="cve"]', style: { "font-size": "13px", "font-weight": "bold", padding: "12px" } },
        { selector: "edge", style: { width: 1.5, "line-color": "rgba(148,163,184,0.35)", "curve-style": "bezier", "target-arrow-shape": "triangle", "target-arrow-color": "rgba(148,163,184,0.35)" } },
      ],
      layout: { name: "concentric", concentric: (n: cytoscape.NodeSingular) => (n.data("type") === "cve" ? 10 : 1), levelWidth: () => 1, minNodeSpacing: 30, padding: 10 },
    })
    cy.on("tap", "node", (evt) => { const u = evt.target.data("url"); if (u) window.open(u, "_blank", "noopener") })
    return () => cy.destroy()
  }, [vuln])
  return <div ref={ref} className="h-[420px] w-full rounded-xl border border-border bg-black/20" />
}
