"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import cytoscape from "cytoscape"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import { neighborhood, type ExposureGraph, type GraphNode, type GraphEdge, type GraphNodeType } from "@/lib/exposure/graph"

/**
 * EXPOSURE INTELLIGENCE GRAPH — investigation view.
 *
 * Renders the model produced by `lib/exposure/graph.ts`. It holds the full
 * graph as an immutable source and derives what is on screen; filtering,
 * focusing and expanding are all PROJECTIONS of that one model, never a second
 * dataset and never a mutation of the first.
 *
 * Nothing here fetches from a provider. Expanding a node reveals data already
 * present in the response, so exploring the graph costs no provider quota.
 */

/** Node palette. Distinct hues per type, muted enough to read at density. */
const NODE_COLOR: Record<GraphNodeType, string> = {
  domain: "#22d3ee",
  ip: "#38bdf8",
  service: "#818cf8",
  product: "#0ea5e9",
  version: "#6366f1",
  cve: "#8b5cf6",
  provider: "#22c55e",
  certificate: "#a78bfa",
  alert: "#ef4444",
}

const NODE_LABEL: Record<GraphNodeType, string> = {
  domain: "Domain", ip: "IP / Asset", service: "Service", product: "Product",
  version: "Version", cve: "CVE", provider: "Provider", certificate: "Certificate", alert: "Alert",
}

/**
 * Evidence colours for `affected_by` edges.
 *
 * The visual weight tracks the evidence: confirmed reads as solid and green,
 * a pivot as a faint dotted line. A graph that drew them identically would
 * imply a product-name guess is as good as a provider confirmation.
 */
const EVIDENCE_EDGE: Record<string, { color: string; style: string; width: number; label: string }> = {
  confirmed: { color: "#10b981", style: "solid", width: 2.4, label: "Confirmed" },
  strong: { color: "#0ea5e9", style: "solid", width: 2, label: "Strong" },
  product: { color: "#f59e0b", style: "dashed", width: 1.5, label: "Product" },
  weak: { color: "#94a3b8", style: "dashed", width: 1.2, label: "Weak" },
  pivot: { color: "#64748b", style: "dotted", width: 1, label: "Pivot" },
}

const EDGE_LABEL: Record<string, string> = {
  resolves_to: "resolves to", exposes: "exposes", runs: "runs",
  has_version: "has version", affected_by: "affected by", triggered: "triggered",
  observed: "observed", associated_with: "associated with",
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const
const EVIDENCE_ORDER = ["confirmed", "strong", "product", "weak", "pivot"] as const

/** Types always present at the top level; the rest appear on expansion. */
const BASE_TYPES = new Set<GraphNodeType>(["domain", "ip", "provider"])
/** Edges that reveal children when their SOURCE is expanded. */
const CHILD_EDGES = new Set(["exposes", "runs", "has_version", "affected_by", "associated_with"])
/** Types an analyst can drill into. */
const EXPANDABLE = new Set<GraphNodeType>(["ip", "service", "product", "version"])

interface Filters {
  types: Set<GraphNodeType>
  severities: Set<string>
  evidence: Set<string>
  providers: Set<string>
  search: string
}

export function ExposureGraphPanel() {
  const [graph, setGraph] = useState<ExposureGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [empty, setEmpty] = useState(false)

  // UI state only — never written back into the graph model.
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [focusId, setFocusId] = useState<string | null>(null)
  const [selected, setSelected] = useState<GraphNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null)
  const [layoutName, setLayoutName] = useState("breadthfirst")
  const [filters, setFilters] = useState<Filters>({
    types: new Set(), severities: new Set(), evidence: new Set(), providers: new Set(), search: "",
  })

  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)

  /**
   * Whether the canvas element is actually in the DOM.
   *
   * The canvas renders only in the populated branch below, so on first paint —
   * while `graph` is still null and the empty-state card is showing — there is
   * no element for cytoscape to attach to. Initialising on mount alone silently
   * produced a permanently blank canvas: the effect found no container, never
   * re-ran, and the header still reported a node count because that comes from
   * React state rather than from cytoscape.
   */
  const hasCanvas = !empty && (graph?.nodes.length ?? 0) > 0

  const fetchGraph = useCallback(async () => {
    const res = await fetch("/api/exposure/graph")
    if (!res.ok) throw new Error(res.status === 401 ? "Sign in to view the graph." : `Graph unavailable (${res.status})`)
    return (await res.json()) as { graph: ExposureGraph; empty: boolean }
  }, [])

  // `loading` starts true, so no synchronous state write happens in the effect.
  useEffect(() => {
    let cancelled = false
    fetchGraph()
      .then((d) => { if (!cancelled) { setGraph(d.graph); setEmpty(d.empty); setError(null) } })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : "Graph unavailable.") })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [fetchGraph])

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const d = await fetchGraph()
      setGraph(d.graph); setEmpty(d.empty); setError(null)
      setExpanded(new Set()); setFocusId(null); setSelected(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Graph unavailable.")
    } finally { setLoading(false) }
  }, [fetchGraph])

  const nodeById = useMemo(() => new Map((graph?.nodes ?? []).map((n) => [n.id, n])), [graph])

  /**
   * Which nodes are on screen.
   *
   * Base layer first, then children of whatever the analyst expanded, then
   * alerts for any visible CVE. Filters apply throughout, so a filtered-out
   * node cannot be revealed by expanding its parent.
   */
  const visibleIds = useMemo(() => {
    if (!graph) return new Set<string>()

    const passes = (n: GraphNode): boolean => {
      if (filters.types.size && !filters.types.has(n.type)) return false
      if (filters.severities.size && n.type === "ip") {
        const sev = typeof n.metadata.severity === "string" ? n.metadata.severity : null
        if (!sev || !filters.severities.has(sev)) return false
      }
      if (filters.providers.size && n.type === "provider") {
        if (!filters.providers.has(String(n.metadata.provider))) return false
      }
      if (filters.search.trim()) {
        if (!n.label.toLowerCase().includes(filters.search.trim().toLowerCase())) return false
      }
      return true
    }

    // An evidence filter restricts which CVEs are reachable, by restricting the
    // edges that reveal them — the filter is about EVIDENCE, not about the CVE.
    const evidenceOk = (e: GraphEdge) =>
      e.kind !== "affected_by" || !filters.evidence.size || (e.evidenceTier != null && filters.evidence.has(e.evidenceTier))

    const visible = new Set<string>()
    for (const n of graph.nodes) if (BASE_TYPES.has(n.type) && passes(n)) visible.add(n.id)

    // Reveal children of expanded nodes until nothing new appears.
    for (let guard = 0; guard < 12; guard++) {
      let changed = false
      for (const e of graph.edges) {
        if (!CHILD_EDGES.has(e.kind)) continue
        if (!visible.has(e.source) || !expanded.has(e.source)) continue
        if (visible.has(e.target) || !evidenceOk(e)) continue
        const target = nodeById.get(e.target)
        if (target && passes(target)) { visible.add(e.target); changed = true }
      }
      if (!changed) break
    }

    // Alerts follow their CVE automatically: an open alert is never something
    // an analyst should have to go looking for.
    for (const e of graph.edges) {
      if (e.kind !== "triggered" || !visible.has(e.source)) continue
      const alert = nodeById.get(e.target)
      if (alert && passes(alert)) visible.add(e.target)
    }

    // Focus is the final projection, applied to whatever survived above.
    if (focusId && visible.has(focusId)) {
      const near = neighborhood(graph, focusId, 2)
      for (const id of [...visible]) if (!near.has(id)) visible.delete(id)
    }
    return visible
  }, [graph, filters, expanded, focusId, nodeById])

  const elements = useMemo<cytoscape.ElementDefinition[]>(() => {
    if (!graph) return []
    const nodes = graph.nodes
      .filter((n) => visibleIds.has(n.id))
      .map((n) => ({
        data: {
          id: n.id, label: n.label, type: n.type,
          severity: typeof n.metadata.severity === "string" ? n.metadata.severity : "",
          // Expandable nodes with hidden children get a visual affordance.
          collapsed: EXPANDABLE.has(n.type) && !expanded.has(n.id) ? "yes" : "no",
        },
      }))
    const edges = graph.edges
      .filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target))
      .map((e) => ({
        data: {
          id: e.id, source: e.source, target: e.target,
          kind: e.kind, evidence: e.evidenceTier ?? "",
          label: EDGE_LABEL[e.kind] ?? e.kind,
        },
      }))
    return [...nodes, ...edges]
  }, [graph, visibleIds, expanded])

  // ── Cytoscape lifecycle ──
  useEffect(() => {
    if (!hasCanvas || !containerRef.current) return
    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      // Matches the visual language of components/threat-graph.tsx.
      style: [
        {
          selector: "node",
          style: {
            "background-color": (e: cytoscape.NodeSingular) => NODE_COLOR[e.data("type") as GraphNodeType] ?? "#94a3b8",
            label: "data(label)", color: "#e7ecf5", "font-size": "9px",
            "text-valign": "center", "text-halign": "center",
            "text-outline-width": 2, "text-outline-color": "#0b1022",
            shape: "round-rectangle", width: "label", height: "label", padding: "7px",
            "border-width": 0,
          },
        },
        { selector: 'node[type="ip"]', style: { "font-size": "11px", "font-weight": "bold", padding: "10px" } },
        { selector: 'node[type="alert"]', style: { shape: "diamond", "font-weight": "bold", padding: "12px" } },
        { selector: 'node[type="provider"]', style: { shape: "ellipse", "font-size": "9px" } },
        // Risk is shown as a border on the asset, so it never competes with the
        // type colour that tells the analyst WHAT the node is.
        { selector: 'node[severity="critical"]', style: { "border-width": 3, "border-color": "#ef4444" } },
        { selector: 'node[severity="high"]', style: { "border-width": 3, "border-color": "#f97316" } },
        { selector: 'node[severity="medium"]', style: { "border-width": 2, "border-color": "#f59e0b" } },
        { selector: 'node[collapsed="yes"]', style: { "border-width": 2, "border-style": "dotted", "border-color": "#94a3b8" } },
        {
          selector: "edge",
          style: {
            width: 1.2, "line-color": "rgba(148,163,184,0.35)", "curve-style": "bezier",
            "target-arrow-shape": "triangle", "target-arrow-color": "rgba(148,163,184,0.35)",
            "arrow-scale": 0.7,
          },
        },
        // DIRECT evidence: a provider actually saw this.
        { selector: 'edge[kind="observed"]', style: { "line-color": "rgba(34,197,94,0.5)", "target-arrow-color": "rgba(34,197,94,0.5)", "line-style": "solid" } },
        { selector: 'edge[kind="triggered"]', style: { "line-color": "#ef4444", "target-arrow-color": "#ef4444", width: 2 } },
        // MATCHED evidence: weight and style follow the tier.
        ...EVIDENCE_ORDER.map((tier) => ({
          selector: `edge[evidence="${tier}"]`,
          style: {
            "line-color": EVIDENCE_EDGE[tier].color,
            "target-arrow-color": EVIDENCE_EDGE[tier].color,
            "line-style": EVIDENCE_EDGE[tier].style,
            width: EVIDENCE_EDGE[tier].width,
          },
        })) as cytoscape.StylesheetStyle[],
        { selector: ".selected", style: { "border-width": 4, "border-color": "#ffffff" } },
      ],
      layout: { name: "preset" },
      wheelSensitivity: 0.2,
      maxZoom: 3,
      minZoom: 0.08,
    })
    cyRef.current = cy

    cy.on("tap", "node", (evt) => {
      const id = evt.target.id() as string
      const model = (evt.target.scratch("_node") ?? null) as GraphNode | null
      setSelectedEdge(null)
      // The model object is captured here, not the Cytoscape element: expanding
      // rebuilds the elements, so the element itself is about to be destroyed.
      setSelected(model)
      // Tapping EXPANDS only. Collapsing is an explicit action in the detail
      // panel, so inspecting a node never hides what the analyst just revealed.
      if (model && EXPANDABLE.has(model.type)) {
        setExpanded((prev) => (prev.has(id) ? prev : new Set(prev).add(id)))
      }
    })
    cy.on("tap", "edge", (evt) => {
      setSelected(null)
      setSelectedEdge(evt.target.scratch("_edge") ?? null)
    })
    cy.on("tap", (evt) => { if (evt.target === cy) { setSelected(null); setSelectedEdge(null) } })

    return () => { cy.destroy(); cyRef.current = null }
  }, [hasCanvas])

  // Feed elements in and re-run layout when the projection changes.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.batch(() => {
      cy.elements().remove()
      cy.add(elements)
      // Attach the model objects so click handlers read real metadata rather
      // than a flattened copy.
      for (const n of graph?.nodes ?? []) {
        const el = cy.getElementById(n.id)
        if (el.nonempty()) el.scratch("_node", n)
      }
      for (const e of graph?.edges ?? []) {
        const el = cy.getElementById(e.id)
        if (el.nonempty()) el.scratch("_edge", e)
      }
    })
    if (cy.elements().length) {
      const layout = cy.layout({
        name: layoutName,
        // `breadthfirst` gives the domain → ip → service → product hierarchy;
        // `cose` reads better for dense provider fan-out.
        ...(layoutName === "breadthfirst" ? { directed: true, spacingFactor: 1.1, padding: 30 } : {}),
        ...(layoutName === "cose" ? { animate: false, nodeRepulsion: 8000, idealEdgeLength: 90, padding: 30 } : {}),
        ...(layoutName === "concentric" ? { concentric: (n: cytoscape.NodeSingular) => (n.data("type") === "ip" ? 10 : 1), levelWidth: () => 1, minNodeSpacing: 25 } : {}),
      } as cytoscape.LayoutOptions)
      // The container is sized by CSS that may settle after cytoscape attached;
      // without an explicit resize the viewport can stay 0x0 and paint nothing.
      layout.one("layoutstop", () => { cy.resize(); cy.fit(undefined, 40) })
      layout.run()
    }
  }, [elements, layoutName, graph])

  // Highlight the current selection without rebuilding the graph.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().removeClass("selected")
    if (selected) cy.getElementById(selected.id).addClass("selected")
  }, [selected])

  const toggle = <T,>(set: Set<T>, value: T): Set<T> => {
    const next = new Set(set)
    if (next.has(value)) next.delete(value)
    else next.add(value)
    return next
  }

  const resetAll = () => {
    setFilters({ types: new Set(), severities: new Set(), evidence: new Set(), providers: new Set(), search: "" })
    setExpanded(new Set())
    setFocusId(null)
    setSelected(null)
    setSelectedEdge(null)
  }

  if (loading && !graph) return <div className="py-10 text-center text-sm text-muted-foreground">Building graph…</div>
  if (error) return <Card className="border-red-500/50 bg-red-500/10 p-4 text-sm">⚠️ {error}</Card>
  if (!graph) return null

  const stats = graph.stats
  const visibleCount = visibleIds.size

  return (
    <div className="space-y-4 p-1">
      <div className="rounded-lg border border-border bg-white/5 p-3 text-xs leading-relaxed text-muted-foreground">
        <b className="text-foreground">Exposure Intelligence Graph.</b> Visualizes provider-backed observations and
        OCTUPUS&apos;s existing vulnerability correlations. <b>It performs no internet scanning</b> — every node comes
        from a record already held, and expanding a node reveals data already loaded, never a new provider query.
        Solid green edges are <b>observed</b> (a provider saw it); dashed edges are <b>matched</b>, styled by evidence
        strength.
      </div>

      {empty || graph.nodes.length === 0 ? (
        <Card className="glass p-10 text-center text-sm text-muted-foreground">
          Nothing to graph yet. The graph is built from enriched and monitored assets — run a search and use{" "}
          <b className="text-foreground">Enrich asset</b> or <b className="text-foreground">Refresh now</b>, or enable
          monitoring, and the observed surface will appear here.
        </Card>
      ) : (
        <>
          {/* ── Controls ── */}
          <div className="space-y-3 rounded-lg border border-border bg-white/5 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Input
                value={filters.search}
                onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
                placeholder="Search nodes…"
                className="h-8 w-full max-w-[220px] text-xs"
              />
              <select
                value={layoutName}
                onChange={(e) => setLayoutName(e.target.value)}
                className="h-8 rounded-md border border-border bg-transparent px-2 text-xs"
              >
                <option value="breadthfirst" className="bg-background">Hierarchy</option>
                <option value="cose" className="bg-background">Force</option>
                <option value="concentric" className="bg-background">Concentric</option>
              </select>
              <Button size="sm" variant="outline" onClick={() => cyRef.current?.fit(undefined, 40)}>Fit</Button>
              <Button size="sm" variant="outline" onClick={() => { cyRef.current?.zoom(cyRef.current.zoom() * 1.3) }}>+</Button>
              <Button size="sm" variant="outline" onClick={() => { cyRef.current?.zoom(cyRef.current.zoom() / 1.3) }}>−</Button>
              <Button
                size="sm"
                variant={expanded.size ? "default" : "outline"}
                onClick={() => setExpanded(expanded.size ? new Set() : new Set(graph.nodes.filter((n) => EXPANDABLE.has(n.type)).map((n) => n.id)))}
              >
                {expanded.size ? "Collapse all" : "Expand all"}
              </Button>
              {focusId && (
                <Button size="sm" variant="default" onClick={() => setFocusId(null)}>
                  Exit focus
                </Button>
              )}
              <Button size="sm" variant="outline" onClick={resetAll}>Reset</Button>
              <Button size="sm" variant="outline" onClick={() => void reload()} disabled={loading}>
                {loading ? "…" : "Reload"}
              </Button>
              <span className="ml-auto text-xs text-muted-foreground">
                {visibleCount} / {graph.nodes.length} nodes
                {stats.truncated && (
                  <span className="ml-2 rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-300"
                    title={`Showing the ${stats.assetsIncluded} highest-risk assets of ${stats.assetsTotal}. A larger graph would not be readable.`}>
                    {stats.assetsIncluded}/{stats.assetsTotal} assets
                  </span>
                )}
              </span>
            </div>

            <FilterRow label="Type">
              {(Object.keys(NODE_LABEL) as GraphNodeType[])
                .filter((t) => (stats.nodeCounts[t] ?? 0) > 0)
                .map((t) => (
                  <Chip key={t} active={filters.types.has(t)} onClick={() => setFilters((f) => ({ ...f, types: toggle(f.types, t) }))}>
                    <span className="mr-1 inline-block h-2 w-2 rounded-full" style={{ background: NODE_COLOR[t] }} />
                    {NODE_LABEL[t]} <span className="opacity-60">{stats.nodeCounts[t]}</span>
                  </Chip>
                ))}
            </FilterRow>

            {stats.severities.length > 0 && (
              <FilterRow label="Risk">
                {SEVERITY_ORDER.filter((s) => stats.severities.some((x) => x.severity === s)).map((s) => (
                  <Chip key={s} active={filters.severities.has(s)} onClick={() => setFilters((f) => ({ ...f, severities: toggle(f.severities, s) }))}>
                    {s} <span className="opacity-60">{stats.severities.find((x) => x.severity === s)?.nodes ?? 0}</span>
                  </Chip>
                ))}
              </FilterRow>
            )}

            {stats.evidenceTiers.length > 0 && (
              <FilterRow label="Evidence">
                {EVIDENCE_ORDER.filter((t) => stats.evidenceTiers.some((x) => x.tier === t)).map((t) => (
                  <Chip key={t} active={filters.evidence.has(t)} onClick={() => setFilters((f) => ({ ...f, evidence: toggle(f.evidence, t) }))}
                    title={`${EVIDENCE_EDGE[t].label} evidence`}>
                    <span className="mr-1 inline-block h-2 w-2 rounded-full" style={{ background: EVIDENCE_EDGE[t].color }} />
                    {EVIDENCE_EDGE[t].label} <span className="opacity-60">{stats.evidenceTiers.find((x) => x.tier === t)?.edges ?? 0}</span>
                  </Chip>
                ))}
              </FilterRow>
            )}

            {/* Only providers actually present are offered. No zero-count chips. */}
            {stats.providers.length > 0 && (
              <FilterRow label="Provider">
                {stats.providers.map((p) => (
                  <Chip key={p.provider} active={filters.providers.has(p.provider)}
                    onClick={() => setFilters((f) => ({ ...f, providers: toggle(f.providers, p.provider) }))}>
                    {p.provider} <span className="opacity-60">{p.nodes}</span>
                  </Chip>
                ))}
              </FilterRow>
            )}
          </div>

          {/* ── Canvas + detail ── */}
          <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
            <div>
              <div ref={containerRef} className="h-[560px] w-full rounded-xl border border-border bg-black/20" />
              <Legend />
            </div>
            <NodeDetail
              node={selected}
              edge={selectedEdge}
              graph={graph}
              onFocus={(id) => { setFocusId(id); setExpanded((p) => new Set(p).add(id)) }}
              focused={focusId}
              expandedIds={expanded}
              onToggleExpand={(id) => setExpanded((p) => {
                const next = new Set(p)
                if (next.has(id)) next.delete(id)
                else next.add(id)
                return next
              })}
            />
          </div>
        </>
      )}
    </div>
  )
}

function FilterRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="w-16 shrink-0 text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
      {children}
    </div>
  )
}

function Chip({ active, onClick, children, title }: { active: boolean; onClick: () => void; children: React.ReactNode; title?: string }) {
  return (
    <button
      type="button" onClick={onClick} title={title}
      className={cn(
        "rounded-full border px-2 py-0.5 text-[11px] capitalize transition-colors",
        active ? "border-violet-400 bg-violet-500/20 text-foreground" : "border-border bg-transparent text-muted-foreground hover:bg-white/5",
      )}
    >
      {children}
    </button>
  )
}

function Legend() {
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-lg border border-border bg-white/5 px-3 py-2 text-[10px] text-muted-foreground">
      {(Object.keys(NODE_LABEL) as GraphNodeType[]).map((t) => (
        <span key={t} className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-sm" style={{ background: NODE_COLOR[t] }} />
          {NODE_LABEL[t]}
        </span>
      ))}
      <span className="mx-1 h-3 w-px bg-border" />
      <span className="flex items-center gap-1"><span className="inline-block h-px w-4" style={{ background: "#22c55e" }} /> observed (direct)</span>
      {EVIDENCE_ORDER.map((t) => (
        <span key={t} className="flex items-center gap-1">
          <span className="inline-block h-px w-4" style={{ background: EVIDENCE_EDGE[t].color }} />
          {EVIDENCE_EDGE[t].label.toLowerCase()} match
        </span>
      ))}
    </div>
  )
}

/** Detail panel. Renders ONLY fields present in the model — no placeholders. */
function NodeDetail({
  node, edge, graph, onFocus, focused, onToggleExpand, expandedIds,
}: {
  node: GraphNode | null
  edge: GraphEdge | null
  graph: ExposureGraph
  onFocus: (id: string) => void
  focused: string | null
  onToggleExpand: (id: string) => void
  expandedIds: Set<string>
}) {
  if (edge) {
    const ev = edge.evidenceTier ? EVIDENCE_EDGE[edge.evidenceTier] : null
    return (
      <Card className="glass h-fit p-4 text-xs">
        <div className="eyebrow mb-2 text-[10px]">Relationship</div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="text-[10px]">{EDGE_LABEL[edge.kind] ?? edge.kind}</Badge>
          {edge.direct && <Badge className="bg-emerald-600 text-[10px] text-white" title="A provider directly reported this.">Observed</Badge>}
          {ev && <Badge className="text-[10px] text-black" style={{ background: ev.color }}>{ev.label}</Badge>}
        </div>
        <dl className="space-y-1">
          <Field label="From" value={graph.nodes.find((n) => n.id === edge.source)?.label ?? edge.source} />
          <Field label="To" value={graph.nodes.find((n) => n.id === edge.target)?.label ?? edge.target} />
          {edge.kind === "affected_by" && (
            <>
              <Field label="Confirmed" value={edge.metadata?.confirmed ? "Yes" : "No"} />
              <Field label="Match type" value={String(edge.metadata?.matchType ?? "—")} />
              <Field label="Matched product" value={String(edge.metadata?.matchedProduct ?? "—")} />
              <Field label="Providers" value={fmtList(edge.metadata?.providers)} />
            </>
          )}
          {edge.metadata?.note ? (
            <p className="pt-1 text-[11px] text-muted-foreground">{String(edge.metadata.note)}</p>
          ) : null}
        </dl>
      </Card>
    )
  }

  if (!node) {
    return (
      <Card className="glass h-fit p-4 text-xs text-muted-foreground">
        <div className="eyebrow mb-2 text-[10px]">Investigation</div>
        <p>Click a node to inspect it, or an edge to see the evidence behind a relationship.</p>
        <p className="mt-2">Clicking an IP, service, product or version also expands its children.</p>
      </Card>
    )
  }

  const m = node.metadata
  const expandable = EXPANDABLE.has(node.type)
  const isExpanded = expandedIds.has(node.id)
  return (
    <Card className="glass h-fit max-h-[640px] overflow-auto p-4 text-xs">
      <div className="mb-2 flex items-center gap-2">
        <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: NODE_COLOR[node.type] }} />
        <span className="eyebrow text-[10px]">{NODE_LABEL[node.type]}</span>
      </div>
      <div className="mb-3 break-all font-mono text-sm text-foreground">{node.label}</div>

      <dl className="space-y-1">
        {node.type === "ip" && (
          <>
            {/* Risk is the EXISTING RBVM result, displayed, never recomputed. */}
            <Field label="Risk" value={m.riskScore == null ? "not scored" : `${m.riskScore} / ${String(m.severity ?? "")}`} />
            <Field label="Organization" value={String(m.organization ?? "—")} />
            <Field label="Country" value={String(m.country ?? "—")} />
            <Field label="Providers" value={fmtList(m.providers)} />
            <Field label="Services" value={String(m.serviceCount ?? 0)} />
            <Field label="Vulnerabilities" value={String(m.vulnerabilityCount ?? 0)} />
            <Field label="Confidence" value={String(m.confidence ?? "—")} />
            {m.isQueryTarget ? (
              <p className="pt-1 text-[11px] text-amber-300">
                Search target with no provider confirmation — it contributes no provenance.
              </p>
            ) : null}
            <FreshnessFields m={m} />
            {Array.isArray(m.providerFreshness) && m.providerFreshness.length > 0 && (
              <div className="pt-1">
                <div className="mb-1 text-muted-foreground">Per provider</div>
                {(m.providerFreshness as Array<{ provider: string; freshness: string; observedAt: string | null }>).map((p) => (
                  <div key={p.provider} className="flex justify-between gap-2">
                    <span>{p.provider}</span>
                    <span className="uppercase text-muted-foreground">{p.freshness}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {node.type === "service" && (
          <>
            <Field label="Port" value={`${m.port}/${String(m.transport ?? "tcp")}`} />
            <Field label="Protocol" value={String(m.protocol ?? "—")} />
            <Field label="Product" value={String(m.product ?? "not reported")} />
            <Field label="Version" value={String(m.version ?? "not reported")} />
            <Field label="Observed by" value={fmtList(m.providers)} />
            {m.conflict ? (
              <div className="mt-2 rounded border border-amber-500/40 bg-amber-500/10 p-2">
                <p className="mb-1 font-semibold text-amber-300">Provider disagreement</p>
                {(m.claims as Array<{ source: string; product: string | null; version: string | null }>).map((c, i) => (
                  <div key={i}>{c.source}: {c.product ?? "?"}{c.version ? ` ${c.version}` : ""}</div>
                ))}
              </div>
            ) : null}
          </>
        )}

        {node.type === "product" && (
          <>
            <Field label="Product" value={String(m.product ?? node.label)} />
            <Field label="Scope" value={m.scope === "host" ? "host-wide" : "service"} />
            {m.scope === "host" ? (
              <p className="pt-1 text-[11px] text-muted-foreground">
                Reported for the host. No source associated it with a specific port, so it is not attached to one.
              </p>
            ) : null}
          </>
        )}

        {node.type === "version" && (
          <>
            <Field label="Product" value={String(m.product ?? "—")} />
            <Field label="Version" value={String(m.version ?? "—")} />
          </>
        )}

        {node.type === "cve" && (
          <>
            <Field label="CVSS" value={m.cvss == null ? "not in CVE database" : String(m.cvss)} />
            <Field label="EPSS" value={m.epss == null ? "—" : String(m.epss)} />
            <Field label="KEV" value={m.isKev == null ? "—" : m.isKev ? "Yes" : "No"} />
            <Field label="Public exploit" value={m.hasExploit == null ? "—" : m.hasExploit ? "Yes" : "No"} />
            <Field label="Provider score" value={m.providerScore == null ? "—" : String(m.providerScore)} />
            <EvidenceForCve graph={graph} cveNodeId={node.id} />
            <a
              href={`https://nvd.nist.gov/vuln/detail/${node.label}`}
              target="_blank" rel="noopener noreferrer"
              className="mt-2 inline-block underline decoration-dotted"
            >
              Open in NVD
            </a>
          </>
        )}

        {node.type === "provider" && (
          <>
            <Field label="Provider" value={String(m.provider)} />
            <p className="pt-1 text-[11px] text-muted-foreground">
              Edges from this node are direct observations. Provider attribution is never merged or inferred.
            </p>
          </>
        )}

        {node.type === "certificate" && (
          <>
            <Field label="Common name" value={String(m.commonName ?? "—")} />
            <Field label="Issuer" value={String(m.issuer ?? "—")} />
            <Field label="Fingerprint" value={String(m.fingerprint ?? "—")} />
            <Field label="Valid to" value={String(m.validTo ?? "—")} />
            <Field label="Expired" value={m.expired == null ? "—" : m.expired ? "Yes" : "No"} />
            <Field label="SANs" value={fmtList(m.sans)} />
          </>
        )}

        {node.type === "alert" && (
          <>
            <Field label="State" value={String(m.state)} />
            <Field label="Severity" value={String(m.severity)} />
            <Field label="Evidence" value={String(m.evidenceTier)} />
            <Field label="Risk" value={m.riskScore == null ? "—" : String(m.riskScore)} />
            <Field label="Created" value={m.createdAt ? new Date(String(m.createdAt)).toLocaleString("en-US") : "—"} />
            {/* Links back to the originating alert so an analyst can move from
                the picture straight into the workflow. */}
            <a
              href={`/exposure?tab=alerts&alert=${encodeURIComponent(String(m.alertId ?? ""))}`}
              className="mt-2 inline-block underline decoration-dotted"
            >
              Open ALT-{String(m.alertId ?? "?")} in SOC Alerts
            </a>
            <p className="pt-1 text-[11px] text-muted-foreground">
              Alerts are shown here, not created here. Manage them in the SOC Alerts tab.
            </p>
          </>
        )}

        {node.type === "domain" && <Field label="Domain" value={String(m.domain)} />}
      </dl>

      <div className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" variant={focused === node.id ? "default" : "outline"} onClick={() => onFocus(node.id)}>
          {focused === node.id ? "Focused" : "Focus"}
        </Button>
        {expandable && (
          <Button size="sm" variant="outline" onClick={() => onToggleExpand(node.id)}>
            {isExpanded ? "Collapse" : "Expand"}
          </Button>
        )}
      </div>
    </Card>
  )
}

/** The evidence backing a CVE, read from the edges that point at it. */
function EvidenceForCve({ graph, cveNodeId }: { graph: ExposureGraph; cveNodeId: string }) {
  const links = graph.edges.filter((e) => e.kind === "affected_by" && e.target === cveNodeId)
  if (!links.length) return null
  return (
    <div className="pt-1">
      <div className="mb-1 text-muted-foreground">Evidence</div>
      {links.map((e) => {
        const ui = e.evidenceTier ? EVIDENCE_EDGE[e.evidenceTier] : null
        return (
          <div key={e.id} className="flex items-center justify-between gap-2">
            <span className="truncate">{graph.nodes.find((n) => n.id === e.source)?.label ?? e.source}</span>
            {ui && <Badge className="shrink-0 text-[10px] text-black" style={{ background: ui.color }}>{ui.label}</Badge>}
          </div>
        )
      })}
      <p className="mt-1 text-[11px] text-muted-foreground">
        {links.some((e) => e.metadata?.confirmed)
          ? "A provider directly reported this host as affected."
          : "Matched by OCTUPUS. Not a provider confirmation."}
      </p>
    </div>
  )
}

/** Observation time and retrieval time, always as two separate facts. */
function FreshnessFields({ m }: { m: Record<string, unknown> }) {
  return (
    <>
      <Field label="Freshness" value={String(m.freshness ?? "unknown").toUpperCase()} />
      <Field label="Provider observed" value={m.observedAt ? new Date(String(m.observedAt)).toLocaleString("en-US") : "not supplied"} />
      <Field label="OCTUPUS fetched" value={m.fetchedAt ? new Date(String(m.fetchedAt)).toLocaleString("en-US") : "—"} />
    </>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words text-right">{value}</dd>
    </div>
  )
}

function fmtList(v: unknown): string {
  return Array.isArray(v) && v.length ? v.join(", ") : "—"
}
