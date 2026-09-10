"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"
import { TONE_CLASS } from "@/lib/risk-engine"
import type { RiskTone } from "@/lib/types"

/**
 * SOC ALERTS — analyst workflow.
 *
 * SEVERITY and EVIDENCE are shown as two separate badges throughout, because
 * they answer different questions: "how bad is this CVE" (the existing RBVM
 * engine) and "how sure are we this asset really runs it". Collapsing them is
 * how a product-name guess becomes a Critical incident.
 *
 * Delivery and ticket state are reported exactly as stored — the UI never
 * implies a message was sent or a ticket exists when neither happened.
 */

interface Alert {
  id: number
  assigned_to: string | null
  asset_key: string
  port: number
  cve_id: string
  kind: string
  state: string
  severity: string
  risk_score: number | null
  previous_risk: number | null
  evidence_tier: string
  payload: Record<string, unknown>
  notification_state: string
  notify_attempts: number
  notify_last_error: string | null
  notify_next_attempt_at: string | null
  notify_claimed_at: string | null
  notify_first_queued_at: string | null
  notified_at: string | null
  escalation_count: number
  ticket_state: string
  ticket_provider: string | null
  ticket_key: string | null
  ticket_url: string | null
  ticket_last_error: string | null
  suppressed_reason: string | null
  suppressed_by: string | null
  created_at: string
  updated_at: string
}

interface TimelineEvent {
  id: number
  type: string
  actor: string
  detail: string | null
  metadata: Record<string, unknown>
  occurred_at: string
}

interface ListResponse {
  alerts: Alert[]
  total: number
  limit: number
  offset: number
  counts: {
    state: Record<string, number>
    severity: Record<string, number>
    notification: Record<string, number>
  }
  integrations: { telegramConfigured: boolean; ticketProvider: string; ticketingConfigured: boolean }
  suppressionReasons: string[]
}

const EVIDENCE_UI: Record<string, { label: string; cls: string; hint: string }> = {
  confirmed: { label: "Confirmed", cls: "bg-emerald-600 text-white", hint: "A provider returned this host when queried for this CVE." },
  strong: { label: "Strong", cls: "bg-sky-600 text-white", hint: "The affected VERSION was fingerprinted on this host." },
  product: { label: "Product", cls: "bg-amber-500 text-black", hint: "Only the product NAME matched. A lead, not a finding." },
  weak: { label: "Weak", cls: "bg-zinc-600 text-white", hint: "Banner or heuristic inference only." },
  pivot: { label: "Pivot", cls: "bg-zinc-700 text-white", hint: "Derived locally; this host was never reported as affected." },
}

const STATE_UI: Record<string, { label: string; cls: string }> = {
  open: { label: "New", cls: "bg-red-500/15 text-red-300" },
  acknowledged: { label: "Acknowledged", cls: "bg-amber-500/15 text-amber-300" },
  in_progress: { label: "In progress", cls: "bg-sky-500/15 text-sky-300" },
  resolved: { label: "Resolved", cls: "bg-emerald-500/15 text-emerald-300" },
  closed: { label: "Closed", cls: "bg-white/5 text-muted-foreground" },
  suppressed: { label: "Suppressed", cls: "bg-violet-500/15 text-violet-300" },
}

const NOTIFY_UI: Record<string, { label: string; cls: string; hint: string }> = {
  pending: { label: "Queued", cls: "bg-white/5 text-muted-foreground", hint: "Queued for delivery. An immediate attempt runs on creation; the scheduler retries." },
  sending: { label: "Sending", cls: "bg-sky-500/15 text-sky-300", hint: "A delivery attempt is in flight right now." },
  sent: { label: "Sent", cls: "bg-emerald-500/15 text-emerald-300", hint: "Telegram accepted the message." },
  retrying: { label: "Retrying", cls: "bg-amber-500/15 text-amber-300", hint: "Delivery failed temporarily and is scheduled to retry." },
  failed: { label: "Failed", cls: "bg-red-500/15 text-red-300", hint: "Delivery failed permanently. The alert itself is unaffected." },
  disabled: { label: "Disabled", cls: "bg-white/5 text-muted-foreground", hint: "Telegram is not configured, so nothing was sent." },
}

const TICKET_UI: Record<string, { label: string; cls: string }> = {
  none: { label: "—", cls: "text-muted-foreground" },
  pending: { label: "Queued", cls: "text-muted-foreground" },
  open: { label: "Open", cls: "text-sky-300" },
  updated: { label: "Updated", cls: "text-sky-300" },
  closed: { label: "Closed", cls: "text-emerald-300" },
  failed: { label: "Failed", cls: "text-red-300" },
}

/** Transitions the analyst may take from each state, mirroring the server machine. */
const ACTIONS: Record<string, Array<{ to: string; label: string }>> = {
  open: [{ to: "acknowledged", label: "Acknowledge" }, { to: "in_progress", label: "Start investigation" }, { to: "resolved", label: "Resolve" }, { to: "suppressed", label: "Suppress" }],
  acknowledged: [{ to: "in_progress", label: "Start investigation" }, { to: "resolved", label: "Resolve" }, { to: "suppressed", label: "Suppress" }],
  in_progress: [{ to: "resolved", label: "Resolve" }, { to: "suppressed", label: "Suppress" }],
  resolved: [{ to: "closed", label: "Close" }, { to: "in_progress", label: "Reopen" }],
  closed: [],
  suppressed: [{ to: "open", label: "Un-suppress" }],
}

const REASON_LABEL: Record<string, string> = {
  false_positive: "False positive", accepted_risk: "Accepted risk", maintenance: "Maintenance",
  compensating_control: "Compensating control", duplicate: "Duplicate", other: "Other",
}

const PAGE_SIZE = 25

function ago(iso: string | null): string {
  if (!iso) return "—"
  const m = Math.round((Date.now() - Date.parse(iso)) / 60000)
  if (m < 1) return "just now"
  if (m < 60) return `${m}m ago`
  if (m < 1440) return `${Math.round(m / 60)}h ago`
  return `${Math.round(m / 1440)}d ago`
}

function str(v: unknown): string | null {
  return typeof v === "string" && v ? v : null
}

/**
 * Delivery latency from REAL timestamps only — queued to delivered.
 * Returns null when either is missing; an invented number would be worse.
 */
function latency(queuedAt: string | null, sentAt: string | null): string | null {
  if (!queuedAt || !sentAt) return null
  const ms = Date.parse(sentAt) - Date.parse(queuedAt)
  if (!Number.isFinite(ms) || ms < 0) return null
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms / 60_000)}m`
}

/** When the next retry is due, or null when none is scheduled. */
function nextRetry(iso: string | null): string | null {
  if (!iso) return null
  const ms = Date.parse(iso) - Date.now()
  if (!Number.isFinite(ms)) return null
  if (ms <= 0) return "due now"
  const m = Math.round(ms / 60000)
  return m < 1 ? "in under a minute" : `in ${m}m`
}

export function ExposureAlertsPanel() {
  const [data, setData] = useState<ListResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<number | null>(null)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [timeline, setTimeline] = useState<TimelineEvent[] | null>(null)
  const [page, setPage] = useState(0)
  const [filters, setFilters] = useState({ state: "", severity: "", evidence: "", notification: "", ticket: "" })
  const [suppressFor, setSuppressFor] = useState<number | null>(null)

  const query = useMemo(() => {
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(filters)) if (v) p.set(k, v)
    p.set("limit", String(PAGE_SIZE))
    p.set("offset", String(page * PAGE_SIZE))
    return p.toString()
  }, [filters, page])

  const fetchAlerts = useCallback(async (qs: string) => {
    const res = await fetch(`/api/exposure/alerts?${qs}`)
    if (!res.ok) throw new Error(res.status === 401 ? "Sign in to view alerts." : `Alerts unavailable (${res.status})`)
    return (await res.json()) as ListResponse
  }, [])

  // `loading` starts true, so nothing is set synchronously in the effect body.
  useEffect(() => {
    let cancelled = false
    fetchAlerts(query)
      .then((d) => { if (!cancelled) { setData(d); setError(null) } })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : "Alerts unavailable.") })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [fetchAlerts, query])

  const reload = useCallback(async () => {
    setLoading(true)
    try { setData(await fetchAlerts(query)); setError(null) }
    catch (e) { setError(e instanceof Error ? e.message : "Alerts unavailable.") }
    finally { setLoading(false) }
  }, [fetchAlerts, query])

  // Selection for batch triage. Held as ids rather than objects so it survives
  // a reload of the underlying page of alerts.
  const [checked, setChecked] = useState<Set<number>>(new Set())
  const [bulkBusy, setBulkBusy] = useState(false)
  const [bulkNote, setBulkNote] = useState("")
  // Distinct from `error`, which replaces the whole panel: a failed action must
  // not hide the rows it was acting on.
  const [actionError, setActionError] = useState<string | null>(null)

  function toggleChecked(id: number) {
    setChecked((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  /**
   * Apply one decision to every selected alert.
   *
   * The API reports per id, so a partial batch is reported honestly: "37 of 40"
   * with the reasons, never a bare success. One alert sitting in a state that
   * forbids the transition must not silently swallow the other thirty-nine.
   */
  async function applyBulk(to: string, reason?: string) {
    if (!checked.size) return
    setBulkBusy(true)
    setActionError(null)
    try {
      const res = await fetch("/api/exposure/alerts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ids: [...checked], state: to,
          ...(reason ? { reason } : {}),
          ...(bulkNote.trim() ? { note: bulkNote.trim() } : {}),
        }),
      })
      const d = (await res.json().catch(() => ({}))) as {
        error?: string; applied?: number[]; failed?: Array<{ id: number; error: string }>; requested?: number
      }
      if (!res.ok) { setActionError(d.error ?? `Bulk action failed (${res.status}).`); return }
      const applied = d.applied?.length ?? 0
      if (d.failed?.length) {
        setActionError(
          `${applied} of ${d.requested} updated. ${d.failed.length} could not change: ` +
          d.failed.slice(0, 3).map((f) => `#${f.id} ${f.error}`).join("; ") +
          (d.failed.length > 3 ? "…" : ""),
        )
      }
      setChecked(new Set())
      setBulkNote("")
      await reload()
    } finally { setBulkBusy(false) }
  }

  async function addNote(id: number, text: string) {
    const res = await fetch("/api/exposure/alerts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "note", id, note: text }),
    })
    const d = (await res.json().catch(() => ({}))) as { error?: string }
    if (!res.ok) { setActionError(d.error ?? "Could not save the note."); return false }
    return true
  }

  async function setAssignment(id: number, assign: boolean) {
    const res = await fetch("/api/exposure/alerts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: assign ? "assign" : "unassign", id }),
    })
    const d = (await res.json().catch(() => ({}))) as { error?: string }
    if (!res.ok) { setActionError(d.error ?? "Could not change assignment."); return false }
    await reload()
    return true
  }

  /**
   * Export what is on screen.
   *
   * The filtered queue is what the analyst reasoned about, so that is what gets
   * handed to a manager or pasted into a ticket. Values are quoted and embedded
   * quotes doubled — an unescaped CVE description containing a comma would
   * otherwise silently shift every later column.
   */
  function exportCsv() {
    const rows = data?.alerts ?? []
    if (!rows.length) return
    const cols = ["id","severity","risk_score","asset_key","port","cve_id","evidence_tier","state","assigned_to","notification_state","ticket_state","created_at"] as const
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`
    // CRLF: Excel on Windows is the overwhelmingly common destination for this
    // file, and it treats a bare LF as one long line.
    const EOL = String.fromCharCode(13, 10)
    const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => esc((r as unknown as Record<string, unknown>)[c])).join(","))].join(EOL)
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }))
    const a = document.createElement("a")
    a.href = url
    a.download = `octupus-alerts-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  async function openDetail(a: Alert) {
    setSelected(a)
    setTimeline(null)
    try {
      const res = await fetch(`/api/exposure/alerts/${a.id}`)
      if (res.ok) {
        const d = (await res.json()) as { alert: Alert; timeline: TimelineEvent[] }
        setSelected(d.alert)
        setTimeline(d.timeline)
      }
    } catch { /* detail is an enhancement; the row already shows the essentials */ }
  }

  async function retryNotification(id: number) {
    setBusy(id)
    try {
      const res = await fetch(`/api/exposure/alerts/${id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "retry_notification" }),
      })
      const d = (await res.json().catch(() => ({}))) as { error?: string; outcome?: string }
      if (!res.ok) setError(d.error ?? `Retry failed (${res.status})`)
      else {
        setError(null)
        await reload()
        if (selected?.id === id) await openDetail({ ...selected })
      }
    } finally { setBusy(null) }
  }

  async function act(id: number, to: string, reason?: string) {
    setBusy(id)
    try {
      const res = await fetch("/api/exposure/alerts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, state: to, ...(reason ? { reason } : {}) }),
      })
      if (!res.ok) {
        const d = (await res.json().catch(() => ({}))) as { error?: string }
        setError(d.error ?? `Action failed (${res.status})`)
      } else {
        setError(null)
        setSuppressFor(null)
        await reload()
        if (selected?.id === id) await openDetail({ ...selected, state: to })
      }
    } finally { setBusy(null) }
  }

  if (loading && !data) return <div className="py-10 text-center text-sm text-muted-foreground">Loading alerts…</div>
  if (error && !data) return <Card className="border-red-500/50 bg-red-500/10 p-4 text-sm">⚠️ {error}</Card>
  if (!data) return null

  const { counts, integrations } = data
  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <div className="space-y-4 p-1">
      <div className="rounded-lg border border-border bg-white/5 p-3 text-xs leading-relaxed text-muted-foreground">
        <b className="text-foreground">Exposure-generated SOC alerts.</b> An alert is raised only after a CVE has been
        correlated to an exposed service <i>and</i> scored by the existing RBVM engine — never because a service simply
        appeared. <b>Telegram and ticketing are delivery and workflow layers</b>: they perform no correlation and no
        risk scoring. Findings backed only by a product-name match or a pivot are recorded and visible, but deliberately
        do not raise alerts.
      </div>

      {actionError && (
        <div className="flex items-start justify-between gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-100">
          <span className="leading-relaxed">{actionError}</span>
          <button onClick={() => setActionError(null)} className="shrink-0 text-amber-300/80 hover:text-amber-200" aria-label="Dismiss">✕</button>
        </div>
      )}

      {/* Integration status, stated plainly rather than implied. */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={cn("rounded-full px-2 py-0.5", integrations.telegramConfigured ? "bg-emerald-500/15 text-emerald-300" : "bg-white/5 text-muted-foreground")}>
          Telegram: {integrations.telegramConfigured ? "configured" : "notifications disabled"}
        </span>
        <span className={cn("rounded-full px-2 py-0.5", integrations.ticketingConfigured ? "bg-emerald-500/15 text-emerald-300" : "bg-white/5 text-muted-foreground")}>
          Ticketing: {integrations.ticketingConfigured ? `${integrations.ticketProvider}` : "not configured"}
        </span>
        <Button size="sm" variant="outline" className="ml-auto" onClick={exportCsv} disabled={!data.alerts.length}>
          Export CSV
        </Button>
        <Button size="sm" variant="outline" onClick={() => void reload()} disabled={loading}>
          {loading ? "…" : "Refresh"}
        </Button>
      </div>

      {error && <Card className="border-red-500/50 bg-red-500/10 p-3 text-sm">⚠️ {error}</Card>}

      {/* KPI summary — real counts only. */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {[
          { label: "New", value: counts.state.open ?? 0, cls: "text-red-400" },
          { label: "Critical", value: counts.severity.critical ?? 0, cls: "text-red-400" },
          { label: "High", value: counts.severity.high ?? 0, cls: "text-orange-400" },
          { label: "In progress", value: counts.state.in_progress ?? 0, cls: "text-sky-400" },
          { label: "Suppressed", value: counts.state.suppressed ?? 0, cls: "text-violet-400" },
          { label: "Resolved", value: (counts.state.resolved ?? 0) + (counts.state.closed ?? 0), cls: "text-emerald-400" },
        ].map((m) => (
          <Card key={m.label} className="glass p-3">
            <div className="eyebrow text-[10px]">{m.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tabular-nums", m.cls)}>{m.value}</div>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-white/5 p-3">
        {([
          ["state", "Status", ["open", "acknowledged", "in_progress", "resolved", "closed", "suppressed"]],
          ["severity", "Severity", ["critical", "high", "medium", "low"]],
          ["evidence", "Evidence", ["confirmed", "strong", "product", "weak", "pivot"]],
          ["notification", "Telegram", ["pending", "sent", "retrying", "failed", "disabled"]],
          ["ticket", "Ticket", ["none", "open", "updated", "closed", "failed"]],
        ] as const).map(([key, label, options]) => (
          <label key={key} className="flex items-center gap-1 text-xs text-muted-foreground">
            {label}
            <select
              className="h-7 rounded-md border border-border bg-transparent px-1.5 text-xs"
              value={filters[key]}
              onChange={(e) => { setPage(0); setFilters((f) => ({ ...f, [key]: e.target.value })) }}
            >
              <option value="" className="bg-background">All</option>
              {options.map((o) => <option key={o} value={o} className="bg-background">{o.replace("_", " ")}</option>)}
            </select>
          </label>
        ))}
        <Button size="sm" variant="outline" onClick={() => { setPage(0); setFilters({ state: "", severity: "", evidence: "", notification: "", ticket: "" }) }}>
          Reset
        </Button>
        <span className="ml-auto text-xs text-muted-foreground">{data.total} alert{data.total === 1 ? "" : "s"}</span>
      </div>

      {data.alerts.length === 0 ? (
        <Card className="glass p-10 text-center text-sm text-muted-foreground">
          {Object.values(filters).some(Boolean)
            ? "No alerts match these filters."
            : "No active alerts. Alerts appear when a monitored asset exposes a service that correlates to a CVE with confirmed or version-level evidence."}
        </Card>
      ) : (
        <>
          {checked.size > 0 && (
            <Card className="glass mb-3 border-primary/40 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium">{checked.size} selected</span>
                <input
                  value={bulkNote}
                  onChange={(e) => setBulkNote(e.target.value)}
                  placeholder="Note applied to each (optional)…"
                  className="min-w-[220px] flex-1 rounded-md border border-border bg-background px-2 py-1 text-sm"
                />
                <Button size="sm" disabled={bulkBusy} onClick={() => void applyBulk("acknowledged")}>Acknowledge</Button>
                <Button size="sm" disabled={bulkBusy} onClick={() => void applyBulk("in_progress")}>Start</Button>
                <Button size="sm" disabled={bulkBusy} onClick={() => void applyBulk("resolved")}>Resolve</Button>
                {/* Suppression always carries a reason, in bulk as individually —
                    the audit trail must not become weaker just because the
                    decision covered forty findings instead of one. */}
                <select
                  className="rounded-md border border-border bg-background px-2 py-1 text-sm"
                  defaultValue=""
                  disabled={bulkBusy}
                  onChange={(e) => { if (e.target.value) { void applyBulk("suppressed", e.target.value); e.target.value = "" } }}
                >
                  <option value="">Suppress with reason…</option>
                  {Object.entries(REASON_LABEL).map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
                <Button size="sm" variant="outline" disabled={bulkBusy} onClick={() => setChecked(new Set())}>Clear</Button>
              </div>
            </Card>
          )}

          <Card className="glass overflow-hidden">
            <div className="max-h-[520px] overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 bg-card">
                  <TableRow>
                    <TableHead className="w-8">
                      <input
                        type="checkbox"
                        aria-label="Select all alerts on this page"
                        // Only ever selects THIS page. A select-all that silently
                        // spanned pages would let one click suppress findings the
                        // analyst never saw.
                        checked={data.alerts.length > 0 && data.alerts.every((a) => checked.has(Number(a.id)))}
                        onChange={(e) =>
                          setChecked(e.target.checked ? new Set(data.alerts.map((a) => Number(a.id))) : new Set())
                        }
                        onClick={(e) => e.stopPropagation()}
                      />
                    </TableHead>
                    <TableHead>Severity</TableHead><TableHead>Risk</TableHead><TableHead>Asset</TableHead>
                    <TableHead>CVE</TableHead><TableHead>Evidence</TableHead><TableHead>Provider</TableHead>
                    <TableHead>Freshness</TableHead><TableHead>Status</TableHead><TableHead>Owner</TableHead>
                    <TableHead>Telegram</TableHead><TableHead>Ticket</TableHead><TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.alerts.map((a) => {
                    const ev = EVIDENCE_UI[a.evidence_tier] ?? EVIDENCE_UI.weak
                    const st = STATE_UI[a.state] ?? STATE_UI.open
                    const nt = NOTIFY_UI[a.notification_state] ?? NOTIFY_UI.pending
                    const tk = TICKET_UI[a.ticket_state] ?? TICKET_UI.none
                    const p = a.payload ?? {}
                    return (
                      <TableRow key={a.id} className="cursor-pointer" onClick={() => void openDetail(a)}>
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            aria-label={`Select alert ${a.cve_id} on ${a.asset_key}`}
                            checked={checked.has(Number(a.id))}
                            onChange={() => toggleChecked(Number(a.id))}
                          />
                        </TableCell>
                        <TableCell>
                          <Badge className={cn("border", TONE_CLASS[(a.severity as RiskTone) ?? "low"])}>{a.severity?.toUpperCase()}</Badge>
                          {a.escalation_count > 0 && <span className="ml-1 text-[10px] text-amber-300" title="This alert was escalated.">▲{a.escalation_count}</span>}
                        </TableCell>
                        <TableCell className="tabular-nums">{a.risk_score ?? "—"}</TableCell>
                        <TableCell className="whitespace-nowrap font-mono text-xs">
                          {str(p.asset) ?? a.asset_key}{a.port > 0 ? `:${a.port}` : ""}
                        </TableCell>
                        <TableCell className="whitespace-nowrap font-mono text-xs">{a.cve_id}</TableCell>
                        <TableCell><Badge className={cn("text-[10px]", ev.cls)} title={ev.hint}>{ev.label}</Badge></TableCell>
                        <TableCell className="text-xs">{Array.isArray(p.providers) && p.providers.length ? (p.providers as string[]).join(", ") : "—"}</TableCell>
                        <TableCell className="text-xs uppercase text-muted-foreground">{str(p.freshness) ?? "unknown"}</TableCell>
                        <TableCell><Badge className={cn("text-[10px]", st.cls)}>{st.label}</Badge></TableCell>
                        <TableCell className="whitespace-nowrap text-xs">
                          {a.assigned_to
                            ? <span className="text-emerald-300" title={a.assigned_to}>claimed</span>
                            : <span className="text-muted-foreground">—</span>}
                        </TableCell>
                        <TableCell><Badge className={cn("text-[10px]", nt.cls)} title={a.notify_last_error ?? nt.hint}>{nt.label}</Badge></TableCell>
                        <TableCell className={cn("text-xs", tk.cls)} title={a.ticket_last_error ?? undefined}>
                          {a.ticket_key ?? tk.label}
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{ago(a.created_at)}</TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          </Card>

          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">
              {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, data.total)} of {data.total} · page {page + 1}/{totalPages}
            </span>
            <div className="flex gap-1">
              <Button size="sm" variant="outline" disabled={loading || page <= 0} onClick={() => setPage(0)}>« First</Button>
              <Button size="sm" variant="outline" disabled={loading || page <= 0} onClick={() => setPage((p) => p - 1)}>‹ Prev</Button>
              <Button size="sm" variant="outline" disabled={loading || page >= totalPages - 1} onClick={() => setPage((p) => p + 1)}>Next ›</Button>
            </div>
          </div>
        </>
      )}

      {selected && (
        <AlertDetail
          alert={selected}
          timeline={timeline}
          busy={busy === selected.id}
          suppressOpen={suppressFor === selected.id}
          reasons={data.suppressionReasons}
          integrations={integrations}
          onClose={() => { setSelected(null); setTimeline(null); setSuppressFor(null) }}
          onAct={(to, reason) => void act(selected.id, to, reason)}
          onSuppressOpen={() => setSuppressFor(selected.id)}
          onRetryNotification={() => void retryNotification(selected.id)}
          onAssign={(assign) => void setAssignment(selected.id, assign)}
          onNote={async (text) => {
            const ok = await addNote(selected.id, text)
            if (ok) await openDetail(selected)
            return ok
          }}
        />
      )}
    </div>
  )
}

/**
 * Free-text note on an alert.
 *
 * The state machine records what changed and the suppression list records which
 * of six categories applied. Neither can hold "confirmed with the vendor, patch
 * lands Tuesday" — and that sentence is the whole reason the next analyst does
 * not repeat the investigation.
 */
function NoteComposer({ onNote, busy }: { onNote: (text: string) => Promise<boolean>; busy: boolean }) {
  const [text, setText] = useState("")
  const [saving, setSaving] = useState(false)
  return (
    <div className="mb-4 flex gap-2">
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter" && text.trim() && !saving) void submit() }}
        placeholder="Add an investigation note…"
        className="flex-1 rounded-md border border-border bg-background px-2 py-1 text-sm"
        maxLength={4000}
      />
      <Button size="sm" disabled={!text.trim() || saving || busy} onClick={() => void submit()}>
        {saving ? "Saving…" : "Add note"}
      </Button>
    </div>
  )

  async function submit() {
    setSaving(true)
    try {
      // Cleared only on success, so a failed save does not silently discard
      // what the analyst wrote.
      if (await onNote(text.trim())) setText("")
    } finally { setSaving(false) }
  }
}

function AlertDetail({
  alert, timeline, busy, suppressOpen, reasons, integrations, onClose, onAct, onSuppressOpen, onRetryNotification,
  onAssign, onNote,
}: {
  alert: Alert
  timeline: TimelineEvent[] | null
  busy: boolean
  suppressOpen: boolean
  reasons: string[]
  integrations: ListResponse["integrations"]
  onClose: () => void
  onAct: (to: string, reason?: string) => void
  onSuppressOpen: () => void
  onRetryNotification: () => void
  onAssign: (assign: boolean) => void
  onNote: (text: string) => Promise<boolean>
}) {
  const p = alert.payload ?? {}
  const ev = EVIDENCE_UI[alert.evidence_tier] ?? EVIDENCE_UI.weak
  const actions = ACTIONS[alert.state] ?? []

  return (
    <Card className="glass p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Badge className={cn("border", TONE_CLASS[(alert.severity as RiskTone) ?? "low"])}>{alert.severity?.toUpperCase()}</Badge>
        <Badge className={ev.cls} title={ev.hint}>{ev.label}</Badge>
        <span className="font-mono text-sm text-foreground">ALT-{alert.id} · {alert.cve_id}</span>
        <Badge className={cn("text-[10px]", (STATE_UI[alert.state] ?? STATE_UI.open).cls)}>
          {(STATE_UI[alert.state] ?? STATE_UI.open).label}
        </Badge>
        <Button
          size="sm"
          variant={alert.assigned_to ? "outline" : "default"}
          className="ml-auto"
          onClick={() => onAssign(!alert.assigned_to)}
          disabled={busy}
          // Claiming is how a shared queue avoids two analysts investigating the
          // same finding without either knowing.
          title={alert.assigned_to ? `Claimed by ${alert.assigned_to}` : "Claim this alert"}
        >
          {alert.assigned_to ? "Release" : "Claim"}
        </Button>
        <Button size="sm" variant="outline" onClick={onClose}>Close</Button>
      </div>

      <NoteComposer onNote={onNote} busy={busy} />

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <div className="eyebrow mb-2 text-[10px]">Investigation context</div>
          <dl className="space-y-1 text-xs">
            <Row label="Asset" value={str(p.asset) ?? alert.asset_key} mono />
            <Row label="Service" value={alert.port > 0 ? `${alert.port}/tcp` : "host-level"} mono />
            <Row label="Product" value={str(p.product) ?? "not reported"} />
            <Row label="Version" value={str(p.version) ?? "not reported"} />
            <Row label="Provider evidence" value={Array.isArray(p.providers) && p.providers.length ? (p.providers as string[]).join(", ") : "none recorded"} />
            <Row label="RBVM risk" value={alert.risk_score == null ? "—" : `${alert.risk_score} / ${alert.severity}`} />
            <Row label="CVSS" value={p.cvss == null ? "UNKNOWN" : String(p.cvss)} />
            <Row label="EPSS" value={p.epss == null ? "UNKNOWN" : String(p.epss)} />
            <Row label="KEV" value={p.isKev == null ? "UNKNOWN" : p.isKev ? "YES" : "No"} />
            <Row label="Public exploit" value={p.hasExploit == null ? "UNKNOWN" : p.hasExploit ? "YES" : "No"} />
            {/* Freshness stays a separate dimension from evidence. */}
            <Row label="Freshness" value={(str(p.freshness) ?? "unknown").toUpperCase()} />
            <Row label="Provider observed" value={str(p.observedAt) ? new Date(str(p.observedAt)!).toLocaleString("en-US") : "not supplied"} />
            <Row label="OCTUPUS retrieved" value={str(p.fetchedAt) ? new Date(str(p.fetchedAt)!).toLocaleString("en-US") : "—"} />
            <Row label="Telegram" value={
              integrations.telegramConfigured
                ? `${(NOTIFY_UI[alert.notification_state] ?? NOTIFY_UI.pending).label}${alert.notify_attempts ? ` (${alert.notify_attempts} attempt${alert.notify_attempts > 1 ? "s" : ""})` : ""}`
                : "notifications disabled"
            } />
            {/* Latency is computed from two recorded timestamps, never estimated. */}
            {latency(alert.notify_first_queued_at, alert.notified_at) && (
              <Row label="Delivery latency" value={latency(alert.notify_first_queued_at, alert.notified_at)!} />
            )}
            {alert.notified_at && <Row label="Delivered at" value={new Date(alert.notified_at).toLocaleString("en-US")} />}
            {nextRetry(alert.notify_next_attempt_at) && alert.notification_state !== "sent" && (
              <Row label="Next retry" value={nextRetry(alert.notify_next_attempt_at)!} />
            )}
            {alert.notify_last_error && <Row label="Delivery error" value={alert.notify_last_error} />}
            <Row label="Ticket" value={
              integrations.ticketingConfigured
                ? alert.ticket_key ?? (TICKET_UI[alert.ticket_state] ?? TICKET_UI.none).label
                : "ticketing not configured"
            } />
            {alert.suppressed_reason && (
              <Row label="Suppressed" value={`${REASON_LABEL[alert.suppressed_reason] ?? alert.suppressed_reason} · by ${alert.suppressed_by ?? "unknown"}`} />
            )}
          </dl>
          {str(p.why) && (
            <p className="mt-2 rounded border border-border bg-white/5 p-2 text-xs text-muted-foreground">
              <b className="text-foreground">Why:</b> {str(p.why)}
            </p>
          )}
        </div>

        <div>
          <div className="eyebrow mb-2 text-[10px]">Timeline</div>
          {timeline === null ? (
            <p className="text-xs text-muted-foreground">Loading…</p>
          ) : timeline.length === 0 ? (
            <p className="text-xs text-muted-foreground">No events recorded.</p>
          ) : (
            <ol className="space-y-1.5 text-xs">
              {timeline.map((e) => (
                <li key={e.id} className="flex gap-2">
                  <span className="w-28 shrink-0 text-muted-foreground">
                    {new Date(e.occurred_at).toLocaleString("en-US", { hour: "2-digit", minute: "2-digit", month: "short", day: "numeric" })}
                  </span>
                  <span className="min-w-0">
                    <b className="text-foreground">{e.type.replace(/_/g, " ")}</b>
                    <span className="text-muted-foreground"> · {e.actor}</span>
                    {e.detail && <span className="block break-words text-muted-foreground">{e.detail}</span>}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-border pt-3">
        {actions.length === 0 && <span className="text-xs text-muted-foreground">This alert is closed. No further transitions are permitted.</span>}
        {/* Manual retry: only where a retry is actually meaningful. A delivered
            message is never re-sendable, and an in-flight one is never
            interruptible. */}
        {integrations.telegramConfigured
          && ["failed", "retrying", "disabled", "pending"].includes(alert.notification_state) && (
          <Button size="sm" variant="outline" disabled={busy} onClick={onRetryNotification}
            title="Requeue and attempt delivery now. Does not change the alert or create a new one.">
            Retry notification
          </Button>
        )}
        {actions.map((a) => (
          a.to === "suppressed" ? (
            <Button key={a.to} size="sm" variant="outline" disabled={busy} onClick={onSuppressOpen}>{a.label}</Button>
          ) : (
            <Button key={a.to} size="sm" variant="outline" disabled={busy} onClick={() => onAct(a.to)}>{a.label}</Button>
          )
        ))}
      </div>

      {suppressOpen && (
        <div className="mt-3 rounded border border-violet-500/40 bg-violet-500/10 p-3">
          {/* Suppression is accountable: a reason is required by the server too. */}
          <p className="mb-2 text-xs text-muted-foreground">
            Choose a reason. Suppression stops notifications for this alert; it does <b>not</b> remove the underlying
            vulnerability, which stays visible in the exposure data.
          </p>
          <div className="flex flex-wrap gap-1.5">
            {reasons.map((r) => (
              <Button key={r} size="sm" variant="outline" disabled={busy} onClick={() => onAct("suppressed", r)}>
                {REASON_LABEL[r] ?? r}
              </Button>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <dt className="w-36 shrink-0 text-muted-foreground">{label}</dt>
      <dd className={cn("min-w-0 break-words", mono && "font-mono")}>{value}</dd>
    </div>
  )
}
