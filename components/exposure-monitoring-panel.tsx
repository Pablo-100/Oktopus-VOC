"use client"

import { useCallback, useEffect, useState } from "react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"

/**
 * Operational view of PERIODIC monitoring.
 *
 * Deliberately not called "real-time": the scheduler re-queries each provider's
 * LATEST INDEXED observation on a cadence. Nothing here scans a host on demand,
 * and the UI must never imply that it does.
 */

interface MonitoringRow {
  asset_key: string
  target: string
  enabled: boolean
  interval_seconds: number
  last_attempt_at: string | null
  last_success_at: string | null
  next_run_at: string
  last_status: string | null
  last_error: string | null
  consecutive_failures: number
  locked_at: string | null
}

interface RunLog {
  run_id: string; asset_key: string; status: string
  providers_succeeded: number; providers_failed: number
  events_created: number; duration_ms: number; completed_at: string; error: string | null
}

interface ChangeLog {
  asset_key: string; kind: string; detail: string
  before_val: string | null; after_val: string | null; occurred_at: string
}

interface Overview {
  totalMonitored: number; enabled: number; paused: number; dueNow: number
  failing: number; deferred: number
  lastRunAt: string | null; lastSuccessAt: string | null; lastFailureAt: string | null
  assets: MonitoringRow[]; recentRuns: RunLog[]; recentChanges: ChangeLog[]
  quota: Array<{ provider: string; used: number; budget: number }>
  maxAssetsPerRun: number
}

/** Status vocabulary. Deferral and partial success are NOT failures. */
const STATUS_UI: Record<string, { label: string; cls: string; hint: string }> = {
  success: { label: "Success", cls: "bg-emerald-500/15 text-emerald-300", hint: "Every configured provider responded." },
  partial: { label: "Partial", cls: "bg-sky-500/15 text-sky-300", hint: "At least one provider responded; the asset was genuinely refreshed." },
  quota_deferred: { label: "Deferred", cls: "bg-amber-500/15 text-amber-300", hint: "Providers were quota-limited. Nothing is wrong with this asset — it retries shortly." },
  no_provider: { label: "No provider", cls: "bg-white/5 text-muted-foreground", hint: "No provider was configured or reachable for this asset." },
  failed: { label: "Failed", cls: "bg-red-500/15 text-red-300", hint: "No provider returned data and the cause was not quota." },
  // Not a fault and not a quota problem: the entitlement to monitor this target
  // no longer holds. Rendered distinctly so it is not read as an outage — the
  // fix is to verify a domain, not to retry.
  unauthorized: {
    label: "Paused — verify domain",
    cls: "bg-amber-500/15 text-amber-300",
    hint: "Monitoring is paused because no verified domain covers this target. Verify a domain under Account and it resumes automatically.",
  },
}

const INTERVAL_LABEL: Array<[number, string]> = [
  [3600, "Hourly"], [6 * 3600, "Every 6h"], [24 * 3600, "Daily"], [7 * 24 * 3600, "Weekly"],
]
function intervalLabel(seconds: number): string {
  const hit = INTERVAL_LABEL.find(([s]) => s === seconds)
  if (hit) return hit[1]
  if (seconds % 3600 === 0) return `Every ${seconds / 3600}h`
  return `Every ${Math.round(seconds / 60)}m`
}

function relative(iso: string | null): string {
  if (!iso) return "never"
  const diff = Date.now() - Date.parse(iso)
  const abs = Math.abs(diff)
  const m = Math.round(abs / 60000)
  const unit = m < 1 ? "just now" : m < 60 ? `${m}m` : m < 1440 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`
  if (unit === "just now") return unit
  return diff >= 0 ? `${unit} ago` : `in ${unit}`
}

export function ExposureMonitoringPanel() {
  const [data, setData] = useState<Overview | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Separate from `error`: a failed ACTION must not replace the whole panel
  // with an error card, which would hide the very rows being acted on.
  const [actionError, setActionError] = useState<string | null>(null)
  const [busyKey, setBusyKey] = useState<string | null>(null)

  // Pure fetch — no state writes, so it can be called from an effect body
  // without synchronously setting state during render (matches /exposure).
  const fetchOverview = useCallback(async (): Promise<Overview> => {
    const res = await fetch("/api/exposure/monitoring")
    if (!res.ok) throw new Error(res.status === 401 ? "Sign in to view monitoring." : `Monitoring unavailable (${res.status})`)
    return (await res.json()) as Overview
  }, [])

  // `loading` starts true, so the initial load needs no synchronous pre-set.
  useEffect(() => {
    let cancelled = false
    fetchOverview()
      .then((d) => { if (!cancelled) { setData(d); setError(null) } })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : "Monitoring unavailable.") })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [fetchOverview])

  /** Explicit user-triggered reload (button, or after a pause/resume write). */
  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await fetchOverview())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Monitoring unavailable.")
    } finally {
      setLoading(false)
    }
  }, [fetchOverview])

  async function toggle(row: MonitoringRow) {
    setBusyKey(row.asset_key)
    setActionError(null)
    try {
      // The response was previously discarded, so a refusal — a 403 for an
      // unverified domain, a 400, a 500 — was indistinguishable from success:
      // the row silently stayed as it was and the user was told nothing.
      const res = await fetch("/api/exposure/monitoring", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assetKey: row.asset_key, target: row.target,
          enabled: !row.enabled, intervalSeconds: row.interval_seconds,
        }),
      })
      if (!res.ok) {
        const d = (await res.json().catch(() => ({}))) as {
          error?: string
          code?: string
          help?: { why?: string; how?: string }
        }
        setActionError(
          d.code === "ownership_required"
            ? `${d.error ?? "Not authorised."} ${d.help?.how ?? ""}`.trim()
            : (d.error ?? `Could not update monitoring (${res.status}).`),
        )
        return
      }
      await load()
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Could not update monitoring.")
    } finally { setBusyKey(null) }
  }

  if (loading && !data) return <div className="py-10 text-center text-sm text-muted-foreground">Loading monitoring state…</div>
  if (error) return <Card className="border-red-500/50 bg-red-500/10 p-4 text-sm">⚠️ {error}</Card>
  if (!data) return null

  const assets = data.assets
  const failingAssets = assets.filter((a) => a.consecutive_failures > 0)

  return (
    <div className="space-y-5 p-1">
      {actionError && (
        <div className="flex items-start justify-between gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-100">
          <span className="leading-relaxed">{actionError}</span>
          <button onClick={() => setActionError(null)} className="shrink-0 text-amber-300/80 hover:text-amber-200" aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}

      {/* What this is — stated plainly, because "monitoring" is easy to over-read. */}
      <div className="rounded-lg border border-border bg-white/5 p-3 text-xs leading-relaxed text-muted-foreground">
        <b className="text-foreground">Periodic monitoring, not real-time.</b> Enabled assets are re-queried on a schedule.
        Each run asks every provider for its <b>latest indexed observation</b> and compares it with the previous snapshot;
        differences become change events. No configured provider scans a host on demand, so a change is detected when the
        provider re-indexes it — not the instant it happens. Monitoring is <b>opt-in per asset</b> and processes at most{" "}
        <b className="text-foreground">{data.maxAssetsPerRun}</b> assets per run to bound provider cost.
      </div>

      {/* Operational counters */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {[
          { label: "Monitored", value: data.totalMonitored, cls: "text-foreground" },
          { label: "Active", value: data.enabled, cls: "text-emerald-400" },
          { label: "Paused", value: data.paused, cls: "text-muted-foreground" },
          { label: "Due now", value: data.dueNow, cls: "text-sky-400" },
          { label: "Deferred", value: data.deferred, cls: "text-amber-400" },
          { label: "Failing", value: data.failing, cls: "text-red-400" },
        ].map((m) => (
          <Card key={m.label} className="glass p-3">
            <div className="eyebrow text-[10px]">{m.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tabular-nums", m.cls)}>{m.value}</div>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Last run */}
        <Card className="glass p-4">
          <div className="eyebrow mb-2 text-[10px]">Scheduler</div>
          <dl className="space-y-1.5 text-sm">
            <div className="flex justify-between gap-2"><dt className="text-muted-foreground">Last run</dt><dd>{relative(data.lastRunAt)}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-muted-foreground">Last success</dt><dd className="text-emerald-300">{relative(data.lastSuccessAt)}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-muted-foreground">Last failure</dt><dd className={data.lastFailureAt ? "text-red-300" : ""}>{relative(data.lastFailureAt)}</dd></div>
          </dl>
          {!data.lastRunAt && (
            <p className="mt-3 text-xs text-muted-foreground">
              No run recorded yet. The worker is triggered externally (GitHub Actions → <code className="font-mono">/api/exposure/monitoring/run</code>);
              with no assets enabled it does nothing and spends no quota.
            </p>
          )}
        </Card>

        {/* Provider quota — the real constraint on how often anything can run */}
        <Card className="glass p-4 lg:col-span-2">
          <div className="eyebrow mb-2 text-[10px]">Provider quota (current hour)</div>
          {data.quota.length === 0 ? (
            <p className="text-xs text-muted-foreground">No quota accounting recorded this hour.</p>
          ) : (
            <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3">
              {data.quota.map((q) => {
                const pct = q.budget > 0 ? Math.min(100, Math.round((q.used / q.budget) * 100)) : 0
                return (
                  <div key={q.provider}>
                    <div className="flex justify-between text-xs">
                      <span className="capitalize">{q.provider}</span>
                      <span className="tabular-nums text-muted-foreground">{q.used}/{q.budget}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/10">
                      <div className={cn("h-full rounded-full", pct >= 90 ? "bg-red-500" : pct >= 60 ? "bg-amber-500" : "bg-emerald-500")} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </Card>
      </div>

      {/* Monitored assets */}
      <Card className="glass overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="eyebrow text-[10px]">Monitored assets</div>
          <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</Button>
        </div>
        <div className="max-h-[420px] overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-card">
              <TableRow>
                <TableHead>Asset</TableHead><TableHead>State</TableHead><TableHead>Interval</TableHead>
                <TableHead>Last attempt</TableHead><TableHead>Last success</TableHead>
                <TableHead>Next run</TableHead><TableHead>Outcome</TableHead><TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {assets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-10 text-center text-sm text-muted-foreground">
                    No asset is monitored yet. Open any asset and choose <b className="text-foreground">Monitor this asset</b> to schedule it.
                  </TableCell>
                </TableRow>
              ) : assets.map((a) => {
                const ui = a.last_status ? STATUS_UI[a.last_status] : null
                return (
                  <TableRow key={a.asset_key}>
                    <TableCell className="whitespace-nowrap font-mono text-xs">{a.target}</TableCell>
                    <TableCell>
                      {a.enabled
                        ? <Badge className="bg-emerald-500/15 text-emerald-300">Active</Badge>
                        : <Badge variant="outline" className="text-muted-foreground">Paused</Badge>}
                      {a.locked_at && <Badge className="ml-1 bg-sky-500/15 text-sky-300" title="A scheduler run currently holds this asset.">Running</Badge>}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs">{intervalLabel(a.interval_seconds)}</TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{relative(a.last_attempt_at)}</TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{relative(a.last_success_at)}</TableCell>
                    <TableCell className="whitespace-nowrap text-xs">{a.enabled ? relative(a.next_run_at) : "—"}</TableCell>
                    <TableCell>
                      {ui
                        ? <Badge className={ui.cls} title={a.last_error ? `${ui.hint}\n${a.last_error}` : ui.hint}>{ui.label}</Badge>
                        : <span className="text-xs text-muted-foreground">Not yet run</span>}
                      {a.consecutive_failures > 0 && (
                        <span className="ml-1 text-[10px] text-red-300" title="Consecutive failures — the retry interval backs off after each one.">
                          ×{a.consecutive_failures}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="outline" disabled={busyKey === a.asset_key} onClick={() => void toggle(a)}>
                        {busyKey === a.asset_key ? "…" : a.enabled ? "Pause" : "Resume"}
                      </Button>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      </Card>

      {/* Assets needing attention — separated from healthy deferrals */}
      {failingAssets.length > 0 && (
        <Card className="glass border-red-500/30 p-4">
          <div className="eyebrow mb-2 text-[10px] text-red-300">Assets needing attention</div>
          <ul className="space-y-1.5 text-xs">
            {failingAssets.map((a) => (
              <li key={a.asset_key} className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-foreground">{a.target}</span>
                <span className="text-red-300">{a.consecutive_failures} consecutive failure{a.consecutive_failures > 1 ? "s" : ""}</span>
                {a.last_error && <span className="text-muted-foreground">· {a.last_error}</span>}
                <span className="text-muted-foreground">· retries {relative(a.next_run_at)}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Changes actually produced by monitoring */}
        <Card className="glass overflow-hidden">
          <div className="border-b border-border px-4 py-3"><div className="eyebrow text-[10px]">Recent changes detected</div></div>
          <div className="max-h-[300px] overflow-auto p-4">
            {data.recentChanges.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No change events recorded. A first run only establishes the baseline snapshot — events appear from the second run onward,
                and only when the asset genuinely changed.
              </p>
            ) : (
              <ul className="space-y-2 text-xs">
                {data.recentChanges.map((c, i) => (
                  <li key={`${c.asset_key}-${i}`} className="flex flex-wrap items-baseline gap-2">
                    <Badge variant="outline" className="font-mono text-[10px]">{c.kind}</Badge>
                    <span className="font-mono text-muted-foreground">{c.asset_key.replace(/^(ip|domain):/, "")}</span>
                    <span className="text-foreground">{c.detail}</span>
                    <span className="ml-auto whitespace-nowrap text-muted-foreground">{relative(c.occurred_at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>

        {/* Execution log */}
        <Card className="glass overflow-hidden">
          <div className="border-b border-border px-4 py-3"><div className="eyebrow text-[10px]">Recent runs</div></div>
          <div className="max-h-[300px] overflow-auto p-4">
            {data.recentRuns.length === 0 ? (
              <p className="text-xs text-muted-foreground">No runs recorded yet.</p>
            ) : (
              <ul className="space-y-2 text-xs">
                {data.recentRuns.map((r, i) => {
                  const ui = STATUS_UI[r.status]
                  return (
                    <li key={`${r.run_id}-${i}`} className="flex flex-wrap items-baseline gap-2">
                      <Badge className={cn("text-[10px]", ui?.cls ?? "bg-white/5")} title={ui?.hint}>{ui?.label ?? r.status}</Badge>
                      <span className="font-mono text-muted-foreground">{r.asset_key.replace(/^(ip|domain):/, "")}</span>
                      <span className="text-muted-foreground">{r.providers_succeeded} ok / {r.providers_failed} failed</span>
                      {r.events_created > 0 && <span className="text-amber-300">{r.events_created} change{r.events_created > 1 ? "s" : ""}</span>}
                      <span className="ml-auto whitespace-nowrap text-muted-foreground">{relative(r.completed_at)}</span>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}
