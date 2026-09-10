/**
 * Periodic Exposure Monitoring — scheduler core (server-only).
 *
 * NOT real-time. This revisits assets on a schedule and compares what each
 * provider currently reports against the last stored snapshot. Provider
 * observation times remain whatever the provider says; the scheduler only ever
 * moves `fetchedAt`.
 *
 * ARCHITECTURAL RULES (deliberate, load-bearing):
 *  - ONE refresh implementation: this calls `refreshAsset()`, the exact function
 *    the manual "Refresh now" button uses. Provider orchestration, quota,
 *    Censys concurrency-1 and failure handling are inherited, never duplicated.
 *  - ONE quota system: `reserveQuota` inside the provider adapters stays
 *    authoritative. The scheduler performs a *pre-flight* check to avoid
 *    starting work it cannot finish, but never bypasses the real gate.
 *  - ONE snapshot/event system: `recordAssetChanges()` (inside `refreshAsset`)
 *    owns `exposure_asset_state` and `exposure_events`.
 *
 * RUNTIME MODEL: short-lived invocation. The deployment is Vercel serverless
 * with `maxDuration = 60`; there is no persistent worker, so no `setInterval`,
 * no in-memory queue. A platform scheduler calls the endpoint frequently and
 * this worker decides which assets are actually due:
 *
 *    invocation -> claim bounded batch -> process -> persist -> exit
 */
import { sql, initDb } from "@/lib/db"
import { refreshAsset } from "@/lib/exposure/orchestrator"
import { quotaUsage } from "@/lib/exposure/quota"
import { redactSecrets } from "@/lib/exposure/providers/_base"
import type { ProviderOutcome } from "@/lib/exposure/types"
import { isTargetAuthorized } from "@/lib/exposure/ownership"

/** Outcome of processing ONE asset. Quota deferral is NOT a failure. */
export type MonitoringStatus =
  | "success"
  | "partial"
  | "failed"
  | "quota_deferred"
  | "no_provider"
  // The user is no longer entitled to monitor this target: they never verified
  // it, or the DNS record that authorised it has been withdrawn.
  | "unauthorized"

export interface MonitoringRow {
  user_id: string
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
  locked_by: string | null
}

export interface MonitoringRunResult {
  runId: string
  scanned: number
  succeeded: number
  partial: number
  failed: number
  skippedQuota: number
  /** Assets skipped because entitlement to monitor them no longer holds. */
  skippedUnauthorized: number
  eventsCreated: number
  durationMs: number
  assets: Array<{ assetKey: string; target: string; status: MonitoringStatus; events: number; error?: string }>
}

/** Supported cadences. Stored as SECONDS so new intervals need no enum changes. */
export const MONITORING_INTERVALS = {
  hourly: 3600,
  every6h: 6 * 3600,
  daily: 24 * 3600,
  weekly: 7 * 24 * 3600,
} as const
export type MonitoringIntervalName = keyof typeof MONITORING_INTERVALS
export const DEFAULT_INTERVAL_SECONDS = MONITORING_INTERVALS.every6h

/** Hard ceilings — cost/quota protection (env-overridable, clamped). */
export function maxAssetsPerRun(): number {
  const raw = Number(process.env.EXPOSURE_MONITOR_MAX_ASSETS_PER_RUN)
  const v = Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 5
  // Upper bound is a safety rail: maxDuration is 60s and each asset costs up
  // to 3 sequential-ish provider calls, so a large batch would simply time out.
  return Math.min(v, 25)
}

/**
 * A lease longer than any plausible run. If an invocation dies mid-flight the
 * asset becomes claimable again after this, rather than being stuck forever.
 */
const LOCK_LEASE_SECONDS = 10 * 60

/** Backoff after consecutive failures — bounded, so an outage cannot cause a retry storm. */
export function backoffSeconds(consecutiveFailures: number, intervalSeconds: number): number {
  if (consecutiveFailures <= 0) return intervalSeconds
  // 5min, 10, 20, 40 … capped at 6h AND never longer than the normal interval
  // would be if that interval is itself short.
  const base = 5 * 60
  const grown = base * 2 ** Math.min(consecutiveFailures - 1, 6)
  return Math.min(grown, 6 * 3600, Math.max(intervalSeconds, base))
}

/** Quota-deferred assets retry soon — nothing is wrong with them. */
const QUOTA_DEFER_SECONDS = 15 * 60

/**
 * Atomically claim a bounded batch of due assets.
 *
 * `FOR UPDATE SKIP LOCKED` is what makes two concurrent scheduler invocations
 * mutually exclusive: the second skips rows the first has locked within the
 * same statement, so an asset can never be claimed twice. Writing `locked_by`
 * in the same statement makes the claim durable beyond the transaction, which
 * a plain row lock could not do across the long provider calls that follow.
 *
 * The selection MUST be a materialized CTE joined to the UPDATE, never
 * `WHERE asset_key IN (SELECT … LIMIT n FOR UPDATE SKIP LOCKED)`. `FOR UPDATE`
 * makes that subquery non-hashable, so the planner may re-execute it once per
 * candidate outer row; each re-execution skips the rows just locked and
 * returns a *different* one, letting a single statement claim far more than
 * `limit` assets. That was observed intermittently in tests and would silently
 * break the per-run cost bound. A CTE is evaluated exactly once, so at most
 * `limit` rows are ever locked.
 */
export async function claimDueAssets(runId: string, limit: number): Promise<MonitoringRow[]> {
  const rows = (await sql`
    WITH ranked AS (
      -- FAIRNESS ACROSS TENANTS.
      -- Ordering purely by next_run_at let one user with hundreds of overdue
      -- assets consume every batch forever, starving everyone else on a shared
      -- provider budget. Ranking within each user and taking the oldest first
      -- across users gives round-robin: each tenant contributes its most
      -- overdue asset before any tenant contributes its second.
      SELECT user_id, asset_key, next_run_at,
             ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY next_run_at ASC) AS rn
      FROM exposure_monitoring
      WHERE enabled = true
        AND next_run_at <= now()
        AND (locked_at IS NULL OR locked_at < now() - (${LOCK_LEASE_SECONDS}::text || ' seconds')::interval)
    ),
    due AS (
      SELECT user_id, asset_key FROM ranked
      ORDER BY rn ASC, next_run_at ASC
      LIMIT ${limit}
      FOR UPDATE SKIP LOCKED
    )
    UPDATE exposure_monitoring m
    SET locked_at = now(), locked_by = ${runId}, updated_at = now()
    FROM due
    WHERE m.user_id = due.user_id AND m.asset_key = due.asset_key
    RETURNING m.*
  `) as MonitoringRow[]
  return rows
}

/** True when a scheduler run currently holds a live lease on this asset. */
export async function isAssetLocked(assetKey: string, userId: string): Promise<boolean> {
  const rows = (await sql`
    SELECT 1 FROM exposure_monitoring
    WHERE user_id = ${userId} AND asset_key = ${assetKey}
      AND locked_at IS NOT NULL
      AND locked_at >= now() - (${LOCK_LEASE_SECONDS}::text || ' seconds')::interval
  `) as unknown[]
  return rows.length > 0
}

/** Release a claim and schedule the next run according to the outcome. */
async function releaseAsset(
  row: MonitoringRow,
  status: MonitoringStatus,
  error: string | null,
): Promise<void> {
  const isFailure = status === "failed"
  const isDeferral =
    status === "quota_deferred" || status === "no_provider" || status === "unauthorized"
  const failures = isFailure ? row.consecutive_failures + 1 : 0

  const delaySeconds = isDeferral
    ? QUOTA_DEFER_SECONDS
    : isFailure
      ? backoffSeconds(failures, row.interval_seconds)
      : row.interval_seconds

  // `last_success_at` advances ONLY on a real success, and is preserved
  // otherwise. This is a CASE inside the single UPDATE rather than a
  // write-then-restore pair: two statements would leave a window in which a
  // successful asset appears to have never succeeded.
  const didSucceed = status === "success" || status === "partial"

  await sql`
    UPDATE exposure_monitoring
    SET locked_at = NULL,
        locked_by = NULL,
        last_attempt_at = now(),
        last_success_at = CASE WHEN ${didSucceed} THEN now() ELSE last_success_at END,
        last_status = ${status},
        last_error = ${error},
        consecutive_failures = ${failures},
        next_run_at = now() + (${delaySeconds}::text || ' seconds')::interval,
        updated_at = now()
    WHERE user_id = ${row.user_id} AND asset_key = ${row.asset_key}
  `
}

/** Pre-flight quota view. Prevents starting work we know cannot reach a provider. */
async function anyQuotaAvailable(): Promise<boolean> {
  try {
    const usage = await quotaUsage()
    if (!usage.length) return true // no bookkeeping available -> fail open
    // Enrichment needs at least one of the enrichment/threat providers.
    return usage.some((u) => ["censys", "netlas", "greynoise"].includes(u.provider) && u.used < u.budget)
  } catch {
    return true
  }
}

/** Classify a refresh outcome from the provider results. Partial success is NOT failure. */
export function classifyRefresh(providers: ProviderOutcome[]): { status: MonitoringStatus; error: string | null } {
  if (!providers.length) return { status: "no_provider", error: "No provider was contacted." }
  const ok = providers.filter((p) => p.status === "success" || p.status === "partial")
  const quota = providers.filter((p) => p.status === "quota_exhausted" || p.status === "rate_limited")
  const configured = providers.filter((p) => p.status !== "not_configured")

  if (ok.length && ok.length === configured.length) return { status: "success", error: null }
  if (ok.length) {
    // At least one provider delivered — the asset was genuinely refreshed.
    // Reporting this as FAILED would discard real evidence and trigger backoff.
    const failed = providers.filter((p) => !ok.includes(p) && p.status !== "not_configured")
    return { status: "partial", error: failed.length ? `${failed.length} provider(s) unavailable: ${failed.map((f) => `${f.provider}=${f.status}`).join(", ")}` : null }
  }
  if (quota.length && quota.length === configured.length) {
    // Nothing succeeded and the reason is purely quota — defer, do not penalise.
    return { status: "quota_deferred", error: quota.map((q) => `${q.provider}=${q.status}`).join(", ") }
  }
  if (!configured.length) return { status: "no_provider", error: "No provider configured." }
  return { status: "failed", error: providers.map((p) => `${p.provider}=${p.status}`).join(", ") }
}

/** Record one asset's execution for observability. Normalized metadata only. */
async function logRun(
  runId: string,
  row: MonitoringRow,
  startedAt: Date,
  status: MonitoringStatus,
  providers: ProviderOutcome[],
  eventsCreated: number,
  error: string | null,
): Promise<void> {
  try {
    const attempted = providers.length
    const succeeded = providers.filter((p) => p.status === "success" || p.status === "partial").length
    const failed = providers.filter((p) => !["success", "partial", "not_configured"].includes(p.status)).length
    const deferrals = providers.filter((p) => p.status === "quota_exhausted" || p.status === "rate_limited").length
    await sql`
      INSERT INTO exposure_monitoring_runs
        (run_id, user_id, asset_key, started_at, status, providers_attempted, providers_succeeded, providers_failed, quota_deferrals, events_created, duration_ms, error)
      VALUES (${runId}, ${row.user_id}, ${row.asset_key}, ${startedAt.toISOString()}, ${status}, ${attempted}, ${succeeded}, ${failed}, ${deferrals}, ${eventsCreated}, ${Date.now() - startedAt.getTime()}, ${error})
    `
  } catch (e) {
    console.error("[exposure-monitoring] run log failed:", e instanceof Error ? e.message : String(e))
  }
}

/**
 * Process one claimed asset. Always releases the claim, even on an unexpected
 * throw — otherwise a bug would leave the asset locked until the lease expires.
 */
async function processAsset(runId: string, row: MonitoringRow): Promise<{ status: MonitoringStatus; events: number; error?: string }> {
  const startedAt = new Date()
  let status: MonitoringStatus = "failed"
  let error: string | null = null
  let events = 0
  let providers: ProviderOutcome[] = []

  try {
    // Entitlement is re-checked on every cycle, not only when monitoring was
    // switched on. Two reasons: rows enabled before this rule existed would
    // otherwise be grandfathered in forever, and an authorisation that rests on
    // a DNS record must stop applying when that record is withdrawn. The asset
    // is SKIPPED, never deleted — the user keeps their configuration and can
    // re-verify, and the reason is recorded where they will see it.
    const auth = await isTargetAuthorized(row.user_id, row.target)
    if (!auth.allowed) {
      status = "unauthorized"
      error = `Monitoring paused: ${auth.reason} Verify the domain under Account to resume.`
      return { status, events: 0, error }
    }

    // THE single refresh implementation — identical to the manual button.
    // It bypasses the search cache and runs snapshot/change detection.
    const result = await refreshAsset(row.target, row.user_id)
    providers = result.providers
    const classified = classifyRefresh(providers)
    status = classified.status
    error = classified.error ? redactSecrets(classified.error) : null
    events = result.changes.length
  } catch (e) {
    status = "failed"
    // Defence in depth: this message is persisted and surfaced in the
    // monitoring UI, so it is scrubbed even though provider errors are already
    // redacted at the source. An unexpected throw can come from anywhere.
    error = redactSecrets(e instanceof Error ? e.message : String(e))
  } finally {
    await releaseAsset(row, status, error).catch((e) =>
      console.error("[exposure-monitoring] release failed:", e instanceof Error ? e.message : String(e)))
    await logRun(runId, row, startedAt, status, providers, events, error)
  }
  return { status, events, error: error ?? undefined }
}

/**
 * One scheduler invocation: claim a bounded batch of due assets, refresh each,
 * persist results, exit. Never processes an unbounded set.
 */
export async function runMonitoringCycle(opts: { limit?: number } = {}): Promise<MonitoringRunResult> {
  const t0 = Date.now()
  const runId = `run_${t0}_${Math.random().toString(36).slice(2, 8)}`
  await initDb()

  const limit = Math.max(1, Math.min(opts.limit ?? maxAssetsPerRun(), maxAssetsPerRun()))
  const result: MonitoringRunResult = {
    runId, scanned: 0, succeeded: 0, partial: 0, failed: 0, skippedQuota: 0, skippedUnauthorized: 0,
    eventsCreated: 0, durationMs: 0, assets: [],
  }

  // Cheap pre-flight: if every enrichment provider is already exhausted there
  // is nothing useful to do, and claiming assets would only burn their
  // next_run_at for no benefit.
  if (!(await anyQuotaAvailable())) {
    result.durationMs = Date.now() - t0
    return result
  }

  const claimed = await claimDueAssets(runId, limit)
  result.scanned = claimed.length

  // Sequential by design: assets are processed one at a time so provider
  // concurrency rules (notably Censys = 1) hold across the whole batch.
  for (const row of claimed) {
    const r = await processAsset(runId, row)
    result.assets.push({ assetKey: row.asset_key, target: row.target, status: r.status, events: r.events, error: r.error })
    result.eventsCreated += r.events
    if (r.status === "success") result.succeeded++
    else if (r.status === "partial") result.partial++
    else if (r.status === "quota_deferred" || r.status === "no_provider") result.skippedQuota++
    else if (r.status === "unauthorized") result.skippedUnauthorized++
    else result.failed++
  }

  result.durationMs = Date.now() - t0
  return result
}

// ───────────────────────────── configuration API ─────────────────────────────

/** Enable/update monitoring for one asset. Explicit opt-in — never implicit. */
export async function setMonitoring(
  assetKey: string,
  target: string,
  userId: string,
  opts: { enabled: boolean; intervalSeconds?: number },
): Promise<MonitoringRow> {
  await initDb()
  const interval = Math.max(300, Math.floor(opts.intervalSeconds ?? DEFAULT_INTERVAL_SECONDS))
  const rows = (await sql`
    INSERT INTO exposure_monitoring (user_id, asset_key, target, enabled, interval_seconds, next_run_at)
    VALUES (${userId}, ${assetKey}, ${target}, ${opts.enabled}, ${interval}, now())
    ON CONFLICT (user_id, asset_key) DO UPDATE SET
      enabled = EXCLUDED.enabled,
      interval_seconds = EXCLUDED.interval_seconds,
      target = EXCLUDED.target,
      -- Re-enabling schedules immediately; pausing leaves next_run_at intact so
      -- resuming later does not lose the original cadence.
      next_run_at = CASE WHEN EXCLUDED.enabled AND NOT exposure_monitoring.enabled THEN now() ELSE exposure_monitoring.next_run_at END,
      updated_at = now()
    RETURNING *
  `) as MonitoringRow[]
  return rows[0]
}

export async function getMonitoring(assetKey: string, userId: string): Promise<MonitoringRow | null> {
  await initDb()
  const rows = (await sql`
    SELECT * FROM exposure_monitoring WHERE user_id = ${userId} AND asset_key = ${assetKey}
  `) as MonitoringRow[]
  return rows[0] ?? null
}

export interface MonitoringRunLog {
  run_id: string
  asset_key: string
  status: string
  providers_succeeded: number
  providers_failed: number
  events_created: number
  duration_ms: number
  completed_at: string
  error: string | null
}

export interface MonitoringChange {
  asset_key: string
  kind: string
  detail: string
  before_val: string | null
  after_val: string | null
  occurred_at: string
}

export interface MonitoringOverview {
  totalMonitored: number
  enabled: number
  paused: number
  dueNow: number
  failing: number
  deferred: number
  /** Monitored assets the user is no longer entitled to query. */
  unauthorized: number
  lastRunAt: string | null
  lastSuccessAt: string | null
  lastFailureAt: string | null
  assets: MonitoringRow[]
  recentRuns: MonitoringRunLog[]
  recentChanges: MonitoringChange[]
  quota: Array<{ provider: string; used: number; budget: number }>
}

/**
 * Everything the operator console needs in ONE round trip: schedule state,
 * recent executions, the changes those executions actually produced, and the
 * quota that constrains the next one.
 */
export async function monitoringOverview(userId: string): Promise<MonitoringOverview> {
  await initDb()
  const assets = (await sql`
    SELECT * FROM exposure_monitoring WHERE user_id = ${userId}
    ORDER BY enabled DESC, next_run_at ASC LIMIT 100
  `) as MonitoringRow[]
  const recentRuns = (await sql`
    SELECT run_id, asset_key, status, providers_succeeded, providers_failed,
           events_created, duration_ms, completed_at, error
    FROM exposure_monitoring_runs WHERE user_id = ${userId}
    ORDER BY completed_at DESC LIMIT 20
  `) as MonitoringRunLog[]

  // Changes are read from the SAME event table the manual refresh writes to —
  // monitoring does not keep a parallel history.
  let recentChanges: MonitoringChange[] = []
  try {
    recentChanges = (await sql`
      SELECT asset_key, kind, detail, before_val, after_val, occurred_at
      FROM exposure_events WHERE user_id = ${userId}
      ORDER BY occurred_at DESC LIMIT 25
    `) as MonitoringChange[]
  } catch { recentChanges = [] }

  const quota = await quotaUsage().catch(() => [])

  const now = Date.now()
  return {
    totalMonitored: assets.length,
    enabled: assets.filter((a) => a.enabled).length,
    paused: assets.filter((a) => !a.enabled).length,
    dueNow: assets.filter((a) => a.enabled && Date.parse(a.next_run_at) <= now).length,
    failing: assets.filter((a) => a.consecutive_failures > 0).length,
    // Deferred is NOT failing: the asset is healthy, the quota window is not.
    deferred: assets.filter((a) => a.last_status === "quota_deferred" || a.last_status === "no_provider").length,
    unauthorized: assets.filter((a) => a.last_status === "unauthorized").length,
    lastRunAt: recentRuns[0]?.completed_at ?? null,
    lastSuccessAt: recentRuns.find((r) => r.status === "success" || r.status === "partial")?.completed_at ?? null,
    lastFailureAt: recentRuns.find((r) => r.status === "failed")?.completed_at ?? null,
    assets,
    recentRuns,
    recentChanges,
    quota,
  }
}
