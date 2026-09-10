/**
 * NOTIFICATION OUTBOX — bounded, restartable delivery.
 *
 * The alert row IS the outbox: `notification_state` records what still needs
 * sending. That avoids a second queue table that could disagree with the alert
 * it describes, and it means a crash mid-send leaves the work visible rather
 * than lost.
 *
 *   alert created -> notification_state = 'pending'
 *   worker claims -> sends via the adapter -> records the outcome
 *
 * Monitoring never calls this. The scheduler triggers the worker, the worker
 * asks the adapter to deliver, and the adapter knows nothing about risk. Each
 * layer answers exactly one question:
 *   monitoring   "something changed"
 *   alert engine "this is actionable"
 *   outbox       "tell the SOC"
 *   ticketing    "create or update the work item"
 *
 * Serverless-safe: one short invocation processes a bounded batch and exits.
 * No timers, no background process, no new infrastructure.
 */
import { sql, initDb } from "@/lib/db"
import { getAppUrl } from "@/lib/app-url"
import {
  deliverTelegram, buildAlertMessage, telegramConfigured, type TelegramTransport,
} from "@/lib/notify/telegram-adapter"
import { recordAlertEvent } from "@/lib/exposure/alert-workflow"
import { redactSecrets } from "@/lib/exposure/providers/_base"
import { ticketProvider, buildTicketContent, type TicketRef } from "@/lib/ticketing"
import type { AlertRow } from "@/lib/notify/types"

/** Per-invocation ceiling. Protects Telegram's rate limit and the function budget. */
const MAX_PER_RUN = 10
/**
 * Retry ceiling. Telegram is not going to start accepting a revoked token on
 * the sixth try, and a permanently failing alert must stop consuming the batch.
 */
const MAX_ATTEMPTS = 5
/** Courtesy gap between sends — Telegram tolerates ~30 messages/second overall. */
const SEND_SPACING_MS = 350

/**
 * How long a delivery claim stays valid.
 *
 * A row in `sending` is owned by whoever claimed it. If that invocation dies —
 * a serverless crash, a timeout, a deploy mid-flight — the row would otherwise
 * be stuck forever. After this lease expires the scheduler may reclaim it.
 *
 * The value is deliberately several times the Telegram request timeout (10s):
 * reclaiming while the original send is still in flight is what would cause a
 * duplicate message, so the window errs heavily toward waiting.
 */
export const CLAIM_LEASE_SECONDS = 120

export interface OutboxResult {
  scanned: number
  sent: number
  failed: number
  retrying: number
  skipped: number
  reclaimed: number
  configured: boolean
  durationMs: number
  alerts: Array<{ id: number; outcome: string; error?: string }>
}

/**
 * Bounded retry schedule, in seconds.
 *
 * Deliberately not "immediate then hammer": attempt 1 is the immediate try,
 * and each subsequent wait grows. Capped so a long outage cannot schedule a
 * retry days away, and never below Telegram's own `retry_after`.
 */
export function backoffSeconds(attempts: number, retryAfter?: number): number {
  // Telegram's own `retry_after` wins when it supplies one — arguing with a
  // rate limiter by retrying sooner only extends the block.
  if (retryAfter && retryAfter > 0) return Math.min(retryAfter, 3600)
  const schedule = [60, 300, 900, 1800]
  return schedule[Math.min(Math.max(0, attempts - 1), schedule.length - 1)]
}

/** Identifies one delivery attempt, for the claim and the audit trail. */
function newRunId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
}

/**
 * Release delivery claims whose lease has expired.
 *
 * A crashed invocation leaves a row in `sending`. Returning it to `retrying`
 * (not `pending`) preserves the fact that an attempt was already made, so the
 * attempt ceiling still applies and a permanently crashing send cannot loop
 * forever.
 */
export async function reclaimStaleClaims(): Promise<number> {
  const rows = (await sql`
    UPDATE exposure_alerts
    SET notification_state = 'retrying',
        notify_claimed_at = NULL,
        notify_claimed_by = NULL,
        notify_last_error = 'Delivery attempt did not complete (claim expired); requeued.',
        notify_next_attempt_at = now(),
        updated_at = now()
    WHERE notification_state = 'sending'
      AND notify_claimed_at IS NOT NULL
      AND notify_claimed_at < now() - (${CLAIM_LEASE_SECONDS}::text || ' seconds')::interval
    RETURNING id, user_id
  `) as Array<{ id: number; user_id: string }>
  for (const r of rows) {
    await recordAlertEvent(r.id, r.user_id, "telegram_failed", "system", "Claim expired; requeued for retry.", { reclaimed: true })
  }
  return rows.length
}

/**
 * Atomically claim due notifications.
 *
 * THE STATE TRANSITION IS THE CLAIM. Moving the row to `sending` in the same
 * statement that selects it is what makes a concurrent claimer unable to see
 * it: `FOR UPDATE SKIP LOCKED` alone only holds until this statement commits,
 * which is *before* the Telegram HTTP call, and that gap was reproducibly
 * sending one alert twice.
 *
 * The materialized CTE is required for the same planner reason as elsewhere:
 * `FOR UPDATE` makes an `IN (SELECT … LIMIT n)` subquery non-hashable, so the
 * planner may re-execute it per row and claim more than the limit.
 */
async function claimDue(limit: number, claimedBy: string): Promise<AlertRow[]> {
  return (await sql`
    WITH due AS (
      SELECT id FROM exposure_alerts
      WHERE notification_state IN ('pending', 'retrying')
        AND (notify_next_attempt_at IS NULL OR notify_next_attempt_at <= now())
        -- A suppressed or closed alert must not notify: suppression is a
        -- deliberate analyst decision and has to actually stop the noise.
        AND state IN ('open', 'acknowledged', 'in_progress')
      ORDER BY
        CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
        created_at ASC
      LIMIT ${limit}
      FOR UPDATE SKIP LOCKED
    )
    UPDATE exposure_alerts a
    SET notification_state = 'sending',
        notify_claimed_at = now(),
        notify_claimed_by = ${claimedBy},
        notify_attempts = a.notify_attempts + 1,
        notify_last_attempt_at = now(),
        notify_first_queued_at = COALESCE(a.notify_first_queued_at, a.created_at, now()),
        updated_at = now()
    FROM due
    WHERE a.id = due.id
    RETURNING a.*
  `) as AlertRow[]
}

/**
 * Claim ONE specific alert for immediate delivery.
 *
 * Same guarantee as the batch claim, scoped to a single id: it returns the row
 * only if this caller won the transition out of `pending`/`retrying`. If the
 * scheduler got there first, this returns nothing and does not send — which is
 * exactly how the immediate path and the scheduler avoid double-sending.
 */
async function claimOne(alertId: number, claimedBy: string): Promise<AlertRow | null> {
  const rows = (await sql`
    UPDATE exposure_alerts
    SET notification_state = 'sending',
        notify_claimed_at = now(),
        notify_claimed_by = ${claimedBy},
        notify_attempts = notify_attempts + 1,
        notify_last_attempt_at = now(),
        notify_first_queued_at = COALESCE(notify_first_queued_at, created_at, now()),
        updated_at = now()
    WHERE id = ${alertId}
      AND notification_state IN ('pending', 'retrying')
      AND (notify_next_attempt_at IS NULL OR notify_next_attempt_at <= now())
      AND state IN ('open', 'acknowledged', 'in_progress')
    RETURNING *
  `) as AlertRow[]
  return rows[0] ?? null
}

/**
 * Deliver one alert and persist the outcome.
 *
 * A failed send must never mark the alert delivered, and must never alter the
 * alert itself — the finding is just as real when Telegram is down.
 */
async function deliverOne(
  alert: AlertRow,
  transport?: TelegramTransport,
  timeoutMs?: number,
): Promise<{ outcome: string; error?: string }> {
  // An escalation is announced as such, so the SOC can tell a new finding from
  // one that got worse.
  const isEscalation = alert.notified_at != null && alert.escalation_count > 0
  const html = buildAlertMessage(alert, { appUrl: getAppUrl(), escalation: isEscalation })
  const result = await deliverTelegram(html, { transport, timeoutMs })

  if (result.status === "sent") {
    await sql`
      UPDATE exposure_alerts
      SET notification_state = 'sent',
          notified_at = now(),
          notify_last_error = NULL,
          notify_next_attempt_at = NULL,
          -- Release the claim: the row is terminal for delivery purposes and
          -- must not be picked up by the stale-claim sweep.
          notify_claimed_at = NULL,
          notify_claimed_by = NULL,
          -- Remember WHAT was announced, so a later identical state stays quiet
          -- while a genuine escalation re-queues.
          notified_severity = severity,
          notified_risk = risk_score,
          updated_at = now()
      WHERE id = ${alert.id}
    `
    await recordAlertEvent(alert.id, alert.user_id, "telegram_sent", "system", null, {
      severity: alert.severity, riskScore: alert.risk_score, escalation: isEscalation,
    })
    return { outcome: "sent" }
  }

  if (result.status === "not_configured") {
    // Not a failure: nothing is misconfigured, Telegram simply is not set up.
    // Marked distinctly so the UI can say "notifications disabled" rather than
    // showing a red delivery error the operator cannot act on.
    await sql`
      UPDATE exposure_alerts
      SET notification_state = 'disabled',
          notify_last_error = ${redactSecrets(result.message)},
          notify_next_attempt_at = NULL,
          notify_claimed_at = NULL,
          notify_claimed_by = NULL,
          updated_at = now()
      WHERE id = ${alert.id}
    `
    await recordAlertEvent(alert.id, alert.user_id, "telegram_skipped", "system", result.message)
    return { outcome: "disabled", error: result.message }
  }

  // `notify_attempts` was already incremented by the CLAIM, so the row we hold
  // carries the current attempt number. Adding one here would double-count and
  // exhaust the retry budget in half the attempts.
  // Defence in depth. The adapter already scrubs its own token from the message
  // it returns, but this value is PERSISTED and later served to the browser, so
  // the app-wide redactor runs over it too — a future error path that forgets
  // to scrub cannot leak a credential into the outbox.
  const safeError = redactSecrets(result.message)
  const attempts = Number(alert.notify_attempts)
  const exhausted = result.status === "permanent" || attempts >= MAX_ATTEMPTS
  const nextState = exhausted ? "failed" : "retrying"
  const delay = exhausted ? null : backoffSeconds(attempts, result.retryAfterSeconds)

  await sql`
    UPDATE exposure_alerts
    SET notification_state = ${nextState},
        notify_last_error = ${safeError},
        notify_next_attempt_at = ${delay == null ? null : new Date(Date.now() + delay * 1000).toISOString()}::timestamptz,
        notify_claimed_at = NULL,
        notify_claimed_by = NULL,
        updated_at = now()
    WHERE id = ${alert.id}
  `
  await recordAlertEvent(alert.id, alert.user_id, "telegram_failed", "system", safeError, {
    attempts, httpStatus: result.httpStatus ?? null, terminal: exhausted,
  })
  return { outcome: nextState, error: result.message }
}

/**
 * Create or update the work item for an alert.
 *
 * Repeated monitoring UPDATES the existing ticket; it never opens a second one
 * for the same finding. A ticket failure is recorded on the alert and does not
 * roll back a successful notification.
 */
export async function syncTicket(alert: AlertRow): Promise<{ state: string; error?: string }> {
  const provider = ticketProvider()
  if (!provider.configured) {
    await sql`UPDATE exposure_alerts SET ticket_state = 'none', ticket_provider = NULL WHERE id = ${alert.id}`
    return { state: "none" }
  }

  const content = buildTicketContent(alert)
  const existing: TicketRef | null = alert.ticket_key
    ? { provider: provider.name, key: alert.ticket_key, url: alert.ticket_url }
    : null

  const result = existing
    ? await provider.update(existing, alert, content)
    : await provider.create(alert, content)

  if (!result.ok) {
    await sql`
      UPDATE exposure_alerts
      SET ticket_state = 'failed', ticket_last_error = ${result.error}, updated_at = now()
      WHERE id = ${alert.id}
    `
    await recordAlertEvent(alert.id, alert.user_id, "ticket_failed", "system", result.error)
    return { state: "failed", error: result.error }
  }

  const state = existing ? "updated" : "open"
  await sql`
    UPDATE exposure_alerts
    SET ticket_state = ${state},
        ticket_provider = ${result.ref.provider},
        ticket_key = ${result.ref.key},
        ticket_url = ${result.ref.url},
        ticket_last_error = NULL,
        updated_at = now()
    WHERE id = ${alert.id}
  `
  await recordAlertEvent(alert.id, alert.user_id, existing ? "ticket_updated" : "ticket_created", "system", result.ref.key, {
    provider: result.ref.provider, key: result.ref.key,
  })
  return { state }
}

/**
 * One bounded delivery cycle.
 *
 * `transport` is injectable so the retry and failure semantics can be proven
 * without a network or real credentials.
 */
export async function runNotificationCycle(
  opts: { limit?: number; transport?: TelegramTransport; syncTickets?: boolean; reclaim?: boolean } = {},
): Promise<OutboxResult> {
  const t0 = Date.now()
  await initDb()
  const runId = newRunId("sched")
  const limit = Math.max(1, Math.min(opts.limit ?? MAX_PER_RUN, MAX_PER_RUN))
  const result: OutboxResult = {
    scanned: 0, sent: 0, failed: 0, retrying: 0, skipped: 0, reclaimed: 0,
    configured: telegramConfigured(), durationMs: 0, alerts: [],
  }

  // The scheduler is now the RECOVERY mechanism: before looking for work, it
  // frees anything an earlier invocation claimed and never finished.
  if (opts.reclaim !== false) result.reclaimed = await reclaimStaleClaims()

  const claimed = await claimDue(limit, runId)
  result.scanned = claimed.length

  for (const alert of claimed) {
    const r = await deliverOne(alert, opts.transport)   // scheduler: default timeout
    result.alerts.push({ id: alert.id, outcome: r.outcome, error: r.error })
    if (r.outcome === "sent") result.sent++
    else if (r.outcome === "failed") result.failed++
    else if (r.outcome === "retrying") result.retrying++
    else result.skipped++

    // Ticketing runs independently of the notification outcome: a Telegram
    // failure must not prevent the work item, and vice versa.
    if (opts.syncTickets !== false) {
      await syncTicket({ ...alert, notification_state: r.outcome })
    }
    if (SEND_SPACING_MS > 0 && claimed.length > 1) {
      await new Promise((resolve) => setTimeout(resolve, SEND_SPACING_MS))
    }
  }

  result.durationMs = Date.now() - t0
  return result
}

/**
 * IMMEDIATE DELIVERY — attempt one alert right after its transaction committed.
 *
 * Called by the alert pipeline once the alert row exists, never from inside the
 * write path: Telegram must never receive a notification for an alert that
 * could still roll back.
 *
 * Bounded and non-throwing by construction. Whatever happens here, the alert is
 * already durably created and the outbox already holds the work — a failure
 * simply leaves it queued for the scheduler, which is the whole point of the
 * outbox. Callers therefore never need to handle an error from this.
 *
 * Returns the outcome for observability; `skipped` means another worker had
 * already claimed it, which is a correct and expected result, not a problem.
 */
export async function deliverAlertNow(
  alertId: number,
  opts: { transport?: TelegramTransport; syncTickets?: boolean; timeoutMs?: number } = {},
): Promise<{ outcome: string; error?: string }> {
  // No user filter here on purpose: this is called with an id the caller has
  // ALREADY proven it owns (evaluateAlerts, or a scoped API lookup). The claim
  // itself carries the owner through, so the audit trail stays attributed.
  try {
    const runId = newRunId("now")
    const alert = await claimOne(alertId, runId)
    // Not claimable: already sent, already claimed by the scheduler, backing
    // off, or the alert is suppressed/closed. All are correct no-ops.
    if (!alert) return { outcome: "skipped" }

    const r = await deliverOne(alert, opts.transport, opts.timeoutMs ?? IMMEDIATE_TIMEOUT_MS)
    if (opts.syncTickets !== false) {
      await syncTicket({ ...alert, notification_state: r.outcome }).catch(() => { /* independent of delivery */ })
    }
    return r
  } catch (e) {
    // The alert stands regardless; the outbox will retry.
    console.error("[outbox] immediate delivery failed:", e instanceof Error ? e.message : String(e))
    return { outcome: "error", error: "Immediate delivery failed; queued for retry." }
  }
}

/**
 * Fire immediate delivery for the alerts an evaluation just raised.
 *
 * Bounded on purpose: this runs inside a refresh request and inside the
 * monitoring worker, and neither may be held open by a slow third party. Beyond
 * the cap, delivery falls through to the scheduler exactly as a failure would.
 */
export const MAX_IMMEDIATE_PER_EVALUATION = 3
/**
 * Per-send budget for the immediate path — shorter than the scheduler's, because
 * this runs inside a refresh request.
 */
export const IMMEDIATE_TIMEOUT_MS = 5_000
/**
 * Total budget across one evaluation. Once spent, remaining alerts fall through
 * to the scheduler exactly as a failure would — which is the outbox working as
 * designed, not a lost notification.
 */
export const IMMEDIATE_BUDGET_MS = 12_000

export async function deliverAlertsNow(
  alertIds: number[],
  opts: { transport?: TelegramTransport; syncTickets?: boolean; timeoutMs?: number } = {},
): Promise<Array<{ id: number; outcome: string }>> {
  const out: Array<{ id: number; outcome: string }> = []
  const startedAt = Date.now()
  for (const id of alertIds.slice(0, MAX_IMMEDIATE_PER_EVALUATION)) {
    // Stop starting new sends once the budget is spent. The remainder stays
    // queued rather than extending the caller's request.
    if (Date.now() - startedAt >= IMMEDIATE_BUDGET_MS) {
      out.push({ id, outcome: "deferred" })
      continue
    }
    const r = await deliverAlertNow(id, opts)
    out.push({ id, outcome: r.outcome })
  }
  return out
}

/**
 * Manual retry, requested by an authenticated analyst.
 *
 * Typically used after a misconfiguration is fixed: the alert failed
 * permanently on a revoked token, the token is replaced, and the analyst wants
 * the message sent without waiting for a new finding.
 *
 * Deliberately narrow:
 *  - `sent` is refused, so a retry can never duplicate a delivered message
 *  - `sending` is refused, so it cannot race an in-flight attempt
 *  - the attempt budget is reset, because the previous exhaustion described a
 *    condition the analyst has now addressed
 *  - it never touches the alert's own lifecycle, and never creates an alert
 */
export async function requeueNotification(
  alertId: number,
  actor: string,
  userId: string,
): Promise<{ ok: boolean; error?: string; code?: "not_found" | "already_sent" | "in_flight" }> {
  // Scoped: an alert in another tenant is simply "not found".
  const rows = (await sql`
    SELECT id, notification_state FROM exposure_alerts WHERE id = ${alertId} AND user_id = ${userId}
  `) as Array<{ id: number; notification_state: string }>
  const current = rows[0]
  if (!current) return { ok: false, error: "Alert not found.", code: "not_found" }
  if (current.notification_state === "sent") {
    return { ok: false, error: "This notification was already delivered.", code: "already_sent" }
  }
  if (current.notification_state === "sending") {
    return { ok: false, error: "A delivery attempt is already in flight.", code: "in_flight" }
  }

  // Guarded in the WHERE clause too: two analysts clicking at once must not
  // both requeue, and the state must not have moved since the read above.
  const updated = (await sql`
    UPDATE exposure_alerts
    SET notification_state = 'pending',
        notify_attempts = 0,
        notify_next_attempt_at = NULL,
        notify_claimed_at = NULL,
        notify_claimed_by = NULL,
        updated_at = now()
    WHERE id = ${alertId} AND user_id = ${userId} AND notification_state = ${current.notification_state}
    RETURNING id
  `) as unknown[]
  if (!updated.length) return { ok: false, error: "Notification state changed; reload and retry.", code: "in_flight" }

  await recordAlertEvent(alertId, userId, "telegram_queued", actor, "Manual retry requested.", {
    from: current.notification_state,
  })
  return { ok: true }
}

/**
 * Delivery latency, in milliseconds, from REAL timestamps only.
 *
 * Queue time to delivery time. Returns null when either timestamp is missing —
 * a plausible-looking number would be worse than no number.
 */
export function deliveryLatencyMs(queuedAt: unknown, sentAt: unknown): number | null {
  const q = queuedAt instanceof Date ? queuedAt.getTime() : typeof queuedAt === "string" ? Date.parse(queuedAt) : NaN
  const s = sentAt instanceof Date ? sentAt.getTime() : typeof sentAt === "string" ? Date.parse(sentAt) : NaN
  if (!Number.isFinite(q) || !Number.isFinite(s)) return null
  const delta = s - q
  return delta >= 0 ? delta : null
}
