/**
 * SOC ALERT WORKFLOW — lifecycle, audit trail, escalation.
 *
 * This is the ANALYST layer over the alert rows that STEP 3 already produces.
 * It is deliberately powerless about intelligence:
 *
 *   - it never scores risk (`lib/risk-engine.ts` owns that)
 *   - it never decides eligibility (`isAlertEligible` owns that)
 *   - it never changes an evidence tier
 *   - it never correlates a CVE or writes a vulnerability record
 *
 * It only moves an existing alert through states, records what happened, and
 * marks work for the notification and ticket adapters to pick up.
 */
import { sql } from "@/lib/db"
import { redactSecrets } from "@/lib/exposure/providers/_base"

/**
 * Lifecycle states.
 *
 * `open` is the project's existing name for NEW and is kept rather than renamed
 * — the column, the partial unique index and STEP 3's tests all use it, and a
 * cosmetic rename would be a migration with no analyst benefit.
 */
export type AlertState = "open" | "acknowledged" | "in_progress" | "resolved" | "closed" | "suppressed"

/** States that still represent a LIVE finding for deduplication purposes. */
export const ACTIVE_STATES: ReadonlySet<AlertState> = new Set<AlertState>(["open", "acknowledged", "in_progress"])

/**
 * Permitted transitions. Anything not listed here is rejected.
 *
 * `closed` is terminal: reopening would let an analyst's closure be undone
 * without a trace, and a finding that genuinely returns raises a NEW alert
 * (the partial unique index only covers active states, so that path is open).
 * `suppressed` can be lifted back to `open` because suppression is explicitly a
 * temporary analyst decision that may carry an expiry.
 */
const TRANSITIONS: Record<AlertState, ReadonlySet<AlertState>> = {
  open: new Set(["acknowledged", "in_progress", "resolved", "suppressed"]),
  acknowledged: new Set(["in_progress", "resolved", "suppressed"]),
  in_progress: new Set(["resolved", "suppressed"]),
  resolved: new Set(["closed", "in_progress"]), // reopen for further work, or close it out
  closed: new Set([]),                          // terminal
  suppressed: new Set(["open"]),                // un-suppress
}

export function canTransition(from: AlertState, to: AlertState): boolean {
  if (from === to) return false // a no-op is not a transition worth recording
  return TRANSITIONS[from]?.has(to) ?? false
}

/** Suppression reasons an analyst may choose. Free text is not accepted as a reason. */
export const SUPPRESSION_REASONS = [
  "false_positive", "accepted_risk", "maintenance",
  "compensating_control", "duplicate", "other",
] as const
export type SuppressionReason = (typeof SUPPRESSION_REASONS)[number]

export type AlertEventType =
  | "alert_created" | "alert_acknowledged" | "alert_started"
  | "alert_resolved" | "alert_closed" | "alert_suppressed" | "alert_unsuppressed"
  | "alert_escalated"
  | "telegram_queued" | "telegram_sent" | "telegram_failed" | "telegram_skipped"
  | "ticket_created" | "ticket_updated" | "ticket_closed" | "ticket_failed"
  | "analyst_note" | "alert_assigned" | "alert_unassigned"

const EVENT_FOR_STATE: Partial<Record<AlertState, AlertEventType>> = {
  acknowledged: "alert_acknowledged",
  in_progress: "alert_started",
  resolved: "alert_resolved",
  closed: "alert_closed",
  suppressed: "alert_suppressed",
  open: "alert_unsuppressed",
}

export interface AlertEvent {
  id: number
  alert_id: number
  type: AlertEventType
  actor: string
  detail: string | null
  metadata: Record<string, unknown>
  occurred_at: string
}

/**
 * Append one audit event.
 *
 * Best-effort by design: losing an audit line must never abort the state change
 * it describes. Metadata is scrubbed before storage because it is later served
 * to the browser.
 */
export async function recordAlertEvent(
  alertId: number,
  userId: string,
  type: AlertEventType,
  actor: string,
  detail?: string | null,
  metadata: Record<string, unknown> = {},
): Promise<void> {
  // An event whose alert does not exist can never be reached from the timeline,
  // so it is noise rather than an audit record. `id` is BIGSERIAL and arrives
  // from the driver as a string, so this coerces rather than type-checks.
  const id = Number(alertId)
  if (!Number.isFinite(id) || !Number.isInteger(id) || id <= 0) return

  try {
    const safe = JSON.parse(redactSecrets(JSON.stringify(metadata))) as Record<string, unknown>
    await sql`
      INSERT INTO exposure_alert_events (alert_id, user_id, type, actor, detail, metadata)
      VALUES (${alertId}, ${userId}, ${type}, ${actor}, ${detail ? redactSecrets(detail) : null}, ${JSON.stringify(safe)}::jsonb)
    `
  } catch (e) {
    console.error("[alert-events] write failed:", e instanceof Error ? e.message : String(e))
  }
}

export interface TransitionInput {
  alertId: number
  /** Tenant performing the transition. An alert outside it is "not found". */
  userId: string
  to: AlertState
  actor: string
  reason?: string | null
  /** Only meaningful for `suppressed`. */
  suppressedUntil?: string | null
  note?: string | null
}

export type TransitionResult =
  | { ok: true; from: AlertState; to: AlertState }
  | { ok: false; error: string; code: "not_found" | "invalid_transition" | "reason_required" }

/**
 * Move an alert to a new state.
 *
 * The guard is applied inside the UPDATE's WHERE clause, not read-then-written:
 * two analysts acting at once would otherwise both read `open` and both
 * succeed, and the second would silently overwrite the first.
 */
export async function transitionAlert(input: TransitionInput): Promise<TransitionResult> {
  // Scoped read: an alert belonging to another tenant is reported as NOT FOUND
  // rather than FORBIDDEN, so the endpoint cannot be used to probe whether an
  // alert id exists for someone else.
  const rows = (await sql`
    SELECT id, state FROM exposure_alerts WHERE id = ${input.alertId} AND user_id = ${input.userId}
  `) as Array<{ id: number; state: AlertState }>
  const current = rows[0]
  if (!current) return { ok: false, error: "Alert not found.", code: "not_found" }

  if (!canTransition(current.state, input.to)) {
    return {
      ok: false,
      code: "invalid_transition",
      error: `Cannot move an alert from "${current.state}" to "${input.to}".`,
    }
  }

  // Suppression must be accountable: who, why, and until when.
  if (input.to === "suppressed") {
    if (!input.reason || !SUPPRESSION_REASONS.includes(input.reason as SuppressionReason)) {
      return {
        ok: false,
        code: "reason_required",
        error: `Suppression requires a reason (${SUPPRESSION_REASONS.join(", ")}).`,
      }
    }
  }

  const updated = (await sql`
    UPDATE exposure_alerts
    SET state = ${input.to},
        updated_at = now(),
        acknowledged_at = CASE WHEN ${input.to} = 'acknowledged' THEN now() ELSE acknowledged_at END,
        started_at      = CASE WHEN ${input.to} = 'in_progress'  THEN now() ELSE started_at END,
        resolved_at     = CASE WHEN ${input.to} = 'resolved'     THEN now() ELSE resolved_at END,
        closed_at       = CASE WHEN ${input.to} = 'closed'       THEN now() ELSE closed_at END,
        suppressed_reason = CASE WHEN ${input.to} = 'suppressed' THEN ${input.reason ?? null} ELSE NULL END,
        suppressed_by     = CASE WHEN ${input.to} = 'suppressed' THEN ${input.actor} ELSE NULL END,
        suppressed_until  = CASE WHEN ${input.to} = 'suppressed' THEN ${input.suppressedUntil ?? null}::timestamptz ELSE NULL END
    WHERE id = ${input.alertId} AND user_id = ${input.userId} AND state = ${current.state}
    RETURNING id
  `) as unknown[]

  if (!updated.length) {
    // Someone else moved it between our read and our write.
    return { ok: false, error: "Alert changed state concurrently; reload and retry.", code: "invalid_transition" }
  }

  const eventType = EVENT_FOR_STATE[input.to] ?? "alert_acknowledged"
  await recordAlertEvent(input.alertId, input.userId, eventType, input.actor, input.note ?? null, {
    from: current.state, to: input.to,
    ...(input.reason ? { reason: input.reason } : {}),
    ...(input.suppressedUntil ? { until: input.suppressedUntil } : {}),
  })
  return { ok: true, from: current.state, to: input.to }
}

/**
 * A finding got worse while its alert was already live.
 *
 * STEP 3's `raiseAlert` cannot express this: the fingerprint is identical, so
 * `ON CONFLICT DO NOTHING` swallows it and the escalation was silently lost.
 * The correct behaviour is to UPDATE the live alert, record why, and re-queue a
 * notification — one alert per finding, with its history intact.
 *
 * Returns false when nothing meaningful changed, so a steady state stays quiet.
 */
export async function escalateAlert(
  fingerprint: string,
  userId: string,
  next: { severity: string; riskScore: number | null; evidenceTier: string },
  actor = "system",
): Promise<{ escalated: boolean; alertId?: number }> {
  const rows = (await sql`
    SELECT id, severity, risk_score, evidence_tier, state
    FROM exposure_alerts
    WHERE user_id = ${userId} AND fingerprint = ${fingerprint}
      AND state IN ('open','acknowledged','in_progress')
    ORDER BY created_at DESC LIMIT 1
  `) as Array<{ id: number; severity: string; risk_score: number | null; evidence_tier: string; state: AlertState }>
  const alert = rows[0]
  if (!alert) return { escalated: false }

  const rank: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 }
  const severityRose = (rank[next.severity] ?? -1) > (rank[alert.severity] ?? -1)
  // Evidence hardening is an escalation in its own right: the same CVE going
  // from a product guess to a provider confirmation changes what it means.
  const tierRank: Record<string, number> = { pivot: 1, weak: 2, product: 3, strong: 4, confirmed: 5 }
  const evidenceHardened = (tierRank[next.evidenceTier] ?? 0) > (tierRank[alert.evidence_tier] ?? 0)

  if (!severityRose && !evidenceHardened) return { escalated: false, alertId: alert.id }

  await sql`
    UPDATE exposure_alerts
    SET severity = ${next.severity},
        risk_score = ${next.riskScore},
        evidence_tier = ${next.evidenceTier},
        previous_risk = risk_score,
        escalation_count = escalation_count + 1,
        -- Re-queue: an escalation is worth telling the SOC about even though
        -- the alert itself already exists.
        notification_state = 'pending',
        notify_attempts = 0,
        notify_next_attempt_at = NULL,
        updated_at = now()
    WHERE id = ${alert.id} AND user_id = ${userId}
  `
  await recordAlertEvent(alert.id, userId, "alert_escalated", actor, null, {
    severityFrom: alert.severity, severityTo: next.severity,
    riskFrom: alert.risk_score, riskTo: next.riskScore,
    evidenceFrom: alert.evidence_tier, evidenceTo: next.evidenceTier,
  })
  return { escalated: true, alertId: alert.id }
}

/** Timeline for one alert. Deterministic order: time, then insertion id. */
/**
 * Normalise an alert id arriving from a client.
 *
 * `exposure_alerts.id` is BIGSERIAL, and the Neon driver returns BIGINT as a
 * STRING to avoid the precision loss a JS number would suffer past 2^53. An id
 * that has been through the API and back therefore arrives as `"5198"`, not
 * `5198` — while the client's TypeScript interface declares `id: number`, which
 * type checking cannot contradict across a JSON boundary. Validating with
 * `typeof === "number"` silently rejected every real alert, so every SOC
 * workflow action answered 400.
 *
 * Returns null for anything that is not a positive integer id.
 */
export function coerceAlertId(value: unknown): number | null {
  const n =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim() !== ""
        ? Number(value)
        : NaN
  if (!Number.isFinite(n)) return null
  const id = Math.floor(n)
  return id > 0 ? id : null
}

/**
 * Free-text analyst note.
 *
 * The state machine records WHAT changed; this records WHY, which is the part
 * that carries an analyst's actual judgement. Suppression already demands a
 * reason from a fixed list, but a list cannot hold "confirmed with the vendor,
 * patch lands Tuesday" — and that sentence is what the next person on the queue
 * needs.
 *
 * Notes are append-only. Editing history would defeat the point of having one.
 */
export async function addAlertNote(
  alertId: number,
  userId: string,
  actor: string,
  note: string,
): Promise<{ ok: boolean; error?: string; code?: "not_found" | "empty" | "too_long" }> {
  const text = note.trim()
  if (!text) return { ok: false, error: "A note cannot be empty.", code: "empty" }
  if (text.length > 4000) return { ok: false, error: "Note is too long (4000 characters max).", code: "too_long" }

  // Scoped: another tenant's alert is "not found", never "forbidden".
  const rows = (await sql`
    SELECT id FROM exposure_alerts WHERE id = ${alertId} AND user_id = ${userId}
  `) as Array<{ id: number }>
  if (!rows[0]) return { ok: false, error: "Alert not found.", code: "not_found" }

  await recordAlertEvent(alertId, userId, "analyst_note", actor, text)
  await sql`UPDATE exposure_alerts SET updated_at = now() WHERE id = ${alertId} AND user_id = ${userId}`
  return { ok: true }
}

/**
 * Claim an alert, hand it to someone, or drop it.
 *
 * `assignee = null` unassigns. The transition is recorded in the timeline so
 * that a handover is auditable rather than implicit.
 */
export async function assignAlert(
  alertId: number,
  userId: string,
  actor: string,
  assignee: string | null,
): Promise<{ ok: boolean; error?: string; code?: "not_found" }> {
  const rows = (await sql`
    SELECT id, assigned_to FROM exposure_alerts WHERE id = ${alertId} AND user_id = ${userId}
  `) as Array<{ id: number; assigned_to: string | null }>
  if (!rows[0]) return { ok: false, error: "Alert not found.", code: "not_found" }
  if (rows[0].assigned_to === assignee) return { ok: true }

  await sql`
    UPDATE exposure_alerts
    SET assigned_to = ${assignee},
        assigned_at = ${assignee ? new Date().toISOString() : null}::timestamptz,
        updated_at = now()
    WHERE id = ${alertId} AND user_id = ${userId}
  `
  await recordAlertEvent(
    alertId, userId,
    assignee ? "alert_assigned" : "alert_unassigned",
    actor,
    assignee ? `Assigned to ${assignee}` : `Unassigned (was ${rows[0].assigned_to ?? "nobody"})`,
    { from: rows[0].assigned_to, to: assignee },
  )
  return { ok: true }
}

/**
 * Apply one transition across many alerts.
 *
 * A queue is triaged in batches — forty findings of the same CVE on the same
 * class of host are one decision, not forty. Acting on them one at a time is
 * how real queues get abandoned.
 *
 * Each alert is evaluated INDEPENDENTLY and the outcome reported per id: a
 * batch is not atomic, because one alert being in a state that forbids the
 * transition is not a reason to refuse the other thirty-nine. The caller is
 * told exactly which succeeded and which did not, rather than a count.
 */
export async function bulkTransition(input: {
  alertIds: number[]
  userId: string
  to: AlertState
  actor: string
  reason?: string | null
  note?: string | null
}): Promise<{
  applied: number[]
  failed: Array<{ id: number; error: string; code?: string }>
}> {
  const applied: number[] = []
  const failed: Array<{ id: number; error: string; code?: string }> = []

  // De-duplicated: a repeated id in the request must not produce two audit
  // events for one decision.
  for (const id of [...new Set(input.alertIds)]) {
    const r = await transitionAlert({
      alertId: id,
      userId: input.userId,
      to: input.to,
      actor: input.actor,
      reason: input.reason ?? null,
    })
    if (r.ok) {
      applied.push(id)
      // The note is attached only where the transition actually landed, so the
      // timeline never carries an explanation for something that did not happen.
      if (input.note?.trim()) {
        await addAlertNote(id, input.userId, input.actor, input.note)
      }
    } else {
      failed.push({ id, error: r.error, code: r.code })
    }
  }
  return { applied, failed }
}

export async function alertTimeline(alertId: number, userId: string): Promise<AlertEvent[]> {
  return (await sql`
    SELECT id, alert_id, type, actor, detail, metadata, occurred_at
    FROM exposure_alert_events
    WHERE alert_id = ${alertId} AND user_id = ${userId}
    ORDER BY occurred_at ASC, id ASC
  `) as AlertEvent[]
}
