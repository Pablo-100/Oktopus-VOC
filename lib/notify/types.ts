/**
 * Shared shape of a persisted SOC alert.
 *
 * Mirrors the `exposure_alerts` row so the notification and ticket adapters can
 * render an alert without importing the workflow module — and, more
 * importantly, without any of them holding their own idea of what an alert is.
 */
export interface AlertRow {
  id: number
  /** Owning tenant. Alerts never cross users. */
  user_id: string
  fingerprint: string
  asset_key: string
  port: number
  cve_id: string
  kind: string
  state: string
  severity: string
  risk_score: number | null
  previous_risk: number | null
  evidence_tier: string
  /** Analyst detail captured when the alert was raised. Never credentials. */
  payload: Record<string, unknown>
  created_at: string
  updated_at: string

  notification_state: string
  notify_attempts: number
  notify_last_error: string | null
  notified_at: string | null
  notified_severity: string | null
  notified_risk: number | null
  escalation_count: number

  ticket_state: string
  ticket_provider: string | null
  ticket_key: string | null
  ticket_url: string | null
  ticket_last_error: string | null
}
