/**
 * TICKETING — provider-neutral work items.
 *
 * A workflow layer. It does not score, correlate, or decide eligibility; it
 * turns an alert that already exists into a work item and keeps the two linked.
 *
 * The interface is deliberately small (`create` / `update` / `close`) so a Jira,
 * ServiceNow or GitHub Issues adapter can be added later without the alert
 * system knowing anything about it. Nothing here is hard-coded to a vendor.
 *
 * DEFAULT IS "NOT CONFIGURED". OCTUPUS must run with no ticketing service
 * attached, and the UI says so plainly rather than implying tickets exist.
 */
import { sql } from "@/lib/db"
import { redactSecrets } from "@/lib/exposure/providers/_base"
import { safeField } from "@/lib/notify/telegram-adapter"
import type { AlertRow } from "@/lib/notify/types"

export type TicketProviderName = "none" | "internal"

export interface TicketRef {
  provider: TicketProviderName
  key: string
  url: string | null
}

export type TicketResult =
  | { ok: true; ref: TicketRef }
  | { ok: false; error: string; configured: boolean }

export interface TicketContent {
  title: string
  description: string
}

/**
 * What every ticket provider must implement.
 *
 * `update` and `close` take the existing reference, so repeated monitoring
 * updates one work item instead of opening a new one every cycle.
 */
export interface TicketProvider {
  readonly name: TicketProviderName
  readonly configured: boolean
  create(alert: AlertRow, content: TicketContent): Promise<TicketResult>
  update(ref: TicketRef, alert: AlertRow, content: TicketContent): Promise<TicketResult>
  /** `alertId` identifies the work item; `ref` carries the provider's own key. */
  close(ref: TicketRef, alertId: number, reason: string): Promise<TicketResult>
}

/**
 * Ticket body, built ONLY from the alert record.
 *
 * Nothing is recomputed and no remediation advice is invented: when the CVE
 * intelligence carries no guidance, the ticket says so instead of offering a
 * plausible-sounding instruction nobody verified.
 */
export function buildTicketContent(alert: AlertRow): TicketContent {
  const p = (alert.payload ?? {}) as Record<string, unknown>
  const sev = (alert.severity ?? "unknown").toUpperCase()
  const asset = String(p.asset ?? alert.asset_key)

  const title = `[${sev}] ${alert.cve_id} on ${asset}`

  const line = (label: string, value: unknown) =>
    value == null || value === "" ? `${label}: UNKNOWN` : `${label}: ${String(value)}`

  const providers = Array.isArray(p.providers) && p.providers.length
    ? (p.providers as unknown[]).join(", ")
    : "none recorded"

  const body = [
    `OCTUPUS alert ALT-${alert.id}`,
    "",
    line("Asset", p.asset ?? alert.asset_key),
    line("Service", alert.port > 0 ? `${alert.port}/tcp` : "host-level"),
    line("Product", p.product),
    line("Version", p.version),
    line("CVE", alert.cve_id),
    "",
    line("Evidence", alert.evidence_tier?.toUpperCase()),
    line("Provider evidence", providers),
    line("RBVM risk", alert.risk_score == null ? null : `${alert.risk_score} / ${alert.severity}`),
    line("CVSS", p.cvss),
    line("EPSS", p.epss),
    line("KEV", p.isKev == null ? null : p.isKev ? "YES" : "No"),
    line("Public exploit", p.hasExploit == null ? null : p.hasExploit ? "YES" : "No"),
    "",
    line("Provider observed", p.observedAt),
    line("OCTUPUS retrieved", p.fetchedAt),
    line("Freshness", p.freshness),
    line("Detected", alert.created_at),
    "",
    `Why: ${p.why ? String(p.why) : "not recorded"}`,
    "",
    "Recommended action:",
    alert.evidence_tier === "confirmed" || alert.evidence_tier === "strong"
      ? "Investigate and remediate the affected service."
      : "Verify the finding before acting — the evidence is a lead, not a confirmation.",
    "",
    // Honest about the limit rather than filling the gap with generic advice.
    "OCTUPUS does not hold vendor remediation guidance for this CVE; consult the vendor advisory linked from the CVE record.",
  ].join("\n")

  // Provider-controlled values reach a third-party system here, so they are
  // flattened and length-bounded exactly as they are for Telegram.
  return { title: stripMarkup(title, 200), description: redactSecrets(stripMarkup(body, 6000)) }
}

/** Plain text for arbitrary ticket backends: no markup, no control characters. */
function stripMarkup(value: string, maxLength: number): string {
  const flat = safeFieldPlain(value)
  return flat.length > maxLength ? `${flat.slice(0, maxLength)}…` : flat
}

/**
 * `safeField` escapes for Telegram HTML. A ticket backend is not HTML, so the
 * control-character and flattening rules are reused while the HTML escaping is
 * undone — otherwise every ticket title would read `&amp;`.
 */
function safeFieldPlain(value: string): string {
  return safeField(value, Number.MAX_SAFE_INTEGER)
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")
}

/**
 * Is this a usable alert id?
 *
 * Coerces rather than type-checks: `exposure_alerts.id` is BIGSERIAL, and the
 * Postgres driver returns BIGINT as a STRING. A `Number.isInteger` guard would
 * therefore reject every real alert, not just a bogus one.
 */
export function validAlertId(id: unknown): boolean {
  const n = Number(id)
  return Number.isFinite(n) && Number.isInteger(n) && n > 0
}

/** No ticketing service attached. Every call reports that honestly. */
class NoneProvider implements TicketProvider {
  readonly name = "none" as const
  readonly configured = false
  private unavailable(): TicketResult {
    return { ok: false, error: "Ticketing is not configured.", configured: false }
  }
  async create(): Promise<TicketResult> { return this.unavailable() }
  async update(): Promise<TicketResult> { return this.unavailable() }
  async close(): Promise<TicketResult> { return this.unavailable() }
}

/**
 * Work items held inside OCTUPUS.
 *
 * Lets a SOC run the workflow end to end without buying a ticketing product,
 * and gives the external adapters a reference implementation. It is explicitly
 * NOT a claim that an external ticket exists — `provider` is `internal` and the
 * UI labels it as such.
 */
class InternalProvider implements TicketProvider {
  readonly name = "internal" as const
  readonly configured = true

  async create(alert: AlertRow, content: TicketContent): Promise<TicketResult> {
    // A work item must reference a real alert. There is no foreign key (the
    // alert table is shared with paths that predate ticketing), so without this
    // an insert with a bogus id would happily create an orphan that no analyst
    // could ever reach from an alert.
    if (!validAlertId(alert.id)) {
      return { ok: false, error: "Cannot create a ticket for an unknown alert.", configured: true }
    }
    try {
      const rows = (await sql`
        INSERT INTO exposure_tickets (alert_id, user_id, provider, title, description, state)
        VALUES (${alert.id}, ${alert.user_id}, 'internal', ${content.title}, ${content.description}, 'open')
        ON CONFLICT (alert_id) DO UPDATE SET
          title = EXCLUDED.title, description = EXCLUDED.description, updated_at = now()
        RETURNING id
      `) as Array<{ id: number }>
      const id = rows[0]?.id
      if (!id) return { ok: false, error: "Ticket insert returned no row.", configured: true }
      return { ok: true, ref: { provider: "internal", key: `SOC-${id}`, url: null } }
    } catch (e) {
      return { ok: false, error: redactSecrets(e instanceof Error ? e.message : String(e)), configured: true }
    }
  }

  async update(ref: TicketRef, alert: AlertRow, content: TicketContent): Promise<TicketResult> {
    if (!validAlertId(alert.id)) {
      return { ok: false, error: "Cannot update a ticket for an unknown alert.", configured: true }
    }
    try {
      await sql`
        UPDATE exposure_tickets
        SET title = ${content.title}, description = ${content.description}, updated_at = now()
        WHERE alert_id = ${alert.id}
      `
      return { ok: true, ref }
    } catch (e) {
      return { ok: false, error: redactSecrets(e instanceof Error ? e.message : String(e)), configured: true }
    }
  }

  async close(ref: TicketRef, alertId: number, reason: string): Promise<TicketResult> {
    try {
      // Keyed by alert_id, which is unique per work item — no parsing of the
      // display key, which is a label rather than an identifier.
      await sql`
        UPDATE exposure_tickets
        SET state = 'closed', close_reason = ${reason}, closed_at = now(), updated_at = now()
        WHERE alert_id = ${alertId}
      `
      return { ok: true, ref }
    } catch (e) {
      return { ok: false, error: redactSecrets(e instanceof Error ? e.message : String(e)), configured: true }
    }
  }
}

/**
 * Which provider is active.
 *
 * `TICKETING_PROVIDER=internal` opts in. Anything else — including unset —
 * means no ticketing, which is the safe default for a fresh install.
 */
export function ticketProvider(): TicketProvider {
  const configured = (process.env.TICKETING_PROVIDER ?? "").trim().toLowerCase()
  if (configured === "internal") return new InternalProvider()
  return new NoneProvider()
}

export function ticketingConfigured(): boolean {
  return ticketProvider().configured
}
