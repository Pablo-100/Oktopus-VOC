/**
 * TELEGRAM NOTIFICATION ADAPTER for SOC alerts.
 *
 * A DELIVERY mechanism, nothing more. It does not score risk, decide
 * eligibility, correlate CVEs or touch an evidence tier — it renders an alert
 * that already exists and reports honestly whether the message left the
 * building.
 *
 * Separate from `lib/telegram.ts` on purpose. That module serves the CVE feed
 * and 0-day notices and returns a bare boolean; a SOC outbox needs to know
 * WHY a send failed, because a 429 should be retried and a revoked token
 * should not. Its `esc()` rule is reused rather than reinvented.
 */
import type { AlertRow } from "@/lib/notify/types"

/** Telegram HTML parse mode requires exactly these three to be escaped. */
export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
}

/**
 * Provider-controlled text is UNTRUSTED.
 *
 * A product name, banner or CVE id comes from an external scanner and can
 * contain anything: markup, control characters, or 10KB of padding. Escaping
 * alone is not enough — an unbounded value would break the message, and a
 * newline-laden one would forge extra "fields" in the layout.
 */
export function safeField(value: unknown, maxLength = 120): string {
  const flattened = String(value ?? "")
    // Unicode escapes rather than literal control characters, so the source
    // file itself can never carry a stray CR/LF/TAB inside the class.
    .replace(/[\u000D\u000A\u0009]+/g, " ")
    // Strip C0/C1 controls: provider text can carry them and they corrupt the
    // rendered message. Written with unicode escapes, which no-control-regex
    // accepts, so no disable directive is needed.
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, "")
    .trim()
  const clipped = flattened.length > maxLength ? flattened.slice(0, maxLength) + "…" : flattened
  return escapeHtml(clipped)
}

export type DeliveryStatus = "sent" | "retryable" | "permanent" | "not_configured"

export interface DeliveryResult {
  status: DeliveryStatus
  /** Operator-facing reason. Never contains a token. */
  message: string
  httpStatus?: number
  /** Seconds Telegram asked us to wait (from `retry_after` on a 429). */
  retryAfterSeconds?: number
}

export function telegramConfigured(): boolean {
  return Boolean(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID)
}

/**
 * Strip anything token-shaped from text that will be stored or displayed.
 *
 * The bot token appears in the request URL, so a fetch error or a proxy message
 * can quote it. This runs on every message this module returns.
 */
function scrubToken(text: string): string {
  const token = process.env.TELEGRAM_BOT_TOKEN
  let out = text
  if (token && token.length >= 8) out = out.split(token).join("[TELEGRAM_BOT_TOKEN]")
  // Also catch the URL shape, so an unknown/rotated token cannot leak either.
  return out.replace(/\/bot[0-9]+:[A-Za-z0-9_-]+/g, "/bot[redacted]")
}

const SEVERITY_ICON: Record<string, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🟢",
}

const EVIDENCE_NOTE: Record<string, string> = {
  confirmed: "a provider reported this host as affected",
  strong: "the affected version was fingerprinted here",
  product: "product name matched only — version unproven",
  weak: "banner/heuristic inference only",
  pivot: "local pivot; host never reported as affected",
}

/**
 * Human age, or null when there is no timestamp to describe.
 *
 * Accepts a Date as well as a string: a timestamp read straight from Postgres
 * arrives as a Date, and a string-only guard silently reported a real provider
 * observation as "not supplied" — under-reporting evidence we actually hold.
 */
function ago(value: unknown): string | null {
  if (!value) return null
  const ms = value instanceof Date ? value.getTime()
    : typeof value === "number" ? value
    : typeof value === "string" ? Date.parse(value)
    : NaN
  if (!Number.isFinite(ms)) return null
  const m = Math.round((Date.now() - ms) / 60000)
  if (m < 1) return "less than a minute ago"
  if (m < 60) return `${m} minutes ago`
  if (m < 1440) return `${Math.round(m / 60)} hours ago`
  return `${Math.round(m / 1440)} days ago`
}

/**
 * Render a SOC alert.
 *
 * Every line comes from the alert record. A field with no value is OMITTED or
 * shown as UNKNOWN — it is never filled with a plausible-looking default,
 * because an invented CVSS or provider in a SOC message is worse than a gap.
 */
export function buildAlertMessage(alert: AlertRow, opts: { appUrl?: string | null; escalation?: boolean } = {}): string {
  const p = (alert.payload ?? {}) as Record<string, unknown>
  const L: string[] = []
  const icon = SEVERITY_ICON[alert.severity?.toLowerCase() ?? ""] ?? "⚪"

  L.push(opts.escalation
    ? "🔺 <b>OCTUPUS SOC · ALERT ESCALATED</b>"
    : "🚨 <b>OCTUPUS SOC ALERT</b>")
  L.push("")
  L.push(`${icon}  <b>${safeField(alert.severity?.toUpperCase() ?? "UNKNOWN", 20)}</b>` +
    (alert.risk_score != null ? `   ·   Risk <b>${safeField(alert.risk_score, 10)}/100</b>` : ""))
  L.push("")

  L.push(`<b>CVE</b>: <code>${safeField(alert.cve_id, 40)}</code>`)
  L.push(`<b>Asset</b>: <code>${safeField(p.asset ?? alert.asset_key, 80)}</code>`)
  // Port 0 means the finding is host-level; saying "0/tcp" would be a lie.
  L.push(`<b>Service</b>: ${alert.port > 0 ? `<code>${safeField(`${alert.port}/tcp`, 20)}</code>` : "host-level"}`)

  const product = p.product ? safeField(p.product, 80) : null
  const version = p.version ? safeField(p.version, 40) : null
  if (product) L.push(`<b>Product</b>: ${product}${version ? ` ${version}` : ""}`)
  else L.push("<b>Product</b>: UNKNOWN")

  const tier = alert.evidence_tier?.toLowerCase() ?? ""
  L.push(`<b>Evidence</b>: <b>${safeField(tier.toUpperCase() || "UNKNOWN", 20)}</b>` +
    (EVIDENCE_NOTE[tier] ? ` — ${escapeHtml(EVIDENCE_NOTE[tier])}` : ""))

  // Provider attribution is never invented. No providers means we say so.
  const providers = Array.isArray(p.providers) ? (p.providers as unknown[]).map((x) => safeField(x, 30)) : []
  L.push(`<b>Provider</b>: ${providers.length ? providers.join(", ") : "none recorded"}`)

  L.push("")
  const facts: string[] = []
  facts.push(`CVSS: ${p.cvss == null ? "UNKNOWN" : safeField(p.cvss, 10)}`)
  facts.push(`EPSS: ${p.epss == null ? "UNKNOWN" : safeField(`${(Number(p.epss) * 100).toFixed(3)}%`, 12)}`)
  facts.push(`KEV: ${p.isKev == null ? "UNKNOWN" : p.isKev ? "YES" : "No"}`)
  facts.push(`Public exploit: ${p.hasExploit == null ? "UNKNOWN" : p.hasExploit ? "YES" : "No"}`)
  L.push(facts.map((f) => `•  ${f}`).join("\n"))

  // Observation age and retrieval time stay distinct, as everywhere else.
  const observed = ago(p.observedAt)
  L.push("")
  L.push(`<b>Provider observed</b>: ${observed ? escapeHtml(observed) : "not supplied"}` +
    (p.freshness ? ` (${safeField(p.freshness, 16).toUpperCase()})` : ""))
  const fetched = ago(p.fetchedAt)
  if (fetched) L.push(`<b>OCTUPUS retrieved</b>: ${escapeHtml(fetched)}`)

  if (typeof p.why === "string" && p.why.trim()) {
    L.push("")
    L.push(`<b>Why</b>: ${safeField(p.why, 220)}`)
  }

  L.push("")
  L.push(tier === "confirmed" || tier === "strong"
    ? "<b>Action</b>: investigate and remediate."
    : "<b>Action</b>: verify before acting — evidence is not a confirmation.")

  if (opts.appUrl) {
    // Only an app-owned URL is linked; nothing provider-controlled is ever
    // interpolated into an href.
    const base = opts.appUrl.replace(/\/+$/, "")
    if (/^https?:\/\//.test(base)) {
      L.push(`<a href="${escapeHtml(`${base}/exposure?alert=${encodeURIComponent(String(alert.id))}`)}">Open in OCTUPUS</a>`)
    }
  }
  L.push(`<i>Alert ALT-${safeField(alert.id, 12)} · OCTUPUS Exposure Intelligence</i>`)
  return L.join("\n")
}

/** Injectable transport, so delivery semantics are testable without a network. */
export type TelegramTransport = (url: string, init: RequestInit) => Promise<Response>

/**
 * Default outbound timeout. `fetch` has no timeout of its own, so without an
 * explicit abort a hung Telegram connection would hold the caller open
 * indefinitely — inside a refresh request or a 60s serverless worker.
 */
const TELEGRAM_TIMEOUT_MS = 10_000

/**
 * Send one message and classify the outcome.
 *
 * The classification is the point: `retryable` (429, 5xx, timeout, network) is
 * worth another attempt; `permanent` (401/403 revoked token, 400 bad chat id)
 * must not be retried forever, because a broken configuration would otherwise
 * hammer Telegram every cycle for as long as it stayed broken.
 */
export async function deliverTelegram(
  html: string,
  opts: { transport?: TelegramTransport; timeoutMs?: number } = {},
): Promise<DeliveryResult> {
  const token = process.env.TELEGRAM_BOT_TOKEN
  const chatId = process.env.TELEGRAM_CHAT_ID
  if (!token || !chatId) {
    return { status: "not_configured", message: "Telegram is not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)." }
  }

  const transport = opts.transport ?? ((url, init) => fetch(url, init))
  // The immediate path passes a shorter budget than the scheduler: a user's
  // refresh must not wait as long as a background worker reasonably can.
  const timeoutMs = opts.timeoutMs && opts.timeoutMs > 0 ? opts.timeoutMs : TELEGRAM_TIMEOUT_MS
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const res = await transport(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: html,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      }),
      signal: controller.signal,
    })

    if (res.ok) return { status: "sent", message: "Delivered.", httpStatus: res.status }

    const body = await res.text().catch(() => "")
    let retryAfter: number | undefined
    let description = ""
    try {
      const parsed = JSON.parse(body) as { description?: string; parameters?: { retry_after?: number } }
      description = parsed.description ?? ""
      retryAfter = parsed.parameters?.retry_after
    } catch {
      description = body.slice(0, 200)
    }
    const detail = scrubToken(description || `HTTP ${res.status}`)

    if (res.status === 429) {
      return { status: "retryable", message: `Rate limited: ${detail}`, httpStatus: 429, retryAfterSeconds: retryAfter }
    }
    if (res.status >= 500) {
      return { status: "retryable", message: `Telegram server error: ${detail}`, httpStatus: res.status }
    }
    // 401/403 = bad or revoked token; 400 = malformed request or unknown chat.
    // None of these fix themselves by retrying.
    return { status: "permanent", message: `Rejected by Telegram: ${detail}`, httpStatus: res.status }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    if (/abort/i.test(msg)) return { status: "retryable", message: `Timed out after ${timeoutMs}ms.` }
    return { status: "retryable", message: `Network error: ${scrubToken(msg)}` }
  } finally {
    clearTimeout(timer)
  }
}
