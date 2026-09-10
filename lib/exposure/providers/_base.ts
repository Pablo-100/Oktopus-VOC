/**
 * Shared plumbing for exposure provider adapters (server-only).
 *
 * Two jobs nothing else should duplicate:
 *  1. Input validation — user-supplied targets are interpolated into provider
 *     URLs, so they are strictly validated as IP/domain/CVE BEFORE any fetch.
 *     Provider hostnames are always hardcoded constants, so a user can never
 *     redirect a request at an internal host (SSRF); the validators below stop
 *     the weaker variant where a crafted "target" smuggles a path or query.
 *  2. Error classification — turning transport/HTTP failures into the
 *     structured ProviderStatus an analyst can act on.
 */
import type { ProviderName, ProviderOutcome, ProviderRole, ProviderStatus } from "@/lib/exposure/types"
import { activeSecretValues } from "@/lib/exposure/credentials"

export const DEFAULT_TIMEOUT_MS = 15_000

/** IPv4/IPv6 literal. Rejects anything carrying a slash, scheme, port or whitespace. */
export function isValidIp(value: string): boolean {
  const v = value.trim()
  if (!v || /[\s/\\?#@]/.test(v)) return false
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const m = ipv4.exec(v)
  if (m) return m.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o.replace(/^0+(?=\d)/, ""))
  // Conservative IPv6: hex groups and colons only.
  return /^[0-9a-fA-F:]+$/.test(v) && v.includes(":") && v.length <= 45
}

/** Registrable hostname. No scheme, path, credentials, port or wildcards. */
export function isValidDomain(value: string): boolean {
  const v = value.trim().toLowerCase()
  if (!v || v.length > 253 || /[\s/\\?#@:]/.test(v)) return false
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(v)
}

export function isValidCve(value: string): boolean {
  return /^CVE-\d{4}-\d{4,7}$/i.test(value.trim())
}

/**
 * Private/loopback/link-local space. Exposure providers only ever index public
 * hosts, so a private target is always a mistake — and refusing it early keeps
 * the app from being used to probe an internal network through a third party.
 */
export function isPrivateIp(value: string): boolean {
  const v = value.trim().toLowerCase()
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v)
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])]
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a >= 224 // multicast + reserved
    )
  }
  // ── IPv6 (C6) ──
  if (v === "::1" || v === "::") return true            // loopback / unspecified
  if (/^fe[89ab][0-9a-f]:/.test(v)) return true          // fe80::/10 link-local
  if (/^f[cd][0-9a-f]{2}:/.test(v)) return true          // fc00::/7 unique local (ULA)
  if (/^ff[0-9a-f]{2}:/.test(v)) return true             // ff00::/8 multicast
  // IPv4-mapped (::ffff:10.0.0.1) — recurse on the embedded IPv4 so an internal
  // address cannot be smuggled past the check in IPv6 form.
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(v)
  if (mapped) return isPrivateIp(mapped[1])
  return false
}

export class ProviderError extends Error {
  constructor(readonly status: ProviderStatus, message: string, readonly retryable: boolean) {
    super(message)
    this.name = "ProviderError"
  }
}

/**
 * Env vars holding credentials. Their VALUES must never reach a message.
 *
 * This is the ONE redaction list for the whole app, so it covers every secret
 * that can end up in stored or displayed text — not only the EASM providers.
 * Delivery and workflow credentials are included because alert audit metadata
 * and notification errors are persisted and then served to the browser: a
 * Telegram token quoted in an upstream error would otherwise be written
 * straight into the timeline.
 */
const CREDENTIAL_ENV = [
  // EASM providers
  "CENSYS_API_TOKEN", "LEAKIX_API_KEY", "NETLAS_API_KEY",
  "FOFA_API_KEY", "FOFA_EMAIL", "ZOOMEYE_API_KEY", "GREYNOISE_API_KEY",
  // Notification / workflow / infrastructure
  "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "CRON_SECRET",
  "OPENROUTER_API_KEY", "NVD_API_KEY", "GITHUB_TOKEN",
  "TICKETING_API_TOKEN", "TICKETING_USER",
] as const

/**
 * Scrub credentials from any text that may be stored or shown to a user.
 *
 * Provider error text is persisted (`exposure_monitoring.last_error`,
 * `exposure_monitoring_runs.error`) and rendered in the monitoring UI, so it is
 * a real egress path. Two ways a secret can get in:
 *   1. FOFA authenticates via the QUERY STRING
 *      (`?email=…&key=…`), so any message quoting a URL carries the key.
 *   2. A provider echoing the request back inside its error body.
 *
 * Both are handled: exact credential values are replaced, and sensitive query
 * parameters are stripped by name so an unknown provider cannot leak one either.
 */
export function redactSecrets(text: string): string {
  let out = text
  for (const name of CREDENTIAL_ENV) {
    const value = process.env[name]
    // Guard against short/empty values matching everywhere.
    if (value && value.length >= 8) out = out.split(value).join(`[${name}]`)
  }
  // Under BYOK the credential in play belongs to a USER and was decrypted from
  // the database, so it appears in no environment variable and the loop above
  // cannot see it. Leaking someone else's paid API key into our stored error
  // text would be worse than leaking our own, so the active request's secrets
  // are scrubbed first-class rather than relying on the pattern rules below.
  for (const value of activeSecretValues()) {
    out = out.split(value).join("[user-credential]")
  }
  // Strip by parameter name too — covers credentials not sourced from env.
  out = out.replace(/([?&](?:key|api_key|apikey|token|access_token|secret|email)=)[^&\s"'>]+/gi, "$1[redacted]")
  // Telegram carries its bot token in the URL PATH, not a query parameter, so
  // the rule above cannot see it. Catches rotated/foreign tokens too.
  out = out.replace(/\/bot[0-9]+:[A-Za-z0-9_-]+/g, "/bot[redacted]")
  // Bearer credentials in a quoted header or curl line.
  out = out.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1[redacted]")
  return out
}

/** Map an HTTP response to a structured provider failure. Body text is included only when it is a short, non-HTML API message. */
export function classifyHttp(res: Response, bodyText: string): ProviderError {
  const raw = bodyText.trim().startsWith("<") ? "" : ` ${bodyText.trim().slice(0, 200)}`
  const snippet = redactSecrets(raw)
  switch (res.status) {
    case 401:
    case 403:
      return new ProviderError("authentication_failed", `HTTP ${res.status} — credentials rejected or this plan lacks access.${snippet}`, false)
    case 402:
      return new ProviderError("quota_exhausted", `HTTP 402 — provider account is out of API credits.${snippet}`, true)
    case 429:
      return new ProviderError("rate_limited", `HTTP 429 — provider rate limit hit; retry shortly.${snippet}`, true)
    case 400:
    case 422:
      // Some providers report an EXHAUSTED ACCOUNT BALANCE with 400/422 rather
      // than 402 (Censys returns 422 "insufficient balance"). Classifying that
      // as a malformed query would be doubly wrong: it blames the query for an
      // account condition, and monitoring would treat it as a hard failure and
      // back the asset off, when the correct response is to defer and retry
      // once credits are available.
      if (/insufficient balance|insufficient credit|out of credit|quota exceeded|no credits/i.test(bodyText)) {
        return new ProviderError("quota_exhausted", `HTTP ${res.status} — provider account is out of API credits.${snippet}`, true)
      }
      return new ProviderError("query_unsupported", `HTTP ${res.status} — provider rejected this query shape.${snippet}`, false)
    case 404:
      return new ProviderError("provider_unavailable", `HTTP 404 — no record for this target.${snippet}`, false)
    default:
      if (res.status >= 500) return new ProviderError("provider_unavailable", `HTTP ${res.status} — provider is having a temporary outage.`, true)
      return new ProviderError("provider_unavailable", `HTTP ${res.status}.${snippet}`, true)
  }
}

/** GET returning parsed JSON, with structured errors. */
export async function getJson<T = unknown>(url: string, headers: Record<string, string> = {}, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  let res: Response
  try {
    res = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    if (/timeout|abort/i.test(msg)) throw new ProviderError("timeout", `Request timed out after ${timeoutMs}ms.`, true)
    // Network errors can quote the request URL, which for FOFA contains the key.
    throw new ProviderError("provider_unavailable", `Network error: ${redactSecrets(msg)}`, true)
  }
  const text = await res.text()
  if (!res.ok) throw classifyHttp(res, text)
  try {
    return JSON.parse(text) as T
  } catch {
    throw new ProviderError("provider_unavailable", "Provider returned a non-JSON response.", true)
  }
}

export function outcome(
  provider: ProviderName,
  role: ProviderRole,
  query: string,
  startedAt: number,
  status: ProviderStatus,
  observationCount: number,
  message?: string,
  retryable = false,
): ProviderOutcome {
  return {
    provider,
    role,
    status,
    message,
    retryable,
    query,
    latencyMs: Date.now() - startedAt,
    observationCount,
    fetchedAt: new Date().toISOString(),
  }
}

export function errorOutcome(provider: ProviderName, role: ProviderRole, query: string, startedAt: number, err: unknown): ProviderOutcome {
  if (err instanceof ProviderError) return outcome(provider, role, query, startedAt, err.status, 0, err.message, err.retryable)
  return outcome(provider, role, query, startedAt, "provider_unavailable", 0, err instanceof Error ? err.message : String(err), true)
}
