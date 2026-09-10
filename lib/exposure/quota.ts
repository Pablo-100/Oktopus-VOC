/**
 * Provider-aware quota control (B4).
 *
 * The route-level limiter (10 req/min/user) is not sufficient here: one search
 * fans out to ~20 upstream calls, and on serverless the in-memory bucket is
 * per-instance, so it cannot cap anything globally. Free-tier exhaustion is
 * already the dominant failure mode in this module — FOFA and ZoomEye are both
 * dead from it — so one analyst must not be able to burn the shared quota.
 *
 * Implemented as a DB-backed fixed-window counter (no new infrastructure).
 * Deliberately fail-OPEN: if the quota table is unreachable we allow the call
 * rather than break exposure search entirely. The provider's own 429/402 is
 * still handled downstream, so this is defence in depth, not the only guard.
 */
import { sql } from "@/lib/db"
import type { ProviderName } from "@/lib/exposure/types"
import { cacheScope } from "@/lib/exposure/credentials"

/**
 * Calls permitted per provider per rolling hour, across ALL users.
 * Sized against each provider's observed free-tier headroom, not guessed:
 *  - censys  : rate-limits aggressively (429 on ~4 of 5 concurrent lookups)
 *  - leakix  : the only working discovery provider — protect it hardest
 *  - netlas  : lookup-only plan, generous but finite
 *  - fofa/zoomeye : already at zero credits; a low cap avoids pointless calls
 *  - greynoise: community tier, per-IP lookups
 */
const HOURLY_BUDGET: Record<ProviderName, number> = {
  censys: 200,
  leakix: 300,
  netlas: 300,
  fofa: 50,
  zoomeye: 50,
  greynoise: 400,
  // Shodan free ("oss") plan: host lookups are not billed against query
  // credits, but the API is still rate limited ~1 req/s. Kept conservative.
  shodan: 200,
  // AbuseIPDB free tier: 1,000 checks/day. 40/hour stays well inside it even
  // if every hour is busy.
  abuseipdb: 40,
}

export type QuotaDecision = { allowed: true } | { allowed: false; retryAfterSeconds: number; used: number; budget: number }

/** Current UTC hour as the fixed-window key. */
function windowKey(): string {
  return new Date().toISOString().slice(0, 13) // YYYY-MM-DDTHH
}

/**
 * Reserve `count` calls against a provider's hourly budget.
 * Atomic: the INSERT..ON CONFLICT increments and returns the post-increment
 * value in one statement, so concurrent instances cannot both slip under the cap.
 */
export async function reserveQuota(provider: ProviderName, count = 1): Promise<QuotaDecision> {
  const budget = HOURLY_BUDGET[provider]
  // Budgets are per SCOPE, not global. A user spending their own credits is
  // metered against their own counter: they must neither be throttled by the
  // platform's shared hourly budget nor able to exhaust it for everyone else,
  // which a single (provider, window) counter allowed. Platform-key traffic all
  // shares the 'platform' scope, which is what keeps the free tier bounded.
  const scope = cacheScope(provider)
  try {
    const rows = (await sql`
      INSERT INTO exposure_provider_quota (provider, scope, window_key, used)
      VALUES (${provider}, ${scope}, ${windowKey()}, ${count})
      ON CONFLICT (provider, scope, window_key)
      DO UPDATE SET used = exposure_provider_quota.used + ${count}
      RETURNING used
    `) as Array<{ used: number }>
    const used = rows[0]?.used ?? 0
    if (used > budget) {
      const secondsIntoHour = new Date().getUTCMinutes() * 60 + new Date().getUTCSeconds()
      return { allowed: false, retryAfterSeconds: 3600 - secondsIntoHour, used, budget }
    }
    return { allowed: true }
  } catch {
    // Fail open — never let quota bookkeeping break the product.
    return { allowed: true }
  }
}

/** Read-only snapshot for the provider health panel. */
export async function quotaUsage(): Promise<Array<{ provider: string; used: number; budget: number }>> {
  try {
    // Reported per provider for the CALLER's scope, so a user on their own keys
    // sees their own consumption rather than the platform's aggregate.
    const rows = (await sql`
      SELECT provider, scope, used FROM exposure_provider_quota WHERE window_key = ${windowKey()}
    `) as Array<{ provider: string; scope: string; used: number }>
    return (Object.keys(HOURLY_BUDGET) as ProviderName[]).map((p) => {
      const scope = cacheScope(p)
      const row = rows.find((r) => r.provider === p && r.scope === scope)
      return { provider: p, used: row?.used ?? 0, budget: HOURLY_BUDGET[p] }
    })
  } catch {
    return []
  }
}
