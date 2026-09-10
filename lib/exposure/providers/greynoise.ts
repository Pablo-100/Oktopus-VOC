/**
 * GreyNoise — THREAT context provider.
 *
 * IMPORTANT CONCEPTUAL BOUNDARY: GreyNoise is not an EPSS source. EPSS is a
 * FIRST.org exploit-prediction score and CISA KEV is a confirmed-exploitation
 * catalogue; both already come from OCTUPUS's own CVE pipeline. GreyNoise
 * answers a different question — "is this IP observed scanning/attacking the
 * internet, and is that traffic benign or malicious". These are surfaced as
 * SEPARATE signals; the earlier "GreyNoise EPSS" label conflated them and has
 * been removed.
 *
 * Verified live 2026-08-29:
 *   GET /v3/community/{ip} -> 200 {ip, noise, riot, classification, name,
 *                                  link, last_seen}  (real IP context)
 *                          -> 404 {noise:false, message:"IP not observed..."}
 *                             which is a VALID "clean" answer, not an error.
 *   GET /v2/riot/{ip}      -> 410 Gone (deprecated) — not used.
 *   GET /v1/cve/{id}       -> 200 CVE exploitation context (see lib/greynoise.ts,
 *                             already integrated with the CVE detail views).
 */
import { sql, initDb } from "@/lib/db"
import type { ProviderOutcome, ThreatContext } from "@/lib/exposure/types"
import type { CveExploitationActivity } from "@/lib/types"
import { outcome, errorOutcome, ProviderError, isValidIp, isPrivateIp, classifyHttp, DEFAULT_TIMEOUT_MS } from "./_base"
import { credential, cacheScope } from "@/lib/exposure/credentials"

const ROLE = "threat" as const
const NAME = "greynoise" as const

type CommunityResponse = {
  ip?: string
  noise?: boolean
  riot?: boolean
  classification?: string
  name?: string
  link?: string
  last_seen?: string
  message?: string
}

function key(): string {
  const k = credential("GREYNOISE_API_KEY")
  if (!k) throw new ProviderError("not_configured", "GREYNOISE_API_KEY is not set.", false)
  return k
}

/** IP threat context. A 404 means "never observed scanning" — a real, useful answer, returned as success. */
export async function lookupGreyNoise(ip: string): Promise<{ threat: ThreatContext | null; outcome: ProviderOutcome }> {
  const started = Date.now()
  const t = ip.trim()
  try {
    if (!isValidIp(t)) throw new ProviderError("query_unsupported", "GreyNoise lookup requires an IP address.", false)
    // The Community endpoint only accepts routable IPv4 ("Request is not a valid
    // routable IPv4 address"). Checked here so an IPv6 asset does not burn a
    // call to earn a guaranteed HTTP 400.
    if (t.includes(":")) throw new ProviderError("query_unsupported", "GreyNoise Community API accepts routable IPv4 addresses only.", false)
    if (isPrivateIp(t)) throw new ProviderError("query_unsupported", "Refusing to look up a private/reserved address.", false)

    let res: Response
    try {
      res = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(t)}`, {
        headers: { key: key(), Accept: "application/json" },
        signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
      })
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      throw new ProviderError(/timeout|abort/i.test(msg) ? "timeout" : "provider_unavailable", msg, true)
    }

    const text = await res.text()
    // 404 carries a meaningful body ("IP not observed scanning the internet") —
    // that is intelligence, not a failure, so it is NOT sent to classifyHttp.
    if (!res.ok && res.status !== 404) throw classifyHttp(res, text)

    const data = JSON.parse(text) as CommunityResponse
    const threat: ThreatContext = {
      ip: data.ip ?? t,
      classification: data.classification ?? (res.status === 404 ? "not_observed" : null),
      noise: Boolean(data.noise),
      riot: Boolean(data.riot),
      actor: data.name && data.name !== "unknown" ? data.name : null,
      lastSeen: data.last_seen ?? null,
      link: data.link ?? null,
    }
    return { threat, outcome: outcome(NAME, ROLE, t, started, "success", 1) }
  } catch (e) {
    return { threat: null, outcome: errorOutcome(NAME, ROLE, t, started, e) }
  }
}

// ───────────────────────── CVE-level exploitation context ─────────────────────
// B1 consolidation: this was `lib/greynoise.ts`, a second GreyNoise client
// living outside the provider abstraction. Same vendor, different endpoint —
// merged here so there is exactly ONE GreyNoise adapter.
//
// Endpoint `GET /v1/cve/{id}` confirmed working on a Community key (verified
// live 2026-08-26 against CVE-2021-44228). Real response shape:
//   { details: { vulnerability_name, ... },
//     exploitation_details: { exploit_found, exploitation_registered_in_kev, epss_score } }
//
// NOTE: `epss_score` here is GreyNoise RELAYING FIRST.org's EPSS. It is not a
// GreyNoise score and must never be labelled "GreyNoise EPSS" — EPSS, KEV and
// GreyNoise activity are three distinct signals.

const CVE_TTL_MS = 6 * 60 * 60 * 1000
const CVE_FAILURE_TTL_MS = 5 * 60 * 1000

function now(): string {
  return new Date().toISOString()
}

function cveDisabled(cveId: string): CveExploitationActivity {
  return { cveId, ok: false, exploited: null, inKev: null, epssScore: null, summary: null, error: "GREYNOISE_API_KEY not set", fetchedAt: now() }
}
function cveFailed(cveId: string, error: unknown): CveExploitationActivity {
  return { cveId, ok: false, exploited: null, inKev: null, epssScore: null, summary: null, error: error instanceof Error ? error.message : String(error), fetchedAt: now() }
}

/** Pure response parser — isolated for testing. Defensive: an unexpected schema yields nulls, never a throw. */
export function parseGreyNoiseCveResponse(cveId: string, data: Record<string, unknown>): CveExploitationActivity {
  const exploitation = data.exploitation_details as Record<string, unknown> | undefined
  const details = data.details as Record<string, unknown> | undefined
  return {
    cveId,
    ok: true,
    exploited: typeof exploitation?.exploit_found === "boolean" ? exploitation.exploit_found : null,
    inKev: typeof exploitation?.exploitation_registered_in_kev === "boolean" ? exploitation.exploitation_registered_in_kev : null,
    epssScore: typeof exploitation?.epss_score === "number" ? exploitation.epss_score : null,
    summary: typeof details?.vulnerability_name === "string" ? details.vulnerability_name : null,
    fetchedAt: now(),
  }
}

async function fetchCveFresh(cveId: string): Promise<CveExploitationActivity> {
  const k = credential("GREYNOISE_API_KEY")
  if (!k) return cveDisabled(cveId)
  try {
    const res = await fetch(`https://api.greynoise.io/v1/cve/${encodeURIComponent(cveId)}`, {
      headers: { key: k, Accept: "application/json" },
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    })
    if (res.status === 404) {
      return { cveId, ok: true, exploited: false, inKev: false, epssScore: null, summary: "No data for this CVE in GreyNoise.", fetchedAt: now() }
    }
    if (!res.ok) throw new Error(`HTTP ${res.status} — check GreyNoise plan/endpoint access`)
    return parseGreyNoiseCveResponse(cveId, (await res.json()) as Record<string, unknown>)
  } catch (e) {
    return cveFailed(cveId, e)
  }
}

/** DB-cached (6h) CVE exploitation-activity lookup. Failures re-checked after 5 min. */
export async function getCveExploitationActivity(cveId: string): Promise<CveExploitationActivity> {
  const key = cveId.trim().toUpperCase()
  if (!key) return cveFailed(cveId, "empty CVE id")
  await initDb()
  const rows = (await sql`SELECT result, fetched_at FROM greynoise_cache WHERE scope = ${cacheScope("greynoise")} AND query = ${key}`) as Array<{ result: CveExploitationActivity; fetched_at: string }>
  const cached = rows[0]
  if (cached) {
    const age = Date.now() - new Date(cached.fetched_at).getTime()
    if (age < (cached.result.ok ? CVE_TTL_MS : CVE_FAILURE_TTL_MS)) return cached.result
  }
  const fresh = await fetchCveFresh(key)
  await sql`
    INSERT INTO greynoise_cache (scope, query, result, fetched_at)
    VALUES (${cacheScope("greynoise")}, ${key}, ${JSON.stringify(fresh)}, now())
    ON CONFLICT (scope, query) DO UPDATE SET result = EXCLUDED.result, fetched_at = now()
  `
  return fresh
}
