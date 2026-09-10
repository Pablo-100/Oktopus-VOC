/**
 * Exposure Intelligence pipeline (server-only).
 *
 *   query -> classify -> DISCOVERY (parallel) -> correlate
 *                     -> ENRICHMENT of top hosts (parallel, per host)
 *                     -> re-correlate -> CVE enrichment from OCTUPUS's own
 *                        `cves` table -> exposure risk -> cache
 *
 * Every provider call is wrapped in Promise.allSettled: one provider failing
 * (or being out of quota) never fails the search, it just contributes a
 * ProviderOutcome explaining itself.
 *
 * Enrichment is capped (ENRICH_LIMIT) because each host costs 3 provider calls;
 * an uncapped fan-out would burn free-tier quota and stall the request.
 */
import { sql, initDb } from "@/lib/db"
import { correlate } from "@/lib/exposure/correlate"
import { riskLevel } from "@/lib/risk-engine"
import { redactSecrets } from "@/lib/exposure/providers/_base"
import { computeExposureRisk, type CveFacts } from "@/lib/exposure/risk"
import { correlateServices, mergeCorrelations } from "@/lib/exposure/cve-correlation"
import { trackAssetVulnerabilities, evaluateAlerts, type TrackingResult, type AlertEvaluation } from "@/lib/exposure/vuln-tracking"
import { deliverAlertsNow } from "@/lib/notify/outbox"
import { searchLeakix, leakixCveUnsupported } from "@/lib/exposure/providers/leakix"
import { lookupNetlas, netlasSearchUnsupported } from "@/lib/exposure/providers/netlas"
import { lookupCensys, searchCensys } from "@/lib/exposure/providers/censys"
import { lookupShodan } from "@/lib/exposure/providers/shodan"
import { lookupAbuseIPDB } from "@/lib/exposure/providers/abuseipdb"
import { lookupGreyNoise } from "@/lib/exposure/providers/greynoise"
import { searchFofa } from "@/lib/exposure/providers/fofa"
import { searchZoomeye } from "@/lib/exposure/providers/zoomeye"
import { isValidIp, isValidCve, isValidDomain, isPrivateIp } from "@/lib/exposure/providers/_base"
import { reserveQuota } from "@/lib/exposure/quota"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { detectChanges, snapshotOf, type AssetSnapshot, type ExposureChange } from "@/lib/exposure/changes"
import { credential, usingOwnKey, resultScope, cacheScope, withUserCredentials } from "@/lib/exposure/credentials"
import type {
  ExposureAsset, ExposureSearchResult, ProviderName, ProviderObservation, ProviderOutcome, QueryType,
} from "@/lib/exposure/types"

const CACHE_TTL_MS = 6 * 60 * 60 * 1000
const FAILURE_TTL_MS = 5 * 60 * 1000
/** Hosts to deep-enrich per search. Each costs Censys + Netlas + GreyNoise calls. */
const ENRICH_LIMIT = 8

export function classifyQuery(raw: string): QueryType {
  const q = raw.trim()
  if (isValidCve(q)) return "cve"
  if (isValidIp(q)) return "ip"
  if (/^\d{1,5}$/.test(q) && Number(q) > 0 && Number(q) <= 65535) return "port"
  if (isValidDomain(q)) return "domain"
  return "product"
}

/** Authoritative CVE facts from OCTUPUS's own pipeline — EASM providers never supply these. */
async function loadCveFacts(cveIds: string[]): Promise<Map<string, CveFacts>> {
  const map = new Map<string, CveFacts>()
  if (!cveIds.length) return map
  const unique = [...new Set(cveIds)]
  const rows = (await sql`
    SELECT cve_id, cvss, epss, is_kev, has_exploit FROM cves WHERE cve_id = ANY(${unique})
  `) as Array<{ cve_id: string; cvss: number | null; epss: number | null; is_kev: boolean; has_exploit: boolean }>
  for (const r of rows) {
    map.set(r.cve_id, { cveId: r.cve_id, cvss: r.cvss, epss: r.epss, isKev: r.is_kev, hasExploit: r.has_exploit })
  }
  return map
}

/**
 * Products affected by a CVE, read from OCTUPUS's OWN CVE data (A3 local pivot).
 * `lib/data.ts` already extracts vendors/products from NVD CPE configurations,
 * so no new parsing is introduced here.
 */
async function loadCveProducts(cveId: string): Promise<string[]> {
  try {
    const rows = (await sql`SELECT data FROM cves WHERE cve_id = ${cveId.toUpperCase()}`) as Array<{ data: { products?: string[]; vendors?: string[] } }>
    const d = rows[0]?.data
    if (!d) return []
    // Products are more selective than vendors; fall back to vendors only if needed.
    const products = (d.products ?? []).filter(Boolean)
    return (products.length ? products : (d.vendors ?? []).filter(Boolean)).slice(0, 3)
  } catch {
    return []
  }
}

/** Collapse a settled provider result into the accumulators, ignoring rejections here (handled by caller). */
function collect(
  settled: PromiseSettledResult<{ observations: ProviderObservation[]; outcome: ProviderOutcome }>,
  observations: ProviderObservation[],
  outcomes: ProviderOutcome[],
  fallback: () => ProviderOutcome,
): void {
  if (settled.status === "fulfilled") {
    observations.push(...settled.value.observations)
    outcomes.push(settled.value.outcome)
  } else {
    // C4: a rejected promise must NOT make the provider vanish from health.
    outcomes.push(fallback())
  }
}

/**
 * Discovery tier.
 *
 * A3: a CVE query is routed to each provider's DOCUMENTED CVE field
 * (`vulnerabilities.cve_id` / `cve=`), never to the generic product path — the
 * old behaviour searched `app="CVE-2021-44228"`, which is meaningless, and
 * free-text on LeakIX, which returns unrelated hosts. Providers with no CVE
 * capability report `query_unsupported` rather than silently falling back.
 *
 * Additionally the CVE is pivoted locally (CVE → affected CPE product) so
 * discovery providers without CVE search still contribute — those results are
 * marked `pivot`, i.e. POTENTIAL exposure, never confirmation.
 */
async function runDiscovery(query: string, type: QueryType): Promise<{ observations: ProviderObservation[]; outcomes: ProviderOutcome[]; pivotProducts: string[] }> {
  const observations: ProviderObservation[] = []
  const outcomes: ProviderOutcome[] = []

  if (type === "cve") {
    const cveId = query.toUpperCase()
    const [fofaRes, zoomRes, censysRes] = await Promise.allSettled([
      withQuota("fofa", "discovery", cveId, () => searchFofa(cveId, "cve")),
      withQuota("zoomeye", "discovery", cveId, () => searchZoomeye(cveId, "cve")),
      withQuota("censys", "discovery", cveId, () => searchCensys(cveId, { cveId })),
    ])
    collect(fofaRes, observations, outcomes, () => providerRejected("fofa", "discovery", cveId, fofaRes))
    collect(zoomRes, observations, outcomes, () => providerRejected("zoomeye", "discovery", cveId, zoomRes))
    collect(censysRes, observations, outcomes, () => providerRejected("censys", "discovery", cveId, censysRes))

    // Providers with no CVE query capability — declared, not faked.
    outcomes.push(leakixCveUnsupported(cveId))
    outcomes.push(netlasSearchUnsupported(cveId))

    // Local pivot: CVE -> affected product -> product discovery.
    const pivotProducts = await loadCveProducts(cveId)
    for (const product of pivotProducts) {
      const pivot = await Promise.allSettled([searchLeakix(product)])
      if (pivot[0].status === "fulfilled") {
        // Mark every pivoted observation as POTENTIAL exposure to this CVE.
        for (const o of pivot[0].value.observations) {
          o.vulnerabilities = [makeVulnerability({
            cveId, matchType: "pivot", matchedProduct: product,
            sources: o.provider ? [o.provider] : [],
          })]
          observations.push(o)
        }
        outcomes.push({ ...pivot[0].value.outcome, query: `${cveId} → product:"${product}"` })
      }
    }
    return { observations, outcomes, pivotProducts }
  }

  const providerType = type === "ip" ? "ip" : type === "domain" ? "domain" : type === "port" ? "port" : "product"
  const [leakixRes, fofaRes, zoomRes, censysRes] = await Promise.allSettled([
    withQuota("leakix", "discovery", query, () => searchLeakix(query)),
    withQuota("fofa", "discovery", query, () => searchFofa(query, providerType)),
    withQuota("zoomeye", "discovery", query, () => searchZoomeye(query, providerType)),
    withQuota("censys", "discovery", query, () => searchCensys(query)),
  ])
  collect(leakixRes, observations, outcomes, () => providerRejected("leakix", "discovery", query, leakixRes))
  collect(fofaRes, observations, outcomes, () => providerRejected("fofa", "discovery", query, fofaRes))
  collect(zoomRes, observations, outcomes, () => providerRejected("zoomeye", "discovery", query, zoomRes))
  collect(censysRes, observations, outcomes, () => providerRejected("censys", "discovery", query, censysRes))

  // Netlas can't do discovery on this plan — say so explicitly rather than omit it.
  outcomes.push(netlasSearchUnsupported(query))
  return { observations, outcomes, pivotProducts: [] }
}

/**
 * B4: gate a provider call on the shared hourly budget. When exhausted the
 * provider reports `rate_limited` (retryable) instead of issuing a call that
 * would burn quota other analysts still need.
 */
async function withQuota(
  provider: ProviderName,
  role: "discovery" | "enrichment" | "threat",
  query: string,
  call: () => Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }>,
): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const decision = await reserveQuota(provider)
  if (!decision.allowed) {
    return {
      observations: [],
      outcome: {
        provider, role, status: "rate_limited",
        message: `Shared hourly budget for ${provider} is exhausted (${decision.used}/${decision.budget}). Protects the account quota from a single search; retries in ${Math.ceil(decision.retryAfterSeconds / 60)} min.`,
        retryable: true, query, latencyMs: 0, observationCount: 0,
        calls: 0, successCalls: 0, failedCalls: 0,
        fetchedAt: new Date().toISOString(),
      },
    }
  }
  return call()
}

/** C4: build a visible health row for a provider whose promise rejected outright. */
function providerRejected(provider: ProviderName, role: "discovery" | "enrichment" | "threat", query: string, settled: PromiseSettledResult<unknown>): ProviderOutcome {
  const reason = settled.status === "rejected" ? settled.reason : undefined
  return {
    provider, role, status: "provider_unavailable",
    message: `Adapter threw unexpectedly: ${reason instanceof Error ? reason.message : String(reason ?? "unknown")}`,
    retryable: true, query, latencyMs: 0, observationCount: 0, fetchedAt: new Date().toISOString(),
  }
}

/**
 * Enrichment tier — deep per-host lookups against providers that support them.
 *
 * `priorityTarget` is the user's literal IP/domain query. Without it, discovery
 * noise (dozens of unrelated hosts LeakIX matched on the string) outranked the
 * asset the user actually asked about and pushed it out of the ENRICH_LIMIT
 * budget — so searching an IP returned everything except that IP.
 */
async function runEnrichment(assets: ExposureAsset[], priorityTarget?: string): Promise<{
  observations: ProviderObservation[]
  outcomes: ProviderOutcome[]
  threats: Map<string, NonNullable<ExposureAsset["threat"]>>
  /** Targets enrichment was actually attempted for (B2 transparency). */
  attempted: Set<string>
  /** Targets where every enrichment call failed. */
  failed: Set<string>
}> {
  const withTarget = priorityTarget
    ? [...assets].sort((a, b) => {
        const aIs = a.ip === priorityTarget || a.domain === priorityTarget ? 0 : 1
        const bIs = b.ip === priorityTarget || b.domain === priorityTarget ? 0 : 1
        return aIs - bIs
      })
    : assets
  const targets = withTarget
    .filter((a) => a.ip || a.domain)
    .slice(0, ENRICH_LIMIT)

  const observations: ProviderObservation[] = []
  const outcomes: ProviderOutcome[] = []
  const threats = new Map<string, NonNullable<ExposureAsset["threat"]>>()

  // Per-provider concurrency. Measured, not guessed: Censys returns HTTP 429 for
  // ~4 of 5 concurrent host lookups on this plan but succeeds 5/5 when issued
  // sequentially, so it MUST stay at 1. Netlas and GreyNoise tolerate parallelism.
  const runLimited = async <T,>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> => {
    let cursor = 0
    const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (cursor < items.length) {
        const item = items[cursor++]
        try { await fn(item) } catch { /* per-item failure never aborts the batch */ }
      }
    })
    await Promise.all(workers)
  }

  const ipTargets = targets.filter((a) => a.ip).map((a) => a.ip!)
  const lookupTargets = targets.map((a) => a.ip ?? a.domain!)
  const attempted = new Set<string>(lookupTargets)
  const succeeded = new Set<string>()

  await Promise.allSettled([
    runLimited(lookupTargets, 3, async (target) => {
      const r = await withQuota("netlas", "enrichment", target, () => lookupNetlas(target))
      observations.push(...r.observations)
      outcomes.push(r.outcome)
      if (r.outcome.status === "success" || r.outcome.status === "partial") succeeded.add(target)
    }),
    // Sequential by necessity — see the note above.
    runLimited(ipTargets, 1, async (ip) => {
      const r = await withQuota("censys", "enrichment", ip, () => lookupCensys(ip))
      observations.push(...r.observations)
      outcomes.push(r.outcome)
      if (r.outcome.status === "success" || r.outcome.status === "partial") succeeded.add(ip)
    }),
    // SHODAN — the only configured provider that reports a per-service VERSION,
    // which is what makes `strong` evidence (and therefore alerting) reachable.
    // Concurrency 1: the free plan is rate limited at roughly one request per
    // second and answers a burst with 429.
    runLimited(ipTargets, 1, async (ip) => {
      const r = await withQuota("shodan", "enrichment", ip, () => lookupShodan(ip))
      observations.push(...r.observations)
      outcomes.push(r.outcome)
      if (r.outcome.status === "success" || r.outcome.status === "partial") succeeded.add(ip)
    }),
    // ABUSEIPDB — reputation only. It never contributes services or CVEs, so it
    // cannot influence what we believe is RUNNING on a host.
    runLimited(ipTargets, 2, async (ip) => {
      // Quota is reserved directly rather than via `withQuota`, which expects a
      // provider that returns observations — this one returns reputation.
      const decision = await reserveQuota("abuseipdb")
      if (!decision.allowed) {
        outcomes.push({
          provider: "abuseipdb", role: "threat", status: "rate_limited",
          message: `Shared hourly budget for abuseipdb is exhausted (${decision.used}/${decision.budget}).`,
          retryable: true, query: ip, latencyMs: 0, observationCount: 0, fetchedAt: new Date().toISOString(),
        })
        return
      }
      const r = await lookupAbuseIPDB(ip)
      outcomes.push(r.outcome)
      if (r.outcome.status === "success") succeeded.add(ip)
      // GreyNoise is the primary threat source and runs after this; it must not
      // be overwritten, so AbuseIPDB only fills a gap it left.
      if (r.threat && !threats.has(ip)) threats.set(ip, r.threat)
    }),
    runLimited(ipTargets, 3, async (ip) => {
      const decision = await reserveQuota("greynoise")
      if (!decision.allowed) {
        outcomes.push({
          provider: "greynoise", role: "threat", status: "rate_limited",
          message: `Shared hourly budget for greynoise is exhausted (${decision.used}/${decision.budget}).`,
          retryable: true, query: ip, latencyMs: 0, observationCount: 0, fetchedAt: new Date().toISOString(),
        })
        return
      }
      const r = await lookupGreyNoise(ip)
      outcomes.push(r.outcome)
      if (r.outcome.status === "success") succeeded.add(ip)
      // GreyNoise is the sharper signal WHEN IT HAS ONE. "Not observed" is an
      // absence of data, not a finding, so it must not erase a real AbuseIPDB
      // report — that would turn "nobody scanned it" into "it is clean".
      const observed = r.threat && r.threat.classification !== "not_observed"
      if (r.threat && (observed || !threats.has(ip))) threats.set(ip, r.threat)
    }),
  ])

  const failed = new Set([...attempted].filter((t) => !succeeded.has(t)))
  return { observations, outcomes, threats, attempted, failed }
}

/**
 * Collapse many per-host outcomes into one row per provider for the health panel.
 *
 * C3: previously this reused a single call's `query` as if it represented the
 * whole provider operation, so the panel showed e.g. "GreyNoise query =
 * 195.201.173.91" — one of eight hosts, presented as THE query. Now the row
 * carries real call accounting and describes the operation instead.
 */
/**
 * Persist what each provider ACTUALLY did on this pass.
 *
 * Best-effort and never awaited into the response path: health bookkeeping must
 * not slow a search or fail one. `configured` cannot answer "is this provider
 * usable right now" — only a real outcome can.
 */
function recordProviderHealth(summary: ProviderOutcome[]): void {
  for (const o of summary) {
    // `not_configured` carries no information about the account; skip it so a
    // provider without a key never overwrites a real observation.
    if (o.status === "not_configured") continue
    const healthy = o.status === "success" || o.status === "partial"
    // Recorded against the SCOPE whose key was used. "Out of credits" is a fact
    // about one account: reporting the platform's exhausted Censys key as this
    // user's status — or vice versa — would be precisely the false information
    // this table was added to eliminate.
    void sql`
      INSERT INTO exposure_provider_health (provider, scope, status, message, observations, checked_at, last_ok_at)
      VALUES (${o.provider}, ${cacheScope(o.provider)}, ${o.status}, ${redactSecrets(o.message ?? "")}, ${o.observationCount}, now(),
              ${healthy ? new Date().toISOString() : null}::timestamptz)
      ON CONFLICT (provider, scope) DO UPDATE SET
        status = EXCLUDED.status,
        message = EXCLUDED.message,
        observations = EXCLUDED.observations,
        checked_at = now(),
        -- Preserved when the current call failed, so the UI can say how long a
        -- provider has been down rather than just that it is down.
        last_ok_at = COALESCE(EXCLUDED.last_ok_at, exposure_provider_health.last_ok_at)
    `.catch(() => { /* health is an enhancement, never a reason to fail */ })
  }
}

function summarizeOutcomes(outcomes: ProviderOutcome[], originatingQuery: string): ProviderOutcome[] {
  const byProvider = new Map<string, ProviderOutcome[]>()
  for (const o of outcomes) {
    const list = byProvider.get(o.provider) ?? []
    list.push(o)
    byProvider.set(o.provider, list)
  }
  const summary: ProviderOutcome[] = []
  for (const [, list] of byProvider) {
    const successes = list.filter((o) => o.status === "success" || o.status === "partial")
    const failures = list.filter((o) => o.status !== "success" && o.status !== "partial")
    const observationCount = list.reduce((n, o) => n + o.observationCount, 0)
    const avgLatency = Math.round(list.reduce((n, o) => n + o.latencyMs, 0) / list.length)
    // Report a success if the provider worked at least once; otherwise surface
    // the first real failure so the analyst sees the actionable reason.
    const representative = successes[0] ?? list[0]
    const status = successes.length > 0 ? (successes.length === list.length ? "success" : "partial") : representative.status
    const failureReason = failures[0]?.message
    summary.push({
      ...representative,
      status,
      observationCount,
      latencyMs: avgLatency,
      calls: list.length,
      successCalls: successes.length,
      failedCalls: failures.length,
      // One row can cover many per-host calls; describe the operation, not one host.
      query: list.length > 1 ? `${originatingQuery} (${list.length} calls)` : representative.query,
      message: failures.length > 0 && successes.length > 0
        ? `${successes.length}/${list.length} calls succeeded. ${failureReason ?? ""}`.trim()
        : representative.message,
    })
  }
  recordProviderHealth(summary)
  return summary.sort((a, b) => a.provider.localeCompare(b.provider))
}

async function runPipeline(query: string, type: QueryType): Promise<ExposureSearchResult> {
  // 1. Discovery
  const discovery = await runDiscovery(query, type)

  // For a direct IP/domain query the target itself is worth enriching even if no
  // discovery provider returned it — seed it so enrichment always has something.
  //
  // A2: the seed is attributed to NO provider (`provider: null`,
  // `origin: "query-target"`). It previously claimed `provider: "leakix"`, which
  // fabricated evidence: LeakIX appeared under "Provider confirmation" and
  // inflated sourceCount/confidence on every direct lookup.
  const seeded: ProviderObservation[] = [...discovery.observations]
  if (type === "ip" || type === "domain") {
    const already = seeded.some((o) => (type === "ip" ? o.ip === query : o.domain === query))
    if (!already) {
      seeded.push({
        provider: null,
        origin: "query-target",
        ip: type === "ip" ? query : null,
        domain: type === "domain" ? query : null,
        hostname: null, services: [], technologies: [], certificates: [], vulnerabilities: [],
        notes: "Search target — no provider has reported this asset.", firstSeen: null, lastSeen: null, raw: null,
      })
    }
  }

  // 2. First correlation pass -> candidate hosts worth enriching
  const candidates = correlate(seeded)

  // 3. Enrichment — the literal query target always gets enriched first.
  const priorityTarget = type === "ip" || type === "domain" ? query : undefined
  const enrichment = await runEnrichment(candidates, priorityTarget)

  // 4. Re-correlate everything together
  const assets = correlate([...seeded, ...enrichment.observations])

  // 5. Attach threat context + enrichment transparency (B2).
  // "not_requested" must never be shown as low confidence: those assets were
  // never examined (ENRICH_LIMIT), which is different from weak evidence.
  for (const a of assets) {
    if (a.ip && enrichment.threats.has(a.ip)) a.threat = enrichment.threats.get(a.ip) ?? null
    const target = a.ip ?? a.domain
    if (target && enrichment.attempted.has(target)) {
      a.enrichmentStatus = enrichment.failed.has(target) ? "failed" : "enriched"
    } else {
      a.enrichmentStatus = "not_requested"
    }
  }

  // 6. CVE enrichment from OCTUPUS's own data + exposure risk
  const allCves = assets.flatMap((a) => a.vulnerabilities.map((v) => v.cveId))
  const facts = await loadCveFacts(allCves)
  for (const a of assets) a.exposureRisk = computeExposureRisk(a, facts)

  // The asset the user literally asked for always ranks first; everything else
  // by exposure risk, then correlation confidence.
  assets.sort((a, b) => {
    if (priorityTarget) {
      const aIs = a.ip === priorityTarget || a.domain === priorityTarget ? 0 : 1
      const bIs = b.ip === priorityTarget || b.domain === priorityTarget ? 0 : 1
      if (aIs !== bIs) return aIs - bIs
    }
    return (b.exposureRisk?.score ?? 0) - (a.exposureRisk?.score ?? 0) || b.confidenceScore - a.confidenceScore
  })

  return {
    query,
    queryType: type,
    assets,
    providers: summarizeOutcomes([...discovery.outcomes, ...enrichment.outcomes], query),
    totalAssets: assets.length,
    fetchedAt: new Date().toISOString(),
    cached: false,
  }
}

export interface PageOptions {
  limit?: number
  offset?: number
}

/** Hard ceiling on one page — bounds the response no matter what a caller asks for. */
export const MAX_PAGE_SIZE = 100
const DEFAULT_PAGE_SIZE = 50

/**
 * Slice a full correlated result into one page.
 *
 * C5: the slice happens SERVER-SIDE, so the browser only ever receives the
 * requested page. `totalAssets` still reports the full correlated count so the
 * client can paginate without ever holding the whole set.
 */
export function paginate(result: ExposureSearchResult, opts: PageOptions = {}): ExposureSearchResult {
  const limit = Math.max(1, Math.min(MAX_PAGE_SIZE, Math.floor(opts.limit ?? DEFAULT_PAGE_SIZE)))
  const offset = Math.max(0, Math.floor(opts.offset ?? 0))
  return {
    ...result,
    assets: result.assets.slice(offset, offset + limit),
    totalAssets: result.assets.length,
    limit,
    offset,
  }
}

/**
 * Public entry point — DB-cached, server-side paginated.
 * Failures cache briefly so a fixed key shows up fast.
 */
export async function exposureSearch(rawQuery: string, userId: string, page: PageOptions = {}): Promise<ExposureSearchResult> {
  return withUserCredentials(userId, () => exposureSearchInScope(rawQuery, userId, page))
}

async function exposureSearchInScope(rawQuery: string, userId: string, page: PageOptions = {}): Promise<ExposureSearchResult> {
  const query = rawQuery.trim()
  if (!query) throw new Error("Empty query")
  const type = classifyQuery(query)
  const cacheKey = `v2:${type}:${query.toLowerCase()}`

  await initDb()
  const rows = (await sql`SELECT result, fetched_at FROM exposure_search_cache WHERE scope = ${resultScope()} AND query = ${cacheKey}`) as Array<{ result: ExposureSearchResult; fetched_at: string }>
  const cached = rows[0]
  if (cached) {
    const age = Date.now() - new Date(cached.fetched_at).getTime()
    const anySuccess = cached.result.providers?.some((p) => p.status === "success" || p.status === "partial")
    if (age < (anySuccess ? CACHE_TTL_MS : FAILURE_TTL_MS)) {
      // Paging a cached result costs zero provider calls — the whole point of
      // caching the full set and slicing per request.
      //
      // FRESHNESS: a cached hit is NOT a live retrieval. `fetchedAt` is rewritten
      // to when the cache entry was actually populated (not now), and every
      // asset is flagged `fromCache` so the UI can say "Cached · updated 17
      // minutes ago" instead of implying we just checked.
      const cacheFetchedAt = new Date(cached.fetched_at).toISOString()
      const marked: ExposureSearchResult = {
        ...cached.result,
        cached: true,
        cachedAt: cacheFetchedAt,
        assets: cached.result.assets.map((a) => ({
          ...a,
          freshness: a.freshness
            ? { ...a.freshness, fromCache: true, fetchedAt: cacheFetchedAt }
            : a.freshness,
          providerFreshness: a.providerFreshness?.map((p) => ({
            ...p,
            freshness: { ...p.freshness, fromCache: true, fetchedAt: cacheFetchedAt },
          })),
        })),
      }
      return paginate(marked, page)
    }
  }

  const result = await runPipeline(query, type)
  // C1: cache the normalized intelligence only — never the raw provider blobs.
  await sql`
    INSERT INTO exposure_search_cache (scope, query, result, fetched_at)
    VALUES (${resultScope()}, ${cacheKey}, ${JSON.stringify(stripRawForCache(result))}, now())
    ON CONFLICT (scope, query) DO UPDATE SET result = EXCLUDED.result, fetched_at = now()
  `
  await recordHistory(result, userId)
  await evictStaleCache()
  return paginate(result, page)
}

/**
 * C1: bounded cache. Evicts rows past the TTL, then trims to a hard row cap so
 * a long tail of unique queries cannot grow the table without limit.
 * Best-effort — never fails a search.
 */
const MAX_CACHE_ROWS = 500
async function evictStaleCache(): Promise<void> {
  try {
    await sql`DELETE FROM exposure_search_cache WHERE fetched_at < now() - interval '24 hours'`
    // Matched on the FULL key. The primary key became (scope, query) when users
    // started bringing their own credentials, so trimming by `query` alone
    // would evict every other tenant's row for the same search term — one
    // user's cache pressure silently destroying another's paid-for results.
    await sql`
      DELETE FROM exposure_search_cache c
      USING (
        SELECT scope, query FROM exposure_search_cache ORDER BY fetched_at DESC OFFSET ${MAX_CACHE_ROWS}
      ) AS stale
      WHERE c.scope = stale.scope AND c.query = stale.query
    `
  } catch (e) {
    console.error("[exposure-cache] eviction failed:", e instanceof Error ? e.message : String(e))
  }
}

/**
 * Append-only exposure history. Records the first and most recent time each
 * asset/service was seen so the UI can show genuine "new asset"/"new service"
 * events instead of inventing a timeline.
 */
async function recordHistory(result: ExposureSearchResult, userId: string): Promise<void> {
  // C2: previously this issued up to 25 sequential awaits inside the request
  // path. One batched statement instead — and a query-target-only asset is
  // skipped, since "the user typed it" is not an observation worth recording.
  const rows = result.assets
    .filter((a) => (a.ip || a.domain) && !a.isQueryTarget)
    .slice(0, 25)
  if (!rows.length) return
  try {
    await sql`
      INSERT INTO exposure_history (user_id, asset_key, query, ip, domain, service_count, vuln_count, risk_score, sources, first_seen, last_seen)
      SELECT ${userId}, t.asset_key, t.query, t.ip, t.domain, t.service_count, t.vuln_count, t.risk_score, t.sources, now(), now()
      FROM UNNEST(
        ${rows.map((a) => a.id)}::text[],
        ${rows.map(() => result.query)}::text[],
        ${rows.map((a) => a.ip)}::text[],
        ${rows.map((a) => a.domain)}::text[],
        ${rows.map((a) => a.services.length)}::int[],
        ${rows.map((a) => a.vulnerabilities.length)}::int[],
        ${rows.map((a) => a.exposureRisk?.score ?? 0)}::real[],
        ${rows.map((a) => JSON.stringify(a.sources))}::jsonb[]
      ) AS t(asset_key, query, ip, domain, service_count, vuln_count, risk_score, sources)
      ON CONFLICT (user_id, asset_key) DO UPDATE SET
        last_seen = now(),
        service_count = EXCLUDED.service_count,
        vuln_count = EXCLUDED.vuln_count,
        risk_score = EXCLUDED.risk_score,
        sources = EXCLUDED.sources
    `
  } catch (e) {
    // History is an enhancement, never a reason to fail a search.
    console.error("[exposure-history] write failed:", e instanceof Error ? e.message : String(e))
  }
}

/**
 * C1: strip bulky raw provider payloads before caching.
 *
 * The cache previously stored every provider's full response per asset, so a
 * single 33-asset query persisted megabytes of JSONB with no eviction. Raw
 * payloads are debugging aids, not intelligence — the normalized model already
 * carries everything the UI renders. They are re-fetchable on demand.
 */
function stripRawForCache(result: ExposureSearchResult): ExposureSearchResult {
  return {
    ...result,
    assets: result.assets.map((a) => ({
      ...a,
      raw: a.raw.map((r) => ({ provider: r.provider, data: { note: "Raw payload not retained in cache — re-run the search to fetch it live." } })),
    })),
  }
}

/**
 * ON-DEMAND enrichment of a SINGLE asset (item 5).
 *
 * Runs the same enrichment tier the pipeline uses — Netlas + Censys + GreyNoise
 * — but for exactly one target, so an analyst can deepen a specific asset the
 * per-search `ENRICH_LIMIT` skipped. Quota and the Censys concurrency-1 rule are
 * respected because it reuses `runEnrichment()` unchanged.
 *
 * Explicitly NOT a bulk operation: enriching every asset automatically is what
 * ENRICH_LIMIT exists to prevent.
 */
export async function enrichSingleAsset(target: string, userId?: string | null): Promise<{
  asset: ExposureAsset | null
  providers: ProviderOutcome[]
}> {
  return withUserCredentials(userId ?? null, () => enrichSingleAssetInScope(target))
}

async function enrichSingleAssetInScope(target: string): Promise<{
  asset: ExposureAsset | null
  providers: ProviderOutcome[]
}> {
  const t = target.trim()
  const isIp = isValidIp(t)
  if (!isIp && !isValidDomain(t)) throw new Error("Enrichment target must be an IP address or a domain.")
  if (isIp && isPrivateIp(t)) throw new Error("Refusing to enrich a private/reserved address.")

  // A minimal seed carrying no provider evidence (A2) — enrichment supplies it.
  const seed: ProviderObservation = {
    provider: null,
    origin: "query-target",
    ip: isIp ? t : null,
    domain: isIp ? null : t,
    hostname: null, services: [], technologies: [], certificates: [], vulnerabilities: [],
    notes: null, firstSeen: null, lastSeen: null, raw: null,
  }

  const seedAsset = correlate([seed])[0]
  const enrichment = await runEnrichment([seedAsset], t)
  const assets = correlate([seed, ...enrichment.observations])

  const asset = assets.find((a) => a.ip === t || a.domain === t) ?? assets[0] ?? null
  if (asset) {
    if (asset.ip && enrichment.threats.has(asset.ip)) asset.threat = enrichment.threats.get(asset.ip) ?? null
    asset.enrichmentStatus = enrichment.failed.has(t) ? "failed" : "enriched"

    // STEP 3 — EXPOSURE -> CVE. Correlate the observed services against
    // OCTUPUS's OWN CVE store, then let the EXISTING RBVM engine score the
    // result. This runs BEFORE `computeExposureRisk` so correlated CVEs are
    // part of the same single risk calculation rather than a second one.
    //
    // Correlation belongs to ENRICHMENT, not discovery: it needs per-service
    // product/version, which only an enriched asset has, and it keeps search
    // pages free of per-asset CVE queries.
    try {
      const correlations = await correlateServices(asset.services)
      // Union, never overwrite — a provider's stronger evidence outranks a
      // local product match, and a local match never promotes itself.
      asset.vulnerabilities = mergeCorrelations(asset.vulnerabilities, correlations)
    } catch (e) {
      // Correlation is an enhancement; never fail a refresh because of it.
      console.error("[exposure-correlation] failed:", e instanceof Error ? e.message : String(e))
    }

    const facts = await loadCveFacts(asset.vulnerabilities.map((v) => v.cveId))
    asset.exposureRisk = computeExposureRisk(asset, facts)
  }
  return { asset, providers: summarizeOutcomes(enrichment.outcomes, t) }
}

/**
 * Persist an asset snapshot and emit normalized change events (items 10–11).
 *
 * Called after a refresh/enrichment, never on a plain cached read — comparing
 * a cached result against itself would manufacture phantom "changes".
 * Best-effort: history is an enhancement, never a reason to fail the request.
 */
export async function recordAssetChanges(asset: ExposureAsset, userId: string): Promise<ExposureChange[]> {
  return (await recordAssetChangesDetailed(asset, userId)).changes
}

/**
 * As `recordAssetChanges`, but also returns the PREVIOUS snapshot.
 *
 * Risk-escalation alerting needs the prior risk, and the prior snapshot is read
 * here anyway — returning it avoids a second query that would race with the
 * write below.
 */
export async function recordAssetChangesDetailed(
  asset: ExposureAsset,
  userId: string,
): Promise<{ changes: ExposureChange[]; previous: AssetSnapshot | null }> {
  const key = asset.id
  if (!key || asset.isQueryTarget) return { changes: [], previous: null }
  try {
    // Scoped: another user's snapshot of the SAME host must never be read as
    // this user's previous state, or their first observation would diff against
    // a stranger's history and emit phantom changes.
    const rows = (await sql`
      SELECT snapshot FROM exposure_asset_state WHERE user_id = ${userId} AND asset_key = ${key}
    `) as Array<{ snapshot: AssetSnapshot }>
    const previous = rows[0]?.snapshot ?? null
    const current = snapshotOf(asset)
    const changes = detectChanges(previous, current)

    await sql`
      INSERT INTO exposure_asset_state (user_id, asset_key, snapshot, updated_at)
      VALUES (${userId}, ${key}, ${JSON.stringify(current)}, now())
      ON CONFLICT (user_id, asset_key) DO UPDATE SET snapshot = EXCLUDED.snapshot, updated_at = now()
    `
    if (changes.length) {
      await sql`
        INSERT INTO exposure_events (user_id, asset_key, kind, detail, before_val, after_val)
        SELECT * FROM UNNEST(
          ${changes.map(() => userId)}::text[],
          ${changes.map(() => key)}::text[],
          ${changes.map((c) => c.kind)}::text[],
          ${changes.map((c) => c.detail)}::text[],
          ${changes.map((c) => c.before ?? null)}::text[],
          ${changes.map((c) => c.after ?? null)}::text[]
        )
      `
    }
    return { changes, previous }
  } catch (e) {
    console.error("[exposure-changes] write failed:", e instanceof Error ? e.message : String(e))
    return { changes: [], previous: null }
  }
}

/**
 * REFRESH NOW (item 15) — force a new provider observation for one asset,
 * bypassing OCTUPUS's own cache, then diff against the last-known snapshot.
 *
 * Distinct from `enrichSingleAsset`:
 *   Enrich  = get enrichment data for an asset we have not deepened yet.
 *   Refresh = deliberately re-query to see whether anything CHANGED, and record
 *             the diff as exposure events.
 *
 * It cannot make a provider re-scan the host — none of them offer that — so it
 * fetches each provider's LATEST indexed observation. The returned freshness
 * still reports the provider's own observation age, which may remain old.
 */
export async function refreshAsset(target: string, userId: string): Promise<{
  asset: ExposureAsset | null
  providers: ProviderOutcome[]
  changes: ExposureChange[]
  tracking: TrackingResult | null
  alerts: AlertEvaluation | null
}> {
  return withUserCredentials(userId, () => refreshAssetInScope(target, userId))
}

async function refreshAssetInScope(target: string, userId: string): Promise<{
  asset: ExposureAsset | null
  providers: ProviderOutcome[]
  changes: ExposureChange[]
  tracking: TrackingResult | null
  alerts: AlertEvaluation | null
}> {
  const { asset, providers } = await enrichSingleAsset(target)
  if (!asset) return { asset: null, providers, changes: [], tracking: null, alerts: null }

  // The full STEP 3 tail, in one place so the scheduler and the manual button
  // cannot drift apart:
  //   exposure -> (correlation + RBVM, in enrichSingleAsset)
  //            -> snapshot/events -> vulnerability relationships -> SOC alerts
  const { changes, previous } = await recordAssetChangesDetailed(asset, userId)

  let tracking: TrackingResult | null = null
  let alerts: AlertEvaluation | null = null
  try {
    tracking = await trackAssetVulnerabilities(asset, providers, userId)
    alerts = await evaluateAlerts(asset, tracking, userId, {
      // Severity is derived from the stored score with the SAME thresholds the
      // risk engine uses, rather than stored separately — one definition.
      // `riskLevel()` from the RBVM engine owns the severity bands — this must
      // not re-declare them, or the two could silently disagree.
      severity: previous ? riskLevel(previous.riskScore).tone : null,
      score: previous?.riskScore ?? null,
    })
  } catch (e) {
    // Alerting must never break a refresh; the exposure data is still valid.
    console.error("[exposure-alerts] failed:", e instanceof Error ? e.message : String(e))
  }

  // STEP 5.1 — IMMEDIATE DELIVERY.
  //
  // Deliberately AFTER every write above has committed: Telegram must never
  // receive a notification for an alert that could still roll back. It also
  // sits outside the try/catch above by design — the outbox already holds the
  // work, so a slow or failing Telegram simply leaves the notification queued
  // for the scheduler. `deliverAlertsNow` never throws and is bounded, so a
  // refresh request can never hang on a third party.
  if (alerts?.alertIds.length) {
    await deliverAlertsNow(alerts.alertIds)
  }

  return { asset, providers, changes, tracking, alerts }
}


/**
 * Lightweight per-provider counts for one product — DISCOVERY ONLY.
 *
 * B1: this replaces the old `lib/exposure-providers.ts#getExposure`, so there is
 * now a single provider abstraction. Deliberately skips enrichment: this backs a
 * small panel inside the CVE/0-day detail dialogs, where a full ~20-call pipeline
 * would be wildly disproportionate (and would burn provider quota per dialog open).
 *
 * The counts are OBSERVATION counts (what the provider returned for this query),
 * not authoritative internet-wide totals — hence `approximate: true` throughout.
 */
export async function productExposureCounts(product: string, userId?: string | null): Promise<ProviderOutcome[]> {
  return withUserCredentials(userId ?? null, () => productExposureCountsInScope(product))
}

async function productExposureCountsInScope(product: string): Promise<ProviderOutcome[]> {
  const term = product.trim()
  if (!term) return []
  const { outcomes } = await runDiscovery(term, "product")
  return summarizeOutcomes(outcomes, term)
}

/**
 * Lightweight per-provider counts of hosts a provider asserts are affected by a
 * CVE — uses each provider's real CVE field, never a product-name fallback (A3).
 * Replaces `lib/exposure-providers.ts#getCveHostExposure`.
 */
export async function cveExposureCounts(cveId: string, userId?: string | null): Promise<ProviderOutcome[]> {
  return withUserCredentials(userId ?? null, () => cveExposureCountsInScope(cveId))
}

async function cveExposureCountsInScope(cveId: string): Promise<ProviderOutcome[]> {
  const id = cveId.trim().toUpperCase()
  if (!isValidCve(id)) return []
  const { outcomes } = await runDiscovery(id, "cve")
  return summarizeOutcomes(outcomes, id)
}

/** Provider configuration status without making any network call. */
/**
 * Which providers are reachable, and on whose credentials.
 *
 * Resolved through `credential()` rather than `process.env` so that inside a
 * user's request this reports THEIR reality: a provider the platform has no key
 * for is still "configured" when the user brought their own, and `source` tells
 * the UI which it is. Outside a credential context it behaves exactly as before
 * and reports the platform's configuration.
 */
export function providerConfiguration(): Array<{
  provider: string
  role: string
  configured: boolean
  source: "user" | "platform" | "none"
}> {
  const entry = (provider: string, role: string, fields: string[]) => {
    const configured = fields.every((f) => Boolean(credential(f)))
    return {
      provider,
      role,
      configured,
      source: (!configured ? "none" : usingOwnKey(provider) ? "user" : "platform") as
        | "user"
        | "platform"
        | "none",
    }
  }
  return [
    entry("leakix", "discovery", ["LEAKIX_API_KEY"]),
    entry("fofa", "discovery", ["FOFA_EMAIL", "FOFA_API_KEY"]),
    entry("zoomeye", "discovery", ["ZOOMEYE_API_KEY"]),
    entry("censys", "enrichment", ["CENSYS_API_TOKEN"]),
    entry("shodan", "enrichment", ["SHODAN_API_KEY"]),
    entry("abuseipdb", "threat", ["ABUSEIPDB_API_KEY"]),
    entry("netlas", "enrichment", ["NETLAS_API_KEY"]),
    entry("greynoise", "threat", ["GREYNOISE_API_KEY"]),
  ]
}
