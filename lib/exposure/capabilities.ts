/**
 * Provider capability matrix — what each adapter ACTUALLY uses.
 *
 * Rules for this file:
 *  - A capability is `true` only if the current adapter code exercises it.
 *    Nothing is listed because a vendor's marketing page claims it.
 *  - `observationTimestampField` names the real JSON path we read; `null` means
 *    the API supplies no observation time, so freshness is genuinely unknown.
 *  - `typicalObservationAge` records what was MEASURED during the freshness
 *    audit (2026-08-30), not a vendor SLA.
 *
 * This drives both the docs and the `/api/exposure/status` response, so the two
 * cannot drift apart.
 */
import type { ProviderName, ProviderRole } from "@/lib/exposure/types"

export interface ProviderCapability {
  provider: ProviderName
  role: ProviderRole
  /** Direct lookup of a known IP/domain. */
  liveLookup: boolean
  /** Free-text / product search. */
  search: boolean
  /** Query by CVE id using the provider's own CVE field. */
  cveSearch: boolean
  /** Does the API return WHEN it observed the host? */
  observationTimestamp: boolean
  /** Exact response path we read the timestamp from — audit trail. */
  observationTimestampField: string | null
  /** Does the adapter extract service/port data? */
  serviceDiscovery: boolean
  /** Does the adapter extract vulnerability/CVE data? */
  vulnerabilityData: boolean
  /** Measured during the audit — null when the provider is unreachable to us. */
  typicalObservationAge: string | null
  rateLimitNotes: string
  /** Why caching is or isn't appropriate for this provider. */
  cacheRecommended: boolean
  /** Anything that materially limits what we can ask for. */
  queryLimitations: string
}

export const PROVIDER_CAPABILITIES: ProviderCapability[] = [
  {
    provider: "leakix",
    role: "discovery",
    liveLookup: false,          // /host/{ip} exists but the adapter does not use it
    search: true,
    cveSearch: false,           // index matches banner text; CVE ids do not appear
    observationTimestamp: true,
    observationTimestampField: "time",
    serviceDiscovery: true,
    vulnerabilityData: false,
    typicalObservationAge: "~98 days (measured 2026-08-30)",
    rateLimitNotes: "Free community API; generous but unpublished. Capped at 300 calls/hour by our own budget.",
    cacheRecommended: true,
    queryLimitations: "Free-text over banner/page content. No CVE field.",
  },
  {
    provider: "censys",
    role: "enrichment",
    liveLookup: true,
    search: false,              // 403 without a paid plan + CENSYS_ORG_ID
    cveSearch: false,           // same plan gate as search
    observationTimestamp: true,
    observationTimestampField: "result.resource.services[].scan_time",
    serviceDiscovery: true,
    vulnerabilityData: false,   // vulnerability fields are not on the free host record
    typicalObservationAge: "~0.1–0.4 days (measured 2026-08-30)",
    rateLimitNotes: "HTTP 429 on ~4 of 5 CONCURRENT host lookups; succeeds 5/5 sequentially. Enrichment concurrency pinned to 1.",
    cacheRecommended: true,
    queryLimitations: "Host lookup by IP only on a free plan. Search needs a paid plan + organization ID.",
  },
  {
    provider: "netlas",
    role: "enrichment",
    liveLookup: true,
    search: false,              // 400 "Only domain or ip is allowed" on this plan
    cveSearch: false,
    observationTimestamp: true,
    // `source[]` is a scan CAMPAIGN, not a per-host probe: hosts from one batch
    // share a `scan_ended_at`, and the end advances while the campaign runs.
    // The START is used so freshness is never overstated (measured 2026-08-31:
    // campaign 959 spanned 2026-08-21 -> 2026-08-31).
    observationTimestampField: "source[].scan_started_at (campaign start; falls back to scan_ended_at / scan_label)",
    serviceDiscovery: false,    // adapter reads software/technologies, not ports
    vulnerabilityData: true,    // software[].cve[] — the richest CVE source we have
    typicalObservationAge: "~9–42 days (measured 2026-08-30)",
    rateLimitNotes: "Not observed hitting a limit; capped at 300 calls/hour by our own budget.",
    cacheRecommended: true,
    queryLimitations: "Direct IP/domain lookup only on this plan. Open-ended search unavailable.",
  },
  {
    provider: "shodan",
    role: "enrichment",
    // Probed live 2026-09-03 on this account (plan "oss", 0 query credits):
    // host lookup works and is NOT billed against query credits; search needs
    // credits this plan lacks, so no search function is offered at all.
    liveLookup: true,
    search: false,
    cveSearch: false,
    observationTimestamp: true,
    observationTimestampField: "data[].timestamp per service, else last_update",
    serviceDiscovery: true,
    vulnerabilityData: true,    // per-service product+version, plus a host CVE list
    typicalObservationAge: "hours to days (measured: ~1 day on 2026-09-03)",
    rateLimitNotes: "Free plan is roughly 1 request/second; the adapter runs at concurrency 1.",
    cacheRecommended: true,
    queryLimitations:
      "Host lookup only. The host-level `vulns` array carries no port, so those CVEs stay asset-level; only per-service `vulns` are attached to a port.",
  },
  {
    provider: "abuseipdb",
    role: "threat",
    // Reputation only: it reports how often an address has been REPORTED, which
    // says nothing about what is running on it.
    liveLookup: true,
    search: false,
    cveSearch: false,
    observationTimestamp: true,
    observationTimestampField: "data.lastReportedAt",
    serviceDiscovery: false,
    vulnerabilityData: false,
    typicalObservationAge: "days to months (date of the last abuse report)",
    rateLimitNotes: "Free tier is 1,000 checks/day; the hourly budget stays well inside it.",
    cacheRecommended: true,
    queryLimitations: "IP reputation only — no services, no products, no CVEs.",
  },
  {
    provider: "greynoise",
    role: "threat",
    liveLookup: true,
    search: false,
    cveSearch: true,            // /v1/cve/{id} for CVE exploitation context
    observationTimestamp: true,
    observationTimestampField: "last_seen (community IP lookup)",
    serviceDiscovery: false,
    vulnerabilityData: true,    // exploit_found / KEV corroboration / relayed EPSS
    typicalObservationAge: "not measurable during audit — community search quota exhausted (429)",
    rateLimitNotes: "Community tier quota is MONTHLY and was exhausted during the audit.",
    cacheRecommended: true,
    queryLimitations: "Community endpoint accepts routable IPv4 only — IPv6 is rejected.",
  },
  {
    provider: "fofa",
    role: "discovery",
    liveLookup: false,
    search: true,
    cveSearch: true,            // cve="..." — implemented, blocked by credits
    observationTimestamp: false,
    observationTimestampField: null,
    serviceDiscovery: true,
    vulnerabilityData: false,
    typicalObservationAge: null,
    rateLimitNotes: "Account has 0 remaining API query credit (remain_api_query: 0).",
    cacheRecommended: true,
    queryLimitations: "Requires BOTH email and key. Field access is plan-dependent.",
  },
  {
    provider: "zoomeye",
    role: "discovery",
    liveLookup: false,
    search: true,
    cveSearch: true,            // cve="..." — implemented, blocked by credits
    observationTimestamp: false,
    observationTimestampField: null,
    serviceDiscovery: true,
    vulnerabilityData: false,
    typicalObservationAge: null,
    rateLimitNotes: "Account has 0 credits (HTTP 402 credits_insufficient).",
    cacheRecommended: true,
    queryLimitations: "POST /v2/search on api.zoomeye.ai; the legacy .org host is retired.",
  },
]

/**
 * NO configured provider performs an on-demand scan of the target. Every one
 * serves records from its own periodic internet-wide scanning. This constant
 * exists so the UI and docs cannot drift into calling the data "real-time".
 */
export const ANY_PROVIDER_SCANS_ON_DEMAND = PROVIDER_CAPABILITIES.some(() => false)

export function capabilityFor(provider: ProviderName): ProviderCapability | undefined {
  return PROVIDER_CAPABILITIES.find((c) => c.provider === provider)
}
