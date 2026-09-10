/**
 * Normalized Exposure Intelligence model.
 *
 * Every provider returns a different shape; nothing provider-specific may
 * reach the UI. Provider adapters emit `ProviderObservation`s, the correlation
 * engine merges them into canonical `ExposureAsset`s.
 *
 * Provider roles are NOT interchangeable — verified live 2026-08-29 against
 * each real API (see docs/exposure-providers-setup.md for the evidence):
 *
 *   DISCOVERY  (free-text query -> candidate hosts)   LeakIX
 *   ENRICHMENT (known IP/domain -> deep detail)       Netlas, Censys
 *   THREAT     (known IP/CVE -> activity context)     GreyNoise
 *
 * Censys search and FOFA/ZoomEye are account-limited (documented per adapter),
 * NOT broken code — they report structured, specific errors rather than a
 * generic "blocked".
 */

export type ProviderName =
  | "censys" | "leakix" | "netlas" | "fofa" | "zoomeye" | "greynoise"
  // Added 2026-09-03. Shodan is what makes VERSION-level evidence reachable;
  // AbuseIPDB is reputation context alongside GreyNoise, not a replacement.
  | "shodan" | "abuseipdb"

/** What a provider is actually useful for — drives orchestration, not cosmetics. */
export type ProviderRole = "discovery" | "enrichment" | "threat"

/**
 * Structured provider outcome. Deliberately granular: an analyst must be able
 * to tell "your key is wrong" from "you're out of quota" from "this plan can't
 * do that" — collapsing these into "Blocked" hides actionable information.
 */
export type ProviderStatus =
  | "success"
  | "partial"
  | "not_configured"
  | "authentication_failed"
  | "rate_limited"
  | "quota_exhausted"
  | "plan_limitation"
  | "query_unsupported"
  | "provider_unavailable"
  | "timeout"

export interface ProviderOutcome {
  provider: ProviderName
  role: ProviderRole
  status: ProviderStatus
  /** Analyst-facing explanation. Never a raw stack trace. */
  message?: string
  /** Whether retrying later could plausibly succeed (quota/rate/outage) vs never (plan/auth). */
  retryable: boolean
  /** The exact query/target sent to the provider — provenance the analyst can verify. */
  query: string
  /** Round-trip time (average across calls when summarized). */
  latencyMs: number
  /** Count of observations produced (0 on failure). */
  observationCount: number
  /** Call accounting — a provider row can summarize many per-host calls (C3). */
  calls?: number
  successCalls?: number
  failedCalls?: number
  fetchedAt: string
}

/**
 * Where an observation came from. `query-target` is the user's own search term
 * materialised as a seed so enrichment has something to work on — it is NOT
 * evidence and must never be counted as a provider source (see A2).
 */
export type ObservationOrigin = "provider" | "query-target"

/**
 * Freshness state of an observation — derived from WHEN THE PROVIDER OBSERVED
 * the host, never from when OCTUPUS fetched it.
 *
 * `live` is defined for completeness but is currently UNREACHABLE: none of the
 * six configured providers performs an on-demand scan. They all serve records
 * from their own periodic internet-wide scans, so the most OCTUPUS can honestly
 * claim is "we fetched their latest indexed observation just now".
 *
 * Measured observation ages at audit time (2026-08-30): LeakIX ~98 days,
 * Netlas 9–42 days, Censys ~0.1–0.4 days. Calling any of that "real-time"
 * would be false.
 */
export type FreshnessState = "live" | "fresh" | "recent" | "stale" | "unknown"

export interface Freshness {
  /** When OCTUPUS retrieved this from the provider (or from its own cache). */
  fetchedAt: string
  /** When the PROVIDER says it observed the host. null when the API supplies none. */
  observedAt: string | null
  /** Age of the OBSERVATION in seconds. null when `observedAt` is unknown. */
  observationAgeSeconds: number | null
  /** True when this came from OCTUPUS's cache rather than a provider call. */
  fromCache: boolean
  state: FreshnessState
}

/** Observation-age thresholds. Deliberately conservative for scan-based data. */
export const FRESHNESS_THRESHOLDS = {
  freshSeconds: 24 * 60 * 60,       // < 1 day
  recentSeconds: 7 * 24 * 60 * 60,  // < 1 week
} as const

/** Classify by OBSERVATION age. Never called with a fetch timestamp. */
export function freshnessStateFor(observationAgeSeconds: number | null): FreshnessState {
  if (observationAgeSeconds == null) return "unknown"
  if (observationAgeSeconds < FRESHNESS_THRESHOLDS.freshSeconds) return "fresh"
  if (observationAgeSeconds < FRESHNESS_THRESHOLDS.recentSeconds) return "recent"
  return "stale"
}

/** Build a Freshness record from a provider-supplied observation timestamp. */
export function makeFreshness(observedAt: string | null | undefined, opts: { fromCache?: boolean; fetchedAt?: string } = {}): Freshness {
  const fetchedAt = opts.fetchedAt ?? new Date().toISOString()
  const parsed = observedAt ? Date.parse(observedAt) : NaN
  const valid = Number.isFinite(parsed) ? new Date(parsed).toISOString() : null
  // A provider timestamp in the future is not usable evidence — treat as unknown.
  const ageSeconds = valid ? Math.max(0, Math.floor((Date.parse(fetchedAt) - parsed) / 1000)) : null
  return {
    fetchedAt,
    observedAt: valid,
    observationAgeSeconds: ageSeconds,
    fromCache: opts.fromCache ?? false,
    state: freshnessStateFor(ageSeconds),
  }
}

/** A single provider's claim about one host/service, before correlation. */
export interface ProviderObservation {
  /**
   * null ONLY for synthetic origins (`query-target`). A null provider never
   * enters `sources`, `sourceCount`, confidence, or provider health.
   */
  provider: ProviderName | null
  origin?: ObservationOrigin
  /** Strongest identifier this observation carries. */
  ip?: string | null
  domain?: string | null
  hostname?: string | null
  asn?: number | null
  organization?: string | null
  country?: string | null
  city?: string | null
  latitude?: number | null
  longitude?: number | null
  services: ExposureService[]
  technologies: ExposureTechnology[]
  certificates: ExposureCertificate[]
  vulnerabilities: ExposureVulnerability[]
  /** Free-form provider notes (e.g. LeakIX leak summary) — displayed, never parsed for logic. */
  notes?: string | null
  firstSeen?: string | null
  lastSeen?: string | null
  /**
   * When the PROVIDER observed this host, taken from its own response
   * (e.g. LeakIX `time`, Censys `services[].scan_time`, Netlas `scan_ended_at`).
   * null when the API supplies no timestamp — never fabricated.
   */
  observedAt?: string | null
  /** Opaque reference back to the provider's own record, for the raw-intelligence view. */
  raw: unknown
}

/**
 * One provider's raw claim about a service. Preserved verbatim so that provider
 * DISAGREEMENT stays visible (B3) — silently letting the first writer win hides
 * fingerprint conflicts that matter before matching a product to a CVE.
 */
export interface ServiceClaim {
  source: ProviderName
  product?: string | null
  vendor?: string | null
  version?: string | null
  protocol?: string | null
}

export interface ExposureService {
  port: number
  transport?: string | null
  protocol?: string | null
  /** Derived consensus value. `claims` remains the authoritative record. */
  product?: string | null
  vendor?: string | null
  version?: string | null
  banner?: string | null
  httpStatus?: number | null
  httpTitle?: string | null
  httpServer?: string | null
  sources: ProviderName[]
  /** Every provider's individual claim for this port. */
  claims: ServiceClaim[]
  /** True when providers reported materially different products/versions here. */
  conflict?: boolean
}

export interface ExposureTechnology {
  name: string
  version?: string | null
  categories: string[]
  sources: ProviderName[]
}

export interface ExposureCertificate {
  commonName?: string | null
  sans: string[]
  issuer?: string | null
  fingerprint?: string | null
  validFrom?: string | null
  validTo?: string | null
  expired?: boolean | null
  sources: ProviderName[]
}

/**
 * A vulnerability as *observed by an exposure provider*. Deliberately carries
 * only what the provider asserted plus its own match confidence — authoritative
 * CVSS/EPSS/KEV enrichment comes from OCTUPUS's existing CVE pipeline
 * (lib/risk-engine.ts + the `cves` table), never from the EASM provider.
 */
/**
 * Strength of the link between a CVE and an asset — ordered weakest to
 * strongest. This distinction is load-bearing: a `pivot` match means only
 * "this CVE affects a product we saw here", which is a LEAD, not a finding.
 *
 *  pivot      — derived locally from CVE -> affected CPE product -> product
 *               seen on this asset. POTENTIAL exposure only. Never treat as
 *               confirmation, and it must not drive an incident on its own.
 *  product    — a provider matched the product name, but not the version.
 *  banner     — inferred from a service banner.
 *  version    — a provider fingerprinted the affected VERSION.
 *  cve-search — a provider directly asserts this host is affected by this CVE
 *               (queried by CVE id). Strongest available evidence.
 */
export type VulnMatchType = "pivot" | "product" | "banner" | "version" | "cve-search" | "unknown"

/**
 * Explicit evidence tier for a CVE↔asset link. Derived from `matchType`, but
 * surfaced as its own field so the distinction is STRUCTURAL rather than
 * something each consumer has to re-derive (and possibly get wrong).
 *
 *   confirmed — a provider, queried by CVE id, returned this host.
 *   strong    — the affected product VERSION was fingerprinted here.
 *   product   — the product name matched; the version is unknown, so the host
 *               may well not be on an affected build.
 *   pivot     — derived locally (CVE → affected CPE product → product seen
 *               here). A LEAD to verify, never a finding.
 *   weak      — heuristic/banner inference, or the provider did not say.
 *
 * Only `confirmed` may be presented as a confirmed vulnerability claim.
 */
export type EvidenceTier = "confirmed" | "strong" | "product" | "pivot" | "weak"

export interface ExposureVulnerability {
  cveId: string
  /** Provider-reported base score — a hint; the canonical value comes from NVD. */
  providerScore?: number | null
  providerSeverity?: string | null
  matchType?: VulnMatchType
  /** Explicit tier — always kept in sync with `matchType` by `evidenceTierFor()`. */
  evidenceTier: EvidenceTier
  /** True ONLY for tier `confirmed`. A pivot can never set this. */
  confirmed: boolean
  matchedProduct?: string | null
  sources: ProviderName[]
  /**
   * Port this CVE was correlated THROUGH, when it came from a specific service.
   * Absent for host-level findings (a provider CVE hit on the whole host, or a
   * local pivot) — those are recorded at port 0 rather than being attributed to
   * a service that never supplied the evidence.
   */
  correlatedPort?: number | null
}

/** Single source of truth mapping match type -> evidence tier. */
export function evidenceTierFor(matchType: VulnMatchType | undefined): EvidenceTier {
  switch (matchType) {
    case "cve-search": return "confirmed"
    case "version": return "strong"
    case "product": return "product"
    case "pivot": return "pivot"
    case "banner": return "weak"
    default: return "weak"
  }
}

/** GreyNoise IP context. NOT an EPSS source — EPSS is a FIRST.org signal, kept separate. */
export interface ThreatContext {
  ip: string
  /** GreyNoise classification: benign / malicious / unknown, or null when never observed. */
  classification?: string | null
  /** true = observed mass-scanning the internet. */
  noise: boolean
  /** true = known benign business service (RIOT). */
  riot: boolean
  /** Actor/provider name when GreyNoise attributes one (e.g. "Shodan.io"). */
  actor?: string | null
  lastSeen?: string | null
  link?: string | null
}

export type ConfidenceLevel = "low" | "medium" | "high" | "very_high"

/**
 * Whether deep enrichment was actually attempted for this asset (B2).
 * "not_requested" is NOT the same as low confidence: the asset was never
 * examined, so an analyst must not read it as "weak evidence".
 */
export type EnrichmentStatus = "not_requested" | "enriched" | "partial" | "failed"

/** Why the correlation engine merged these observations — shown to the analyst as evidence. */
export interface CorrelationEvidence {
  /** e.g. "exact-ip", "domain", "cert-fingerprint" */
  basis: string
  detail: string
}

/** The canonical, correlated asset — one real-world host, however many providers saw it. */
export interface ExposureAsset {
  /** Stable synthetic id derived from the strongest identifier (ip, else domain). */
  id: string
  ip?: string | null
  /** Primary domain for display. `domains` holds the full relationship set. */
  domain?: string | null
  /**
   * Every domain observed pointing at this asset. A domain is a RELATIONSHIP,
   * never an identity (A1) — two IPs sharing a domain stay two assets.
   */
  domains: string[]
  hostnames: string[]
  asn?: number | null
  organization?: string | null
  country?: string | null
  city?: string | null
  latitude?: number | null
  longitude?: number | null

  services: ExposureService[]
  technologies: ExposureTechnology[]
  certificates: ExposureCertificate[]
  vulnerabilities: ExposureVulnerability[]
  threat?: ThreatContext | null

  /** Every provider that independently observed this asset. Excludes synthetic origins. */
  sources: ProviderName[]
  sourceCount: number
  confidence: ConfidenceLevel
  confidenceScore: number
  evidence: CorrelationEvidence[]
  /** Was deep enrichment attempted? Distinguishes "unexamined" from "weakly evidenced". */
  enrichmentStatus: EnrichmentStatus
  /** True when this asset exists only because the user searched for it (no provider evidence). */
  isQueryTarget: boolean

  firstSeen?: string | null
  lastSeen?: string | null

  /**
   * Freshness of the asset as a whole — the FRESHEST provider observation
   * backing it, plus when OCTUPUS last fetched. Kept distinct on purpose:
   * "we checked 2 min ago" and "the provider saw this 98 days ago" are
   * different facts and must never be collapsed into one "live" claim.
   */
  freshness?: Freshness | null
  /** Per-provider freshness, so the analyst can see which source is stale. */
  providerFreshness?: Array<{ provider: ProviderName; freshness: Freshness }>

  /** Populated by lib/exposure/risk.ts once CVE enrichment has run. */
  exposureRisk?: ExposureRisk | null

  /** Per-provider raw payloads for the "View raw intelligence" panel. Never contains secrets. */
  raw: Array<{ provider: ProviderName; data: unknown }>
}

/**
 * Exposure-aware risk. Deliberately ADDITIVE to the existing RBVM score rather
 * than a replacement — `baseRbvm` is the unchanged CVE risk from
 * lib/risk-engine.ts, and `exposureFactor` explains what internet exposure adds.
 */
export interface ExposureRisk {
  score: number
  severity: "critical" | "high" | "medium" | "low"
  /** Highest RBVM score among this asset's correlated CVEs (0 when none). */
  baseRbvm: number
  /** Multiplier applied for real-world exposure evidence. */
  exposureFactor: number
  /** Human-readable contributions, so the number is never a black box. */
  factors: Array<{ label: string; delta: number; detail: string }>
  slaHours: number
  /** CVE ids that drove the score, highest-risk first. */
  drivingCves: string[]
}

export interface ExposureSearchResult {
  query: string
  queryType: QueryType
  /** The requested PAGE of assets — not necessarily the full correlated set. */
  assets: ExposureAsset[]
  providers: ProviderOutcome[]
  /** Total correlated assets available for this query (across all pages). */
  totalAssets: number
  /** Pagination echo — present on paginated responses so the client can page without guessing. */
  limit?: number
  offset?: number
  /** When this result was produced by the pipeline (NOT when providers observed the hosts). */
  fetchedAt: string
  cached: boolean
  /** When the cache entry was populated. Present only when `cached` is true. */
  cachedAt?: string
}

export type QueryType = "ip" | "domain" | "cve" | "port" | "product"
