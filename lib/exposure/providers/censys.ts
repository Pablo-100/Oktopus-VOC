/**
 * Censys — ENRICHMENT provider (host lookup), search is plan-limited.
 *
 * Verified live 2026-08-29 against the current Censys **Platform** API. The
 * configured credential is a Platform personal access token (`censys_<id>_<secret>`),
 * which is NOT accepted by the legacy `search.censys.io/api/v2` endpoints —
 * those need an API-ID/secret pair and answer 401. Findings:
 *
 *   POST api.platform.censys.io/v3/global/search/query
 *     -> 403 "This endpoint requires an organization ID for API access.
 *             Free users can only access this endpoint through the Platform UI."
 *        i.e. search is a genuine PLAN limitation, not a wrong endpoint or a
 *        broken key. Passing an org-id header does not lift it on a free plan.
 *
 *   GET api.platform.censys.io/v3/global/asset/host/{ip}
 *     -> 200 with rich data: location, autonomous_system, whois, services[].
 *        Confirmed stable (3/3 consecutive successes). Some individual assets
 *        answer 401 rather than 404, which is why a 401 on a single host is
 *        reported per-target instead of being treated as a global auth failure.
 *
 * If a paid plan + org id later become available, set CENSYS_ORG_ID and the
 * search path below activates with no other change.
 */
import type { ProviderObservation, ProviderOutcome, ExposureService } from "@/lib/exposure/types"
import { getJson, outcome, errorOutcome, ProviderError, isValidIp, isPrivateIp } from "./_base"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { credential } from "@/lib/exposure/credentials"

const ROLE = "enrichment" as const
const NAME = "censys" as const
const PLATFORM = "https://api.platform.censys.io"

type CensysService = {
  port?: number
  protocol?: string
  transport_protocol?: string
  banner?: string
  /** When Censys last scanned THIS service. Verified present 2026-08-30. */
  scan_time?: string
  software?: Array<{ product?: string; vendor?: string; version?: string }>
  cert?: { fingerprint_sha256?: string; names?: string[] }
}
type CensysHost = {
  result?: {
    resource?: {
      ip?: string
      location?: { country?: string; city?: string; coordinates?: { latitude?: number; longitude?: number } }
      autonomous_system?: { asn?: number; name?: string; description?: string }
      whois?: { organization?: { name?: string } }
      services?: CensysService[]
      dns?: { names?: string[] }
    }
  }
}

function token(): string {
  const t = credential("CENSYS_API_TOKEN")
  if (!t) throw new ProviderError("not_configured", "CENSYS_API_TOKEN is not set.", false)
  return t
}

/** Deep host lookup by IP — the capability this plan actually has. */
export async function lookupCensys(ip: string): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const started = Date.now()
  const t = ip.trim()
  try {
    if (!isValidIp(t)) throw new ProviderError("query_unsupported", "Censys host lookup requires an IP address.", false)
    if (isPrivateIp(t)) throw new ProviderError("query_unsupported", "Refusing to look up a private/reserved address.", false)

    const data = await getJson<CensysHost>(`${PLATFORM}/v3/global/asset/host/${encodeURIComponent(t)}`, {
      Authorization: `Bearer ${token()}`,
    })
    const r = data.result?.resource
    if (!r?.ip) {
      return { observations: [], outcome: outcome(NAME, ROLE, t, started, "success", 0, "Censys has no record for this host.") }
    }

    const services: ExposureService[] = (r.services ?? []).map((s) => {
      const product = s.software?.[0]?.product ?? null
      const vendor = s.software?.[0]?.vendor ?? null
      const version = s.software?.[0]?.version ?? null
      return {
        port: Number(s.port ?? 0),
        transport: s.transport_protocol?.toLowerCase() ?? null,
        protocol: s.protocol ?? null,
        product,
        vendor,
        version,
        banner: s.banner?.slice(0, 500) ?? null,
        httpStatus: null,
        httpTitle: null,
        httpServer: null,
        sources: [NAME],
        // B3: retained so a Censys "http_server" vs LeakIX "Apache" disagreement is visible.
        claims: [{ source: NAME, product, vendor, version, protocol: s.protocol ?? null }],
      }
    }).filter((s) => s.port > 0)

    const certs = (r.services ?? [])
      .map((s) => s.cert)
      .filter((c): c is NonNullable<CensysService["cert"]> => Boolean(c?.fingerprint_sha256))
      .map((c) => ({
        commonName: c.names?.[0] ?? null,
        sans: c.names ?? [],
        issuer: null,
        fingerprint: c.fingerprint_sha256 ?? null,
        validFrom: null,
        validTo: null,
        expired: null,
        sources: [NAME],
      }))

    // FRESHNESS: the newest per-service scan_time is the best available
    // statement of when Censys actually saw this host. Measured 2026-08-30:
    // ~0.1–0.4 days old — the freshest of the configured providers, but still
    // an indexed scan record, not an on-demand probe.
    const scanTimes = (r.services ?? [])
      .map((s) => s.scan_time)
      .filter((t): t is string => Boolean(t) && Number.isFinite(Date.parse(t!)))
      .sort()
    const observedAt = scanTimes.length ? scanTimes[scanTimes.length - 1] : null

    const observation: ProviderObservation = {
      provider: NAME,
      ip: r.ip,
      domain: null,
      hostname: r.dns?.names?.[0] ?? null,
      asn: r.autonomous_system?.asn ?? null,
      organization: r.whois?.organization?.name ?? r.autonomous_system?.name ?? null,
      country: r.location?.country ?? null,
      city: r.location?.city ?? null,
      latitude: r.location?.coordinates?.latitude ?? null,
      longitude: r.location?.coordinates?.longitude ?? null,
      services,
      technologies: [],
      certificates: certs,
      vulnerabilities: [],
      notes: null,
      firstSeen: null,
      lastSeen: observedAt,
      observedAt,
      raw: r,
    }
    return { observations: [observation], outcome: outcome(NAME, ROLE, t, started, "success", 1) }
  } catch (e) {
    return { observations: [], outcome: errorOutcome(NAME, ROLE, t, started, e) }
  }
}

/** Censys query DSL for a product name. */
export function buildCensysQuery(product: string): string {
  return `services.software.product="${product.replace(/"/g, '\\"')}"`
}

/** Censys query DSL for a CVE — its documented CVE field, not a free-text guess. */
export function buildCensysCveQuery(cveId: string): string {
  return `vulnerabilities.cve_id="${cveId.replace(/"/g, '\\"')}"`
}

/**
 * Free-text / CVE search. Requires a paid plan + organization id; without
 * CENSYS_ORG_ID we report the exact documented limitation rather than making a
 * call we know returns 403.
 *
 * `matchType` is threaded through so a CVE-id search can mark its results as
 * `cve-search` (a direct provider assertion) rather than a weaker inference.
 */
export async function searchCensys(
  query: string,
  opts: { cveId?: string } = {},
): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const started = Date.now()
  const dsl = opts.cveId ? buildCensysCveQuery(opts.cveId) : buildCensysQuery(query)
  const orgId = credential("CENSYS_ORG_ID")
  if (!orgId) {
    return {
      observations: [],
      outcome: outcome(NAME, "discovery", dsl, started, "plan_limitation", 0,
        "Censys search requires a paid plan with an organization ID (free accounts can only search via the Censys web UI). Censys still enriches every discovered host by IP. Set CENSYS_ORG_ID to enable.", false),
    }
  }
  try {
    const data = await getJson<{ result?: { hits?: Array<{ resource?: { ip?: string } }> } }>(
      `${PLATFORM}/v3/global/search/query?query=${encodeURIComponent(dsl)}&page_size=50`,
      { Authorization: `Bearer ${token()}`, "X-Organization-ID": orgId, "Content-Type": "application/json" },
    )
    const hits = data.result?.hits ?? []
    const observations: ProviderObservation[] = hits
      .map((h) => h.resource?.ip)
      .filter((ip): ip is string => Boolean(ip))
      .map((ip) => ({
        provider: NAME, ip, domain: null, hostname: null,
        services: [], technologies: [], certificates: [],
        // A direct CVE-id hit is the provider asserting this host is affected.
        vulnerabilities: opts.cveId
          ? [makeVulnerability({ cveId: opts.cveId, matchType: "cve-search", sources: [NAME] })]
          : [],
        notes: null, firstSeen: null, lastSeen: null, raw: { ip },
      }))
    return { observations, outcome: outcome(NAME, "discovery", dsl, started, "success", observations.length) }
  } catch (e) {
    return { observations: [], outcome: errorOutcome(NAME, "discovery", dsl, started, e) }
  }
}
