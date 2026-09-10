/**
 * SHODAN — host enrichment.
 *
 * MEASURED CAPABILITY (probed live 2026-09-03 against this account):
 *   plan: "oss" (free), query_credits: 0, scan_credits: 0
 *   -> /shodan/host/{ip}  WORKS. Host lookup does not consume query credits.
 *   -> /shodan/host/search DOES NOT: it needs query credits this plan lacks.
 * So this adapter is LOOKUP-ONLY, exactly like Censys on its current plan.
 * Offering a search function that always fails would be worse than not
 * offering one.
 *
 * WHY THIS PROVIDER MATTERS: Shodan reports a per-service `product` AND
 * `version` (e.g. `OpenSSH 6.6.1p1`) plus CPE strings. Every other configured
 * provider on this deployment gives product names at best, which caps evidence
 * at the `product` tier — a tier that deliberately cannot raise an alert. Shodan
 * is what makes version-level (`strong`) evidence reachable.
 */
import type {
  ProviderObservation, ProviderOutcome, ExposureService, ExposureVulnerability, ServiceClaim,
} from "@/lib/exposure/types"
import { getJson, outcome, errorOutcome, ProviderError, isValidIp, isPrivateIp } from "./_base"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { credential } from "@/lib/exposure/credentials"

const NAME = "shodan" as const
const ROLE = "enrichment" as const

/**
 * Upper bound on CVEs taken from one host.
 *
 * Shodan returned 125 CVEs for a single Apache host in testing. Every one of
 * them would become a vulnerability record and, at `strong` evidence, a
 * candidate alert — a storm from one asset. The cap bounds the blast radius;
 * the findings that matter most survive because the RBVM layer ranks them.
 */
const MAX_HOST_VULNS = 40

interface ShodanService {
  port?: number
  transport?: string
  product?: string
  version?: string
  data?: string
  timestamp?: string
  cpe23?: string[]
  cpe?: string[]
  vulns?: Record<string, unknown>
  http?: { status?: number; title?: string; server?: string }
  ssl?: { cert?: { fingerprint?: { sha256?: string }; subject?: { CN?: string }; issuer?: { CN?: string }; expired?: boolean } }
}

interface ShodanHost {
  ip_str?: string
  ports?: number[]
  hostnames?: string[]
  domains?: string[]
  org?: string
  isp?: string
  asn?: string
  os?: string | null
  country_name?: string
  city?: string
  last_update?: string
  /** Host-wide CVE list Shodan derived from the software it fingerprinted. */
  vulns?: string[]
  data?: ShodanService[]
}

function key(): string {
  const k = credential("SHODAN_API_KEY")
  if (!k) throw new ProviderError("not_configured", "SHODAN_API_KEY is not set.", false)
  return k
}

/** Newest per-service observation, falling back to the host record's own stamp. */
function observedAt(host: ShodanHost): string | null {
  const stamps = (host.data ?? [])
    .map((s) => s.timestamp)
    .concat(host.last_update ? [host.last_update] : [])
    .filter((t): t is string => Boolean(t) && Number.isFinite(Date.parse(t!)))
    .map((t) => new Date(Date.parse(t)).toISOString())
    .sort()
  return stamps.length ? stamps[stamps.length - 1] : null
}

/** Normalize Shodan's `data[]` into services. Product/version copied, never inferred. */
export function parseShodanServices(host: ShodanHost): ExposureService[] {
  const byPort = new Map<number, ExposureService>()
  for (const s of host.data ?? []) {
    const port = typeof s.port === "number" ? s.port : Number(s.port)
    if (!Number.isFinite(port) || port <= 0 || port > 65535) continue

    const product = s.product?.trim() || null
    const version = s.version?.trim() || null
    const claim: ServiceClaim = {
      source: NAME, product, vendor: null, version,
      protocol: s.transport?.toLowerCase() ?? null,
    }
    const existing = byPort.get(port)
    if (existing) {
      // Shodan can report the same port more than once (multiple probes).
      if (!existing.product && product) existing.product = product
      if (!existing.version && version) existing.version = version
      if (!existing.claims.some((c) => c.product === claim.product && c.version === claim.version)) {
        existing.claims.push(claim)
      }
      continue
    }
    byPort.set(port, {
      port,
      transport: s.transport?.toLowerCase() ?? "tcp",
      protocol: s.http ? "http" : null,
      product, vendor: null, version,
      // The banner is raw remote output: bounded here so a hostile host cannot
      // push megabytes into our storage.
      banner: s.data ? s.data.slice(0, 500) : null,
      httpStatus: s.http?.status ?? null,
      httpTitle: s.http?.title ?? null,
      httpServer: s.http?.server ?? null,
      sources: [NAME],
      claims: [claim],
    })
  }

  // Ports Shodan lists but supplies no service record for: the port is real
  // evidence, the software is not, so it stays null rather than guessed.
  for (const p of host.ports ?? []) {
    if (!byPort.has(p)) {
      byPort.set(p, {
        port: p, transport: "tcp", protocol: null,
        product: null, vendor: null, version: null, banner: null,
        httpStatus: null, httpTitle: null, httpServer: null,
        sources: [NAME], claims: [{ source: NAME, product: null, vendor: null, version: null, protocol: null }],
      })
    }
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port)
}

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i

/**
 * Shodan's CVEs, mapped to the evidence model.
 *
 * Tier is `version` -> STRONG, never `confirmed`. Shodan derives these from the
 * software VERSION it fingerprinted; it does not verify the host is exploitable
 * and it was not queried "which hosts have this CVE". Calling that `confirmed`
 * would overstate exactly the way the evidence model exists to prevent.
 *
 * A CVE listed against a specific service is attached to that port. The
 * host-wide `vulns` array carries no port, so it stays host-level (port 0)
 * rather than being pinned to a service Shodan never associated it with.
 */
export function parseShodanVulns(host: ShodanHost): ExposureVulnerability[] {
  const out: ExposureVulnerability[] = []
  const seen = new Set<string>()

  for (const s of host.data ?? []) {
    const port = typeof s.port === "number" ? s.port : Number(s.port)
    if (!s.vulns || !Number.isFinite(port)) continue
    for (const raw of Object.keys(s.vulns)) {
      const cveId = raw.trim().toUpperCase()
      if (!CVE_RE.test(cveId) || seen.has(`${port}|${cveId}`)) continue
      seen.add(`${port}|${cveId}`)
      out.push({
        correlatedPort: port,
        ...makeVulnerability({
          cveId, matchType: "version", sources: [NAME],
          matchedProduct: s.product?.trim() || null,
        }),
      })
    }
  }

  for (const raw of (host.vulns ?? []).slice(0, MAX_HOST_VULNS)) {
    const cveId = raw.trim().toUpperCase()
    if (!CVE_RE.test(cveId) || seen.has(`0|${cveId}`)) continue
    // Already attributed to a specific port above? Then it is not host-level.
    if ([...seen].some((k) => k.endsWith(`|${cveId}`))) continue
    seen.add(`0|${cveId}`)
    out.push({
      correlatedPort: null,
      ...makeVulnerability({ cveId, matchType: "version", sources: [NAME], matchedProduct: null }),
    })
  }
  return out
}

/** Certificates Shodan saw, when a service exposed TLS. */
function parseShodanCerts(host: ShodanHost) {
  const certs = []
  for (const s of host.data ?? []) {
    const fp = s.ssl?.cert?.fingerprint?.sha256?.trim()
    if (!fp) continue
    certs.push({
      commonName: s.ssl?.cert?.subject?.CN ?? null,
      sans: [] as string[],
      issuer: s.ssl?.cert?.issuer?.CN ?? null,
      fingerprint: fp,
      validFrom: null, validTo: null,
      expired: s.ssl?.cert?.expired ?? null,
      sources: [NAME],
    })
  }
  return certs
}

/**
 * Deep host lookup by IP.
 *
 * Refuses anything that is not a public IP before spending a call: Shodan has
 * no record for a private address, and asking would leak internal addressing to
 * a third party.
 */
export async function lookupShodan(ip: string): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const started = Date.now()
  const t = ip.trim()
  try {
    if (!isValidIp(t)) throw new ProviderError("query_unsupported", "Shodan host lookup requires an IP address.", false)
    if (isPrivateIp(t)) throw new ProviderError("query_unsupported", "Refusing to look up a private/reserved address.", false)

    // The key travels in the query string, which is Shodan's only auth scheme.
    // `redactSecrets` in _base covers `key=` so it can never reach a stored error.
    const host = await getJson<ShodanHost>(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(t)}?key=${encodeURIComponent(key())}`,
      {},
    )
    if (!host?.ip_str) {
      return { observations: [], outcome: outcome(NAME, ROLE, t, started, "success", 0, "Shodan has no record for this host.") }
    }

    const services = parseShodanServices(host)
    const vulnerabilities = parseShodanVulns(host)
    const observation: ProviderObservation = {
      provider: NAME,
      ip: host.ip_str ?? t,
      domain: null,
      hostname: host.hostnames?.[0] ?? null,
      asn: host.asn ? Number(String(host.asn).replace(/^AS/i, "")) || null : null,
      organization: host.org ?? host.isp ?? null,
      country: host.country_name ?? null,
      city: host.city ?? null,
      services,
      technologies: host.os
        ? [{ name: host.os, version: null, categories: ["Operating systems"], sources: [NAME] }]
        : [],
      certificates: parseShodanCerts(host),
      vulnerabilities,
      notes: null,
      firstSeen: null,
      lastSeen: observedAt(host),
      // Shodan's OWN observation time — never our fetch time.
      observedAt: observedAt(host),
      raw: host,
    } as ProviderObservation

    return {
      observations: [observation],
      outcome: outcome(NAME, ROLE, t, started, "success", 1),
    }
  } catch (e) {
    return { observations: [], outcome: errorOutcome(NAME, ROLE, t, started, e) }
  }
}
