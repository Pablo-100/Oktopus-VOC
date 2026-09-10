/**
 * Netlas — the richest ENRICHMENT provider.
 *
 * Verified live 2026-08-29. This key's plan does NOT permit open-ended search
 * (`/api/host/search/` answers every query, however well-formed, with
 * `400 "Only domain or ip is allowed as search query parameter"`), but it DOES
 * permit direct lookups, and those return the deepest data of any configured
 * provider:
 *
 *   GET /api/host/{ip|domain}   -> software[] each carrying a full cve[] array
 *                                  (name, base_score, severity, attack_vector,
 *                                  match_type, match_product) + technology tags
 *   GET /api/domains/?q=domain  -> DNS records (a, aaaa, ns, txt, zone)
 *   GET /api/whois_ip/?q=ip     -> WHOIS / netblock registration
 *
 * So Netlas is wired as a lookup/enrichment provider, never as a search one —
 * that is a real capability boundary, not a workaround.
 */
import type { ProviderObservation, ProviderOutcome, ExposureTechnology, ExposureVulnerability, ExposureService } from "@/lib/exposure/types"
import { getJson, outcome, errorOutcome, ProviderError, isValidIp, isValidDomain, isPrivateIp } from "./_base"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { credential } from "@/lib/exposure/credentials"

const ROLE = "enrichment" as const
const NAME = "netlas" as const

type NetlasCve = {
  name?: string
  base_score?: string | number
  severity?: string
  match_type?: string
  match_product?: string
}
type NetlasSoftware = {
  cve?: NetlasCve[]
  tag?: Array<{ name?: string; fullname?: string; category?: string[]; [k: string]: unknown }>
  uri?: string
}
/**
 * Netlas reports which SCAN each record came from. Verified present
 * 2026-08-30: `source[].scan_ended_at` / `scan_label`, with observations
 * 9–42 days old. This is batch scan data, never a live probe.
 */
type NetlasScanSource = { scan_label?: string; scan_started_at?: string; scan_ended_at?: string }
/**
 * Netlas reports open ports separately from `software`, e.g.
 *   {"prot4":"tcp","prot7":"http","protocol":"http","port":80}
 * `prot4` is the transport (tcp/udp), `prot7`/`protocol` the application layer.
 */
export type NetlasPort = { port?: number | string; prot4?: string; prot7?: string; protocol?: string }
type NetlasHostResponse = { software?: NetlasSoftware[]; source?: NetlasScanSource[]; ports?: NetlasPort[] }
type NetlasDomainResponse = {
  items?: Array<{
    data?: { domain?: string; a?: string[]; aaaa?: string[]; ns?: string[]; txt?: string[]; zone?: string; "@timestamp"?: string }
    scan_label?: string
  }>
}

/** Newest scan timestamp Netlas reports for a host record, or null. */
/**
 * Newest scan WINDOW Netlas reports for a host record, as [start, end].
 *
 * `source[]` describes a scan CAMPAIGN, not a per-host probe. Verified live
 * 2026-08-31: campaign id 959 spans `scan_started_at` 2026-08-21 to
 * `scan_ended_at` 2026-08-31, and two unrelated hosts return the identical
 * `scan_ended_at` to the millisecond because they came from the same batch.
 *
 * The host was therefore observed at some UNKNOWN point inside that window.
 */
export function netlasScanWindow(res: NetlasHostResponse | undefined): { start: string | null; end: string | null } {
  const parse = (t: string | undefined) =>
    t && Number.isFinite(Date.parse(t)) ? new Date(Date.parse(t)).toISOString() : null

  let start: string | null = null
  let end: string | null = null
  for (const src of res?.source ?? []) {
    const e = parse(src.scan_ended_at) ?? parse(src.scan_label)
    const st = parse(src.scan_started_at)
    // Track the most recent campaign, and keep ITS start.
    if (e && (!end || e > end)) { end = e; start = st ?? null }
    else if (!end && st && (!start || st > start)) start = st
  }
  return { start, end }
}

/**
 * The observation timestamp OCTUPUS will report for a Netlas record.
 *
 * Deliberately the campaign's START, not its end. Using `scan_ended_at` made
 * every Netlas asset look FRESH indefinitely — a campaign's end time keeps
 * advancing while it runs, so a host scanned ten days ago was being presented
 * as "observed two minutes ago". The start is the earliest the host could have
 * been seen, which is the only bound that cannot overstate freshness.
 *
 * Falls back to the end only when no start is supplied, since some record is
 * better than none and the alternative is UNKNOWN.
 */
export function netlasObservedAt(res: NetlasHostResponse | undefined): string | null {
  const { start, end } = netlasScanWindow(res)
  return start ?? end
}

function key(): string {
  const k = credential("NETLAS_API_KEY")
  if (!k) throw new ProviderError("not_configured", "NETLAS_API_KEY is not set.", false)
  return k
}

function parseSoftware(software: NetlasSoftware[]): { technologies: ExposureTechnology[]; vulnerabilities: ExposureVulnerability[] } {
  const techByName = new Map<string, ExposureTechnology>()
  const vulnById = new Map<string, ExposureVulnerability>()

  for (const s of software) {
    for (const t of s.tag ?? []) {
      const name = (t.fullname || t.name || "").trim()
      if (!name) continue
      // Netlas nests the version under a key named after the tag, e.g. {cloudflare:{version:""}}.
      const nested = t.name && typeof t[t.name] === "object" ? (t[t.name] as { version?: string }) : undefined
      const version = nested?.version?.trim() || null
      const existing = techByName.get(name.toLowerCase())
      if (existing) {
        if (!existing.version && version) existing.version = version
      } else {
        techByName.set(name.toLowerCase(), { name, version, categories: t.category ?? [], sources: [NAME] })
      }
    }
    for (const c of s.cve ?? []) {
      const cveId = c.name?.trim().toUpperCase()
      if (!cveId || !/^CVE-\d{4}-\d{4,7}$/.test(cveId)) continue
      if (vulnById.has(cveId)) continue
      const score = typeof c.base_score === "string" ? Number(c.base_score) : c.base_score
      const mt = c.match_type
      vulnById.set(cveId, makeVulnerability({
        cveId,
        providerScore: Number.isFinite(score) ? (score as number) : null,
        providerSeverity: c.severity?.toLowerCase() ?? null,
        // Netlas tells us HOW it matched — "product" means product-name-only,
        // which is materially weaker evidence than a version match. Preserved
        // because the risk layer weights it.
        matchType: mt === "product" || mt === "version" || mt === "banner" ? mt : "unknown",
        matchedProduct: c.match_product ?? null,
        sources: [NAME],
      }))
    }
  }
  return { technologies: [...techByName.values()], vulnerabilities: [...vulnById.values()] }
}

/**
 * Netlas `ports[]` -> normalized services.
 *
 * Without this Netlas contributes technologies and CVEs but no ports, so
 * service counts under-report and periodic monitoring loses its primary change
 * signal (a port opening or closing). Product/version are deliberately left
 * null: `ports[]` carries no product claim, and `software[]` is host-wide
 * rather than per-port, so attributing a product to a port here would invent an
 * association Netlas never asserted.
 */
export function parsePorts(ports: NetlasPort[]): ExposureService[] {
  const byPort = new Map<number, ExposureService>()
  for (const p of ports) {
    const port = typeof p.port === "string" ? Number(p.port) : p.port
    if (!Number.isFinite(port) || (port as number) <= 0 || (port as number) > 65535) continue
    const transport = p.prot4?.toLowerCase() ?? null
    const protocol = (p.protocol ?? p.prot7)?.toLowerCase() ?? null
    const existing = byPort.get(port as number)
    if (existing) {
      if (!existing.protocol && protocol) existing.protocol = protocol
      if (!existing.transport && transport) existing.transport = transport
      continue
    }
    byPort.set(port as number, {
      port: port as number,
      transport,
      protocol,
      product: null,
      vendor: null,
      version: null,
      banner: null,
      httpStatus: null,
      httpTitle: null,
      httpServer: null,
      sources: [NAME],
      claims: [{ source: NAME, product: null, vendor: null, version: null, protocol }],
    })
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port)
}

/**
 * Attribute Netlas `software[]` entries to the PORT they were observed on.
 *
 * Netlas states the association itself: each software entry carries a `uri`
 * such as `http://45.33.32.156:80/`. Using it is reading what the provider
 * reported, not inferring — and without it the product/version Netlas supplies
 * would be discarded, leaving ports with no product and CVE correlation with
 * nothing to work from.
 *
 * Operating-system tags are deliberately NOT used as a service product: Ubuntu
 * running on the host is not the software listening on port 80, and claiming
 * otherwise would attach kernel CVEs to a web server.
 */
export function softwareByPort(software: NetlasSoftware[]): Map<number, { product: string; version: string | null }> {
  const byPort = new Map<number, { product: string; version: string | null }>()

  for (const entry of software) {
    const port = portFromUri(entry.uri)
    if (port === null) continue

    for (const t of entry.tag ?? []) {
      const categories = (t.category ?? []).map((c) => c.toLowerCase())
      if (categories.includes("operating systems")) continue // not the listening service
      const name = (t.fullname || t.name || "").trim()
      if (!name) continue
      const nested = t.name && typeof t[t.name] === "object" ? (t[t.name] as { version?: string }) : undefined
      const version = nested?.version?.trim() || null

      const current = byPort.get(port)
      // Prefer a claim that carries a version — it is strictly better evidence.
      if (!current || (!current.version && version)) byPort.set(port, { product: name, version })
    }
  }
  return byPort
}

/** Port from a Netlas software URI, using the scheme default when implicit. */
export function portFromUri(uri: string | undefined): number | null {
  if (!uri) return null
  try {
    const u = new URL(uri)
    if (u.port) {
      const p = Number(u.port)
      return Number.isFinite(p) && p > 0 && p <= 65535 ? p : null
    }
    if (u.protocol === "http:") return 80
    if (u.protocol === "https:") return 443
    return null
  } catch {
    return null
  }
}

/** Deep lookup for a single IP or domain. */
export async function lookupNetlas(target: string): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const started = Date.now()
  const t = target.trim()
  try {
    const isIp = isValidIp(t)
    if (!isIp && !isValidDomain(t)) {
      throw new ProviderError("query_unsupported", "Netlas lookup accepts only an IP address or a domain on this plan.", false)
    }
    if (isIp && isPrivateIp(t)) throw new ProviderError("query_unsupported", "Refusing to look up a private/reserved address.", false)

    const k = key()
    const [hostRes, domainRes] = await Promise.allSettled([
      getJson<NetlasHostResponse>(`https://app.netlas.io/api/host/${encodeURIComponent(t)}`, { "X-API-Key": k }),
      isIp ? Promise.resolve<NetlasDomainResponse>({}) : getJson<NetlasDomainResponse>(`https://app.netlas.io/api/domains/?q=${encodeURIComponent(t)}`, { "X-API-Key": k }),
    ])

    if (hostRes.status === "rejected" && domainRes.status === "rejected") throw hostRes.reason

    const software = hostRes.status === "fulfilled" ? hostRes.value.software ?? [] : []
    const { technologies, vulnerabilities } = parseSoftware(software)
    const services = hostRes.status === "fulfilled" ? parsePorts(hostRes.value.ports ?? []) : []
    // Netlas reports which port each software entry was seen on; carry that
    // product/version onto the matching service instead of dropping it.
    const perPort = softwareByPort(software)
    for (const svc of services) {
      const sw = perPort.get(svc.port)
      if (!sw) continue
      svc.product = sw.product
      svc.version = sw.version
      svc.claims = [{ source: NAME, product: sw.product, vendor: null, version: sw.version, protocol: svc.protocol ?? null }]
    }

    // Domain lookups resolve to IPs — genuinely new correlation identifiers.
    const dnsData = domainRes.status === "fulfilled" ? domainRes.value.items?.[0]?.data : undefined
    const resolvedIps = [...(dnsData?.a ?? []), ...(dnsData?.aaaa ?? [])].filter((x) => isValidIp(x))

    const hostPayload = hostRes.status === "fulfilled" ? hostRes.value : undefined
    // FRESHNESS from Netlas's own scan metadata — never fabricated.
    const observedAt = netlasObservedAt(hostPayload)
      ?? (domainRes.status === "fulfilled" ? domainRes.value.items?.[0]?.data?.["@timestamp"] ?? null : null)

    const observations: ProviderObservation[] = []
    const base = {
      provider: NAME,
      services,
      certificates: [],
      technologies,
      vulnerabilities,
      notes: null,
      firstSeen: null,
      lastSeen: observedAt,
      observedAt,
    }

    if (isIp) {
      observations.push({ ...base, ip: t, domain: null, hostname: null, raw: hostRes.status === "fulfilled" ? hostRes.value : null } as ProviderObservation)
    } else {
      observations.push({ ...base, ip: null, domain: t, hostname: null, raw: { host: hostRes.status === "fulfilled" ? hostRes.value : null, dns: dnsData ?? null } } as ProviderObservation)
      // Each resolved IP becomes its own observation so the correlation engine
      // can merge it with what the other providers independently saw at that IP.
      for (const ip of resolvedIps.slice(0, 10)) {
        observations.push({
          provider: NAME, ip, domain: t, hostname: null,
          services: [], technologies: [], certificates: [], vulnerabilities: [],
          notes: `Resolved from DNS for ${t}`, firstSeen: null, lastSeen: observedAt,
          observedAt,
          raw: { resolvedFrom: t, dns: dnsData ?? null },
        } as ProviderObservation)
      }
    }

    const partial = hostRes.status === "rejected" || domainRes.status === "rejected"
    return {
      observations,
      outcome: outcome(NAME, ROLE, t, started, partial ? "partial" : "success", observations.length,
        partial ? "One Netlas endpoint failed; returning what succeeded." : undefined, partial),
    }
  } catch (e) {
    return { observations: [], outcome: errorOutcome(NAME, ROLE, t, started, e) }
  }
}

/**
 * Netlas cannot serve free-text discovery on this plan — reported explicitly
 * rather than silently returning nothing. (The bare `/api/host/?q=` endpoint
 * appears to answer any query, but returns the SAME default record regardless
 * of input, so it must never be used as a search: it would be fabricated data.)
 */
export function netlasSearchUnsupported(query: string): ProviderOutcome {
  return outcome(NAME, "discovery", query, Date.now(), "plan_limitation", 0,
    "This Netlas plan supports direct IP/domain lookups only, not open-ended search. Netlas still enriches every host discovered by other providers.", false)
}
