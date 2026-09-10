/**
 * LeakIX — the DISCOVERY provider.
 *
 * Verified live 2026-08-29: `GET https://leakix.net/search?scope=service|leak&q=`
 * returns an array of real observations (ip, host, port, protocol, http{...},
 * ssl{...}, summary). This is currently the only configured provider whose
 * free tier permits open-ended search, so it seeds the pipeline with candidate
 * hosts that the enrichment providers then deepen.
 *
 * `scope=leak` additionally surfaces exposure/leak findings (LeakIX's actual
 * specialty) which `scope=service` does not.
 */
import type { ProviderObservation, ProviderOutcome, ExposureService } from "@/lib/exposure/types"
import { getJson, outcome, errorOutcome, ProviderError, isValidIp } from "./_base"
import { credential } from "@/lib/exposure/credentials"

const ROLE = "discovery" as const
const NAME = "leakix" as const

type LeakixRecord = {
  event_type?: string
  event_source?: string
  ip?: string
  host?: string
  reverse?: string
  port?: string
  protocol?: string
  transport?: string[]
  summary?: string
  time?: string
  http?: { status?: number; title?: string; url?: string; header?: Record<string, string> }
  ssl?: { certificate?: { cn?: string; domain?: string[]; issuer_name?: string; not_before?: string; not_after?: string; fingerprint?: string } }
  geoip?: { country_name?: string; city_name?: string; location?: { lat?: number; lon?: number } }
  network?: { organization_name?: string; asn?: number }
  protocol_version?: string
  service?: { software?: { name?: string; version?: string; vendor?: string } }
}

function key(): string {
  const k = credential("LEAKIX_API_KEY")
  if (!k) throw new ProviderError("not_configured", "LEAKIX_API_KEY is not set.", false)
  return k
}

function toObservation(r: LeakixRecord): ProviderObservation | null {
  const ip = r.ip?.trim()
  const host = r.host?.trim()
  if (!ip && !host) return null

  const port = Number(r.port)
  const product = r.service?.software?.name ?? r.http?.header?.server ?? null
  const vendor = r.service?.software?.vendor ?? null
  const version = r.service?.software?.version ?? null
  const services: ExposureService[] = Number.isFinite(port) && port > 0 ? [{
    port,
    transport: r.transport?.[0] ?? null,
    protocol: r.protocol ?? null,
    product,
    vendor,
    version,
    banner: null,
    httpStatus: r.http?.status ?? null,
    httpTitle: r.http?.title ?? null,
    httpServer: r.http?.header?.server ?? null,
    sources: [NAME],
    // B3: this provider's own claim, retained so disagreement stays visible.
    claims: [{ source: NAME, product, vendor, version, protocol: r.protocol ?? null }],
  }] : []

  const cert = r.ssl?.certificate
  return {
    provider: NAME,
    ip: ip || null,
    domain: host && !isValidIp(host) ? host : null,
    hostname: r.reverse || host || null,
    asn: r.network?.asn ?? null,
    organization: r.network?.organization_name ?? null,
    country: r.geoip?.country_name ?? null,
    city: r.geoip?.city_name ?? null,
    latitude: r.geoip?.location?.lat ?? null,
    longitude: r.geoip?.location?.lon ?? null,
    services,
    technologies: [],
    certificates: cert ? [{
      commonName: cert.cn ?? null,
      sans: cert.domain ?? [],
      issuer: cert.issuer_name ?? null,
      fingerprint: cert.fingerprint ?? null,
      validFrom: cert.not_before ?? null,
      validTo: cert.not_after ?? null,
      expired: cert.not_after ? new Date(cert.not_after).getTime() < Date.now() : null,
      sources: [NAME],
    }] : [],
    vulnerabilities: [],
    // LeakIX's `summary` on a leak event is its most valuable field (it explains
    // WHAT was exposed) — surfaced verbatim rather than parsed.
    notes: r.summary?.trim() ? r.summary.trim().slice(0, 2000) : null,
    firstSeen: null,
    lastSeen: r.time ?? null,
    // FRESHNESS: LeakIX's `time` is when IT observed the service, not when we
    // fetched. Measured 2026-08-30: search results were ~98 days old, so this
    // provider must never be presented as a live view of the internet.
    observedAt: r.time ?? null,
    raw: r,
  }
}

async function fetchScope(query: string, scope: "service" | "leak"): Promise<LeakixRecord[]> {
  const url = `https://leakix.net/search?scope=${scope}&q=${encodeURIComponent(query)}`
  const data = await getJson<LeakixRecord[] | null>(url, { "api-key": key(), Accept: "application/json" })
  return Array.isArray(data) ? data : []
}

/**
 * LeakIX cannot search by CVE id (A3).
 *
 * Verified live 2026-08-29: LeakIX free-text search matches banner/page CONTENT,
 * and a CVE identifier essentially never appears there — querying
 * "CVE-2021-44228" returned an unrelated NFC hardware site. Silently falling
 * back to a free-text search would therefore present irrelevant hosts as CVE
 * findings, so this reports `query_unsupported` instead. LeakIX still
 * contributes to CVE investigations via the local product pivot.
 */
export function leakixCveUnsupported(cveId: string): ProviderOutcome {
  return outcome(NAME, ROLE, cveId, Date.now(), "query_unsupported", 0,
    "LeakIX has no CVE query field; its free-text index matches banner content, where CVE ids do not appear. Reached instead via the local CVE→product pivot.", false)
}

/** Free-text discovery. Queries both scopes so leak findings aren't lost, then dedups by fingerprint-ish key. */
export async function searchLeakix(query: string): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const started = Date.now()
  try {
    const [svc, leak] = await Promise.allSettled([fetchScope(query, "service"), fetchScope(query, "leak")])
    const records: LeakixRecord[] = []
    if (svc.status === "fulfilled") records.push(...svc.value)
    if (leak.status === "fulfilled") records.push(...leak.value)

    // Both scopes rejecting means the provider genuinely failed; one failing is partial.
    if (svc.status === "rejected" && leak.status === "rejected") throw svc.reason

    const seen = new Set<string>()
    const observations: ProviderObservation[] = []
    for (const r of records) {
      const o = toObservation(r)
      if (!o) continue
      const k = `${o.ip ?? o.domain}|${o.services[0]?.port ?? "-"}|${r.event_source ?? ""}`
      if (seen.has(k)) continue
      seen.add(k)
      observations.push(o)
    }

    const partial = svc.status === "rejected" || leak.status === "rejected"
    return {
      observations,
      outcome: outcome(NAME, ROLE, query, started, partial ? "partial" : "success", observations.length,
        partial ? "One LeakIX scope failed; results are from the remaining scope." : undefined, partial),
    }
  } catch (e) {
    return { observations: [], outcome: errorOutcome(NAME, ROLE, query, started, e) }
  }
}
