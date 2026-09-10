/**
 * ZoomEye — DISCOVERY provider, currently quota-exhausted.
 *
 * Verified live 2026-08-29:
 *   - The legacy `api.zoomeye.org` host is retired for this region: it answered
 *     "this service not available in your area, please use api.zoomeye.ai
 *     instead", and now returns 502 outright. Do not resurrect it.
 *   - On `api.zoomeye.ai`, `GET /v2/search` -> 405 (method not allowed) and
 *     `POST /v2/search` -> 402 {"code":50000,"error":"credits_insufficient"}.
 *     So POST /v2/search is the correct endpoint and the `API-KEY` header is
 *     the correct auth (a Bearer header is rejected earlier, at auth); the only
 *     blocker is an empty credit balance on the account.
 *
 * The adapter is complete; it returns data as soon as the account has credits.
 */
import type { ProviderObservation, ProviderOutcome, ExposureService } from "@/lib/exposure/types"
import { outcome, errorOutcome, ProviderError, classifyHttp, DEFAULT_TIMEOUT_MS } from "./_base"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { credential } from "@/lib/exposure/credentials"

const ROLE = "discovery" as const
const NAME = "zoomeye" as const

type ZoomEyeResponse = {
  code?: number
  total?: number
  data?: Array<{
    ip?: string
    port?: number
    domain?: string
    hostname?: string
    service?: string
    protocol?: string
    product?: string
    version?: string
    os?: string
    country?: string
    city?: string
    organization?: string
    asn?: number
    title?: string
  }>
}

function key(): string {
  const k = credential("ZOOMEYE_API_KEY")
  if (!k) throw new ProviderError("not_configured", "ZOOMEYE_API_KEY is not set.", false)
  return k
}

export type ZoomeyeQueryType = "product" | "ip" | "domain" | "port" | "cve"

export function buildZoomeyeQuery(term: string, type: ZoomeyeQueryType = "product"): string {
  const escaped = term.replace(/"/g, '\\"')
  switch (type) {
    case "ip": return `ip="${escaped}"`
    case "domain": return `domain="${escaped}"`
    case "port": return `port="${escaped}"`
    // ZoomEye's documented CVE dork — NOT a product search on the CVE string.
    case "cve": return `cve="${escaped}"`
    default: return `app="${escaped}"`
  }
}

export async function searchZoomeye(term: string, type: ZoomeyeQueryType = "product"): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const started = Date.now()
  const query = buildZoomeyeQuery(term, type)
  try {
    const qbase64 = Buffer.from(query).toString("base64")
    let res: Response
    try {
      res = await fetch("https://api.zoomeye.ai/v2/search", {
        method: "POST",
        headers: { "API-KEY": key(), "Content-Type": "application/json" },
        body: JSON.stringify({ qbase64, page: 1, pagesize: 50 }),
        signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
      })
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      throw new ProviderError(/timeout|abort/i.test(msg) ? "timeout" : "provider_unavailable", msg, true)
    }

    const text = await res.text()
    if (res.status === 402 || /credits_insufficient/.test(text)) {
      throw new ProviderError("quota_exhausted", "ZoomEye account has no remaining API credits. Top up the account to enable ZoomEye.", true)
    }
    if (!res.ok) throw classifyHttp(res, text)

    const data = JSON.parse(text) as ZoomEyeResponse
    const observations: ProviderObservation[] = (data.data ?? []).map((d) => {
      const port = Number(d.port)
      const protocol = d.protocol ?? d.service ?? null
      const services: ExposureService[] = Number.isFinite(port) && port > 0 ? [{
        port, transport: null, protocol,
        product: d.product ?? null, vendor: null, version: d.version ?? null,
        banner: null, httpStatus: null, httpTitle: d.title ?? null, httpServer: null,
        sources: [NAME],
        claims: [{ source: NAME, product: d.product ?? null, vendor: null, version: d.version ?? null, protocol }],
      }] : []
      return {
        provider: NAME,
        ip: d.ip ?? null,
        domain: d.domain ?? null,
        hostname: d.hostname ?? null,
        asn: d.asn ?? null,
        organization: d.organization ?? null,
        country: d.country ?? null,
        city: d.city ?? null,
        latitude: null, longitude: null,
        services, technologies: [], certificates: [],
        vulnerabilities: type === "cve"
          ? [makeVulnerability({ cveId: term, matchType: "cve-search", sources: [NAME] })]
          : [],
        notes: d.os ? `OS: ${d.os}` : null,
        firstSeen: null, lastSeen: null,
        raw: d,
      }
    })
    return { observations, outcome: outcome(NAME, ROLE, query, started, "success", observations.length) }
  } catch (e) {
    return { observations: [], outcome: errorOutcome(NAME, ROLE, query, started, e) }
  }
}
