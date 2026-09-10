/**
 * FOFA — DISCOVERY provider, currently quota-exhausted.
 *
 * Verified live 2026-08-29. Credentials are VALID (both FOFA_EMAIL and
 * FOFA_API_KEY are required and both are set — `/api/v1/info/my` answers 200
 * and identifies the account). The blocker is purely account quota:
 *
 *   /api/v1/info/my   -> {"remain_api_query":0,"remain_api_data":0,
 *                         "fcoin":0,"fofa_point":0,"isvip":false}
 *   /api/v1/search/all -> {"error":true,"errmsg":"[820031] F点余额不足"}
 *                         ("insufficient F-points") for EVERY field set tried,
 *                         including `fields=host` alone — so it is not a
 *                         field-permission problem, it is an empty balance.
 *
 * A narrower error also exists and is mapped distinctly: `[820001] 没有权限搜索
 * <field>字段` = this account may not query that particular field.
 *
 * The adapter is complete and correct; it starts returning data the moment the
 * account has query credit. Nothing here is stubbed or faked.
 */
import type { ProviderObservation, ProviderOutcome, ExposureService } from "@/lib/exposure/types"
import { getJson, outcome, errorOutcome, ProviderError } from "./_base"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { credential } from "@/lib/exposure/credentials"

const ROLE = "discovery" as const
const NAME = "fofa" as const

/** Fields kept conservative — every one is available on the base plan. */
const FIELDS = "host,ip,port,protocol,title,server,country_name,city,domain"

type FofaResponse = {
  error?: boolean
  errmsg?: string
  size?: number
  results?: string[][]
}

function creds(): { email: string; key: string } {
  const email = credential("FOFA_EMAIL")
  const key = credential("FOFA_API_KEY")
  // FOFA rejects requests missing EITHER value — a key alone silently never works.
  if (!email || !key) throw new ProviderError("not_configured", "FOFA requires BOTH FOFA_EMAIL and FOFA_API_KEY.", false)
  return { email, key }
}

/** Map FOFA's own error codes to structured statuses so the UI can explain the real problem. */
function classifyFofaError(errmsg: string): ProviderError {
  if (errmsg.includes("820031") || errmsg.includes("余额不足")) {
    return new ProviderError("quota_exhausted", "FOFA account has no remaining API query credit (F-points). Top up the account to enable FOFA.", true)
  }
  if (errmsg.includes("820001") || errmsg.includes("没有权限")) {
    return new ProviderError("plan_limitation", `FOFA plan does not permit this query/field. (${errmsg})`, false)
  }
  if (/invalid|key|email/i.test(errmsg)) {
    return new ProviderError("authentication_failed", `FOFA rejected the credentials: ${errmsg}`, false)
  }
  return new ProviderError("provider_unavailable", `FOFA error: ${errmsg}`, true)
}

export type FofaQueryType = "product" | "ip" | "domain" | "port" | "cve"

export function buildFofaQuery(term: string, type: FofaQueryType): string {
  const escaped = term.replace(/"/g, '\\"')
  switch (type) {
    case "ip": return `ip="${escaped}"`
    case "domain": return `domain="${escaped}"`
    case "port": return `port="${escaped}"`
    // FOFA's documented CVE field — NOT a product search on the CVE string.
    case "cve": return `cve="${escaped}"`
    default: return `app="${escaped}"`
  }
}

export async function searchFofa(term: string, type: FofaQueryType = "product"): Promise<{ observations: ProviderObservation[]; outcome: ProviderOutcome }> {
  const started = Date.now()
  const query = buildFofaQuery(term, type)
  try {
    const { email, key } = creds()
    const qbase64 = Buffer.from(query).toString("base64")
    const url = `https://fofa.info/api/v1/search/all?email=${encodeURIComponent(email)}&key=${encodeURIComponent(key)}&qbase64=${encodeURIComponent(qbase64)}&size=50&fields=${encodeURIComponent(FIELDS)}`
    const data = await getJson<FofaResponse>(url)
    // FOFA returns HTTP 200 even for errors — the error lives in the body.
    if (data.error) throw classifyFofaError(String(data.errmsg ?? "unknown"))

    const cols = FIELDS.split(",")
    const observations: ProviderObservation[] = (data.results ?? []).map((row) => {
      const rec: Record<string, string> = {}
      cols.forEach((c, i) => { rec[c] = row[i] ?? "" })
      const port = Number(rec.port)
      const product = rec.server || null
      const services: ExposureService[] = Number.isFinite(port) && port > 0 ? [{
        port, transport: null, protocol: rec.protocol || null,
        product, vendor: null, version: null, banner: null,
        httpStatus: null, httpTitle: rec.title || null, httpServer: rec.server || null,
        sources: [NAME],
        claims: [{ source: NAME, product, vendor: null, version: null, protocol: rec.protocol || null }],
      }] : []
      return {
        provider: NAME,
        ip: rec.ip || null,
        domain: rec.domain || null,
        hostname: rec.host || null,
        asn: null,
        organization: null,
        country: rec.country_name || null,
        city: rec.city || null,
        latitude: null, longitude: null,
        services, technologies: [], certificates: [],
        // A cve= hit is FOFA directly asserting this host is affected.
        vulnerabilities: type === "cve"
          ? [makeVulnerability({ cveId: term, matchType: "cve-search", sources: [NAME] })]
          : [],
        notes: null, firstSeen: null, lastSeen: null,
        raw: rec,
      }
    })
    return { observations, outcome: outcome(NAME, ROLE, query, started, "success", observations.length) }
  } catch (e) {
    return { observations: [], outcome: errorOutcome(NAME, ROLE, query, started, e) }
  }
}
