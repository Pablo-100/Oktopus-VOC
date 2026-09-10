/**
 * Archive NVD — Tier A : recherche des CVE ANCIENNES par ID exact
 * (CVE-YYYY-NNNN hors de la fenêtre de synchro, ou jamais collectées).
 *
 * Stratégie « ne pas saturer la base » : AUCUN insert PostgreSQL. On lit les
 * flux JSON NVD v1.1 par année (nvdcve-1.1-{year}.json.gz), on mappe en Vuln[],
 * on enrichit à la volée (KEV memoïsé + EPSS + risk score), on renvoie.
 * Les archives annuelles sont ~30-120 Mo décompressés : on ne garde en mémoire
 * QUE la Map cveId→Vuln de l'année demandée (10 min), jamais le JSON brut.
 */
import { gunzipSync } from "node:zlib"
import { computeRiskScore, riskLevel, severityFromCvss } from "@/lib/risk-engine"
import type { Vuln } from "@/lib/types"

const FEED_1_1 = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
const CACHE_TTL_MS = 10 * 60 * 1000

// Cache année → promesse (évite le re-téléchargement du .gz pendant 10 min)
const cache = new Map<number, Map<string, Vuln>>()
const inflight = new Map<number, Promise<Map<string, Vuln>>>()

/** Extrait l'année d'un ID CVE (format CVE-YYYY-NNNN+). */
export function yearFromCveId(cveId: string): number | null {
  const m = /^CVE-(\d{4})-\d{4,}$/i.exec(cveId)
  return m ? Number(m[1]) : null
}

/** Télécharge UNE année, décompresse, mappe en Map<cveId, Vuln>. */
export async function fetchYearArchive(year: number): Promise<Map<string, Vuln>> {
  const hit = cache.get(year)
  if (hit) return hit

  let p = inflight.get(year)
  if (!p) {
    p = (async () => {
      const url = FEED_1_1.replace("{year}", String(year))
      const res = await fetch(url, { cache: "no-store" })
      if (!res.ok) throw new Error(`NVD feed HTTP ${res.status} (${year})`)
      const buf = Buffer.from(await res.arrayBuffer())
      const decompressed = gunzipSync(buf).toString("utf8")
      const json = JSON.parse(decompressed) as { CVE_Items?: Item11[] }
      return mapItems(json.CVE_Items ?? [])
    })().finally(() => {
      inflight.delete(year)
    })
    inflight.set(year, p)
  }
  const map = await p
  cache.set(year, map)
  // purge lazy : on laisse vieillir le cache, il est remplacé au prochain TTL
  setTimeout(() => cache.delete(year), CACHE_TTL_MS).unref?.()
  return map
}

/** Force une purge explicite (tests). */
export function resetArchiveCache(): void {
  cache.clear()
  inflight.clear()
}

/**
 * Tier A : lookup par ID exact dans le flux de son année.
 * DB-first en amont (route) ; ici archive only. Renvoie null si absent.
 */
export async function lookupArchive(cveId: string): Promise<Vuln | null> {
  const year = yearFromCveId(cveId)
  if (!year) return null
  const map = await fetchYearArchive(year)
  const v = map.get(cveId.toUpperCase())
  if (!v) return null
  // Enrichissement à la volée (KEV + EPSS + risk) — n'insère JAMAIS en base.
  await enrichInflight([v])
  return v
}

/**
 * Enrichissement RBVM à la volée (partagé collecteur/archive).
 * Mutates les objets en place, ne touche pas à la base.
 */
export async function enrichInflight(vulns: Vuln[]): Promise<void> {
  const { loadKevServer } = await import("@/lib/kev-cache")
  const { fetchEpss } = await import("@/lib/data")
  const [kev, epssMap] = await Promise.all([loadKevServer(), fetchEpss(vulns.map((v) => v.cveId))])
  for (const v of vulns) {
    const key = v.cveId.toUpperCase()
    const isKev = kev.has(key)
    const epssData = epssMap.get(key)
    const epss = epssData ? epssData.epss : null
    const bestCvss = v.cvssV3 !== "-" ? v.cvssV3 : v.cvssV2 !== "-" ? v.cvssV2 : 0
    v.epss = epss
    v.epssPercentile = epssData ? epssData.percentile : null
    v.isKev = isKev
    if (isKev) v.hasExploit = true
    v.riskScore = computeRiskScore(bestCvss, epss, isKev)
    v.riskLevel = riskLevel(v.riskScore).level
  }
}

// ---------------------------------------------------------------------------
// Mapping flux NVD v1.1 (CVE_Items) -> Vuln[]  (contrat identique à processNvd)
// ---------------------------------------------------------------------------
// Structure du flux NVD v1.1 (documentée, pas de `any`)
interface Cve11 {
  CVE_data_meta?: { ID?: string }
  description?: { description_data?: Array<{ lang: string; value: string }> }
  references?: { reference_data?: Array<{ url: string; tags?: string[] }> }
  problemtype?: { problemtype_data?: Array<{ description?: Array<{ value: string }> }> }
}
interface Impact11 {
  baseMetricV3?: { cvssV3?: MetricV3 }
  baseMetricV2?: { cvssV2?: MetricV2 }
}
interface MetricV3 {
  baseScore?: number
  attackVector?: string
  vectorString?: string
  attackComplexity?: string
  confidentialityImpact?: string
  integrityImpact?: string
  availabilityImpact?: string
}
interface MetricV2 {
  baseScore?: number
  accessVector?: string
  vectorString?: string
  accessComplexity?: string
  confidentialityImpact?: string
  integrityImpact?: string
  availabilityImpact?: string
}
interface Item11 {
  cve?: Cve11
  impact?: Impact11
  configurations?: { nodes?: Array<{ cpe_match?: Array<{ cpe23Uri?: string }> }> }
  publishedDate?: string
  lastModifiedDate?: string
}

function mapItems(items: Item11[]): Map<string, Vuln> {
  const map = new Map<string, Vuln>()
  for (const item of items) {
    const v = mapItem(item)
    if (v) map.set(v.cveId, v)
  }
  return map
}

function mapItem(item: Item11): Vuln | null {
  const cveId = String(item.cve?.CVE_data_meta?.ID ?? "").toUpperCase()
  if (!cveId) return null

  const description =
    item.cve?.description?.description_data?.find((d) => d.lang === "en")?.value ?? "No description available"

  const v3 = item.impact?.baseMetricV3?.cvssV3 ?? {}
  const v2 = item.impact?.baseMetricV2?.cvssV2 ?? {}
  const severity = severityFromCvss(v3.baseScore ?? v2.baseScore ?? null)

  const cweSet = new Set<string>()
  for (const pt of item.cve?.problemtype?.problemtype_data ?? []) {
    for (const d of pt.description ?? []) {
      if (/^CWE-\d+$/i.test(d.value)) cweSet.add(d.value.toUpperCase())
    }
  }

  const references = (item.cve?.references?.reference_data ?? []).map((r) => ({
    url: r.url,
    tags: r.tags ?? [],
  }))
  const hasExploit = references.some((r) => (r.tags ?? []).includes("Exploit"))

  const vendorSet = new Set<string>()
  const productSet = new Set<string>()
  for (const node of item.configurations?.nodes ?? []) {
    for (const cpe of node.cpe_match ?? []) {
      const { vendor, product } = expandCpe(cpe.cpe23Uri ?? "")
      if (vendor) vendorSet.add(vendor)
      if (product) productSet.add(product)
    }
  }

  const pub = new Date(item.publishedDate ?? "")

  return {
    cveId,
    description,
    cvssV2: v2.baseScore ?? "-",
    cvssV3: v3.baseScore ?? "-",
    severity,
    cwes: [...cweSet],
    attackVector: v3.attackVector ?? v2.accessVector ?? "-",
    references,
    hasExploit,
    vendors: [...vendorSet].slice(0, 8),
    products: [...productSet].slice(0, 8),
    vector: v3.vectorString ?? v2.vectorString ?? "-",
    complexity: v3.attackComplexity ?? v2.accessComplexity ?? "-",
    impactC: v3.confidentialityImpact ?? v2.confidentialityImpact ?? "-",
    impactI: v3.integrityImpact ?? v2.integrityImpact ?? "-",
    impactA: v3.availabilityImpact ?? v2.availabilityImpact ?? "-",
    publishedDate: pub.toLocaleDateString("fr-FR"),
    sortDate: pub,
    lastModified: item.lastModifiedDate ?? null,
    epss: null,
    epssPercentile: null,
    isKev: false,
    riskScore: null,
    riskLevel: "",
  } satisfies Vuln
}

function expandCpe(uri: string): { vendor: string; product: string } {
  // cpe:2.3:part:vendor:product:version:...
  const parts = String(uri ?? "").split(":")
  const clean = (s: string | undefined) => (s && s !== "*" && s !== "-" ? s.replace(/_/g, " ") : "")
  return { vendor: clean(parts[3]), product: clean(parts[4]) }
}