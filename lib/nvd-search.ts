/**
 * Recherche NVD 2.0 — Tier B : recherche par MOT-CLÉ sur archive complète
 * (keywordSearch), sans saturer la base : ZERO insert PostgreSQL.
 *
 * Stratégie :
 *  - 1ère requête : keywordSearch toutes périodes (resultsPerPage=2000).
 *  - Si la page est pleine (totalResults > 2000) : on découpe en fenêtres de
 *    publication de 120 jours max (contrainte NVD), sur les ~3 dernières années,
 *    pour récupérer des résultats faisables. Cap au-delà : 1er 2000 suffit.
 *  - Enrichissement à la volée (KEV/EPSS/risk) via enrichInflight.
 *  - Cache LRU en mémoire (50 entrées, 10 min) — le keywordSearch coûte des
 *    appels NVD, on ne le refait pas pour la même requête.
 */
import { processNvd } from "@/lib/data"
import { fetchJson } from "@/lib/fetch-json"
import { enrichInflight } from "@/lib/nvd-archive"
import type { Vuln } from "@/lib/types"

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const PER_PAGE = 2000
const WINDOW_MS = 120 * 864e5 // NVD : max 120 jours par fenêtre de dates
const YEARS_BACK = 3 // fenêtres sur les 3 dernières années si saturation
const LRU_MAX = 50
const LRU_TTL_MS = 10 * 60 * 1000

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

const cache = new Map<string, { at: number; vulns: Vuln[] }>()

function nvdHeaders(): Record<string, string> {
  const headers: Record<string, string> = {}
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY
  return headers
}

async function nvdQuery(
  keyword: string,
  start?: Date,
  end?: Date,
): Promise<{ vulns: Vuln[]; totalResults: number }> {
  const p = new URLSearchParams({ keywordSearch: keyword, resultsPerPage: String(PER_PAGE) })
  if (start && end) {
    p.set("pubStartDate", start.toISOString())
    p.set("pubEndDate", end.toISOString())
  }
  const j = await fetchJson<{ vulnerabilities?: unknown[]; totalResults?: number }>(
    `${NVD_URL}?${p.toString()}`,
    nvdHeaders(),
  )
  const vulns = processNvd({ vulnerabilities: j.vulnerabilities ?? [] })
  return { vulns, totalResults: Number(j.totalResults ?? vulns.length) }
}

/** Recherche par mot-clé — au plus NVD 1 page + jusqu'à 3 fenêtres. */
export async function findVulnsByKeyword(keyword: string): Promise<Vuln[]> {
  const key = keyword.trim().toLowerCase()
  if (!key) return []

  const hit = cache.get(key)
  if (hit && Date.now() - hit.at < LRU_TTL_MS) return hit.vulns

  const all: Vuln[] = []
  const first = await nvdQuery(keyword)
  all.push(...first.vulns)
  if (first.totalResults > PER_PAGE) {
    // Saturation : on recharge en fenêtres de 120j sur les ~3 dernières années.
    const now = new Date()
    let cursor = new Date(now.getFullYear() - YEARS_BACK, 0, 1)
    for (let w = 0; w < 6 && all.length < PER_PAGE; w++) {
      const start = new Date(cursor)
      const end = new Date(Math.min(start.getTime() + WINDOW_MS, now.getTime()))
      if (end <= start) break
      try {
        const r = await nvdQuery(keyword, start, end)
        all.push(...r.vulns)
      } catch { /* fenêtre ignorée */ }
      cursor = new Date(end.getTime() + 1)
      await sleep(700) // courtoisie débit NVD
    }
  }

  const deDup = [...new Map(all.map((v) => [v.cveId, v])).values()]
  const vulns = deDup.slice(0, PER_PAGE)
  await enrichInflight(vulns)

  cache.set(key, { at: Date.now(), vulns })
  if (cache.size > LRU_MAX) {
    const oldest = [...cache.entries()].sort((a, b) => a[1].at - b[1].at)[0]
    if (oldest) cache.delete(oldest[0])
  }
  return vulns
}

/** Purge explicite (tests). */
export function resetSearchCache(): void {
  cache.clear()
}