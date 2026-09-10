/**
 * Catalogue CISA KEV — version MEMOISÉE (30 min).
 *
 * Le feed KEV est grosso modo stable entre deux publications CISA : le refetch
 * systématique à chaque run collector est un gaspillage de bande passante et de
 * latence. Ce module expose un accès unique, partagé par le collecteur CVE, le
 * collecteur 0-day et l'archive (Tier A/B).
 */
import { fetchJson } from "@/lib/fetch-json"

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const TTL_MS = 30 * 60 * 1000

export interface KevEntry {
  cveID: string
  dateAdded: string
  vendorProject: string
  product: string
  vulnerabilityName: string
}

let cache: { at: number; entries: KevEntry[] } | null = null
let inflight: Promise<KevEntry[]> | null = null

async function fetchFresh(): Promise<KevEntry[]> {
  const data = await fetchJson<{ vulnerabilities?: Array<Record<string, unknown>> }>(KEV_URL)
  const vulns = data.vulnerabilities ?? []
  const entries = vulns.map((v) => ({
    cveID: String(v.cveID ?? "").toUpperCase(),
    dateAdded: String(v.dateAdded ?? ""),
    vendorProject: String(v.vendorProject ?? ""),
    product: String(v.product ?? ""),
    vulnerabilityName: String(v.vulnerabilityName ?? ""),
  }))
  cache = { at: Date.now(), entries }
  return entries
}

/** Catalogue complet (mémorisé 30 min, une seule requête en vol à la fois). */
export async function loadKevFull(): Promise<KevEntry[]> {
  if (cache && Date.now() - cache.at < TTL_MS) return cache.entries
  if (inflight) return inflight
  inflight = fetchFresh()
    .catch((e: unknown) => {
      // En cas d'échec réseau, on sert la dernière copie connue (stale-while-error).
      if (cache) return cache.entries
      throw e
    })
    .finally(() => {
      inflight = null
    })
  return inflight
}

/** Set des cveID majuscules (l'existant). */
export async function loadKevServer(): Promise<Set<string>> {
  try {
    const full = await loadKevFull()
    return new Set(full.map((k) => k.cveID))
  } catch {
    return new Set()
  }
}

/** Purge explicite (tests). */
export function resetKevCache(): void {
  cache = null
  inflight = null
}