/**
 * Backfill HISTORIQUE complet : charge TOUT le catalogue NVD (1999 → aujourd'hui)
 * dans `cves`. Idempotent et résumable (fichier de progression local).
 *
 * Stratégie :
 *  - Pagination NVD 2.0 SANS fenêtre de dates (catalogue entier), 2000/page.
 *  - EPSS : téléchargement BULK (epss_scores.csv.gz) -> 1 requête au lieu de ~2800.
 *  - KEV : loadKevFull() (1 requête).
 *  - Enrichissement + upsert (mêmes fonctions que le collecteur).
 *  - PAS d'alertes Telegram (backfill historique).
 *  - sync_state id=1 mis à jour -> le prochain sync incrémental repart de là.
 *
 * Usage : bun scripts/backfill-cves.ts
 */
import { sql, initDb } from "@/lib/db"
import { processNvd } from "@/lib/data"
import { loadKevFull, fetchJson } from "@/lib/collector"
import { computeRiskScore, riskLevel } from "@/lib/risk-engine"
import type { Vuln } from "@/lib/types"

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const EPSS_BULK_URL = "https://epss.cyentia.com/epss_scores.csv.gz"
const EPSS_API_ALL_URL = "https://api.first.org/data/v1/epss" // fallback : tout le catalogue en 1 requête
const PER_PAGE = 2000
const CHUNK_UPSERT = 1000
// Mode lean : au-delà de ces seuils, on allège `data` pour tenir sous la limite de stockage Neon
// (free = 512 Mo). Tier 1 : retire les références (plus gros bloc). Tier 2 : retire vendors/products.
const LEAN_TIER1_MB = 350
const LEAN_TIER2_MB = 450
// Chemin Windows SÛR : process.cwd() = racine next-app quand on lance `bun scripts/backfill-cves.ts`
const PROGRESS_FILE = `${process.cwd()}/.backfill-progress.json`

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function loadProgress(): Promise<number> {
  try {
    const raw = Bun.file(PROGRESS_FILE)
    if (!raw.exists()) return 0
    const parsed = JSON.parse(await raw.text()) as { startIndex?: number; done?: boolean }
    if (parsed.done) return 0 // déjà terminé -> on repart de zéro (idempotent)
    return parsed.startIndex ?? 0
  } catch {
    return 0
  }
}

async function saveProgress(startIndex: number) {
  try {
    await Bun.write(PROGRESS_FILE, JSON.stringify({ startIndex }))
  } catch (e) {
    console.warn("[progress] écriture impossible:", (e as Error).message)
  }
}

/** EPSS bulk -> Map<cveId, {epss, percentile}>. 1 requête pour tout le catalogue. */
async function loadEpssBulk(): Promise<Map<string, { epss: number; percentile: number }>> {
  const map = new Map<string, { epss: number; percentile: number }>()
  const ua = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OCTUPUS-VOC/1.0" }
  try {
    const res = await fetch(EPSS_BULK_URL, { headers: ua })
    if (res.ok) {
      const buf = await res.arrayBuffer()
      const text = Bun.gunzipSync(new Uint8Array(buf)).toString()
      for (const line of text.split("\n")) {
        if (!line.startsWith("CVE-")) continue
        const [cve, epss, pct] = line.split(",")
        if (!cve) continue
        map.set(cve.toUpperCase(), { epss: parseFloat(epss), percentile: parseFloat(pct) })
      }
      console.log(`[epss] bulk CSV: ${map.size} scores chargés`)
      return map
    }
    console.warn("[epss] bulk CSV HTTP", res.status, "-> fallback API")
  } catch (e) {
    console.warn("[epss] erreur bulk CSV:", (e as Error).message, "-> fallback API")
  }
  // Fallback : API FIRST.org (toutes les CVE en 1 réponse JSON, ~300K lignes)
  try {
    const res = await fetch(EPSS_API_ALL_URL, { headers: ua })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const json = (await res.json()) as { data?: Array<{ cve: string; epss: string; percentile: string }> }
    for (const row of json.data ?? []) {
      map.set(row.cve.toUpperCase(), { epss: parseFloat(row.epss), percentile: parseFloat(row.percentile) })
    }
    console.log(`[epss] API all: ${map.size} scores chargés`)
  } catch (e) {
    console.warn("[epss] échec fallback API:", (e as Error).message)
  }
  return map
}

/** Même logique d'enrichissement que le collecteur (enrichServer). */
function enrichVulns(vulns: Vuln[], kev: Set<string>, epssMap: Map<string, { epss: number; percentile: number }>) {
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

let leanTier = 0 // 0 = plein, 1 = sans references, 2 = sans references/vendors/products
let dbSizeMb = 0

async function refreshDbSizeMb(): Promise<void> {
  const r = (await sql`SELECT pg_database_size(current_database()) AS b`) as Array<{ b: number }>
  dbSizeMb = Math.round((r[0]?.b ?? 0) / 1048576)
  if (dbSizeMb >= LEAN_TIER2_MB) leanTier = 2
  else if (dbSizeMb >= LEAN_TIER1_MB) leanTier = 1
}

/** Allège la charge JSON stockée quand la base approche la limite Neon. */
function leanVuln(v: Vuln): Vuln {
  if (leanTier === 0) return v
  if (leanTier >= 1) v.references = []
  if (leanTier >= 2) {
    v.vendors = []
    v.products = []
  }
  return v
}

/** Upsert local par gros lots (plus rapide que batchUpsert pour 300K lignes). */
async function bulkUpsert(vulns: Vuln[]) {
  for (let i = 0; i < vulns.length; i += CHUNK_UPSERT) {
    const chunk = vulns.slice(i, i + CHUNK_UPSERT)
    const stmts = chunk.map((v) => {
      const lean = leanVuln(v)
      const bestCvss = v.cvssV3 !== "-" ? Number(v.cvssV3) : v.cvssV2 !== "-" ? Number(v.cvssV2) : null
      const published = v.sortDate ? new Date(v.sortDate).toISOString() : null
      return sql`
        INSERT INTO cves (cve_id, risk_score, severity, is_kev, has_exploit, epss, cvss, published, last_modified, data, synced_at)
        VALUES (${v.cveId}, ${v.riskScore ?? 0}, ${v.severity}, ${v.isKev}, ${v.hasExploit}, ${v.epss}, ${bestCvss}, ${published}, ${v.lastModified}, ${JSON.stringify(lean)}, now())
        ON CONFLICT (cve_id) DO UPDATE SET
          risk_score = EXCLUDED.risk_score, severity = EXCLUDED.severity, is_kev = EXCLUDED.is_kev,
          has_exploit = EXCLUDED.has_exploit, epss = EXCLUDED.epss, cvss = EXCLUDED.cvss,
          published = EXCLUDED.published, last_modified = EXCLUDED.last_modified,
          data = EXCLUDED.data, synced_at = now()`
    })
    await sql.transaction(stmts)
  }
}

const t0 = Date.now()
await initDb()

console.log("== Backfill historique NVD ==")
const kevList = await loadKevFull()
const kev = new Set(kevList.map((k) => k.cveID))
console.log(`[kev] ${kev.size} entrées`)
const epssMap = await loadEpssBulk()

const headers: Record<string, string> = {}
if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY

let startIndex = await loadProgress()
let total = Infinity
let processed = 0
let page = 0

for (;;) {
  const url = `${NVD_URL}?resultsPerPage=${PER_PAGE}&startIndex=${startIndex}`
  const data = await fetchJson(url, headers)
  const items = (data.vulnerabilities ?? []) as unknown[]
  total = Number(data.totalResults ?? total)
  if (!items.length) break

  await saveProgress(startIndex) // sauve AVANT traitement -> un crash relit cette page

  const vulns = processNvd({ vulnerabilities: items })
  enrichVulns(vulns, kev, epssMap)
  await bulkUpsert(vulns)

  processed += vulns.length
  page++
  startIndex += PER_PAGE

  if (page % 10 === 0 || startIndex >= total) {
    await refreshDbSizeMb()
    console.log(`[page ${page}] ${processed}/${total} CVE (${((processed / total) * 100).toFixed(1)}%), DB: ${dbSizeMb} Mo, lean=${leanTier}`)
  }
  if (startIndex >= total) break
  await sleep(700) // courtoisie rate-limit NVD (50 req/30s avec clé)
}

// sync_state -> le prochain sync incrémental (lastMod) repart d'ici, et le dashboard affiche le vrai total
const now = new Date()
await sql`
  INSERT INTO sync_state (id, last_sync, last_run_at, total_cves, last_status)
  VALUES (1, ${now.toISOString()}, ${now.toISOString()}, ${processed}, 'ok')
  ON CONFLICT (id) DO UPDATE SET
    last_sync = EXCLUDED.last_sync, last_run_at = EXCLUDED.last_run_at,
    total_cves = EXCLUDED.total_cves, last_status = 'ok'`

// nettoyage du fichier de progression
try {
  await Bun.write(PROGRESS_FILE, JSON.stringify({ startIndex, done: true }))
} catch { /* ignore */ }

console.log(`== Backfill terminé : ${processed} CVE en ${((Date.now() - t0) / 1000).toFixed(0)}s ==`)
process.exit(0)