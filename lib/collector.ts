/**
 * Collecteur de fond OCTUPUS-VOC (serveur uniquement).
 *
 * Architecture : NVD → traitement → enrichissement (EPSS/KEV/RBVM) → PostgreSQL.
 * Les utilisateurs ne touchent JAMAIS l'API NVD : ils lisent la base (instantané).
 * Synchronisation INCRÉMENTALE via la fenêtre lastModified de NVD 2.0.
 * Alertes Telegram pilotées par le serveur (indépendantes des visiteurs).
 */
import { sql, initDb } from "@/lib/db"
import { processNvd, fetchEpss } from "@/lib/data"
import { computeRiskScore, riskLevel } from "@/lib/risk-engine"
import { sendTelegram, ctxFromVuln } from "@/lib/telegram"
import type { Vuln } from "@/lib/types"

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const PER_PAGE = 2000
const BOOTSTRAP_DAYS = 7 // 1er run : profondeur de la fenêtre initiale
const OVERLAP_MIN = 30 // chevauchement pour ne rien rater entre 2 runs
const MAX_ALERTS_PER_RUN = 20

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** fetch JSON avec retry (429 / 5xx) + backoff. */
async function fetchJson(url: string, headers: Record<string, string> = {}, retries = 4): Promise<Record<string, unknown>> {
  let lastErr: unknown
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { headers })
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return (await res.json()) as Record<string, unknown>
    } catch (e) {
      lastErr = e
      if (attempt < retries) await sleep(1500 * (attempt + 1)) // backoff linéaire
    }
  }
  throw lastErr
}

/** Catalogue CISA KEV (live). */
async function loadKevServer(): Promise<Set<string>> {
  try {
    const j = await fetchJson(KEV_URL)
    const items = (j.vulnerabilities ?? []) as Array<{ cveID?: string }>
    return new Set(items.map((v) => String(v.cveID).toUpperCase()))
  } catch {
    return new Set()
  }
}

/** Récupère les CVE d'une fenêtre NVD (paginé). `base` = params de fenêtre (pub* ou lastMod*). */
async function fetchNvdWindow(base: Record<string, string>): Promise<unknown[]> {
  const headers: Record<string, string> = {}
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY
  const all: unknown[] = []
  let startIndex = 0
  for (;;) {
    const p = new URLSearchParams(base)
    p.set("resultsPerPage", String(PER_PAGE))
    p.set("startIndex", String(startIndex))
    const j = await fetchJson(`${NVD_URL}?${p.toString()}`, headers)
    const items = (j.vulnerabilities ?? []) as unknown[]
    all.push(...items)
    const total = Number(j.totalResults ?? 0)
    startIndex += PER_PAGE
    if (startIndex >= total || items.length === 0) break
    await sleep(700) // courtoisie rate-limit NVD (50 req/30s avec clé)
  }
  return all
}

/** Enrichit les CVE (EPSS + KEV + Risk Score RBVM). */
async function enrichServer(vulns: Vuln[]): Promise<void> {
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

/** Upsert par lots (transactions Neon) pour limiter les allers-retours. */
async function batchUpsert(vulns: Vuln[]): Promise<void> {
  const CHUNK = 100
  for (let i = 0; i < vulns.length; i += CHUNK) {
    const chunk = vulns.slice(i, i + CHUNK)
    const stmts = chunk.map((v) => {
      const bestCvss = v.cvssV3 !== "-" ? Number(v.cvssV3) : v.cvssV2 !== "-" ? Number(v.cvssV2) : null
      const published = v.sortDate ? new Date(v.sortDate).toISOString() : null
      return sql`
        INSERT INTO cves (cve_id, risk_score, severity, is_kev, has_exploit, epss, cvss, published, last_modified, data, synced_at)
        VALUES (${v.cveId}, ${v.riskScore ?? 0}, ${v.severity}, ${v.isKev}, ${v.hasExploit}, ${v.epss}, ${bestCvss}, ${published}, ${v.lastModified}, ${JSON.stringify(v)}, now())
        ON CONFLICT (cve_id) DO UPDATE SET
          risk_score = EXCLUDED.risk_score, severity = EXCLUDED.severity, is_kev = EXCLUDED.is_kev,
          has_exploit = EXCLUDED.has_exploit, epss = EXCLUDED.epss, cvss = EXCLUDED.cvss,
          published = EXCLUDED.published, last_modified = EXCLUDED.last_modified,
          data = EXCLUDED.data, synced_at = now()`
    })
    await sql.transaction(stmts)
  }
}

/** Alertes Telegram (serveur) : High/Critical/KEV/EPSS élevé, dé-doublonnées. */
async function sendAlerts(vulns: Vuln[]): Promise<number> {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) return 0
  const candidates = vulns
    .filter((v) => v.riskLevel === "Critique" || v.riskLevel === "Élevé" || v.isKev || (v.epss ?? 0) >= 0.5)
    .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
    .slice(0, MAX_ALERTS_PER_RUN)

  let sent = 0
  for (const v of candidates) {
    const exists = (await sql`SELECT 1 FROM alerts_sent WHERE cve_id = ${v.cveId} LIMIT 1`) as unknown[]
    if (exists.length) continue
    const ok = await sendTelegram(ctxFromVuln(v))
    if (ok) {
      await sql`INSERT INTO alerts_sent (cve_id) VALUES (${v.cveId}) ON CONFLICT DO NOTHING`
      sent++
      await sleep(400) // courtoisie rate-limit Telegram
    }
  }
  return sent
}

export type SyncResult = {
  ok: boolean
  fetched: number
  processed: number
  alerted: number
  total: number
  since: string
  durationMs: number
  error?: string
}

/** Cycle complet de synchronisation (appelé par le cron). `skipAlerts` pour le seed initial. */
export async function syncCves(opts: { skipAlerts?: boolean } = {}): Promise<SyncResult> {
  const t0 = Date.now()
  await initDb()
  try {
    const state = (await sql`SELECT last_sync FROM sync_state WHERE id = 1`) as Array<{ last_sync: string | null }>
    const lastSync = state[0]?.last_sync ? new Date(state[0].last_sync) : null
    const now = new Date()
    const since = lastSync
      ? new Date(lastSync.getTime() - OVERLAP_MIN * 60 * 1000)
      : new Date(now.getTime() - BOOTSTRAP_DAYS * 864e5)

    // 1er run : CVE PUBLIÉES (dataset récent propre). Ensuite : CVE MODIFIÉES (incrémental).
    const base: Record<string, string> = lastSync
      ? { lastModStartDate: since.toISOString(), lastModEndDate: now.toISOString() }
      : { pubStartDate: since.toISOString(), pubEndDate: now.toISOString() }
    const raw = await fetchNvdWindow(base)
    const vulns = processNvd({ vulnerabilities: raw })
    await enrichServer(vulns)
    await batchUpsert(vulns)
    const alerted = opts.skipAlerts ? 0 : await sendAlerts(vulns)

    const totalRows = (await sql`SELECT COUNT(*)::int AS n FROM cves`) as Array<{ n: number }>
    const total = totalRows[0]?.n ?? 0
    await sql`
      INSERT INTO sync_state (id, last_sync, last_run_at, total_cves, last_status)
      VALUES (1, ${now.toISOString()}, ${now.toISOString()}, ${total}, 'ok')
      ON CONFLICT (id) DO UPDATE SET
        last_sync = EXCLUDED.last_sync, last_run_at = EXCLUDED.last_run_at,
        total_cves = EXCLUDED.total_cves, last_status = 'ok'`

    const result: SyncResult = { ok: true, fetched: raw.length, processed: vulns.length, alerted, total, since: since.toISOString(), durationMs: Date.now() - t0 }
    console.log("[collector] sync OK", result)
    return result
  } catch (e) {
    const msg = (e as Error).message
    console.error("[collector] sync ERROR", msg)
    try {
      await sql`INSERT INTO sync_state (id, last_run_at, last_status) VALUES (1, now(), ${"error: " + msg})
                ON CONFLICT (id) DO UPDATE SET last_run_at = now(), last_status = ${"error: " + msg}`
    } catch { /* ignore */ }
    return { ok: false, fetched: 0, processed: 0, alerted: 0, total: 0, since: "", durationMs: Date.now() - t0, error: msg }
  }
}
