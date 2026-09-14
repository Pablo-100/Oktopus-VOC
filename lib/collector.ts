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
import { fetchJson } from "@/lib/fetch-json"
import { loadKevServer } from "@/lib/kev-cache"
import type { Vuln } from "@/lib/types"

// Ré-exports pour compat (zero-day-collector.ts, scripts/backfill-cves.ts) :
// l'implémentation vit désormais dans lib/fetch-json.ts + lib/kev-cache.ts.
export { fetchJson } from "@/lib/fetch-json"
export { loadKevFull, loadKevServer } from "@/lib/kev-cache"

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const PER_PAGE = 2000
const BOOTSTRAP_DAYS = 7 // 1er run : profondeur de la fenêtre initiale
const OVERLAP_MIN = 30 // chevauchement pour ne rien rater entre 2 runs

/**
 * Fenêtre maximale traitée par exécution.
 *
 * Sans borne, la fenêtre demandée est `now - last_sync`, qui grandit tant que
 * le cron ne tourne pas. Passé un certain écart, la requête NVD ne tient plus
 * dans le budget de 60 s de la fonction : elle est tuée, `last_sync` — écrit
 * seulement en fin de parcours — n'avance jamais, et l'exécution suivante
 * redemande exactement la même fenêtre trop grande. Le rattrapage devient
 * impossible : quatre jours d'arrêt suffisaient à figer la synchronisation
 * définitivement.
 *
 * En bornant la fenêtre, chaque exécution progresse d'au plus 12 h et écrit son
 * avancement. Un écart de quatre jours se résorbe donc en huit exécutions —
 * quarante minutes au rythme de cinq minutes — au lieu de ne jamais se
 * résorber.
 */
const MAX_WINDOW_HOURS = 12
const MAX_ALERTS_PER_RUN = 20

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

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
export async function enrichServer(vulns: Vuln[]): Promise<void> {
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
export async function batchUpsert(vulns: Vuln[], importedBy?: string | null): Promise<void> {
  const CHUNK = 100
  for (let i = 0; i < vulns.length; i += CHUNK) {
    const chunk = vulns.slice(i, i + CHUNK)
    const stmts = chunk.map((v) => {
      const bestCvss = v.cvssV3 !== "-" ? Number(v.cvssV3) : v.cvssV2 !== "-" ? Number(v.cvssV2) : null
      const published = v.sortDate ? new Date(v.sortDate).toISOString() : null
      return sql`
        INSERT INTO cves (cve_id, risk_score, severity, is_kev, has_exploit, epss, cvss, published, last_modified, data, imported_by, synced_at)
        VALUES (${v.cveId}, ${v.riskScore ?? 0}, ${v.severity}, ${v.isKev}, ${v.hasExploit}, ${v.epss}, ${bestCvss}, ${published}, ${v.lastModified}, ${JSON.stringify(v)}, ${importedBy ?? null}, now())
        ON CONFLICT (cve_id) DO UPDATE SET
          risk_score = EXCLUDED.risk_score, severity = EXCLUDED.severity, is_kev = EXCLUDED.is_kev,
          has_exploit = EXCLUDED.has_exploit, epss = EXCLUDED.epss, cvss = EXCLUDED.cvss,
          published = EXCLUDED.published, last_modified = EXCLUDED.last_modified,
          data = EXCLUDED.data, synced_at = now(),
          imported_by = COALESCE(EXCLUDED.imported_by, cves.imported_by)`
    })
    await sql.transaction(stmts)
  }
}

/**
 * Alertes Telegram (serveur) : toutes les CVE qualifiantes EN BASE (High/Critical/KEV/EPSS≥0.5)
 * PAS encore envoyées — backlog inclus, pas seulement le lot du run. Triées par risque, capées.
 */
async function sendAlerts(): Promise<number> {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) return 0
  const rows = (await sql`
    SELECT c.data FROM cves c
    WHERE (c.severity IN ('critical','high') OR c.is_kev = true OR c.epss >= 0.5)
      AND NOT EXISTS (SELECT 1 FROM alerts_sent a WHERE a.cve_id = c.cve_id)
    ORDER BY c.risk_score DESC
    LIMIT ${MAX_ALERTS_PER_RUN}`) as Array<{ data: Vuln }>
  const candidates = rows.map((r) => r.data)

  let sent = 0
  for (const v of candidates) {
    // Réservation ATOMIQUE : seul le 1er process qui insère envoie. Élimine tout doublon,
    // même si deux runs (cron + manuel) tournent en même temps. Pas de fenêtre SELECT→INSERT.
    const claim = (await sql`INSERT INTO alerts_sent (cve_id) VALUES (${v.cveId}) ON CONFLICT DO NOTHING RETURNING cve_id`) as unknown[]
    if (!claim.length) continue // déjà réservé/envoyé -> on saute
    const ok = await sendTelegram(ctxFromVuln(v))
    if (ok) {
      sent++
      await sleep(400) // courtoisie rate-limit Telegram
    } else {
      // échec d'envoi -> on relâche la réservation pour retenter au prochain run
      await sql`DELETE FROM alerts_sent WHERE cve_id = ${v.cveId}`
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
  /** Fin de la fenêtre réellement traitée par cette exécution. */
  until?: string
  /**
   * `false` lorsqu'il reste du retard à rattraper : la fenêtre a été bornée et
   * une nouvelle exécution est nécessaire. Permet à l'ordonnanceur et à
   * `/api/health` de distinguer « à jour » de « en train de rattraper », deux
   * états qui se ressemblaient jusqu'ici.
   */
  caughtUp?: boolean
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

    // Borne haute de la fenêtre : au plus MAX_WINDOW_HOURS après son début.
    // C'est ce qui rend le rattrapage possible (cf. MAX_WINDOW_HOURS).
    const maxEnd = new Date(since.getTime() + MAX_WINDOW_HOURS * 3600_000)
    const until = maxEnd < now ? maxEnd : now
    const caughtUp = until >= now

    // 1er run : CVE PUBLIÉES (dataset récent propre). Ensuite : CVE MODIFIÉES (incrémental).
    const base: Record<string, string> = lastSync
      ? { lastModStartDate: since.toISOString(), lastModEndDate: until.toISOString() }
      : { pubStartDate: since.toISOString(), pubEndDate: until.toISOString() }
    const raw = await fetchNvdWindow(base)
    const vulns = processNvd({ vulnerabilities: raw })
    await enrichServer(vulns)
    await batchUpsert(vulns)
    // Hygiène : retire de alerts_sent les entrées orphelines (CVE absentes de la base)
    await sql`DELETE FROM alerts_sent a WHERE NOT EXISTS (SELECT 1 FROM cves c WHERE c.cve_id = a.cve_id)`
    const alerted = opts.skipAlerts ? 0 : await sendAlerts()

    const totalRows = (await sql`SELECT COUNT(*)::int AS n FROM cves`) as Array<{ n: number }>
    const total = totalRows[0]?.n ?? 0
    // `last_sync` avance jusqu'à la FIN DE LA FENÊTRE traitée, pas jusqu'à
    // `now` : sinon l'exécution prétendrait avoir couvert un intervalle qu'elle
    // n'a pas demandé, et les CVE de cet intervalle seraient perdues.
    await sql`
      INSERT INTO sync_state (id, last_sync, last_run_at, total_cves, last_status)
      VALUES (1, ${until.toISOString()}, ${now.toISOString()}, ${total}, 'ok')
      ON CONFLICT (id) DO UPDATE SET
        last_sync = EXCLUDED.last_sync, last_run_at = EXCLUDED.last_run_at,
        total_cves = EXCLUDED.total_cves, last_status = 'ok'`

    const result: SyncResult = { ok: true, fetched: raw.length, processed: vulns.length, alerted, total, since: since.toISOString(), durationMs: Date.now() - t0, caughtUp, until: until.toISOString() }
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
