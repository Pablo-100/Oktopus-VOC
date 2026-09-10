/**
 * Collecteur 0-day / pré-CVE OCTUPUS-VOC (serveur uniquement).
 *
 * 4 sources gratuites/communautaires, vérifiées individuellement contre leur API
 * réelle (échec indépendant via Promise.allSettled) :
 *  1. CISA KEV prepub    -> dateAdded < published (jointure table cves) — SEUL test
 *                           valide de "exploité avant divulgation publique"
 *  2. GitHub Advisories  -> type=reviewed, cve_id=null (GHSA sans CVE assigné)
 *  3. Google Project Zero -> tracker officiel des 0-day exploités in-the-wild
 *  4. Actualité cyber (RSS) -> BleepingComputer/THN filtrés par mots-clés 0-day
 *
 * RETIRÉS (2026-08-22, cf. investigation) — produisaient des FAUX 0-day :
 *  - NVD `cveStatus=RESERVED` : paramètre inexistant côté API NVD 2.0 (confirmé
 *    HTTP 404 même avec les valeurs cveStatus documentées) — NVD n'indexe que
 *    les CVE déjà publiées, les IDs "reserved" vivent chez CVE.org/MITRE, pas NVD.
 *    Un futur remplacement viable : le dépôt git CVEProject/cvelistV5 (lourd,
 *    nécessite de parcourir l'arbre GitHub), volontairement non implémenté ici
 *    plutôt que de fournir une fausse source.
 *  - defend.network : sa propre métadonnée (`meta.window`) déclare qu'elle liste
 *    "les CVE avec une activité datée dans les 7 derniers jours (ajout KEV,
 *    brief quotidien, rapport hebdo)" — PAS des 0-day. `kindFromDefend()`
 *    labellisait `exploitation === "kev-confirmed"` en "prepub_exploited" sans
 *    jamais comparer les dates, faisant remonter des CVE de 2008/2021/2023
 *    (déjà publiques depuis des années) comme si c'étaient des 0-day fraîches.
 *    C'est le bug rapporté : "je vois juste des CVE" — c'était vrai, littéralement.
 *
 * Fusion : clé normalisée (cve_id | ghsa:XXX | src:<source>:<id>)
 *   priorité enrichissement : p0 > kev > github > news
 *   priorité kind          : prepub_exploited > reserved > advisory
 * Scoring : computeZeroDayRisk (même échelle RBVM 0-100 que le dashboard)
 * Alertes Telegram : même garde-fous que sendAlerts() (réservation atomique, cap 10/run)
 * sync_state id=2 réutilisée (total_cves = compteur 0-day)
 */
import { sql, initDb } from "@/lib/db"
import { fetchJson, loadKevFull } from "@/lib/collector"
import { computeZeroDayRisk, zeroDaySeverity } from "@/lib/risk-engine"
import { sendTelegram, sendTelegramRaw, ctxFromZeroDay } from "@/lib/telegram"
import { fetchGoogleP0, fetchRssNews } from "@/lib/zero-day-news"
import { normalizeKey } from "@/lib/zero-day-util"
import type { ZeroDay, ZeroDayKind, ZeroDayExploitState } from "@/lib/types"

export { normalizeKey }

const GITHUB_ADV_URL = "https://api.github.com/advisories"
const BOOTSTRAP_DAYS = 7
const OVERLAP_MIN = 30
const MAX_ZD_ALERTS_PER_RUN = 10
// A source erroring 3 runs in a row (~15 min at the 5-min cron cadence) is a real
// break, not noise — re-alert at most once every 6h so a stuck source doesn't spam.
const SOURCE_FAILURE_ALERT_THRESHOLD = 3
const SOURCE_REALERT_COOLDOWN_MS = 6 * 60 * 60 * 1000

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

function riskFields(
  kind: ZeroDayKind,
  exploitState: ZeroDayExploitState,
  isKev: boolean,
  hasExploit: boolean,
  cvss?: number | null,
  epss?: number | null
) {
  const riskScore = computeZeroDayRisk(kind, exploitState, isKev, hasExploit, cvss, epss)
  const severity = zeroDaySeverity(riskScore)
  return { riskScore, severity }
}

async function fetchKevPrepub(): Promise<ZeroDay[]> {
  const kevFull = await loadKevFull()
  if (!kevFull.length) return []
  const kevIds = kevFull.map((k) => k.cveID)
  const rows = (await sql`SELECT cve_id, published FROM cves WHERE cve_id = ANY(${kevIds})`) as Array<{ cve_id: string; published: string | null }>
  const publishedMap = new Map(rows.map((r) => [r.cve_id, r.published ? new Date(r.published) : null]))
  const all: ZeroDay[] = []
  for (const k of kevFull) {
    const published = publishedMap.get(k.cveID) ?? null
    const dateAdded = k.dateAdded ? new Date(k.dateAdded) : null
    if (!published || !dateAdded) continue
    if (dateAdded < published) {
      const { riskScore, severity } = riskFields("prepub_exploited", "kev-confirmed", true, true, null, null)
      all.push({
        id: k.cveID,
        source: "kev",
        kind: "prepub_exploited",
        cveId: k.cveID,
        ghsaId: null,
        title: k.vulnerabilityName,
        product: k.product,
        exploitState: "kev-confirmed",
        verification: "verified",
        isKev: true,
        hasExploit: true,
        riskScore,
        severity,
        cvss: null,
        epss: null,
        firstSeenAt: dateAdded.toISOString(),
        lastSeenAt: new Date().toISOString(),
        becameCve: false,
        resolvedAt: null,
        description: null,
        permalink: null,
        references: [],
        data: k,
      })
    }
  }
  return all
}

async function fetchGhsaNoCve(since: Date): Promise<ZeroDay[]> {
  const headers: Record<string, string> = { Accept: "application/vnd.github+json" }
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  const params = new URLSearchParams()
  params.set("type", "reviewed")
  params.set("per_page", "100")
  // GitHub requires a range qualifier (">2026-01-01"), not a bare ISO date —
  // a bare date returns HTTP 422 "The date input '...' is invalid." (verified
  // live against the real API; this silently zeroed out the whole source).
  params.set("updated", `>${since.toISOString().slice(0, 10)}`)
  const url = `${GITHUB_ADV_URL}?${params.toString()}`
  const j = await fetchJson(url, headers)
  const items = (j as unknown as Array<Record<string, unknown>>) ?? []
  const all: ZeroDay[] = []
  for (const item of items) {
    const cveId = item.cve_id ? String(item.cve_id).toUpperCase() : null
    if (cveId) continue // on garde seulement les advisories SANS CVE
    const ghsaId = item.ghsa_id ? String(item.ghsa_id).toUpperCase() : null
    if (!ghsaId) continue
    // GitHub's actual schema (verified live): `cvss_severities` is an OBJECT keyed
    // by version ({cvss_v3:{score}, cvss_v4:{score}}), not an array — `[0]?.score`
    // always evaluated to null. `references` is a flat array of URL strings, not
    // `{url}` objects — `.map(r => r.url)` always produced `undefined`. Both silently
    // dropped real data (CVSS always null, references always [null, null, ...]).
    const cvssSeverities = item.cvss_severities as { cvss_v3?: { score?: number }; cvss_v4?: { score?: number } } | undefined
    const cvss = cvssSeverities?.cvss_v3?.score ?? cvssSeverities?.cvss_v4?.score ?? null
    const references = ((item.references as string[]) ?? []).map((r) => String(r))
    const htmlUrl = item.html_url ? String(item.html_url) : null
    const { riskScore, severity } = riskFields("advisory", "none", false, false, cvss, null)
    all.push({
      id: `GHSA:${ghsaId}`,
      source: "github",
      kind: "advisory",
      cveId: null,
      ghsaId,
      title: item.summary ? String(item.summary) : ghsaId,
      product: null,
      exploitState: "none",
      verification: "verified",
      isKev: false,
      hasExploit: false,
      riskScore,
      severity,
      cvss,
      epss: null,
      firstSeenAt: item.published_at ? String(item.published_at) : new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      becameCve: false,
      resolvedAt: null,
      description: item.description ? String(item.description) : null,
      permalink: htmlUrl,
      references,
      data: item,
    })
  }
  return all
}

export function mergeRecords(records: ZeroDay[]): ZeroDay[] {
  const byKey = new Map<string, ZeroDay>()
  const sourcePriority: Record<string, number> = { p0: 4, kev: 3, github: 2, news: 1 }
  const kindPriority = { prepub_exploited: 3, reserved: 2, advisory: 1 }
  for (const r of records) {
    const existing = byKey.get(r.id)
    if (!existing) {
      byKey.set(r.id, r)
      continue
    }
    // Priorité enrichissement
    if (sourcePriority[r.source] > sourcePriority[existing.source]) {
      // source plus riche -> remplacer mais garder first_seen_at
      const merged = { ...r, firstSeenAt: existing.firstSeenAt, lastSeenAt: new Date().toISOString() }
      byKey.set(r.id, merged)
    } else if (sourcePriority[r.source] === sourcePriority[existing.source]) {
      // Même source -> kind plus fort gagne
      if (kindPriority[r.kind] > kindPriority[existing.kind]) {
        const merged = { ...existing, kind: r.kind, lastSeenAt: new Date().toISOString() }
        byKey.set(r.id, merged)
      } else {
        existing.lastSeenAt = new Date().toISOString()
      }
    } else {
      existing.lastSeenAt = new Date().toISOString()
    }
  }
  return [...byKey.values()]
}

type SourceRunResult = { name: string; result: PromiseSettledResult<ZeroDay[]> }

/**
 * Upserts per-source health, and sends one Telegram admin alert the run a source
 * crosses SOURCE_FAILURE_ALERT_THRESHOLD consecutive errors (not on every run after
 * that -> no spam), re-alerting only after SOURCE_REALERT_COOLDOWN_MS if still broken.
 */
async function trackSourceHealth(sources: SourceRunResult[]): Promise<void> {
  for (const s of sources) {
    const failed = s.result.status === "rejected"
    const emptyOk = s.result.status === "fulfilled" && s.result.value.length === 0
    const reason = failed ? (s.result as PromiseRejectedResult).reason : null
    const errorMsg = failed ? String(reason?.message ?? reason) : null

    const rows = (await sql`
      INSERT INTO zero_day_source_health (source, consecutive_failures, consecutive_empty, last_ok_at, last_error, updated_at)
      VALUES (
        ${s.name},
        ${failed ? 1 : 0},
        ${emptyOk ? 1 : 0},
        ${failed ? null : new Date().toISOString()},
        ${errorMsg},
        now()
      )
      ON CONFLICT (source) DO UPDATE SET
        consecutive_failures = CASE WHEN ${failed} THEN zero_day_source_health.consecutive_failures + 1 ELSE 0 END,
        consecutive_empty    = CASE WHEN ${emptyOk} THEN zero_day_source_health.consecutive_empty + 1 ELSE 0 END,
        last_ok_at            = CASE WHEN ${failed} THEN zero_day_source_health.last_ok_at ELSE now() END,
        last_error            = CASE WHEN ${failed} THEN ${errorMsg} ELSE zero_day_source_health.last_error END,
        updated_at            = now()
      RETURNING consecutive_failures, last_alerted_at
    `) as Array<{ consecutive_failures: number; last_alerted_at: string | null }>

    const row = rows[0]
    if (!row || row.consecutive_failures < SOURCE_FAILURE_ALERT_THRESHOLD) continue
    const lastAlerted = row.last_alerted_at ? new Date(row.last_alerted_at).getTime() : 0
    if (Date.now() - lastAlerted < SOURCE_REALERT_COOLDOWN_MS) continue

    const sent = await sendTelegramRaw(
      `<b>⚠️ OCTUPUS-VOC · 0-day source down</b>\n\n` +
        `Source <b>${s.name}</b> has failed <b>${row.consecutive_failures}</b> consecutive sync runs.\n` +
        `Last error: <code>${String(errorMsg ?? "unknown").slice(0, 300)}</code>`
    )
    if (sent) await sql`UPDATE zero_day_source_health SET last_alerted_at = now() WHERE source = ${s.name}`
  }
}

export type SyncZeroDaysResult = {
  ok: boolean
  fetched: number
  processed: number
  alerted: number
  total: number
  durationMs: number
  error?: string
}

/** Cycle complet de synchronisation 0-day (appelé par le cron APRÈS syncCves). */
export async function syncZeroDays(): Promise<SyncZeroDaysResult> {
  const t0 = Date.now()
  await initDb()
  try {
    const state = (await sql`SELECT last_sync FROM sync_state WHERE id = 2`) as Array<{ last_sync: string | null }>
    const lastSync = state[0]?.last_sync ? new Date(state[0].last_sync) : null
    const now = new Date()
    const since = lastSync
      ? new Date(lastSync.getTime() - OVERLAP_MIN * 60 * 1000)
      : new Date(now.getTime() - BOOTSTRAP_DAYS * 864e5)

    // 1. Collecte parallèle (échec indépendant par source)
    const [kevRes, ghsaRes, p0Res, rssRes] = await Promise.allSettled([
      fetchKevPrepub(),
      fetchGhsaNoCve(since),
      fetchGoogleP0(since),
      fetchRssNews(),
    ])

    const sources = [
      { name: "kev", result: kevRes },
      { name: "github", result: ghsaRes },
      { name: "p0", result: p0Res },
      { name: "news", result: rssRes },
    ]
    let fetched = 0
    const allRecords: ZeroDay[] = []
    for (const s of sources) {
      if (s.result.status === "fulfilled") {
        fetched += s.result.value.length
        allRecords.push(...s.result.value)
      } else {
        console.error(`[zero-day-collector] ${s.name} ERROR:`, s.result.reason)
      }
    }

    // 1b. Per-source health tracking + alerting — two of the six sources are
    // screen-scrapes (Google Sheet gviz, RSS) that can break silently; without
    // this, a broken scraper just logs to a console nobody reads.
    await trackSourceHealth(sources)

    // 2. Fusion + scoring
    const merged = mergeRecords(allRecords)
    for (const r of merged) {
      const { riskScore, severity } = riskFields(r.kind, r.exploitState, r.isKev, r.hasExploit, r.cvss, r.epss)
      r.riskScore = riskScore
      r.severity = severity
    }

    // 3. Upsert par lots de 100 (ne pas écraser first_seen_at)
    const CHUNK = 100
    for (let i = 0; i < merged.length; i += CHUNK) {
      const chunk = merged.slice(i, i + CHUNK)
      const stmts = chunk.map((r) =>
        sql`
          INSERT INTO zero_days (id, source, kind, cve_id, ghsa_id, title, product, exploit_state, verification, is_kev, has_exploit, risk_score, severity, cvss, epss, first_seen_at, last_seen_at, became_cve, resolved_at, description, permalink, references_json, data, synced_at)
          VALUES (${r.id}, ${r.source}, ${r.kind}, ${r.cveId}, ${r.ghsaId}, ${r.title}, ${r.product}, ${r.exploitState}, ${r.verification}, ${r.isKev}, ${r.hasExploit}, ${r.riskScore}, ${r.severity}, ${r.cvss}, ${r.epss}, ${r.firstSeenAt}, ${r.lastSeenAt}, ${r.becameCve}, ${r.resolvedAt}, ${r.description ?? null}, ${r.permalink ?? null}, ${JSON.stringify(r.references ?? [])}, ${JSON.stringify(r.data)}, now())
          ON CONFLICT (id) DO UPDATE SET
            source = EXCLUDED.source, kind = EXCLUDED.kind, cve_id = EXCLUDED.cve_id, ghsa_id = EXCLUDED.ghsa_id,
            title = EXCLUDED.title, product = EXCLUDED.product, exploit_state = EXCLUDED.exploit_state,
            verification = EXCLUDED.verification, is_kev = EXCLUDED.is_kev, has_exploit = EXCLUDED.has_exploit,
            risk_score = EXCLUDED.risk_score, severity = EXCLUDED.severity, cvss = EXCLUDED.cvss, epss = EXCLUDED.epss,
            last_seen_at = EXCLUDED.last_seen_at, became_cve = EXCLUDED.became_cve, resolved_at = EXCLUDED.resolved_at,
            description = EXCLUDED.description, permalink = EXCLUDED.permalink, references_json = EXCLUDED.references_json,
            data = EXCLUDED.data, synced_at = now()
        `
      )
      await sql.transaction(stmts)
    }

    // 4. Résolution « devenue CVE » (jointure table cves)
    await sql`
      UPDATE zero_days SET became_cve = true, resolved_at = now()
      WHERE became_cve = false
        AND cve_id IS NOT NULL
        AND EXISTS (SELECT 1 FROM cves c WHERE c.cve_id = zero_days.cve_id)
    `

    // 5. Alertes Telegram (mêmes garde-fous que sendAlerts)
    // Reconstruit un ZeroDay complet depuis les VRAIES colonnes normalisées —
    // `data` seule n'est que le payload brut de la source (ex. l'entrée KEV telle
    // quelle) et n'a ni `.kind` ni `.riskScore` ni `.references` -> ctxFromZeroDay()
    // plantait dessus (`z.references.find` sur `undefined`).
    let alerted = 0
    if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
      const rows = (await sql`
        SELECT id, cve_id, ghsa_id, kind, title, product, exploit_state, verification,
               is_kev, has_exploit, risk_score, severity, cvss, epss, description,
               permalink, references_json, became_cve, first_seen_at, last_seen_at, resolved_at, data
        FROM zero_days
        WHERE (risk_score >= 70 OR kind = 'prepub_exploited' OR exploit_state IN ('kev-confirmed','source-reported'))
          AND NOT EXISTS (SELECT 1 FROM zero_day_alerts_sent a WHERE a.id = zero_days.id)
        ORDER BY risk_score DESC
        LIMIT ${MAX_ZD_ALERTS_PER_RUN}
      `) as Array<Record<string, unknown>>
      for (const row of rows) {
        const id = String(row.id)
        const claim = (await sql`INSERT INTO zero_day_alerts_sent (id) VALUES (${id}) ON CONFLICT DO NOTHING RETURNING id`) as unknown[]
        if (!claim.length) continue
        const zd: ZeroDay = {
          id,
          source: "kev", // non pertinent pour l'alerte, valeur arbitraire du type union
          kind: row.kind as ZeroDayKind,
          cveId: (row.cve_id as string) ?? null,
          ghsaId: (row.ghsa_id as string) ?? null,
          title: row.title as string,
          product: (row.product as string) ?? null,
          exploitState: row.exploit_state as ZeroDayExploitState,
          verification: row.verification as ZeroDay["verification"],
          isKev: Boolean(row.is_kev),
          hasExploit: Boolean(row.has_exploit),
          riskScore: Number(row.risk_score),
          severity: row.severity as string,
          cvss: (row.cvss as number) ?? null,
          epss: (row.epss as number) ?? null,
          firstSeenAt: (row.first_seen_at as string) ?? null,
          lastSeenAt: (row.last_seen_at as string) ?? null,
          becameCve: Boolean(row.became_cve),
          resolvedAt: (row.resolved_at as string) ?? null,
          description: (row.description as string) ?? null,
          permalink: (row.permalink as string) ?? null,
          references: (row.references_json as string[]) ?? [],
          data: row.data,
        }
        const ok = await sendTelegram(ctxFromZeroDay(zd))
        if (ok) {
          alerted++
          await sleep(400)
        } else {
          await sql`DELETE FROM zero_day_alerts_sent WHERE id = ${id}`
        }
      }
    }

    // 6. sync_state id=2
    const totalRows = (await sql`SELECT COUNT(*)::int AS n FROM zero_days`) as Array<{ n: number }>
    const total = totalRows[0]?.n ?? 0
    await sql`
      INSERT INTO sync_state (id, last_sync, last_run_at, total_cves, last_status)
      VALUES (2, ${now.toISOString()}, ${now.toISOString()}, ${total}, 'ok')
      ON CONFLICT (id) DO UPDATE SET
        last_sync = EXCLUDED.last_sync, last_run_at = EXCLUDED.last_run_at,
        total_cves = EXCLUDED.total_cves, last_status = 'ok'
    `

    return { ok: true, fetched, processed: merged.length, alerted, total, durationMs: Date.now() - t0 }
  } catch (e) {
    const msg = (e as Error).message
    console.error("[zero-day-collector] syncZeroDays ERROR:", msg)
    try {
      await sql`INSERT INTO sync_state (id, last_run_at, last_status) VALUES (2, now(), ${"error: " + msg})
                ON CONFLICT (id) DO UPDATE SET last_run_at = now(), last_status = ${"error: " + msg}`
    } catch { /* ignore */ }
    return { ok: false, fetched: 0, processed: 0, alerted: 0, total: 0, durationMs: Date.now() - t0, error: msg }
  }
}