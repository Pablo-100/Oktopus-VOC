/**
 * Sources 0-day additionnelles (serveur uniquement) — décision : étendre le pipeline existant.
 *
 *  5. Google Project Zero — In-the-wild 0-day tracker (Google Sheets, feuil "All")
 *  6. Actualité cyber — RSS BleepingComputer + The Hacker News filtrés par mots-clés
 *
 * Contraintes :
 *  - échec indépendant par feed/source (try/catch à l'intérieur -> aucun rejet global)
 *  - dédup par clé normalisée (mêmes règles que zero-day-collector, cf. zero-day-util)
 *  - rss-parser : garde `serverExternalPackages` dans next.config.ts (APIs Node)
 */
import Parser from "rss-parser"
import { computeZeroDayRisk, zeroDaySeverity } from "@/lib/risk-engine"
import { normalizeKey, extractCveId } from "@/lib/zero-day-util"
import type { ZeroDay } from "@/lib/types"

const P0_SHEET_ID = "1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY"
const P0_GID_ALL = "1190662839"
const P0_VIZ_URL = `https://docs.google.com/spreadsheets/d/${P0_SHEET_ID}/gviz/tq?gid=${P0_GID_ALL}&tqx=out:json&headers=1`

const RSS_FEEDS = [
  "https://www.bleepingcomputer.com/feed/",
  "https://feeds.feedburner.com/TheHackersNews",
]
const RSS_KEYWORDS = /zero[- ]?day|0[- ]?day|exploited in the wild|under active attack|unpatched/i
const CVE_RE = /CVE-\d{4}-\d{4,7}/i

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

/** `Date(2026,6,14)` -> ISO (mois 0-indexé côté Google). Retourne null si invalide. */
function gvizDate(v: string | null | undefined): string | null {
  if (!v) return null
  const m = /^Date\((\d{4}),(\d{1,2}),(\d{1,2})\)$/.exec(v.trim())
  if (!m) return null
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]), Number(m[3])))
  return isNaN(d.getTime()) ? null : d.toISOString()
}

/** Déprotège le wrapper `/*O_ __o*\/\ngoogle.visualization.Query.setResponse({...})`. */
function parseGvizPayload(raw: string): unknown {
  const start = raw.indexOf("(")
  const close = raw.lastIndexOf(")")
  if (start < 0 || close <= start) throw new Error("gviz: malformed wrapper")
  return JSON.parse(raw.slice(start + 1, close))
}

type GvizRow = Array<{ v?: unknown } | null>
type GvizTable = {
  table?: {
    cols?: Array<{ label?: string }>
    rows?: Array<{ c: GvizRow }>
  }
}

/**
 * Google P0 — entrées 0-day exploitées in-the-wild (feuil "All").
 * Ne garde que les entrées de la fenêtre de synchro (patch/discovery récents ou sans date).
 */
export async function fetchGoogleP0(since: Date): Promise<ZeroDay[]> {
  const res = await fetch(P0_VIZ_URL, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(20_000) })
  if (!res.ok) throw new Error(`gviz HTTP ${res.status}`)
  const raw = await res.text()
  const payload = parseGvizPayload(raw) as GvizTable
  const cols = payload.table?.cols ?? []
  const rows = payload.table?.rows ?? []
  if (!cols.length || !rows.length) return []

  const idx = (label: string) => cols.findIndex((c) => c.label === label)
  const iCve = idx("CVE")
  const iVendor = idx("Vendor")
  const iProduct = idx("Product")
  const iType = idx("Type")
  const iDesc = idx("Description")
  const iDiscovered = idx("Date Discovered")
  const iPatched = idx("Date Patched")
  const iAdvisory = idx("Advisory")
  const iAnalysis = idx("Analysis URL")

  const cell = (row: GvizRow, i: number) => (i >= 0 ? row[i]?.v : undefined)

  const out: ZeroDay[] = []
  for (const row of rows) {
    const cve = (cell(row.c, iCve) as string | null) ?? ""
    const cveId = CVE_RE.test(cve) ? cve.toUpperCase() : null

    const vendor = String(cell(row.c, iVendor) ?? "").trim()
    const product = String(cell(row.c, iProduct) ?? "").trim()
    const desc = String(cell(row.c, iDesc) ?? "").trim()
    const patched = gvizDate(typeof cell(row.c, iPatched) === "string" ? (cell(row.c, iPatched) as string) : null)
    const discovered = gvizDate(typeof cell(row.c, iDiscovered) === "string" ? (cell(row.c, iDiscovered) as string) : null)

    // Fenêtre : entrées patchees/découvertes récemment OU encore actives (pas de dates)
    const isRecent = (patched && Date.parse(patched) >= since.getTime()) || (discovered && Date.parse(discovered) >= since.getTime()) || (!patched && !discovered)
    if (!isRecent) continue

    const analysis = String(cell(row.c, iAnalysis) ?? "").trim() || null
    const advisory = String(cell(row.c, iAdvisory) ?? "").trim() || null
    const references = [analysis, advisory].filter((x): x is string => Boolean(x))

    const title = desc || `${vendor}${product ? " " + product : ""}` || cveId || "Google Project Zero 0-day"
    const riskScore = computeZeroDayRisk("prepub_exploited", "source-reported", false, true, null, null)
    const keyId = cveId ?? normalizeKey(undefined, undefined, "p0", `${vendor}|${product}|${patched ?? ""}`)

    out.push({
      id: keyId,
      source: "p0",
      kind: "prepub_exploited",
      cveId,
      ghsaId: null,
      title,
      product: product || null,
      exploitState: "source-reported",
      verification: "verified",
      isKev: false,
      hasExploit: true,
      riskScore,
      severity: zeroDaySeverity(riskScore),
      cvss: null,
      epss: null,
      firstSeenAt: discovered ?? patched ?? new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      becameCve: false,
      resolvedAt: patched ?? null,
      description: desc || null,
      permalink: analysis ?? advisory ?? null,
      references,
      data: { vendor, product, type: cell(row.c, iType) ?? null, analysis, advisory, patched, discovered },
    })
  }
  return out
}

export function matchesZeroDayKeywords(text: string): boolean {
  return RSS_KEYWORDS.test(text ?? "")
}

type RssItem = { title?: string; link?: string; guid?: string; contentSnippet?: string; isoDate?: string; pubDate?: string }

/** Item RSS -> ZeroDay (source news, kind advisory ou prepub_exploited si exploitation signalée). */
export function rssItemToZeroDay(feedKey: string, item: RssItem): ZeroDay | null {
  const title = (item.title ?? "").trim()
  if (!matchesZeroDayKeywords(title)) return null

  const cve = extractCveId(`${title} ${item.contentSnippet ?? ""}`)
  const link = item.link ?? item.guid ?? ""
  const exploitFlag = /exploited in the wild|under active attack/i.test(title)
  const kind = exploitFlag ? "prepub_exploited" : "advisory"
  const exploitState = exploitFlag ? "source-reported" : "none"
  const riskScore = computeZeroDayRisk(kind, exploitState, false, exploitFlag, null, null)
  const published = item.isoDate ?? item.pubDate ?? new Date().toISOString()

  return {
    id: normalizeKey(cve ?? undefined, undefined, "news", `${feedKey}:${link || title}`),
    source: "news",
    kind,
    cveId: cve,
    ghsaId: null,
    title: title.slice(0, 300),
    product: null,
    exploitState,
    verification: "partial",
    isKev: false,
    hasExploit: exploitFlag,
    riskScore,
    severity: zeroDaySeverity(riskScore),
    cvss: null,
    epss: null,
    firstSeenAt: published,
    lastSeenAt: new Date().toISOString(),
    becameCve: false,
    resolvedAt: null,
    description: item.contentSnippet ? item.contentSnippet.slice(0, 600) : null,
    permalink: link,
    references: link ? [link] : [],
    data: { title, link, published },
  }
}

/** RSS filtré par mots-clés — un feed KO ne fait pas tomber les autres. */
export async function fetchRssNews(): Promise<ZeroDay[]> {
  const parser = new Parser({
    timeout: 15_000,
    headers: { "User-Agent": UA, Accept: "application/rss+xml, application/xml;q=0.9, */*;q=0.8" },
  })
  const out: ZeroDay[] = []
  for (const feed of RSS_FEEDS) {
    try {
      const parsed = await parser.parseURL(feed)
      const feedKey = new URL(feed).host.replace(/^www\./, "")
      for (const item of parsed.items ?? []) {
        const rec = rssItemToZeroDay(feedKey, item as RssItem)
        if (rec) out.push(rec)
      }
    } catch (e) {
      console.error(`[zero-news] RSS ${feed} ERROR:`, (e as Error).message)
    }
  }
  return out
}