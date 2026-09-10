/**
 * Construction & envoi des alertes Telegram (serveur uniquement).
 * Utilisé par le collecteur de fond ET la route /api/telegram.
 */
import type { Vuln, ZeroDay } from "@/lib/types"
import { THREAT_MAP } from "@/lib/threat-map"

export type AlertCtx = {
  cve_id: string
  severity?: string
  risk_score?: number | null
  risk_level?: string
  cvss?: string | number
  epss?: string | null
  kev?: boolean
  exploit?: boolean
  cwe?: string[]
  capec?: string[]
  attack?: string[]
  description?: string
  advisory?: string | null
}

function esc(s: string) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}
function trunc(s: string, n: number) {
  return s.length > n ? s.slice(0, n) + "…" : s
}

export function buildMessage(c: AlertCtx) {
  const sevLabel: Record<string, string> = { critical: "CRITIQUE", high: "ÉLEVÉE", medium: "MOYENNE", low: "FAIBLE" }
  const sevDot: Record<string, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" }
  const sev = c.severity || "low"
  const rule = "━━━━━━━━━━━━━━━━━━━━"
  const L: string[] = []

  L.push("<b>OCTUPUS-VOC · Alerte vulnérabilité</b>")
  L.push("")
  L.push(`${sevDot[sev] || "⚪"}  <b>${esc(c.cve_id)}</b>`)
  L.push(`Sévérité : <b>${sevLabel[sev] || "-"}</b>${c.risk_score != null ? `   ·   Risk : <b>${c.risk_score}/100</b> (${esc(c.risk_level || "")})` : ""}`)

  L.push(rule)
  L.push("<b>Signaux</b>")
  L.push(`•  CVSS : <code>${esc(String(c.cvss ?? "-"))}</code>`)
  L.push(`•  EPSS : <code>${esc(String(c.epss ?? "-"))}</code>`)
  L.push(`•  CISA KEV : <b>${c.kev ? "Oui — activement exploité" : "Non"}</b>`)
  L.push(`•  Exploit public : <b>${c.exploit ? "Oui" : "Non"}</b>`)

  if (c.cwe?.length || c.capec?.length || c.attack?.length) {
    L.push(rule)
    L.push("<b>Faiblesses &amp; techniques</b>")
    if (c.cwe?.length) L.push(`•  CWE : ${esc(c.cwe.join(", "))}`)
    if (c.capec?.length) L.push(`•  CAPEC : ${esc(c.capec.join(", "))}`)
    if (c.attack?.length) L.push(`•  ATT&amp;CK : ${esc(c.attack.join(", "))}`)
  }

  if (c.description) {
    L.push(rule)
    L.push("<b>Description</b>")
    L.push(esc(trunc(c.description, 400)))
  }

  L.push(rule)
  L.push(`🔗 <a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}">Fiche NVD</a>` + (c.advisory ? `   ·   <a href="${esc(c.advisory)}">Advisory éditeur</a>` : ""))
  return L.join("\n")
}

/** Sends a message to Telegram. Returns true on success. */
export async function sendTelegram(ctx: AlertCtx): Promise<boolean> {
  return sendTelegramRaw(buildMessage(ctx))
}

/**
 * Sends a raw pre-formatted HTML message to Telegram (no CVE context needed) —
 * used for operational notices such as 0-day source health alerts.
 */
export async function sendTelegramRaw(html: string): Promise<boolean> {
  const token = process.env.TELEGRAM_BOT_TOKEN
  const chatId = process.env.TELEGRAM_CHAT_ID
  if (!token || !chatId) return false
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: html, parse_mode: "HTML", disable_web_page_preview: true }),
    })
    return r.ok
  } catch {
    return false
  }
}

/** Construit un contexte d'alerte enrichi (CAPEC/ATT&CK) depuis une CVE traitée. */
export function ctxFromVuln(v: Vuln): AlertCtx {
  const capec = new Set<string>()
  const attack = new Set<string>()
  for (const c of v.cwes) {
    const m = THREAT_MAP[c.replace(/\D/g, "")]
    if (m) {
      m.capec.forEach((x) => capec.add(x.id))
      m.attack.forEach((x) => attack.add(x.id))
    }
  }
  const advisory = v.references.find((r) => (r.tags ?? []).some((t) => /advisory|vendor/i.test(t)))?.url ?? null
  const cvss = v.cvssV3 !== "-" ? v.cvssV3 : v.cvssV2
  return {
    cve_id: v.cveId,
    severity: v.severity,
    risk_score: v.riskScore,
    risk_level: v.riskLevel,
    cvss,
    epss: v.epss != null ? (v.epss * 100).toFixed(1) + "%" : null,
    kev: v.isKev,
    exploit: v.hasExploit,
    cwe: v.cwes,
    capec: [...capec],
    attack: [...attack],
    description: v.description,
    advisory,
  }
}

/** Contexte d'alerte pour un 0-day (plus léger, sans CAPEC/ATT&CK enrichis). */
export function ctxFromZeroDay(z: ZeroDay): AlertCtx {
  const advisory = z.references.find((r) => /advisory|vendor/i.test(r))
  const cvssVal = z.cvss
  return {
    cve_id: z.cveId ?? z.id,
    severity: z.severity,
    risk_score: z.riskScore,
    risk_level: z.severity,
    cvss: cvssVal ?? undefined,
    epss: z.epss != null ? (z.epss * 100).toFixed(1) + "%" : null,
    kev: z.isKev,
    exploit: z.hasExploit,
    cwe: z.references.map((r) => r.replace(/.*\/(CWE-\d+).*/, "$1")).filter((r) => /^CWE-\d+$/.test(r)),
    capec: [],
    attack: [],
    description: z.description ?? undefined,
    advisory,
  }
}

/** Construit le message Telegram pour un 0-day (plus court, pas de section CAPEC/ATT&CK). */
export function buildZeroDayMessage(z: ZeroDay): string {
  const sevLabel: Record<string, string> = { critical: "CRITIQUE", high: "ÉLEVÉE", medium: "MOYENNE", low: "FAIBLE" }
  const sevDot: Record<string, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" }
  const sev = z.severity || "low"
  const rule = "━━━━━━━━━━━━━━━━━━━━"
  const L: string[] = []
  const cvssVal = z.cvss

  L.push("<b>OCTUPUS-VOC · Alerte 0-day / pré-CVE</b>")
  L.push("")
  L.push(`${sevDot[sev] || "⚪"}  <b>${esc(z.id)}</b> ${z.kind === "prepub_exploited" ? "🔥" : z.kind === "reserved" ? "🕐" : "🧩"}`)
  L.push(`Kind : <b>${z.kind}</b> · Source : <b>${z.source}</b>`)
  L.push(`Sévérité : <b>${sevLabel[sev] || "-"}</b>   ·   Risk : <b>${z.riskScore}/100</b>`)

  L.push(rule)
  L.push("<b>Signaux</b>")
  L.push(`•  CVSS : <code>${esc(String(cvssVal ?? "-"))}</code>`)
  L.push(`•  EPSS : <code>${esc(String(z.epss ?? "-"))}</code>`)
  L.push(`•  CISA KEV : <b>${z.isKev ? "Oui — activement exploité" : "Non"}</b>`)
  L.push(`•  Exploit public : <b>${z.exploitState ?? "—"}</b>`)

  if (z.description) {
    L.push(rule)
    L.push("<b>Description</b>")
    L.push(esc(trunc(z.description, 300)))
  }

  L.push(rule)
  const nvdLink = z.cveId ? `   ·   <a href="https://nvd.nist.gov/vuln/detail/${esc(z.cveId)}">Fiche NVD</a>` : ""
  const ghsaLink = z.ghsaId ? `   ·   <a href="https://github.com/advisories/${esc(z.ghsaId)}">GitHub Advisory</a>` : ""
  const defendLink = z.permalink ? `   ·   <a href="${esc(z.permalink)}">defend.network</a>` : ""
  L.push(`${nvdLink}${ghsaLink}${defendLink}`)
  return L.join("\n")
}
