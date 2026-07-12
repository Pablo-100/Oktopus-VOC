/**
 * Construction & envoi des alertes Telegram (serveur uniquement).
 * Utilisé par le collecteur de fond ET la route /api/telegram.
 */
import type { Vuln } from "@/lib/types"
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
  const sev: Record<string, string> = { critical: "⚫ CRITIQUE", high: "🔴 ÉLEVÉE", medium: "🟡 MOYENNE", low: "🟢 FAIBLE" }
  const L: string[] = []
  L.push("🚨 <b>OCTUPUS — Alerte CVE</b>", "")
  L.push(`<b>${esc(c.cve_id)}</b>  ${sev[c.severity || ""] || ""}`)
  if (c.risk_score != null) L.push(`<b>Risk Score:</b> ${c.risk_score}/100 — ${esc(c.risk_level || "")}`)
  L.push(`<b>CVSS:</b> ${esc(String(c.cvss ?? "-"))}   |   <b>EPSS:</b> ${esc(String(c.epss ?? "-"))}`)
  if (c.kev) L.push("⚠️ <b>CISA KEV</b> — activement exploité")
  if (c.exploit) L.push("💥 <b>Exploit public</b> connu")
  if (c.cwe?.length) L.push(`<b>CWE:</b> ${esc(c.cwe.join(", "))}`)
  if (c.capec?.length) L.push(`<b>CAPEC:</b> ${esc(c.capec.join(", "))}`)
  if (c.attack?.length) L.push(`<b>ATT&amp;CK:</b> ${esc(c.attack.join(", "))}`)
  if (c.description) L.push("", `<b>Description:</b> ${esc(trunc(c.description, 500))}`)
  L.push("", `🔗 <a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}">NVD</a>` + (c.advisory ? ` · <a href="${esc(c.advisory)}">Advisory</a>` : ""))
  return L.join("\n")
}

/** Envoie un message à Telegram. Renvoie true si OK. */
export async function sendTelegram(ctx: AlertCtx): Promise<boolean> {
  const token = process.env.TELEGRAM_BOT_TOKEN
  const chatId = process.env.TELEGRAM_CHAT_ID
  if (!token || !chatId) return false
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: buildMessage(ctx), parse_mode: "HTML", disable_web_page_preview: true }),
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
    epss: v.epss != null ? v.epss.toFixed(4) : null,
    kev: v.isKev,
    exploit: v.hasExploit,
    cwe: v.cwes,
    capec: [...capec],
    attack: [...attack],
    description: v.description,
    advisory,
  }
}
