import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"

// GET -> { sent: [cve_id...] } : dédup partagé (persisté en base)
export async function GET(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  try {
    await initDb()
    const rows = (await sql`SELECT cve_id FROM alerts_sent`) as Array<{ cve_id: string }>
    return NextResponse.json({ sent: rows.map((r) => r.cve_id) })
  } catch {
    return NextResponse.json({ sent: [] })
  }
}

function esc(s: string) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}
function trunc(s: string, n: number) {
  return s.length > n ? s.slice(0, n) + "…" : s
}

type Ctx = {
  cve_id: string; severity?: string; risk_score?: number | null; risk_level?: string
  cvss?: string | number; epss?: string | null; kev?: boolean; exploit?: boolean
  cwe?: string[]; capec?: string[]; attack?: string[]; description?: string; advisory?: string | null
}

function buildMessage(c: Ctx) {
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

export async function POST(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  const token = process.env.TELEGRAM_BOT_TOKEN
  const chatId = process.env.TELEGRAM_CHAT_ID
  if (!token || !chatId) return NextResponse.json({ error: "Telegram non configuré (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)" }, { status: 503 })

  let ctx: Ctx
  try { ctx = (await req.json()).context } catch { return NextResponse.json({ error: "JSON invalide" }, { status: 400 }) }
  if (!ctx?.cve_id) return NextResponse.json({ error: "context.cve_id requis" }, { status: 400 })

  // Dédup côté serveur (partagé entre tous les analystes) : ne jamais renvoyer 2x la même CVE
  try {
    await initDb()
    const exists = (await sql`SELECT 1 FROM alerts_sent WHERE cve_id = ${ctx.cve_id} LIMIT 1`) as unknown[]
    if (exists.length) return NextResponse.json({ ok: true, skipped: true })
  } catch { /* si la base est indisponible, on continue quand même */ }

  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: buildMessage(ctx), parse_mode: "HTML", disable_web_page_preview: true }),
    })
    const data = await r.json()
    if (!r.ok) return NextResponse.json({ error: data.description || "Échec Telegram" }, { status: 502 })
    try { await sql`INSERT INTO alerts_sent (cve_id) VALUES (${ctx.cve_id}) ON CONFLICT DO NOTHING` } catch { /* ignore */ }
    return NextResponse.json({ ok: true })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 })
  }
}
