import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { sendTelegram, type AlertCtx } from "@/lib/telegram"

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

// POST { context } -> envoi manuel d'une alerte (dédup serveur partagé)
export async function POST(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) {
    return NextResponse.json({ error: "Telegram non configuré (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)" }, { status: 503 })
  }

  let ctx: AlertCtx
  try { ctx = (await req.json()).context } catch { return NextResponse.json({ error: "JSON invalide" }, { status: 400 }) }
  if (!ctx?.cve_id) return NextResponse.json({ error: "context.cve_id requis" }, { status: 400 })

  // Dédup côté serveur (partagé)
  try {
    await initDb()
    const exists = (await sql`SELECT 1 FROM alerts_sent WHERE cve_id = ${ctx.cve_id} LIMIT 1`) as unknown[]
    if (exists.length) return NextResponse.json({ ok: true, skipped: true })
  } catch { /* base indisponible -> on continue */ }

  const ok = await sendTelegram(ctx)
  if (!ok) return NextResponse.json({ error: "Échec de l'envoi Telegram" }, { status: 502 })
  try { await sql`INSERT INTO alerts_sent (cve_id) VALUES (${ctx.cve_id}) ON CONFLICT DO NOTHING` } catch { /* ignore */ }
  return NextResponse.json({ ok: true })
}
