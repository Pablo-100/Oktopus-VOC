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

  // Réservation ATOMIQUE (anti-doublon, même en concurrence) : seul le 1er insert envoie.
  let claimed = true
  try {
    await initDb()
    const claim = (await sql`INSERT INTO alerts_sent (cve_id) VALUES (${ctx.cve_id}) ON CONFLICT DO NOTHING RETURNING cve_id`) as unknown[]
    if (!claim.length) return NextResponse.json({ ok: true, skipped: true }) // déjà envoyé
  } catch { claimed = false /* base indispo -> on tente l'envoi sans dédup */ }

  const ok = await sendTelegram(ctx)
  if (!ok) {
    if (claimed) { try { await sql`DELETE FROM alerts_sent WHERE cve_id = ${ctx.cve_id}` } catch { /* ignore */ } }
    return NextResponse.json({ error: "Échec de l'envoi Telegram" }, { status: 502 })
  }
  return NextResponse.json({ ok: true })
}
