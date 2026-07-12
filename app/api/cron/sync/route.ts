import { NextResponse } from "next/server"
import { syncCves } from "@/lib/collector"

// Autorise jusqu'à 60 s d'exécution (Vercel). Le seed initial se fait en local.
export const maxDuration = 60
export const dynamic = "force-dynamic"

/**
 * Endpoint de synchronisation, appelé par le planificateur (Vercel Cron / GitHub Actions).
 * Sécurisé par CRON_SECRET : header `Authorization: Bearer <secret>` OU `?token=<secret>`.
 */
function authorized(req: Request): boolean {
  const secret = process.env.CRON_SECRET
  if (!secret) return true // non défini (dev) -> autorisé. EN PROD : définir CRON_SECRET.
  if (req.headers.get("authorization") === `Bearer ${secret}`) return true
  return new URL(req.url).searchParams.get("token") === secret
}

export async function GET(req: Request) {
  if (!authorized(req)) return NextResponse.json({ error: "Non autorisé" }, { status: 401 })
  const result = await syncCves()
  return NextResponse.json(result, { status: result.ok ? 200 : 500 })
}
