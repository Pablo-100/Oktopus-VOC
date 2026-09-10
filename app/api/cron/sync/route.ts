import { NextResponse } from "next/server"
import { syncCves } from "@/lib/collector"

// Autorise jusqu'à 60 s d'exécution (Vercel). Le seed initial se fait en local.
export const maxDuration = 60
export const dynamic = "force-dynamic"

/**
 * Endpoint de synchronisation, appelé par le planificateur (Vercel Cron / GitHub Actions).
 * Sécurisé par CRON_SECRET : header `Authorization: Bearer <secret>` UNIQUEMENT.
 * FAIL-CLOSED : si CRON_SECRET n'est pas défini -> 503, jamais d'accès ouvert.
 * Le `?token=` a été retiré (fuitait le secret dans les logs/proxies).
 * N'exécute QUE syncCves(). Le sync 0-day a sa propre route (/api/cron/zero-days)
 * et donc son propre budget de 60 s : quand les deux partageaient cette
 * invocation, syncCves() consommait toute l'allocation et syncZeroDays()
 * n'était jamais atteint — la fonction était tuée sans lever d'erreur, donc
 * rien n'était journalisé et les données 0-day ont gelé silencieusement.
 */
export function authorized(req: Request): boolean {
  const secret = process.env.CRON_SECRET
  if (!secret) return false // fail-closed : pas de secret configuré -> refus
  const provided = req.headers.get("authorization")
  if (!provided || !provided.startsWith("Bearer ")) return false
  // Comparaison à temps constant (évite les fuites par timing)
  const given = provided.slice("Bearer ".length)
  if (given.length !== secret.length) return false
  let diff = 0
  for (let i = 0; i < given.length; i++) diff |= given.charCodeAt(i) ^ secret.charCodeAt(i)
  return diff === 0
}

export async function GET(req: Request) {
  if (!authorized(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  const cveResult = await syncCves()
  return NextResponse.json({ cve: cveResult }, { status: cveResult.ok ? 200 : 500 })
}

/**
 * Scheduler services differ on which verb they use to "trigger" a job, and the
 * choice is a dropdown the operator can change without touching this code. A
 * verb mismatch answers 405 — which no dashboard reads as an outage, so the CVE
 * feed would silently freeze while every health indicator stayed green. Both
 * verbs do the same thing so the schedule cannot be misconfigured into silence.
 */
export async function POST(req: Request) {
  return GET(req)
}
