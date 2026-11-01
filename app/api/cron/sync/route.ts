import { NextResponse, after } from "next/server"
import { syncCves } from "@/lib/collector"

// Autorise jusqu'à 60 s d'exécution (Vercel). Le seed initial se fait en local.
// 300 s = plafond Hobby avec Fluid compute. Laisse le rattrapage enchaîner
// assez de fenêtres pour combler plusieurs jours de retard en un seul appel.
export const maxDuration = 300
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
  // Réponse IMMÉDIATE, travail en arrière-plan via after() (waitUntil sur
  // Vercel, jusqu'au maxDuration de 300 s). cron-job.org coupe la requête à
  // 30 s, compte un échec, et DÉSACTIVE le job après plusieurs échecs — c'est
  // ce qui a figé la synchro quand un rattrapage dépassait 30 s. Le résultat
  // reste consultable dans sync_state et les logs.
  // `?wait=1` garde l'ancien comportement synchrone (debug / workflow manuel).
  if (new URL(req.url).searchParams.get("wait") === "1") {
    const cveResult = await syncCves()
    return NextResponse.json({ cve: cveResult }, { status: cveResult.ok ? 200 : 500 })
  }
  after(async () => {
    await syncCves()
  })
  return NextResponse.json({ cve: { started: true } }, { status: 200 })
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
