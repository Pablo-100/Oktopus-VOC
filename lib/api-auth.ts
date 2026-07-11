import { NextResponse } from "next/server"
import { auth } from "@/lib/auth"

/**
 * Garde d'API RÉEL (couche 2). Contrairement au proxy (couche 1, optimiste),
 * ceci valide la session côté serveur contre la base -> impossible à falsifier.
 * Usage dans une route :
 *   const gate = await requireUser(req); if (gate.deny) return gate.deny
 */
export async function requireUser(req: Request) {
  const session = await auth.api.getSession({ headers: req.headers })
  if (!session?.user) {
    return { user: null, deny: NextResponse.json({ error: "Authentification requise" }, { status: 401 }) }
  }
  return { user: session.user, deny: null as null }
}
