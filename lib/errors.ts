/**
 * Erreurs API sûres.
 *
 * Règle : les routes ne renvoient JAMAIS `(e as Error).message` brut au client
 * (fuite d'infra/stack). `apiError` log le vrai message côté serveur et renvoie
 * un message générique. Les erreurs métier intentionnelles (400/401/404/503)
 * restent précises là où c'est voulu.
 */
import { NextResponse } from "next/server"

const GENERIC_ERROR = "Une erreur interne est survenue"

export function apiError(
  err: unknown,
  scope: string,
  extra: Record<string, unknown> = {},
): NextResponse {
  const message = err instanceof Error ? err.message : String(err)
  console.error(`[api-error:${scope}]`, message)
  if (err instanceof Error && err.stack) console.error(err.stack)
  return NextResponse.json({ error: GENERIC_ERROR, ...extra }, { status: 500 })
}

export { GENERIC_ERROR }