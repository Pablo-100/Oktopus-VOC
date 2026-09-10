/**
 * Rate limiting en mémoire (glissière de fenêtre, par clé IP+utilisateur).
 *
 * Pour les endpoints coûteux ou à quota : /api/cve-lookup, /api/cve-search,
 * /api/cves/import, /api/ai (coût OpenRouter), /api/telegram POST (spam SOC).
 * Serverless : l'état vit par instance — sécurité « best-effort » suffisante ici
 * (les vrais garde-fous sont l'auth et NVD quota). Retour 429 + Retry-After.
 */
import { NextResponse } from "next/server"

type Bucket = { count: number; windowStart: number }
const buckets = new Map<string, Bucket>()

/** Charge un bucket (ou crée la fenêtre) — éviction lazy. */
export function hit(key: string, limit: number, windowMs: number): { ok: boolean; retryAfterMs: number } {
  const now = Date.now()
  const b = buckets.get(key)
  if (!b || now - b.windowStart >= windowMs) {
    buckets.set(key, { count: 1, windowStart: now })
    return { ok: true, retryAfterMs: 0 }
  }
  if (b.count >= limit) {
    return { ok: false, retryAfterMs: Math.max(0, b.windowStart + windowMs - now) }
  }
  b.count++
  return { ok: true, retryAfterMs: 0 }
}

/** Nettoyage des buckets expirés (appel ponctuel, évite la fuite mémoire). */
export function pruneBuckets(now = Date.now()): void {
  for (const [k, b] of buckets) {
    if (now - b.windowStart >= 60_000) buckets.delete(k)
  }
}

/**
 * Middleware pratique : `const denied = rateLimited(key, limit, window); if (denied) return denied`
 */
export function rateLimited(key: string, limit: number, windowMs: number): NextResponse | null {
  const r = hit(key, limit, windowMs)
  if (r.ok) return null
  return NextResponse.json(
    { error: "Too many requests — try again shortly." },
    { status: 429, headers: { "Retry-After": String(Math.ceil(r.retryAfterMs / 1000)) } },
  )
}

/** Clé stable depuis une requête : user id si session, sinon IP. */
export function keyFrom(req: Request, userId?: string): string {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown"
  return `${userId ?? "anon"}:${ip}`
}