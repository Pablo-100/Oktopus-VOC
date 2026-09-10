/**
 * Canonical public base URL for this deployment (server-side).
 *
 * Single source of truth, shared by lib/auth.ts (session/OAuth baseURL) and
 * lib/mailer.ts (links + logo in transactional emails). Previously mailer.ts
 * hardcoded a fallback to the ORIGINAL author's deployment, so any install
 * that forgot BETTER_AUTH_URL silently sent emails pointing at someone else's
 * site and hotlinked their logo. Never hardcode a deployment URL here.
 *
 * Resolution order:
 *   1. BETTER_AUTH_URL              — explicit, always wins
 *   2. VERCEL_PROJECT_PRODUCTION_URL — stable production alias (Vercel sets it)
 *   3. VERCEL_URL                    — per-deployment URL (preview builds)
 *   4. http://localhost:3000         — local dev
 */
export function getAppUrl(): string {
  const raw =
    process.env.BETTER_AUTH_URL ||
    (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "") ||
    (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "") ||
    "http://localhost:3000"
  return raw.replace(/\/+$/, "")
}
