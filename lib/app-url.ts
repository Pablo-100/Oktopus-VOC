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
 *   1. BETTER_AUTH_URL              — explicit, unless it points at localhost
 *                                     while running on Vercel (see below)
 *   2. VERCEL_PROJECT_PRODUCTION_URL — stable production alias (Vercel sets it)
 *   3. VERCEL_URL                    — per-deployment URL (preview builds)
 *   4. http://localhost:3000         — local dev
 */

/** A base URL that only makes sense on a developer's own machine. */
function isLocal(url: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?$/i.test(url.trim())
}

export function getAppUrl(): string {
  const explicit = process.env.BETTER_AUTH_URL?.trim()
  const vercel =
    (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "") ||
    (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "")

  // A localhost BETTER_AUTH_URL on a deployed instance is always a mistake, and
  // a uniquely nasty one: session cookies get issued for `localhost`, the
  // browser silently discards them, and sign-in "succeeds" while no session
  // ever sticks. Nothing errors — the user simply cannot stay logged in, and
  // the platform looks broken with no message anywhere explaining why.
  //
  // Copying .env.local into a hosting dashboard is the normal way to arrive
  // here, so the deployment URL wins over a local-looking override rather than
  // trusting a value that cannot possibly be right.
  if (explicit && vercel && isLocal(explicit)) {
    console.warn(
      `[app-url] Ignoring BETTER_AUTH_URL="${explicit}": it points at localhost but this is a deployed ` +
        `instance. Using ${vercel} instead — session cookies issued for localhost would be discarded by the ` +
        "browser and nobody could stay signed in. Set BETTER_AUTH_URL to the public URL to silence this.",
    )
    return vercel.replace(/\/+$/, "")
  }

  const raw = explicit || vercel || "http://localhost:3000"
  return raw.replace(/\/+$/, "")
}
