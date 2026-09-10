import { NextRequest, NextResponse } from "next/server"
import { getSessionCookie } from "better-auth/cookies"

/**
 * Route protection.
 *
 * INVERTED ON PURPOSE. This used to name the pages that WERE gated, which meant
 * every page added afterwards was public until somebody remembered to add it —
 * and `/zero-days` shipped readable to anonymous visitors for exactly that
 * reason. Naming the public pages instead makes the safe case the default: a
 * new page is protected the moment it exists, and making something public is a
 * deliberate edit to this file rather than an omission.
 *
 * WHAT THIS IS AND IS NOT:
 * `getSessionCookie` only checks that a session cookie is PRESENT. It runs no
 * database query, because this executes on every request. A forged or expired
 * cookie passes it — so this is a redirect for humans, never the security
 * boundary. That boundary is unchanged: every API route validates the session
 * server-side with `requireUser`. Both layers are needed; neither substitutes
 * for the other.
 */

/**
 * The only pages reachable while signed out.
 *
 * The marketing page and the sign-in flow obviously qualify. The legal pages do
 * too: terms and a privacy policy readable only after you have accepted them
 * would be meaningless, and several jurisdictions require them to be publicly
 * accessible.
 */
const PUBLIC_PAGES = new Set([
  "/",
  "/login",
  "/signup",
  "/forgot-password",
  "/verify-email",
  "/privacy",
  "/terms",
])

/** Sign-in screens a signed-in user should not be left sitting on. */
const AUTH_PAGES = new Set(["/login", "/signup", "/forgot-password"])

/**
 * Content-Security-Policy, carrying a fresh nonce on every request.
 *
 * THE BUG THIS FIXES: the policy previously lived in next.config.ts as a static
 * `script-src 'self'`, applied only when NODE_ENV === "production". Next.js
 * ships the RSC payload and its bootstrap in ELEVEN inline <script> tags, and
 * `'self'` does not permit inline script — so in every production build the
 * browser blocked all of them, React never received its payload, and hydration
 * never began. Nothing errored server-side: pages rendered, the HTML was
 * byte-identical to a working build, and curl saw a perfect 200. Only a real
 * browser enforces CSP, which is why every check passed while the site sat
 * frozen — counters at zero, clock at --:--:--, forms stuck on "Loading…".
 *
 * It worked in development purely because the policy was never applied there.
 *
 * `'unsafe-inline'` would also have unblocked it, and would have thrown away
 * the protection the header exists to provide. A nonce keeps the policy strict:
 * only scripts carrying this request's random value execute, so an injected
 * <script> still cannot run. `'strict-dynamic'` lets the nonced bootstrap load
 * the rest of the chunks, which is how Next's loader works.
 *
 * The cost is honest: a nonce is per-request, so responses carrying one cannot
 * be cached as static HTML. For an application that is behind authentication on
 * every page but five, that is a small price for a policy that actually holds.
 */
function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https://*.nvd.nist.gov https://avatars.githubusercontent.com https://*.googleusercontent.com https://*.gstatic.com",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join("; ")
}

/** 128 bits of randomness, base64. Must never repeat between requests. */
function makeNonce(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return btoa(String.fromCharCode(...bytes))
}

/**
 * Attach the policy to a response, and to the REQUEST headers.
 *
 * Next.js discovers the nonce by reading the Content-Security-Policy header of
 * the incoming request and then stamps it onto every script tag it emits.
 * Setting it only on the response would leave the scripts unnonced — and still
 * blocked.
 */
function withCsp(request: NextRequest, response: NextResponse, nonce: string, csp: string): NextResponse {
  response.headers.set("Content-Security-Policy", csp)
  response.headers.set("x-nonce", nonce)
  return response
}

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl
  const hasSession = Boolean(getSessionCookie(request))

  const nonce = makeNonce()
  const csp = buildCsp(nonce)

  // The nonce has to reach Next through the REQUEST headers; that is where it
  // looks when deciding what to stamp on the scripts it renders.
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set("x-nonce", nonce)
  requestHeaders.set("Content-Security-Policy", csp)
  const pass = () => NextResponse.next({ request: { headers: requestHeaders } })

  if (hasSession) {
    if (AUTH_PAGES.has(pathname)) {
      return NextResponse.redirect(new URL("/dashboard", request.url))
    }
    return withCsp(request, pass(), nonce, csp)
  }

  if (PUBLIC_PAGES.has(pathname)) return withCsp(request, pass(), nonce, csp)

  // The destination is preserved so signing in lands where the user was going.
  // A link shared with a colleague should still open the right page after they
  // authenticate, instead of dropping them on the dashboard.
  const url = new URL("/login", request.url)
  url.searchParams.set("redirect", pathname + search)
  return NextResponse.redirect(url)
}

export const config = {
  /**
   * Everything except what must answer before a session exists.
   *
   * `/api` is excluded wholesale: those routes authenticate themselves and must
   * return 401 to their caller. Redirecting a `fetch()` to an HTML login page
   * would make the client parse markup as JSON and report a parse error instead
   * of "you are signed out". Static assets are excluded because gating them
   * breaks the login page's own styling.
   */
  matcher: [
    "/((?!api|_next/static|_next/image|favicon.ico|icon.png|.*\\.(?:png|jpg|jpeg|svg|webp|ico|txt|xml|webmanifest)$).*)",
  ],
}
