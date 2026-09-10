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

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl
  const hasSession = Boolean(getSessionCookie(request))

  if (hasSession) {
    if (AUTH_PAGES.has(pathname)) {
      return NextResponse.redirect(new URL("/dashboard", request.url))
    }
    return NextResponse.next()
  }

  if (PUBLIC_PAGES.has(pathname)) return NextResponse.next()

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
