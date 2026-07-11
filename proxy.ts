import { NextRequest, NextResponse } from "next/server"
import { getSessionCookie } from "better-auth/cookies"

// Pages accessibles UNIQUEMENT connecté. Sans compte -> juste l'accueil "/".
// (Le matcher ci-dessous limite déjà l'exécution à ces routes.)
export function proxy(request: NextRequest) {
  const sessionCookie = getSessionCookie(request)
  if (!sessionCookie) {
    const url = new URL("/login", request.url)
    url.searchParams.set("redirect", request.nextUrl.pathname)
    return NextResponse.redirect(url)
  }
  return NextResponse.next()
}

export const config = {
  // Seules ces routes sont gardées ; "/", "/login", "/signup", les /api/* et assets restent publics.
  matcher: ["/dashboard/:path*", "/statistics/:path*", "/assets/:path*", "/account/:path*"],
}
