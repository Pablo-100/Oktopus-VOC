import { NextResponse } from "next/server"
import { mailProviderConfigured } from "@/lib/mailer"

export const dynamic = "force-dynamic"

/**
 * Whether this deployment can actually send email.
 *
 * Registration issues no session until a six-digit code is entered, and that
 * code arrives by email. If no provider is configured the code is generated,
 * logged server-side, and never delivered — so the sign-up screen sits there
 * asking for a number that does not exist, and the operator's first user
 * concludes the product is broken. Nothing in the UI could distinguish that
 * from a slow inbox.
 *
 * Deliberately UNAUTHENTICATED: the page that needs this answer is the one you
 * are stuck on before you have an account. It returns a single boolean and
 * never the provider name, credentials, or any address — knowing that a site
 * can send mail is not a secret, and it is already obvious to anyone who
 * completes a sign-up.
 */
export async function GET() {
  return NextResponse.json(
    { configured: mailProviderConfigured() },
    { headers: { "Cache-Control": "no-store" } },
  )
}
