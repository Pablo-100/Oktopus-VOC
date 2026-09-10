import { NextResponse } from "next/server"
import { createHash } from "crypto"
import { authorized } from "@/app/api/cron/sync/route"

export const dynamic = "force-dynamic"

/**
 * What configuration the RUNNING deployment actually has.
 *
 * Environment variables on Vercel are bound to a deployment. Editing them in
 * the dashboard changes nothing until a redeploy, so "I set the variable" and
 * "the running code can see the variable" are different statements — and there
 * is otherwise no way to tell them apart from outside. That gap turns a
 * one-line misconfiguration into an afternoon of guessing.
 *
 * Never returns a secret. For each variable it reports only whether a value is
 * present, its length, and a short SHA-256 fingerprint. The fingerprint is
 * enough to answer "is this the same value I have locally?" by comparing it
 * against one computed from the known value, and useless for anything else: a
 * hash prefix cannot be reversed into the key.
 *
 * Gated behind CRON_SECRET — the same fail-closed, constant-time Bearer check
 * the scheduled jobs use. A deployment with no CRON_SECRET rejects everything.
 */

/** Stable, non-reversible identity for a configured value. */
function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 12)
}

/** Variables worth confirming after a deploy, and why each one matters. */
const WATCHED: Array<{ key: string; why: string }> = [
  { key: "BETTER_AUTH_URL", why: "Origin session cookies are issued for. A localhost value on a deployment means nobody stays signed in." },
  { key: "BETTER_AUTH_SECRET", why: "Signs sessions. Changing it invalidates every existing session." },
  { key: "CREDENTIAL_ENCRYPTION_KEY", why: "Seals user-supplied provider keys. Missing means BYOK refuses to store anything." },
  { key: "DATABASE_URL", why: "Everything." },
  { key: "CRON_SECRET", why: "Authenticates the scheduled jobs." },
  { key: "APP_URL", why: "Links in emails and Telegram messages." },
]

export async function GET(req: Request) {
  if (!authorized(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  return NextResponse.json(
    {
      // Which deployment answered — so the reply cannot be mistaken for an
      // older one still serving traffic.
      deployment: {
        commit: process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ?? null,
        env: process.env.VERCEL_ENV ?? "local",
        productionUrl: process.env.VERCEL_PROJECT_PRODUCTION_URL ?? null,
      },
      variables: WATCHED.map(({ key, why }) => {
        const raw = process.env[key]
        const value = raw?.trim() ?? ""
        return {
          key,
          present: value.length > 0,
          length: value.length,
          fingerprint: value ? fingerprint(value) : null,
          // URLs are not secrets and the whole point of checking them is to see
          // the actual value, so these are returned in full.
          value: value && (key === "BETTER_AUTH_URL" || key === "APP_URL") ? value : undefined,
          why,
        }
      }),
      checkedAt: new Date().toISOString(),
    },
    { headers: { "Cache-Control": "no-store" } },
  )
}
