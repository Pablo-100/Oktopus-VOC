import { NextResponse } from "next/server"
import { toNextJsHandler } from "better-auth/next-js"

/**
 * Better Auth's catch-all route, guarded against the misconfigured case.
 *
 * WHY THE IMPORT IS DEFERRED: `lib/auth.ts` calls `betterAuth({...})` at module
 * scope, and that throws when BETTER_AUTH_SECRET is absent. A module that
 * throws while loading takes the whole route with it, so Next answers EVERY
 * path under /api/auth with a bare 500 — including paths that do not exist.
 * A guard written as a normal top-of-handler check would never run, because the
 * module holding it never finishes loading. Importing inside the handler is
 * what makes the check reachable at all.
 *
 * WHY THE EMPTY BODY MATTERS: that bare 500 carries no body. The browser client
 * calls `/api/auth/get-session` on every page, tries to parse `""` as JSON and
 * throws — and React hydration never completes. Every page then freezes on
 * whatever the server rendered: a login form stuck on "Loading…", a clock stuck
 * at --:--:--, nothing interactive, and no error visible anywhere. One missing
 * variable presents as a dead site.
 *
 * A 503 with a real JSON body is parseable. The client treats it as an ordinary
 * failed request, hydration completes, the page stays interactive, and the
 * cause is legible instead of invisible.
 */

/** Configuration the auth stack cannot start without. */
function missingConfig(): string[] {
  const missing: string[] = []
  if (!process.env.DATABASE_URL?.trim()) missing.push("DATABASE_URL")
  if (!process.env.BETTER_AUTH_SECRET?.trim()) missing.push("BETTER_AUTH_SECRET")
  return missing
}

function configError(missing: string[], detail?: string) {
  return NextResponse.json(
    {
      error: "Authentication is not configured on this deployment.",
      code: "AUTH_NOT_CONFIGURED",
      // Variable NAMES, never values. The operator cannot fix this without
      // knowing which ones are absent, and a name discloses nothing.
      missing,
      detail,
      hint: "Set these environment variables in the hosting dashboard and redeploy — environment changes never apply to an already-running deployment.",
    },
    { status: 503, headers: { "Cache-Control": "no-store" } },
  )
}

type Handler = (req: Request) => Promise<Response>

/**
 * Load Better Auth only once the configuration is known to be present.
 *
 * Cached after the first success so the dynamic import costs nothing on
 * subsequent requests.
 */
let cached: { GET: Handler; POST: Handler } | null = null

async function handlers(): Promise<{ GET: Handler; POST: Handler }> {
  if (cached) return cached
  const { auth } = await import("../../../../lib/auth")
  cached = toNextJsHandler(auth.handler) as { GET: Handler; POST: Handler }
  return cached
}

async function handle(req: Request, method: "GET" | "POST"): Promise<Response> {
  const missing = missingConfig()
  if (missing.length) {
    console.error(`[auth] Refusing the request: missing ${missing.join(", ")}.`)
    return configError(missing)
  }
  try {
    return await (await handlers())[method](req)
  } catch (e) {
    // The configuration looked complete but initialisation still failed — a
    // malformed DATABASE_URL, an unreachable database. Reported as JSON for the
    // same reason: an empty body breaks the client that has to read it.
    const detail = e instanceof Error ? e.message : String(e)
    console.error("[auth] Initialisation failed:", detail)
    return configError([], detail.slice(0, 200))
  }
}

export async function GET(req: Request) {
  return handle(req, "GET")
}

export async function POST(req: Request) {
  return handle(req, "POST")
}
