import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { exposureSearch } from "@/lib/exposure/orchestrator"

/**
 * Exposure Intelligence search — the full pipeline (discovery -> enrichment ->
 * correlation -> CVE/RBVM enrichment -> exposure risk).
 *
 * Server-side only: every provider API key stays in this process and never
 * reaches the browser. Rate-limited more tightly than the read-only routes
 * because a single call can fan out to ~20 upstream provider requests.
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 10, 60_000)
  if (denied) return denied

  try {
    const sp = new URL(req.url).searchParams
    const q = sp.get("q")?.trim()
    if (!q) return NextResponse.json({ error: "Missing ?q=" }, { status: 400 })
    if (q.length > 200) return NextResponse.json({ error: "Query too long (max 200 characters)." }, { status: 400 })

    // C5: server-side pagination. Only the requested page is serialized to the
    // client; `totalAssets` reports the full correlated count so the UI can page
    // without ever holding the whole set in the browser.
    const rawLimit = sp.get("limit")
    const rawOffset = sp.get("offset")
    const limit = rawLimit != null ? Number(rawLimit) : undefined
    const offset = rawOffset != null ? Number(rawOffset) : undefined
    if ((limit != null && !Number.isFinite(limit)) || (offset != null && !Number.isFinite(offset))) {
      return NextResponse.json({ error: "limit and offset must be numbers." }, { status: 400 })
    }

    const result = await exposureSearch(q, gate.user.id, { limit, offset })
    return NextResponse.json(result, { headers: { "Cache-Control": "private, max-age=60" } })
  } catch (e) {
    return apiError(e, "exposure-search")
  }
}
