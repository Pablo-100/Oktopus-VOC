import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { loadGraphFromStore } from "@/lib/exposure/graph-data"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

/**
 * EXPOSURE GRAPH — read-only investigation data.
 *
 * Authentication plus one call into `loadGraphFromStore`, which assembles the
 * graph from records OCTUPUS already holds. This endpoint contacts no provider,
 * writes nothing, and returns only normalized graph data — never raw provider
 * payloads, and never anything derived from a credential.
 *
 * GET                -> the highest-risk slice of the persisted surface
 * GET ?assetKey=...  -> one asset's neighbourhood
 * GET ?limit=N       -> smaller graph (capped server-side)
 */
export const dynamic = "force-dynamic"

export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // the heaviest read in the app: builds the full node/edge projection.
  const denied = rateLimited(keyFrom(req, gate.user.id), 20, 60_000)
  if (denied) return denied

  try {
    const url = new URL(req.url)
    const limitRaw = Number(url.searchParams.get("limit"))
    const result = await loadGraphFromStore(gate.user.id, {
      assetKey: url.searchParams.get("assetKey"),
      limit: Number.isFinite(limitRaw) ? limitRaw : undefined,
    })
    return NextResponse.json(result, { headers: { "Cache-Control": "private, max-age=30" } })
  } catch (e) {
    return apiError(e, "exposure-graph")
  }
}
