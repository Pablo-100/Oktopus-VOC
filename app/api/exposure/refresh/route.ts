import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { refreshAsset } from "@/lib/exposure/orchestrator"
import { isAssetLocked } from "@/lib/exposure/monitoring"
import { isValidIp } from "@/lib/exposure/providers/_base"

/**
 * REFRESH NOW — force a fresh provider fetch for ONE asset and diff it against
 * the last-known snapshot, recording normalized change events.
 *
 * Distinct from `/api/exposure/enrich`:
 *   enrich  = obtain enrichment for an asset we have not deepened yet
 *   refresh = deliberately re-query to detect CHANGE, and persist the diff
 *
 * IMPORTANT SEMANTICS: this bypasses OCTUPUS's own cache, but it cannot make a
 * provider re-scan the host — none of the configured providers offer on-demand
 * scanning. It retrieves each provider's LATEST indexed observation, whose age
 * is reported honestly in the response freshness.
 *
 * POST { "target": "1.2.3.4" | "example.com" }
 */
export async function POST(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // Tighter than enrich: refresh is explicitly a re-query, so it must not
  // become a cheap way to hammer providers.
  const denied = rateLimited(keyFrom(req, gate.user.id), 10, 60_000)
  if (denied) return denied

  try {
    const body = (await req.json().catch(() => null)) as { target?: unknown } | null
    const target = typeof body?.target === "string" ? body.target.trim() : ""
    if (!target) return NextResponse.json({ error: "Missing 'target' (IP or domain)." }, { status: 400 })
    if (target.length > 253) return NextResponse.json({ error: "Target too long." }, { status: 400 })

    // Item 20: never run a manual refresh concurrently with a scheduler run on
    // the same asset — two simultaneous refreshes would double-spend provider
    // quota and race on the snapshot/event write.
    const assetKey = isValidIp(target) ? `ip:${target.toLowerCase()}` : `domain:${target.toLowerCase()}`
    if (await isAssetLocked(assetKey, gate.user.id)) {
      return NextResponse.json(
        { error: "Asset refresh already in progress.", assetKey, inProgress: true },
        { status: 409 },
      )
    }

    const { asset, providers, changes } = await refreshAsset(target, gate.user.id)
    return NextResponse.json({ target, asset, providers, changes })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    if (/must be an IP|private\/reserved/i.test(msg)) return NextResponse.json({ error: msg }, { status: 400 })
    return apiError(e, "exposure-refresh")
  }
}
