import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { enrichSingleAsset } from "@/lib/exposure/orchestrator"

/**
 * On-demand enrichment of ONE asset (item 5).
 *
 * The per-search `ENRICH_LIMIT` deliberately leaves most discovered assets
 * un-enriched so a single search cannot burn provider quota. This lets an
 * analyst deepen one specific asset they care about, without ever triggering a
 * bulk enrichment.
 *
 * POST { "target": "1.2.3.4" | "example.com" }
 *
 * Rate limited tighter than search (each call = up to 3 provider requests) and
 * still subject to the shared per-provider hourly quota inside the orchestrator.
 */
export async function POST(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 15, 60_000)
  if (denied) return denied

  try {
    const body = (await req.json().catch(() => null)) as { target?: unknown } | null
    const target = typeof body?.target === "string" ? body.target.trim() : ""
    if (!target) return NextResponse.json({ error: "Missing 'target' (IP or domain)." }, { status: 400 })
    if (target.length > 253) return NextResponse.json({ error: "Target too long." }, { status: 400 })

    const { asset, providers } = await enrichSingleAsset(target, gate.user.id)
    return NextResponse.json({ target, asset, providers })
  } catch (e) {
    // Validation failures are the caller's problem, not a server fault.
    const msg = e instanceof Error ? e.message : String(e)
    if (/must be an IP|private\/reserved/i.test(msg)) {
      return NextResponse.json({ error: msg }, { status: 400 })
    }
    return apiError(e, "exposure-enrich")
  }
}
