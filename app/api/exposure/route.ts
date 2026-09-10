import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { productExposureCounts } from "@/lib/exposure/orchestrator"
import type { ExposureResult } from "@/lib/types"

/**
 * Per-provider internet-exposure counts for a product name.
 *
 * B1 migration: now backed by the single `lib/exposure/` provider abstraction
 * (previously the parallel `lib/exposure-providers.ts`, which disagreed with it
 * about provider capabilities). Discovery only — deliberately does not run the
 * full correlation pipeline, because this backs a small panel inside the
 * CVE/0-day detail dialogs.
 *
 * The legacy `ExposureResult[]` response shape is preserved so the existing
 * CVE and 0-day detail views keep working unchanged.
 * ?product= required.
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 20, 60_000)
  if (denied) return denied

  try {
    const product = new URL(req.url).searchParams.get("product")?.trim()
    if (!product) return NextResponse.json({ error: "Missing ?product=" }, { status: 400 })
    if (product.length > 200) return NextResponse.json({ error: "Query too long." }, { status: 400 })

    const outcomes = await productExposureCounts(product, gate.user.id)
    const results: ExposureResult[] = outcomes.map((o) => ({
      provider: o.provider,
      query: o.query,
      ok: o.status === "success" || o.status === "partial",
      count: o.status === "success" || o.status === "partial" ? o.observationCount : null,
      // Observation counts are what the provider returned for this query, not an
      // authoritative internet-wide total — always flagged as approximate.
      approximate: true,
      error: o.message,
      fetchedAt: o.fetchedAt,
    }))
    return NextResponse.json({ product, results }, { headers: { "Cache-Control": "private, max-age=60" } })
  } catch (e) {
    return apiError(e, "exposure")
  }
}
