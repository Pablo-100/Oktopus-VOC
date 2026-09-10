import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { cveExposureCounts } from "@/lib/exposure/orchestrator"
import type { ExposureResult } from "@/lib/types"

/**
 * Per-provider counts of hosts a provider asserts are affected by a CVE.
 *
 * B1 migration: backed by the single `lib/exposure/` abstraction. Each provider
 * is queried through its DOCUMENTED CVE field (`vulnerabilities.cve_id`,
 * `cve=`); providers with no CVE capability report `query_unsupported` rather
 * than silently falling back to a product-name search (A3).
 *
 * Legacy `ExposureResult[]` shape preserved for the existing detail dialogs.
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 20, 60_000)
  if (denied) return denied

  try {
    const cve = new URL(req.url).searchParams.get("cve")?.trim()
    if (!cve) return NextResponse.json({ error: "Missing ?cve=" }, { status: 400 })

    const outcomes = await cveExposureCounts(cve, gate.user.id)
    const results: ExposureResult[] = outcomes.map((o) => ({
      provider: o.provider,
      query: o.query,
      ok: o.status === "success" || o.status === "partial",
      count: o.status === "success" || o.status === "partial" ? o.observationCount : null,
      approximate: true,
      error: o.message,
      fetchedAt: o.fetchedAt,
    }))
    return NextResponse.json({ cve, results }, { headers: { "Cache-Control": "private, max-age=60" } })
  } catch (e) {
    return apiError(e, "exposure-by-cve")
  }
}
