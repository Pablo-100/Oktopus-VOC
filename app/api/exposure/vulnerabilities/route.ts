import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

/**
 * Exposure → CVE relationships: the traceable record behind every finding.
 *
 * Answers "why does OCTUPUS believe this asset is affected by this CVE?" with
 * the evidence tier, the providers that supplied it, the product/version that
 * matched, and both timestamps (provider observation vs OCTUPUS retrieval).
 *
 * CVE facts are joined from the EXISTING `cves` table — this endpoint does not
 * hold its own copy of CVSS/EPSS/KEV.
 *
 * GET ?assetKey=  -> relationships for one asset (default: active only)
 * GET             -> highest-risk active relationships across all assets
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // correlated read across vulnerabilities and CVEs.
  const denied = rateLimited(keyFrom(req, gate.user.id), 30, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const url = new URL(req.url)
    const assetKey = url.searchParams.get("assetKey")?.trim()
    const includeResolved = url.searchParams.get("includeResolved") === "1"
    const limitRaw = Number(url.searchParams.get("limit"))
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(Math.floor(limitRaw), 200) : 100

    const rows = assetKey
      ? await sql`
          SELECT v.*, c.cvss, c.epss, c.is_kev, c.has_exploit, c.severity AS cve_severity
          FROM exposure_vulnerability v
          LEFT JOIN cves c ON c.cve_id = v.cve_id
          WHERE v.user_id = ${gate.user.id} AND v.asset_key = ${assetKey}
            AND (${includeResolved} OR v.status = 'active')
          ORDER BY
            CASE v.evidence_tier
              WHEN 'confirmed' THEN 0 WHEN 'strong' THEN 1 WHEN 'product' THEN 2
              WHEN 'weak' THEN 3 ELSE 4 END,
            c.cvss DESC NULLS LAST
          LIMIT ${limit}`
      : await sql`
          SELECT v.*, c.cvss, c.epss, c.is_kev, c.has_exploit, c.severity AS cve_severity
          FROM exposure_vulnerability v
          LEFT JOIN cves c ON c.cve_id = v.cve_id
          WHERE v.user_id = ${gate.user.id} AND v.status = 'active'
          ORDER BY v.risk_score DESC NULLS LAST, c.cvss DESC NULLS LAST
          LIMIT ${limit}`

    return NextResponse.json(
      { vulnerabilities: rows },
      { headers: { "Cache-Control": "private, max-age=30" } },
    )
  } catch (e) {
    return apiError(e, "exposure-vulnerabilities")
  }
}
