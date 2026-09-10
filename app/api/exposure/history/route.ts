import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

/**
 * Exposure history — real first-seen/last-seen records accumulated by the
 * orchestrator on each search. No synthetic events: a row exists only because
 * that asset was genuinely observed.
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // per-asset history scan.
  const denied = rateLimited(keyFrom(req, gate.user.id), 30, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const rows = (await sql`
      SELECT asset_key, query, ip, domain, service_count, vuln_count, risk_score, sources, first_seen, last_seen
      FROM exposure_history
      WHERE user_id = ${gate.user.id}
      ORDER BY last_seen DESC
      LIMIT 100
    `) as Array<Record<string, unknown>>
    return NextResponse.json({ history: rows }, { headers: { "Cache-Control": "private, max-age=30" } })
  } catch (e) {
    return apiError(e, "exposure-history")
  }
}
