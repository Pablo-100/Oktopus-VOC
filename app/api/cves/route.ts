import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import type { Vuln } from "@/lib/types"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

// Live feed window: the `cves` table also holds the full historical backfill
// (80k+ rows) for the Archive Search dialog, so ordering this endpoint by
// risk_score DESC alone silently returns the all-time top-N-by-risk — which is
// almost entirely "critical" once N is smaller than the total critical count.
// That starved the dashboard of every Medium/Low and most High CVEs regardless
// of recency (bug: dashboard appeared to show "critical only"). Scope to a
// recent window instead, but always keep KEV-flagged CVEs regardless of age
// (an old-but-actively-exploited flaw like Log4Shell must not vanish from the
// KEV preset just because it's outside the recency window).
const RECENT_WINDOW_DAYS = 7

/**
 * Lecture des CVE déjà traitées & enrichies par le collecteur (depuis PostgreSQL).
 * AUCUN appel NVD ici -> réponse quasi instantanée. Tri par Risk Score décroissant.
 * ?search= filtre optionnel (id ou description).
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // paged read over the shared CVE table.
  const denied = rateLimited(keyFrom(req, gate.user.id), 60, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const search = new URL(req.url).searchParams.get("search")?.trim()
    const rows = (search
      ? await sql`SELECT data FROM cves
          WHERE cve_id ILIKE ${"%" + search + "%"} OR (data->>'description') ILIKE ${"%" + search + "%"}
          ORDER BY risk_score DESC, published DESC NULLS LAST LIMIT 3000`
      : await sql`SELECT data FROM cves
          WHERE published >= now() - (${RECENT_WINDOW_DAYS}::text || ' days')::interval OR is_kev = true
          ORDER BY risk_score DESC, published DESC NULLS LAST LIMIT 5000`) as Array<{ data: Vuln }>

    const state = (await sql`SELECT last_sync, total_cves, last_run_at, last_status FROM sync_state WHERE id = 1`) as Array<{
      last_sync: string | null; total_cves: number; last_run_at: string | null; last_status: string | null
    }>

    return NextResponse.json(
      {
        cves: rows.map((r) => r.data),
        lastSync: state[0]?.last_sync ?? null,
        lastRunAt: state[0]?.last_run_at ?? null,
        status: state[0]?.last_status ?? null,
        total: state[0]?.total_cves ?? rows.length,
      },
      { headers: { "Cache-Control": "private, max-age=30" } },
    )
  } catch (e) {
    return apiError(e, "cves", { cves: [] })
  }
}
