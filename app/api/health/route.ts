import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

export const dynamic = "force-dynamic"

/**
 * Operational health of the ingestion pipelines.
 *
 * The failure mode this exists to prevent has already happened once here: the
 * zero-day sync was silently starved of its time budget for twelve days while
 * every indicator still read healthy, because nothing reported the AGE of the
 * data — only whether the last call threw. So freshness is computed and
 * returned explicitly, and a source that has stopped producing is called stale
 * rather than "ok".
 *
 * Read-only, per-user rate limited, and it exposes no credentials: only
 * timestamps, counts and the health verdicts derived from them.
 */

/** Beyond this, a feed is not merely quiet — it has stopped. */
const STALE_AFTER_HOURS = { cve: 6, zeroDay: 24 } as const

interface SyncRow {
  id: number
  last_sync: string | null
  last_run_at: string | null
  total_cves: number | null
  last_status: string | null
}

function hoursSince(iso: string | null): number | null {
  if (!iso) return null
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return null
  return (Date.now() - t) / 3_600_000
}

/**
 * A verdict, not a raw timestamp.
 *
 * "Last run 14 hours ago" requires the reader to know what normal looks like
 * for that feed; "stale" does not.
 */
function verdict(hours: number | null, staleAfter: number): "ok" | "stale" | "never" {
  if (hours === null) return "never"
  return hours > staleAfter ? "stale" : "ok"
}

export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 30, 60_000)
  if (denied) return denied

  try {
    await initDb()

    const syncRows = (await sql`SELECT id, last_sync, last_run_at, total_cves, last_status FROM sync_state WHERE id IN (1, 2)`) as SyncRow[]
    const cve = syncRows.find((r) => Number(r.id) === 1) ?? null
    const zero = syncRows.find((r) => Number(r.id) === 2) ?? null

    const cveHours = hoursSince(cve?.last_run_at ?? cve?.last_sync ?? null)
    const zeroHours = hoursSince(zero?.last_run_at ?? zero?.last_sync ?? null)

    // Per-source scrapers break silently: two of the zero-day sources are HTML
    // and RSS scrapes that keep returning 200 with nothing in them.
    const sources = (await sql`
      SELECT source, consecutive_failures, consecutive_empty, last_ok_at, last_error
      FROM zero_day_source_health ORDER BY source
    `.catch(() => [])) as Array<{
      source: string
      consecutive_failures: number
      consecutive_empty: number
      last_ok_at: string | null
      last_error: string | null
    }>

    // Newest record actually held, per source. A feed that runs successfully
    // and stores nothing new is the exact shape of the earlier outage, and only
    // this number reveals it.
    const freshness = (await sql`
      SELECT source, max(first_seen_at)::text AS newest, count(*)::int AS n
      FROM zero_days GROUP BY source ORDER BY source
    `.catch(() => [])) as Array<{ source: string; newest: string | null; n: number }>

    const monitoring = (await sql`
      SELECT status, count(*)::int AS n
      FROM exposure_monitoring_runs
      WHERE user_id = ${gate.user.id} AND started_at > now() - interval '24 hours'
      GROUP BY status
    `.catch(() => [])) as Array<{ status: string; n: number }>

    const cveCount = (await sql`SELECT count(*)::int AS n FROM cves`.catch(() => [{ n: 0 }])) as Array<{ n: number }>

    return NextResponse.json(
      {
        pipelines: [
          {
            name: "CVE synchronisation",
            status: verdict(cveHours, STALE_AFTER_HOURS.cve),
            hoursSinceRun: cveHours === null ? null : Math.round(cveHours * 10) / 10,
            expectedWithinHours: STALE_AFTER_HOURS.cve,
            lastStatus: cve?.last_status ?? null,
            records: cveCount[0]?.n ?? 0,
          },
          {
            name: "Zero-day synchronisation",
            status: verdict(zeroHours, STALE_AFTER_HOURS.zeroDay),
            hoursSinceRun: zeroHours === null ? null : Math.round(zeroHours * 10) / 10,
            expectedWithinHours: STALE_AFTER_HOURS.zeroDay,
            lastStatus: zero?.last_status ?? null,
            records: zero?.total_cves ?? 0,
          },
        ],
        sources: sources.map((s) => {
          const f = freshness.find((x) => x.source === s.source)
          const ageHours = hoursSince(f?.newest ?? null)
          return {
            source: s.source,
            records: f?.n ?? 0,
            newest: f?.newest ?? null,
            newestAgeHours: ageHours === null ? null : Math.round(ageHours),
            consecutiveFailures: s.consecutive_failures,
            // Distinguished from failing on purpose: a scraper returning 200
            // with an empty body is not an error, and is the more dangerous case
            // because nothing logs it.
            consecutiveEmpty: s.consecutive_empty,
            lastOkAt: s.last_ok_at,
            lastError: s.last_error,
            status:
              s.consecutive_failures > 0 ? "failing"
              : s.consecutive_empty >= 5 ? "producing nothing"
              : "ok",
          }
        }),
        monitoring: Object.fromEntries(monitoring.map((m) => [m.status, m.n])),
        checkedAt: new Date().toISOString(),
      },
      { headers: { "Cache-Control": "private, max-age=30" } },
    )
  } catch (e) {
    return apiError(e, "health")
  }
}
