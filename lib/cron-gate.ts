import { NextResponse } from "next/server"

/**
 * Limits scheduled jobs to the first minutes of each hour.
 *
 * Neon suspends an idle compute only after ~5 minutes. An external scheduler
 * calling every 5 minutes therefore kept the database awake 24/7, which used up
 * the free plan's monthly compute quota by mid-month; from then on every query,
 * sign-in included, failed until the quota reset. The schedule lives in a
 * third-party service (cron-job.org) this code cannot control, so the limit is
 * enforced here: outside the window a call is answered immediately, before any
 * database access, and the database is left asleep.
 *
 * With a 5-minute scheduler this allows the runs at :00 and :05, i.e. two per
 * hour. `?force=1` bypasses the window for a manual run.
 */
const WINDOW_MINUTES = 10

export function outsideCronWindow(req: Request): NextResponse | null {
  if (new URL(req.url).searchParams.get("force") === "1") return null
  const minute = new Date().getUTCMinutes()
  if (minute < WINDOW_MINUTES) return null
  return NextResponse.json(
    { skipped: true, reason: `Runs only during the first ${WINDOW_MINUTES} minutes of each hour (UTC) to let the database sleep. Use ?force=1 to run now.` },
    { status: 200, headers: { "Cache-Control": "no-store" } },
  )
}
