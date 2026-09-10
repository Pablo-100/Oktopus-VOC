import { NextResponse } from "next/server"
import { syncZeroDays } from "@/lib/zero-day-collector"
import { authorized } from "@/app/api/cron/sync/route"

/**
 * ZERO-DAY SYNC — its own scheduled invocation.
 *
 * Split out of `/api/cron/sync` because the two syncs shared one 60s serverless
 * budget: `syncCves()` runs first over ~87k CVEs and consumed the whole
 * allowance, so `syncZeroDays()` was never reached. The function was killed
 * rather than throwing, so nothing was logged and `zero_day_source_health` kept
 * reporting the last SUCCESSFUL run — the data silently froze on 2026-08-22
 * while every source still showed `fails=0`.
 *
 * Measured in isolation the zero-day sync takes ~8s, so starvation was the only
 * problem. Giving it its own invocation gives it its own budget.
 *
 * Same fail-closed Bearer auth as the CVE sync — the check is imported rather
 * than reimplemented so there is one definition of "is this the scheduler".
 */
export const maxDuration = 60
export const dynamic = "force-dynamic"

export async function GET(req: Request) {
  if (!authorized(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  const result = await syncZeroDays()
  return NextResponse.json(result, { status: result.ok ? 200 : 500 })
}

export async function POST(req: Request) {
  return GET(req)
}
