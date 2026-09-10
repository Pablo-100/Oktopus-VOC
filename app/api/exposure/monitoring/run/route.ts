import { NextResponse } from "next/server"
import { apiError } from "@/lib/errors"
import { runMonitoringCycle } from "@/lib/exposure/monitoring"
import { authorized } from "@/app/api/cron/sync/route"

// Vercel serverless ceiling. The batch limit in lib/exposure/monitoring.ts is
// sized so a run finishes well inside this.
export const maxDuration = 60
export const dynamic = "force-dynamic"

/**
 * Periodic Exposure Monitoring worker.
 *
 * Invoked by the platform scheduler (GitHub Actions cron — the mechanism this
 * project already uses for /api/cron/sync). Short-lived by design: claim a
 * bounded batch of due assets, refresh them, persist, exit. There is no
 * long-running worker, and none is assumed.
 *
 * AUTH: reuses `authorized()` from the existing cron route — Bearer
 * `CRON_SECRET`, constant-time comparison, FAIL-CLOSED (no secret configured
 * means every request is refused, never open). This endpoint is NOT public and
 * deliberately requires no user session, because no user is present.
 *
 * The platform may call this far more often than any asset needs; the worker
 * itself decides what is actually due.
 */
export async function POST(req: Request) {
  if (!authorized(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  try {
    const result = await runMonitoringCycle()
    return NextResponse.json(result)
  } catch (e) {
    return apiError(e, "exposure-monitoring-run")
  }
}

/** GET behaves identically — some schedulers can only issue GET. */
export async function GET(req: Request) {
  return POST(req)
}
