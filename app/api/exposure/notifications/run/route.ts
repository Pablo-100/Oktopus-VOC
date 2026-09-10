import { NextResponse } from "next/server"
import { apiError } from "@/lib/errors"
import { authorized } from "@/app/api/cron/sync/route"
import { runNotificationCycle } from "@/lib/notify/outbox"

/**
 * NOTIFICATION OUTBOX WORKER.
 *
 * Machine-invoked and fail-closed: it reuses the same constant-time Bearer
 * check as the CVE sync and exposure monitoring workers, so an unauthenticated
 * caller can never trigger a notification burst.
 *
 * Drains a BOUNDED batch of pending/retrying alerts and exits — the serverless
 * shape the rest of OCTUPUS already uses. Monitoring does not call this; the
 * scheduler does, after the monitoring cycle.
 */
export const maxDuration = 60
export const dynamic = "force-dynamic"

export async function POST(req: Request) {
  if (!authorized(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  try {
    return NextResponse.json(await runNotificationCycle())
  } catch (e) {
    return apiError(e, "exposure-notifications-run")
  }
}

export async function GET(req: Request) {
  return POST(req)
}
