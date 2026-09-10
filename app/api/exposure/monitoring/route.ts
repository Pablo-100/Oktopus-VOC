import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { isValidIp, isValidDomain, isPrivateIp } from "@/lib/exposure/providers/_base"
import { isTargetAuthorized } from "@/lib/exposure/ownership"
import {
  monitoringOverview, setMonitoring, getMonitoring,
  MONITORING_INTERVALS, DEFAULT_INTERVAL_SECONDS, maxAssetsPerRun,
  type MonitoringIntervalName,
} from "@/lib/exposure/monitoring"

/**
 * Monitoring configuration + operational overview.
 *
 * Session-guarded (unlike the scheduler worker, which is machine-invoked and
 * uses the cron Bearer secret).
 *
 * GET  -> overview, or ?assetKey= for one asset's monitoring state
 * POST -> enable / pause / set interval for one asset (explicit opt-in only)
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  try {
    const assetKey = new URL(req.url).searchParams.get("assetKey")?.trim()
    if (assetKey) {
      return NextResponse.json({ monitoring: await getMonitoring(assetKey, gate.user.id) })
    }
    const overview = await monitoringOverview(gate.user.id)
    return NextResponse.json({
      ...overview,
      intervals: MONITORING_INTERVALS,
      maxAssetsPerRun: maxAssetsPerRun(),
    }, { headers: { "Cache-Control": "private, max-age=15" } })
  } catch (e) {
    return apiError(e, "exposure-monitoring")
  }
}

export async function POST(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 30, 60_000)
  if (denied) return denied

  try {
    const body = (await req.json().catch(() => null)) as {
      assetKey?: unknown; target?: unknown; enabled?: unknown; interval?: unknown; intervalSeconds?: unknown
    } | null

    const assetKey = typeof body?.assetKey === "string" ? body.assetKey.trim() : ""
    const target = typeof body?.target === "string" ? body.target.trim() : ""
    if (!assetKey || !target) {
      return NextResponse.json({ error: "Both 'assetKey' and 'target' are required." }, { status: 400 })
    }
    // The scheduler will feed `target` straight into the provider pipeline, so
    // it is validated here as strictly as any other provider input.
    if (!isValidIp(target) && !isValidDomain(target)) {
      return NextResponse.json({ error: "Target must be an IP address or a domain." }, { status: 400 })
    }
    if (isValidIp(target) && isPrivateIp(target)) {
      return NextResponse.json({ error: "Refusing to monitor a private/reserved address." }, { status: 400 })
    }
    if (typeof body?.enabled !== "boolean") {
      return NextResponse.json({ error: "'enabled' must be a boolean." }, { status: 400 })
    }

    // Interval by friendly name, or explicit seconds. Anything else falls back
    // to the conservative default rather than erroring.
    let intervalSeconds = DEFAULT_INTERVAL_SECONDS
    if (typeof body.interval === "string" && body.interval in MONITORING_INTERVALS) {
      intervalSeconds = MONITORING_INTERVALS[body.interval as MonitoringIntervalName]
    } else if (typeof body.intervalSeconds === "number" && Number.isFinite(body.intervalSeconds)) {
      intervalSeconds = body.intervalSeconds
    }

    // Entitlement is checked only when ENABLING. Disabling must always be
    // permitted: a user who loses a domain, or whose DNS record is removed,
    // would otherwise be unable to switch off monitoring they no longer want —
    // an authorisation check that traps people in the state it disapproves of.
    if (body.enabled) {
      const auth = await isTargetAuthorized(gate.user.id, target)
      if (!auth.allowed) {
        return NextResponse.json(
          {
            error: auth.reason,
            code: "ownership_required",
            // Everything the UI needs to explain the next step, so the user is
            // not left with a bare refusal.
            help: {
              why: "Continuous monitoring repeatedly queries this host, stores its history and raises alerts. One-off search and enrichment stay open to any target, because those only read data providers already collected.",
              how: "Verify a domain you control under Account, then monitor that domain or any address it resolves to.",
            },
          },
          { status: 403 },
        )
      }
    }

    const monitoring = await setMonitoring(assetKey, target, gate.user.id, { enabled: body.enabled, intervalSeconds })
    return NextResponse.json({ monitoring })
  } catch (e) {
    return apiError(e, "exposure-monitoring")
  }
}
