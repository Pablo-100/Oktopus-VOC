import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { alertTimeline } from "@/lib/exposure/alert-workflow"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { requeueNotification, deliverAlertNow } from "@/lib/notify/outbox"

/**
 * One alert with its full investigation context.
 *
 * A PROJECTION of existing records — the alert row, its audit trail, the
 * vulnerability relationship it came from, and the CVE facts already held.
 * It computes nothing and stores nothing.
 */
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  try {
    await initDb()
    const { id: raw } = await ctx.params
    const id = Number(raw)
    if (!Number.isFinite(id) || id <= 0) {
      return NextResponse.json({ error: "Invalid alert id." }, { status: 400 })
    }

    const rows = (await sql`SELECT * FROM exposure_alerts WHERE id = ${id} AND user_id = ${gate.user.id}`) as Array<Record<string, unknown>>
    const alert = rows[0]
    if (!alert) return NextResponse.json({ error: "Alert not found." }, { status: 404 })

    // Authoritative CVE facts from the EXISTING store — not a second copy.
    const cve = (await sql`
      SELECT cve_id, cvss, epss, is_kev, has_exploit, severity, risk_score
      FROM cves WHERE cve_id = ${String(alert.cve_id)}
    `) as Array<Record<string, unknown>>

    // The vulnerability relationship that produced this alert (STEP 3).
    const vuln = (await sql`
      SELECT asset_key, port, cve_id, evidence_tier, confirmed, match_type,
             source_providers, product, version, matched_via,
             observed_at, fetched_at, status, first_seen_at, last_seen_at
      FROM exposure_vulnerability
      WHERE user_id = ${gate.user.id} AND asset_key = ${String(alert.asset_key)}
        AND port = ${Number(alert.port)} AND cve_id = ${String(alert.cve_id)}
    `) as Array<Record<string, unknown>>

    const ticket = (await sql`
      SELECT id, provider, title, state, created_at, updated_at, closed_at
      FROM exposure_tickets WHERE alert_id = ${id} AND user_id = ${gate.user.id}
    `) as Array<Record<string, unknown>>

    return NextResponse.json({
      // `SELECT *` hands back a BIGINT id as a STRING (the Neon driver avoids
      // the precision loss a JS number would suffer past 2^53). The detail
      // dialog's workflow buttons post this id straight back, so it is
      // normalised here as well as in the list route — otherwise acting on an
      // alert worked from the table and failed from its own detail view.
      alert: { ...alert, id: Number(alert.id) },
      timeline: await alertTimeline(id, gate.user.id),
      cve: cve[0] ?? null,
      vulnerability: vuln[0] ?? null,
      ticket: ticket[0] ?? null,
    }, { headers: { "Cache-Control": "private, max-age=10" } })
  } catch (e) {
    return apiError(e, "exposure-alert-detail")
  }
}

/**
 * Analyst actions on ONE alert's NOTIFICATION.
 *
 * Only `retry_notification` is accepted. Alert lifecycle transitions live on
 * the collection route; this endpoint cannot change alert state and cannot
 * create an alert.
 *
 * POST { "action": "retry_notification" }
 */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // Tight limit: a retry triggers an outbound third-party call.
  const denied = rateLimited(`notify-retry:${keyFrom(req, gate.user.id)}`, 10, 60_000)
  if (denied) return denied

  try {
    await initDb()
    const { id: raw } = await ctx.params
    const id = Number(raw)
    if (!Number.isFinite(id) || id <= 0) {
      return NextResponse.json({ error: "Invalid alert id." }, { status: 400 })
    }
    const body = (await req.json().catch(() => null)) as { action?: unknown } | null
    if (body?.action !== "retry_notification") {
      return NextResponse.json({ error: "Unsupported action." }, { status: 400 })
    }

    // The actor is the authenticated session, never a client-supplied name.
    const requeued = await requeueNotification(id, gate.user.id, gate.user.id)
    if (!requeued.ok) {
      const status = requeued.code === "not_found" ? 404 : 409
      return NextResponse.json({ error: requeued.error, code: requeued.code }, { status })
    }

    // Attempt straight away so the analyst sees a result rather than waiting
    // for the scheduler. A failure simply leaves it queued.
    const result = await deliverAlertNow(id)
    return NextResponse.json({ id, requeued: true, outcome: result.outcome, error: result.error ?? null })
  } catch (e) {
    return apiError(e, "exposure-alert-retry")
  }
}
