import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import {
  issueVerification,
  checkVerification,
  listOwnership,
  removeOwnership,
  normalizeTarget,
  isDomain,
  TXT_PREFIX,
} from "@/lib/exposure/ownership"

export const dynamic = "force-dynamic"

/**
 * Domain ownership verification.
 *
 * Gates continuous monitoring only. One-off search and enrichment stay open,
 * because every provider here is passive — a single lookup reads data the
 * provider already collected and is no different from using their own website.
 * Monitoring is different in kind: it schedules repeated queries against a
 * host, accumulates its history, and pages a human when it changes. A hosted
 * product should not let a stranger point that at infrastructure they have no
 * relationship with.
 */

export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 60, 60_000)
  if (denied) return denied
  try {
    return NextResponse.json(
      { targets: await listOwnership(gate.user.id), txtPrefix: TXT_PREFIX },
      { headers: { "Cache-Control": "no-store" } },
    )
  } catch (e) {
    return apiError(e, "exposure-ownership-get")
  }
}

/**
 * `action: "start"` issues a token to publish; `action: "check"` performs the
 * DNS lookup. They are separate because publishing a record takes minutes and
 * the user will retry the check several times.
 */
export async function POST(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // A check performs a live DNS query, so this is tighter than a plain read.
  const denied = rateLimited(`ownership:${keyFrom(req, gate.user.id)}`, 20, 60_000)
  if (denied) return denied

  try {
    const body = (await req.json().catch(() => null)) as { action?: unknown; target?: unknown } | null
    const action = typeof body?.action === "string" ? body.action : ""
    const raw = typeof body?.target === "string" ? body.target : ""
    const target = normalizeTarget(raw)

    if (!target) return NextResponse.json({ error: "A 'target' domain is required." }, { status: 400 })
    if (target.length > 253) return NextResponse.json({ error: "Domain is too long." }, { status: 400 })
    if (!isDomain(target)) {
      return NextResponse.json(
        {
          error:
            "Only a domain can be verified. An IP address is authorised automatically while a domain you have verified resolves to it.",
        },
        { status: 400 },
      )
    }

    if (action === "start") {
      return NextResponse.json({ target: await issueVerification(gate.user.id, target), txtPrefix: TXT_PREFIX })
    }
    if (action === "check") {
      return NextResponse.json({ target: await checkVerification(gate.user.id, target), txtPrefix: TXT_PREFIX })
    }
    return NextResponse.json({ error: "'action' must be 'start' or 'check'." }, { status: 400 })
  } catch (e) {
    return apiError(e, "exposure-ownership-post")
  }
}

export async function DELETE(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 30, 60_000)
  if (denied) return denied
  try {
    const body = (await req.json().catch(() => null)) as { target?: unknown } | null
    const target = typeof body?.target === "string" ? normalizeTarget(body.target) : ""
    if (!target) return NextResponse.json({ error: "A 'target' is required." }, { status: 400 })
    // Scoped to the caller, so a user can only ever drop their own claim.
    await removeOwnership(gate.user.id, target)
    return NextResponse.json({ ok: true, targets: await listOwnership(gate.user.id) })
  } catch (e) {
    return apiError(e, "exposure-ownership-delete")
  }
}
