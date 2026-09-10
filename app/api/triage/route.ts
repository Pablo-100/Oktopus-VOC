import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

// ── Tenancy TRIAGE : scopé par utilisateur ────────────────────────────────
// Anciennement un workspace SOC partagé. La condition prévue par cette note
// ("si un multi-client arrivait un jour") est désormais remplie : le produit
// est multi-utilisateurs, chacun avec sa propre surface d'exposition. La table
// porte maintenant `user_id` et la PK est (user_id, cve_id) — le triage d'un
// analyste n'écrase plus celui d'un autre.

// GET -> { triage: { [cveId]: { status, note?, assignee? } } }
export async function GET(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  // reads and writes triage state.
  const denied = rateLimited(keyFrom(req, gate.user.id), 30, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const rows = (await sql`SELECT cve_id, status, note, assignee FROM triage WHERE user_id = ${gate.user.id}`) as Array<{ cve_id: string; status: string; note: string | null; assignee: string | null }>
    const triage: Record<string, { status: string; note?: string; assignee?: string }> = {}
    for (const r of rows) triage[r.cve_id] = { status: r.status, note: r.note ?? undefined, assignee: r.assignee ?? undefined }
    return NextResponse.json({ triage })
  } catch (e) {
    return apiError(e, "triage")
  }
}

// POST { cve_id, status, note?, assignee? } -> upsert (status 'new' = suppression)
export async function POST(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  // reads and writes triage state.
  const denied = rateLimited(keyFrom(req, gate.user.id), 30, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const { cve_id, status, note, assignee } = await req.json()
    if (!cve_id) return NextResponse.json({ error: "cve_id is required" }, { status: 400 })
    if (!status || status === "new") {
      await sql`DELETE FROM triage WHERE cve_id = ${cve_id} AND user_id = ${gate.user.id}`
    } else {
      await sql`
        INSERT INTO triage (user_id, cve_id, status, note, assignee, updated_at)
        VALUES (${gate.user.id}, ${cve_id}, ${status}, ${note ?? null}, ${assignee ?? null}, now())
        ON CONFLICT (user_id, cve_id) DO UPDATE
          SET status = EXCLUDED.status, note = EXCLUDED.note, assignee = EXCLUDED.assignee, updated_at = now()`
    }
    return NextResponse.json({ ok: true })
  } catch (e) {
    return apiError(e, "triage")
  }
}
