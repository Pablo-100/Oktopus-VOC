import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"

// GET -> { triage: { [cveId]: { status, note?, assignee? } } }
export async function GET(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  try {
    await initDb()
    const rows = (await sql`SELECT cve_id, status, note, assignee FROM triage`) as Array<{ cve_id: string; status: string; note: string | null; assignee: string | null }>
    const triage: Record<string, { status: string; note?: string; assignee?: string }> = {}
    for (const r of rows) triage[r.cve_id] = { status: r.status, note: r.note ?? undefined, assignee: r.assignee ?? undefined }
    return NextResponse.json({ triage })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 })
  }
}

// POST { cve_id, status, note?, assignee? } -> upsert (status 'new' = suppression)
export async function POST(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  try {
    await initDb()
    const { cve_id, status, note, assignee } = await req.json()
    if (!cve_id) return NextResponse.json({ error: "cve_id requis" }, { status: 400 })
    if (!status || status === "new") {
      await sql`DELETE FROM triage WHERE cve_id = ${cve_id}`
    } else {
      await sql`
        INSERT INTO triage (cve_id, status, note, assignee, updated_at)
        VALUES (${cve_id}, ${status}, ${note ?? null}, ${assignee ?? null}, now())
        ON CONFLICT (cve_id) DO UPDATE
          SET status = EXCLUDED.status, note = EXCLUDED.note, assignee = EXCLUDED.assignee, updated_at = now()`
    }
    return NextResponse.json({ ok: true })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 })
  }
}
