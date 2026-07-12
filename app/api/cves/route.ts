import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import type { Vuln } from "@/lib/types"

/**
 * Lecture des CVE déjà traitées & enrichies par le collecteur (depuis PostgreSQL).
 * AUCUN appel NVD ici -> réponse quasi instantanée. Tri par Risk Score décroissant.
 * ?search= filtre optionnel (id ou description).
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  try {
    await initDb()
    const search = new URL(req.url).searchParams.get("search")?.trim()
    const rows = (search
      ? await sql`SELECT data FROM cves
          WHERE cve_id ILIKE ${"%" + search + "%"} OR (data->>'description') ILIKE ${"%" + search + "%"}
          ORDER BY risk_score DESC, published DESC NULLS LAST LIMIT 3000`
      : await sql`SELECT data FROM cves
          ORDER BY risk_score DESC, published DESC NULLS LAST LIMIT 3000`) as Array<{ data: Vuln }>

    const state = (await sql`SELECT last_sync, total_cves, last_run_at, last_status FROM sync_state WHERE id = 1`) as Array<{
      last_sync: string | null; total_cves: number; last_run_at: string | null; last_status: string | null
    }>

    return NextResponse.json(
      {
        cves: rows.map((r) => r.data),
        lastSync: state[0]?.last_sync ?? null,
        lastRunAt: state[0]?.last_run_at ?? null,
        status: state[0]?.last_status ?? null,
        total: state[0]?.total_cves ?? rows.length,
      },
      { headers: { "Cache-Control": "private, max-age=30" } },
    )
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message, cves: [] }, { status: 500 })
  }
}
