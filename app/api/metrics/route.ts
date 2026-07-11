import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"

// GET -> métriques VOC : répartition du triage + compteurs
export async function GET(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  try {
    await initDb()
    const statusRows = (await sql`SELECT status, COUNT(*)::int AS n FROM triage GROUP BY status`) as Array<{ status: string; n: number }>
    const byStatus: Record<string, number> = {}
    for (const r of statusRows) byStatus[r.status] = r.n
    const assets = (await sql`SELECT COUNT(*)::int AS n FROM assets`) as Array<{ n: number }>
    const sent = (await sql`SELECT COUNT(*)::int AS n FROM alerts_sent`) as Array<{ n: number }>
    return NextResponse.json({
      byStatus,
      triaged: Object.values(byStatus).reduce((a, b) => a + b, 0),
      resolved: byStatus["resolved"] ?? 0,
      inProgress: byStatus["in_progress"] ?? 0,
      assets: assets[0]?.n ?? 0,
      alertsSent: sent[0]?.n ?? 0,
    })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 })
  }
}
