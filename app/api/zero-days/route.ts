import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { buildZeroDayWhere } from "@/lib/zero-day-filter"
import { explainZeroDay } from "@/lib/zero-day-explain"
import { apiError } from "@/lib/errors"
import type { ZeroDay } from "@/lib/types"

/**
 * Reads 0-days already processed & enriched by the collector (from PostgreSQL).
 * NO external call here -> near-instant response. Sorted by risk_score descending.
 * ?kind= reserved|prepub_exploited|advisory|resolved (became_cve=true)
 * ?search= optional filter (title, cve_id, ghsa_id, product)
 * ?active= true -> became_cve=false
 *
 * PUBLIC endpoint (deliberately not gated by requireUser): the 0-day tracker is the
 * public flagship feature. Abuse is bounded by IP-based rate limiting instead of auth.
 */
export async function GET(req: Request) {
  const denied = rateLimited(keyFrom(req), 60, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const sp = new URL(req.url).searchParams
    const kind = sp.get("kind")?.trim()
    const search = sp.get("search")?.trim()
    const active = sp.get("active")

    // SAFE filter: `kind` goes through a strict whitelist, `search` only as bound
    // parameters (see lib/zero-day-filter.ts — NO SQL concatenation).
    const whereFragment = buildZeroDayWhere({ kind, search, active })
    const rows = (
      whereFragment
        ? await sql`SELECT * FROM zero_days ${whereFragment} ORDER BY risk_score DESC, first_seen_at DESC LIMIT 500`
        : await sql`SELECT * FROM zero_days ORDER BY risk_score DESC, first_seen_at DESC LIMIT 500`
    ) as Array<Record<string, unknown>>

    const state = (await sql`SELECT last_sync, total_cves, last_run_at, last_status FROM sync_state WHERE id = 2`) as Array<{
      last_sync: string | null; total_cves: number; last_run_at: string | null; last_status: string | null
    }>

    // Reconstruct the real ZeroDay shape from the normalized columns. The `data`
    // column is only the raw per-source payload (e.g. a bare CISA KEV entry) —
    // returning it alone previously shipped the browser objects with NO `.kind`,
    // `.riskScore`, `.severity`, `.exploitState`, or `.references`, which is why the
    // 0-day tracker rendered as if it were just an ordinary CVE list.
    const zeroDays: ZeroDay[] = rows.map((r) => {
      const base = {
        id: String(r.id),
        source: r.source as ZeroDay["source"],
        kind: r.kind as ZeroDay["kind"],
        cveId: (r.cve_id as string) ?? null,
        ghsaId: (r.ghsa_id as string) ?? null,
        title: r.title as string,
        product: (r.product as string) ?? null,
        exploitState: r.exploit_state as ZeroDay["exploitState"],
        verification: r.verification as ZeroDay["verification"],
        isKev: Boolean(r.is_kev),
        hasExploit: Boolean(r.has_exploit),
        riskScore: Number(r.risk_score),
        severity: r.severity as string,
        cvss: (r.cvss as number) ?? null,
        epss: (r.epss as number) ?? null,
        firstSeenAt: (r.first_seen_at as string) ?? null,
        lastSeenAt: (r.last_seen_at as string) ?? null,
        becameCve: Boolean(r.became_cve),
        resolvedAt: (r.resolved_at as string) ?? null,
        description: (r.description as string) ?? null,
        permalink: (r.permalink as string) ?? null,
        references: (r.references_json as string[]) ?? [],
        data: r.data,
      }
      // Always present, plain-language explanation — unlike `description` (null for
      // KEV, dense technical writeup for GitHub advisories), written for a reader
      // with no security background.
      return { ...base, plainSummary: explainZeroDay(base) }
    })

    return NextResponse.json(
      {
        zeroDays,
        lastSync: state[0]?.last_sync ?? null,
        lastRunAt: state[0]?.last_run_at ?? null,
        status: state[0]?.last_status ?? null,
        total: state[0]?.total_cves ?? rows.length,
      },
      { headers: { "Cache-Control": "public, max-age=30, s-maxage=30" } },
    )
  } catch (e) {
    return apiError(e, "zero-days", { zeroDays: [] })
  }
}