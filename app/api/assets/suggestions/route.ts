import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

export const dynamic = "force-dynamic"

/**
 * Inventory suggestions drawn from what the platform has actually OBSERVED.
 *
 * The two halves of this product were disconnected. The exposure side already
 * knows what is running on the user's hosts — Shodan and Netlas report OpenSSH,
 * Exim, Dovecot, cPanel by name — while the CVE side asked the same user to
 * hand-pick their stack from a list of CPE facets. Declaring by hand what the
 * platform has already measured is busywork, and it is where inventories go
 * stale.
 *
 * So this proposes the observed software, mapped onto the CPE vocabulary the
 * CVE data actually uses, and reports how many CVEs each match carries so the
 * user can judge the mapping rather than trust it blindly.
 */

/** Bounded: this is a suggestion list, not an export. */
const MAX_SUGGESTIONS = 25

/**
 * Candidate CPE product names for a provider-reported product string.
 *
 * Providers report marketing names ("Apache httpd", "Apache HTTP Server"); NVD
 * uses CPE names ("http_server", "openssh"). Neither is derivable from the
 * other, so several plausible forms are tried and the one with real CVE
 * coverage wins.
 */
export function candidates(observed: string): string[] {
  const lower = observed.toLowerCase().trim()
  const tokens = lower.split(/\s+/).filter(Boolean)
  const out = new Set<string>([lower])
  if (tokens.length > 1) {
    out.add(tokens[tokens.length - 1])
    out.add(tokens[0])
    // CPE joins words with underscores: "http server" -> "http_server".
    out.add(tokens.join("_"))
    out.add(tokens.slice(1).join("_"))
  }
  return [...out].filter((c) => c.length >= 3 && c.length <= 60)
}

export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 20, 60_000)
  if (denied) return denied

  try {
    await initDb()

    // What the providers reported on this user's own assets, and where.
    const observed = (await sql`
      SELECT product, count(DISTINCT asset_key)::int AS hosts
      FROM exposure_vulnerability
      WHERE user_id = ${gate.user.id} AND product IS NOT NULL AND product <> ''
      GROUP BY product
      ORDER BY hosts DESC, product ASC
      LIMIT ${MAX_SUGGESTIONS}
    `) as Array<{ product: string; hosts: number }>

    // Already declared — suggesting these again is noise.
    const owned = (await sql`
      SELECT lower(coalesce(product, '')) AS product, lower(coalesce(vendor, '')) AS vendor
      FROM assets WHERE user_id = ${gate.user.id}
    `) as Array<{ product: string; vendor: string }>
    const ownedSet = new Set(owned.flatMap((o) => [o.product, o.vendor]).filter(Boolean))

    const suggestions: Array<{
      observed: string
      hosts: number
      match: string | null
      cveCount: number
      criticalCount: number
      kevCount: number
    }> = []

    for (const row of observed) {
      // Best match by coverage, not first hit: "Apache httpd" matches the
      // vendor "apache" with a couple of CVEs and the product "http_server"
      // with hundreds. Taking the first would quietly under-report.
      let best: { name: string; total: number; critical: number; kev: number } | null = null
      for (const c of candidates(row.product)) {
        const r = (await sql`
          SELECT count(*)::int AS total,
                 count(*) FILTER (WHERE severity = 'critical')::int AS critical,
                 count(*) FILTER (WHERE is_kev)::int AS kev
          FROM cves
          WHERE data->'products' ? ${c} OR data->'vendors' ? ${c}
        `) as Array<{ total: number; critical: number; kev: number }>
        const total = r[0]?.total ?? 0
        if (total > (best?.total ?? 0)) best = { name: c, total, critical: r[0].critical, kev: r[0].kev }
      }

      if (best && ownedSet.has(best.name)) continue
      // Providers name the same software differently — "Apache HTTP Server" and
      // "Apache httpd" both resolve to `apache`. Offering both would be two
      // buttons for one decision, and the second would be refused as a
      // duplicate after the first was accepted.
      if (best && suggestions.some((x) => x.match === best!.name)) {
        const existing = suggestions.find((x) => x.match === best!.name)!
        existing.hosts = Math.max(existing.hosts, row.hosts)
        // Keep both provider names visible so the user can see why it matched.
        if (!existing.observed.includes(row.product)) existing.observed += ` / ${row.product}`
        continue
      }
      suggestions.push({
        observed: row.product,
        hosts: row.hosts,
        // Reported as null rather than guessed when nothing matched: a
        // suggestion that silently tracks the wrong software is worse than no
        // suggestion.
        match: best?.name ?? null,
        cveCount: best?.total ?? 0,
        criticalCount: best?.critical ?? 0,
        kevCount: best?.kev ?? 0,
      })
    }

    return NextResponse.json(
      { suggestions: suggestions.filter((s) => s.match !== null) },
      { headers: { "Cache-Control": "private, max-age=60" } },
    )
  } catch (e) {
    return apiError(e, "asset-suggestions")
  }
}
