import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

// GET -> { assets: [...] } (uniquement ceux de l'utilisateur connecté)
export async function GET(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  // small CRUD over the user's own assets.
  const denied = rateLimited(keyFrom(req, gate.user.id), 60, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const assets = (await sql`
      SELECT id, name, vendor, product, criticality, owner
      FROM assets WHERE user_id = ${gate.user.id}
      ORDER BY
        -- Criticality first: it was collected, badged, and then ignored by
        -- everything. An asset the user marked critical now actually leads the
        -- list instead of being ordered by when they happened to add it.
        CASE criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
        created_at DESC
    `) as Array<{ id: number; name: string; vendor: string | null; product: string | null; criticality: string; owner: string | null }>

    // How many CVEs actually affect each declared asset.
    //
    // This page exists to answer "which CVEs affect me", and it never showed
    // the answer — the user declared a stack and then had to leave for the
    // dashboard to find out whether it mattered. The GIN index on
    // `data->'products'` keeps this in the tens of milliseconds per asset.
    const withImpact = await Promise.all(
      assets.map(async (a) => {
        const vendor = a.vendor?.toLowerCase().trim() || null
        const product = a.product?.toLowerCase().trim() || null
        if (!vendor && !product) return { ...a, impact: { total: 0, critical: 0, kev: 0, maxRisk: 0 } }
        const r = (await sql`
          SELECT count(*)::int AS total,
                 count(*) FILTER (WHERE severity = 'critical')::int AS critical,
                 count(*) FILTER (WHERE is_kev)::int AS kev,
                 COALESCE(max(risk_score), 0)::float AS max_risk
          FROM cves
          WHERE (${product}::text IS NOT NULL AND data->'products' ? ${product})
             OR (${vendor}::text  IS NOT NULL AND data->'vendors'  ? ${vendor})
        `.catch(() => [{ total: 0, critical: 0, kev: 0, max_risk: 0 }])) as Array<{
          total: number; critical: number; kev: number; max_risk: number
        }>
        return {
          ...a,
          impact: {
            total: r[0]?.total ?? 0,
            critical: r[0]?.critical ?? 0,
            kev: r[0]?.kev ?? 0,
            maxRisk: Math.round(r[0]?.max_risk ?? 0),
          },
        }
      }),
    )
    return NextResponse.json({ assets: withImpact })
  } catch (e) {
    return apiError(e, "assets")
  }
}

// POST { name, vendor?, product?, criticality?, owner? } -> insert
export async function POST(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  // small CRUD over the user's own assets.
  const denied = rateLimited(keyFrom(req, gate.user.id), 60, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const b = await req.json()
    if (!b.name) return NextResponse.json({ error: "name is required" }, { status: 400 })

    const vendor = typeof b.vendor === "string" && b.vendor.trim() ? b.vendor.trim().toLowerCase() : null
    const product = typeof b.product === "string" && b.product.trim() ? b.product.trim().toLowerCase() : null

    // Declaring the same vendor/product twice adds nothing and double-counts it
    // everywhere downstream. The guided picker makes this easy to do by
    // accident — check apache, add, check apache again — so it is refused
    // rather than silently duplicated.
    if (vendor || product) {
      const dupe = (await sql`
        SELECT id, name FROM assets
        WHERE user_id = ${gate.user.id}
          AND lower(coalesce(vendor, '')) = ${vendor ?? ""}
          AND lower(coalesce(product, '')) = ${product ?? ""}
        LIMIT 1
      `) as Array<{ id: number; name: string }>
      if (dupe[0]) {
        return NextResponse.json(
          { error: `Already in your inventory as "${dupe[0].name}".`, code: "duplicate", existingId: dupe[0].id },
          { status: 409 },
        )
      }
    }

    const rows = await sql`
      INSERT INTO assets (user_id, name, vendor, product, criticality, owner)
      VALUES (${gate.user.id}, ${b.name}, ${vendor}, ${product}, ${b.criticality ?? "medium"}, ${b.owner ?? null})
      RETURNING id, name, vendor, product, criticality, owner`
    return NextResponse.json({ asset: rows[0] })
  } catch (e) {
    return apiError(e, "assets")
  }
}

// DELETE ?id=123
export async function DELETE(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  // small CRUD over the user's own assets.
  const denied = rateLimited(keyFrom(req, gate.user.id), 60, 60_000)
  if (denied) return denied
  try {
    await initDb()
    const id = new URL(req.url).searchParams.get("id")
    if (!id) return NextResponse.json({ error: "id is required" }, { status: 400 })
    // AND user_id -> impossible de supprimer l'actif d'un autre compte
    await sql`DELETE FROM assets WHERE id = ${Number(id)} AND user_id = ${gate.user.id}`
    return NextResponse.json({ ok: true })
  } catch (e) {
    return apiError(e, "assets")
  }
}
