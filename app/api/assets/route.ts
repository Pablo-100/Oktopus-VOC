import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"

// GET -> { assets: [...] } (uniquement ceux de l'utilisateur connecté)
export async function GET(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  try {
    await initDb()
    const assets = await sql`SELECT id, name, vendor, product, criticality, owner FROM assets WHERE user_id = ${gate.user.id} ORDER BY created_at DESC`
    return NextResponse.json({ assets })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 })
  }
}

// POST { name, vendor?, product?, criticality?, owner? } -> insert
export async function POST(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  try {
    await initDb()
    const b = await req.json()
    if (!b.name) return NextResponse.json({ error: "name requis" }, { status: 400 })
    const rows = await sql`
      INSERT INTO assets (user_id, name, vendor, product, criticality, owner)
      VALUES (${gate.user.id}, ${b.name}, ${b.vendor ?? null}, ${b.product ?? null}, ${b.criticality ?? "medium"}, ${b.owner ?? null})
      RETURNING id, name, vendor, product, criticality, owner`
    return NextResponse.json({ asset: rows[0] })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 })
  }
}

// DELETE ?id=123
export async function DELETE(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  try {
    await initDb()
    const id = new URL(req.url).searchParams.get("id")
    if (!id) return NextResponse.json({ error: "id requis" }, { status: 400 })
    // AND user_id -> impossible de supprimer l'actif d'un autre compte
    await sql`DELETE FROM assets WHERE id = ${Number(id)} AND user_id = ${gate.user.id}`
    return NextResponse.json({ ok: true })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 })
  }
}
