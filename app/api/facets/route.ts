import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"

/**
 * Valeurs réelles présentes dans la base (éditeurs & produits), pour alimenter
 * un sélecteur guidé côté client. Garantit que les choix de l'utilisateur
 * matchent exactement les CVE (pas de faute de frappe possible).
 */
type Facet = { name: string; count: number }
let cache: { at: number; vendors: Facet[]; products: Facet[] } | null = null
const TTL = 5 * 60 * 1000

export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  try {
    if (cache && Date.now() - cache.at < TTL) {
      return NextResponse.json({ vendors: cache.vendors, products: cache.products, cached: true })
    }
    await initDb()
    const vendors = (await sql`
      SELECT val AS name, COUNT(*)::int AS count
      FROM cves, jsonb_array_elements_text(data->'vendors') AS val
      WHERE val <> '' AND val <> '*' AND val <> '-'
      GROUP BY val ORDER BY count DESC, name ASC LIMIT 800`) as Facet[]
    const products = (await sql`
      SELECT val AS name, COUNT(*)::int AS count
      FROM cves, jsonb_array_elements_text(data->'products') AS val
      WHERE val <> '' AND val <> '*' AND val <> '-'
      GROUP BY val ORDER BY count DESC, name ASC LIMIT 800`) as Facet[]
    cache = { at: Date.now(), vendors, products }
    return NextResponse.json({ vendors, products }, { headers: { "Cache-Control": "private, max-age=300" } })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message, vendors: [], products: [] }, { status: 500 })
  }
}
