import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"

/**
 * Proxy serveur vers l'API NVD 2.0.
 * - La clé API (NVD_API_KEY) est envoyée en header côté serveur -> pas de preflight CORS,
 *   et débit 50 req/30s au lieu de 5.
 * - Le client appelle /api/nvd?<mêmes params que NVD> en same-origin (pas de "Failed to fetch").
 */
export async function GET(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  const inUrl = new URL(req.url)
  const nvd = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0")
  inUrl.searchParams.forEach((v, k) => nvd.searchParams.set(k, v))

  const headers: Record<string, string> = {}
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY

  try {
    const r = await fetch(nvd.toString(), { headers })
    const body = await r.text()
    return new NextResponse(body, {
      status: r.status,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 502 })
  }
}
