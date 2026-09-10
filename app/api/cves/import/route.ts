import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { processNvd } from "@/lib/data"
import { enrichServer, batchUpsert } from "@/lib/collector"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

/**
 * Import un CVE spécifique par son ID depuis NVD (à la demande).
 * POST /api/cves/import  { "cveId": "CVE-1999-0001" }
 * ou GET  /api/cves/import?cveId=CVE-1999-0001
 */
export async function POST(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny

  const limited = rateLimited(`import:${keyFrom(req, gate.user?.email)}`, 10, 60_000)
  if (limited) return limited

  try {
    const body = await req.json().catch(() => ({}))
    const cveId = (body.cveId || "").toUpperCase().trim()
    if (!cveId || !/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      return NextResponse.json({ error: "cveId invalid (format: CVE-YYYY-NNNN)" }, { status: 400 })
    }
    return await importCve(cveId, gate.user?.email ?? gate.user?.name ?? null)
  } catch (e) {
    return apiError(e, "cves-import")
  }
}

export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny

  const cveId = new URL(req.url).searchParams.get("cveId")?.toUpperCase().trim()
  if (!cveId || !/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
    return NextResponse.json({ error: "cveId is required (format: CVE-YYYY-NNNN)" }, { status: 400 })
  }
  return await importCve(cveId, gate.user?.email ?? gate.user?.name ?? null)
}

async function importCve(cveId: string, importedBy?: string | null) {
  await initDb()

  // Vérifier si déjà en base
  const existing = await sql`SELECT cve_id, risk_score, severity, is_kev, has_exploit, data FROM cves WHERE cve_id = ${cveId}`
  if (existing.length) {
    return NextResponse.json({
      imported: false,
      message: "Déjà présent en base",
      cve: existing[0].data,
    })
  }

  // Fetch depuis NVD
  const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
  const headers: Record<string, string> = {}
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY

  const res = await fetch(`${NVD_URL}?cveId=${cveId}`, { headers })
  if (!res.ok) {
    return NextResponse.json({ error: `NVD HTTP ${res.status}: CVE non trouvée` }, { status: 404 })
  }

  const data = await res.json()
  const vulns = processNvd(data)
  if (!vulns.length) {
    return NextResponse.json({ error: "CVE not found in NVD response" }, { status: 404 })
  }

  // Enrichir + upsert
  await enrichServer(vulns)
  await batchUpsert(vulns, importedBy)

  const v = vulns[0]
  return NextResponse.json({
    imported: true,
    cveId: v.cveId,
    riskScore: v.riskScore,
    severity: v.severity,
    isKev: v.isKev,
    hasExploit: v.hasExploit,
    cve: v,
  })
}