import { initDb, sql } from "@/lib/db"
import { processNvd } from "@/lib/data"
import { enrichServer, batchUpsert } from "@/lib/collector"

async function importCve(cveId: string) {
  await initDb()

  const existing = await sql`SELECT cve_id FROM cves WHERE cve_id = ${cveId}`
  if (existing.length) {
    console.log("Already in DB:", cveId)
    return
  }

  const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
  const headers: Record<string, string> = {}
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY

  const res = await fetch(`${NVD_URL}?cveId=${cveId}`, { headers })
  if (!res.ok) {
    console.error(`NVD HTTP ${res.status}: ${cveId} not found`)
    return
  }

  const data = await res.json()
  const vulns = processNvd(data)
  if (!vulns.length) {
    console.error("CVE not found in NVD response")
    return
  }

  await enrichServer(vulns)
  await batchUpsert(vulns)

  const v = vulns[0]
  console.log("Imported:", {
    cveId: v.cveId,
    riskScore: v.riskScore,
    severity: v.severity,
    isKev: v.isKev,
    hasExploit: v.hasExploit,
  })
}

await importCve("CVE-1999-0001")
process.exit(0)