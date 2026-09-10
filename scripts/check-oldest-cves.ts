import { sql, initDb } from "@/lib/db"

await initDb()
const rows = await sql`SELECT cve_id, published FROM cves ORDER BY published ASC LIMIT 10`
console.log("Oldest CVEs:", JSON.stringify(rows, null, 2))
const total = await sql`SELECT COUNT(*)::int as n FROM cves`
console.log("Total CVEs in DB:", total[0]?.n)
process.exit(0)