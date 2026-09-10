import { sql, initDb } from "@/lib/db"

await initDb()
const rows = await sql`SELECT id, source, kind, cve_id, title, risk_score, severity, exploit_state, first_seen_at FROM zero_days ORDER BY risk_score DESC LIMIT 20`
console.log("Top 20 zero_days:", JSON.stringify(rows, null, 2))
const count = await sql`SELECT COUNT(*)::int as n FROM zero_days`
console.log("Total:", count[0]?.n)
process.exit(0)