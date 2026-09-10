import { sql, initDb } from "../lib/db"

await initDb()
const r = await sql`
  SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size,
         (SELECT count(*)::int FROM cves) AS n_cves,
         (SELECT pg_size_pretty(sum(pg_column_size(data))) FROM cves) AS data_size
`
console.log(JSON.stringify(r, null, 2))
process.exit(0)