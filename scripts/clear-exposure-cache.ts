/** One-off: clear exposure/greynoise caches after a code fix, so the next lookup re-fetches live instead of waiting out the TTL. */
import { sql, initDb } from "@/lib/db"

async function main() {
  await initDb()
  const a = await sql`DELETE FROM exposure_cache`
  const b = await sql`DELETE FROM greynoise_cache`
  console.log("Cleared exposure_cache and greynoise_cache.", a, b)
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1) })
