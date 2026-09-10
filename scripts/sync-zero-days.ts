import { syncZeroDays } from "@/lib/zero-day-collector"
import { initDb } from "@/lib/db"

await initDb()
const result = await syncZeroDays()
console.log("Sync result:", JSON.stringify(result, null, 2))
process.exit(result.ok ? 0 : 1)