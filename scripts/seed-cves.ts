/**
 * Seed initial de la table `cves` : lance le collecteur en local (une fois),
 * pour ne pas faire subir le premier gros run à Vercel. `skipAlerts` = pas de
 * spam Telegram sur le backlog. Usage : bun run scripts/seed-cves.ts
 */
import { readFileSync } from "fs"

for (const line of readFileSync(".env.local", "utf8").split(/\r?\n/)) {
  const m = line.match(/^([A-Z0-9_]+)=(.*)$/)
  if (m) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "")
}

const { syncCves } = await import("@/lib/collector")
console.log("⏳ Seed en cours (fetch NVD + enrichissement + upsert)…")
const result = await syncCves({ skipAlerts: true })
console.log(JSON.stringify(result, null, 2))
process.exit(result.ok ? 0 : 1)
