/**
 * Live diagnostic for the Exposure Intelligence module.
 * Run: bun run scripts/test-exposure.ts [query]
 *
 * Bun auto-loads .env.local, so this exercises the real keys against the real
 * vendor APIs (consumes a small amount of each provider's quota).
 * Prints NO secret values.
 */
import { exposureSearch, providerConfiguration } from "@/lib/exposure/orchestrator"
import { quotaUsage } from "@/lib/exposure/quota"
import { sql } from "@/lib/db"

async function main() {
  const query = process.argv[2] ?? "Apache"

  console.log("Provider configuration:")
  for (const p of providerConfiguration()) {
    console.log(`  ${p.provider.padEnd(10)} ${p.role.padEnd(11)} ${p.configured ? "configured" : "not configured"}`)
  }

  // Dev harness: runs as the installation owner (oldest account).
  const ownerRow = (await sql`SELECT id FROM "user" ORDER BY "createdAt" ASC LIMIT 1`) as Array<{ id: string }>
  const r = await exposureSearch(query, ownerRow[0]?.id ?? "__legacy__")
  console.log(`\n=== "${r.query}" (type: ${r.queryType}) cached=${r.cached} assets=${r.totalAssets} ===`)

  console.log("\n--- PROVIDER HEALTH ---")
  for (const p of r.providers) {
    const calls = p.calls != null ? ` calls=${p.successCalls}/${p.calls}` : ""
    console.log(`  ${p.provider.padEnd(10)} ${p.role.padEnd(11)} ${p.status.padEnd(20)} obs=${String(p.observationCount).padStart(3)}${calls} ${p.latencyMs}ms`)
    if (p.message) console.log(`             -> ${p.message.slice(0, 150)}`)
  }

  console.log("\n--- TOP ASSETS ---")
  for (const a of r.assets.slice(0, 5)) {
    console.log(`\n  ${a.id}  risk=${a.exposureRisk?.score ?? 0} (${a.exposureRisk?.severity}) conf=${a.confidence}(${a.confidenceScore}) enrich=${a.enrichmentStatus} sources=[${a.sources.join(",")}]${a.isQueryTarget ? " [QUERY-TARGET, no provider evidence]" : ""}`)
    if (a.domains.length) console.log(`     domains: ${a.domains.join(", ")}`)
    if (a.organization || a.country) console.log(`     org=${a.organization ?? "-"} country=${a.country ?? "-"} asn=${a.asn ?? "-"}`)
    if (a.services.length) console.log(`     services: ${a.services.slice(0, 6).map((s) => `${s.port}/${s.protocol ?? "?"}${s.product ? `(${s.product})` : ""}${s.conflict ? "[CONFLICT]" : ""}[${s.sources.join("+")}]`).join(", ")}`)
    if (a.technologies.length) console.log(`     tech: ${a.technologies.slice(0, 5).map((t) => t.name + (t.version ? " " + t.version : "")).join(", ")}`)
    if (a.vulnerabilities.length) console.log(`     CVEs(${a.vulnerabilities.length}): ${a.vulnerabilities.slice(0, 4).map((v) => `${v.cveId}[${v.matchType}]`).join(", ")}`)
    if (a.threat) console.log(`     threat: class=${a.threat.classification} noise=${a.threat.noise} riot=${a.threat.riot} actor=${a.threat.actor ?? "-"}`)
    if (a.evidence.length) console.log(`     evidence: ${a.evidence.map((e) => e.basis).join(", ")}`)
  }

  console.log("\n--- PROVIDER QUOTA (shared hourly window) ---")
  for (const q of await quotaUsage()) console.log(`  ${q.provider.padEnd(10)} ${q.used}/${q.budget}`)
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1) })
