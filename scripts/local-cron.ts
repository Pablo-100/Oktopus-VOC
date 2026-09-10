/**
 * LOCAL SCHEDULER — validate the cron jobs before hosting them.
 *
 * Windows has no `crontab`, and the point of this script is not to replace one:
 * it calls the SAME HTTP endpoints, with the SAME Bearer secret, on the SAME
 * cadences that cron-job.org (or GitHub Actions) will use in production. If it
 * works here it works there, and if the secret or the URL is wrong you find out
 * on your machine instead of discovering weeks of silently frozen data.
 *
 *   bun run scripts/local-cron.ts              # loop forever, real cadences
 *   bun run scripts/local-cron.ts --once       # one pass of every job, then exit
 *   bun run scripts/local-cron.ts --fast       # every job every 30s (demo/debug)
 *   APP_URL=https://your-app.vercel.app bun run scripts/local-cron.ts
 *
 * Requires CRON_SECRET (and APP_URL when not targeting localhost). Never prints
 * either: a scheduler log is exactly the kind of place a secret gets leaked.
 */
import { existsSync, readFileSync } from "fs"

// Load .env.local the same way the app does in development.
if (existsSync(".env.local")) {
  for (const line of readFileSync(".env.local", "utf8").split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "")
  }
}

const APP_URL = (process.env.APP_URL ?? "http://localhost:3000").replace(/\/+$/, "")
const SECRET = process.env.CRON_SECRET
const ONCE = process.argv.includes("--once")
const FAST = process.argv.includes("--fast")

if (!SECRET) {
  console.error("CRON_SECRET is not set. Add it to .env.local — it must match the value the app reads.")
  process.exit(1)
}

interface Job {
  name: string
  path: string
  /** Production cadence, in seconds. */
  everySeconds: number
  why: string
}

/**
 * The four scheduled jobs, with the cadence each actually needs.
 *
 * They are SEPARATE HTTP calls on purpose. When the CVE and zero-day syncs
 * shared one invocation the CVE pass consumed the whole 60s serverless budget
 * and the zero-day pass was never reached — it was killed rather than throwing,
 * so nothing was logged and the data silently froze for twelve days while every
 * source still reported healthy. One job per call, one budget per job.
 */
const JOBS: Job[] = [
  { name: "cve-sync", path: "/api/cron/sync", everySeconds: 300,
    why: "Pulls new CVEs from NVD and re-scores them." },
  { name: "zero-day-sync", path: "/api/cron/zero-days", everySeconds: 300,
    why: "Pulls pre-disclosure/0-day intelligence. Its own call so a slow CVE sync cannot starve it." },
  { name: "exposure-monitoring", path: "/api/exposure/monitoring/run", everySeconds: 900,
    why: "Re-queries providers for monitored assets and records what changed." },
  { name: "soc-notifications", path: "/api/exposure/notifications/run", everySeconds: 900,
    why: "Drains the alert outbox: retries and stale-claim recovery." },
]

const stamp = () => new Date().toISOString().replace("T", " ").slice(0, 19)

async function runJob(job: Job): Promise<void> {
  const started = Date.now()
  try {
    const res = await fetch(`${APP_URL}${job.path}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${SECRET}` },
      signal: AbortSignal.timeout(120_000),
    })
    const took = ((Date.now() - started) / 1000).toFixed(1)
    const body = await res.text()

    if (!res.ok) {
      // 401 here almost always means CRON_SECRET differs between this shell and
      // the running app — the single most common cause of "the cron does
      // nothing" in production.
      const hint = res.status === 401
        ? "  <-- CRON_SECRET does not match the value the app is running with"
        : ""
      console.error(`${stamp()}  ${job.name.padEnd(20)} HTTP ${res.status} (${took}s)${hint}`)
      console.error(`    ${body.slice(0, 200)}`)
      return
    }

    // Summarise rather than dumping the payload; these responses can be large.
    let summary = body.slice(0, 160)
    try {
      const j = JSON.parse(body) as Record<string, unknown>
      const pick = (k: string) => (j[k] === undefined ? null : j[k])
      const parts = ["ok", "fetched", "processed", "total", "scanned", "sent", "failed", "retrying", "reclaimed", "eventsCreated"]
        .map((k) => (pick(k) === null ? null : `${k}=${JSON.stringify(pick(k))}`))
        .filter(Boolean)
      if (parts.length) summary = parts.join(" ")
      else if (j.cve) summary = `cve=${JSON.stringify(j.cve).slice(0, 120)}`
    } catch { /* not JSON — the truncated body is fine */ }

    console.log(`${stamp()}  ${job.name.padEnd(20)} OK  (${took}s)  ${summary}`)
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    const hint = /fetch failed|ECONNREFUSED/i.test(msg)
      ? `  <-- is the app running at ${APP_URL}?`
      : ""
    console.error(`${stamp()}  ${job.name.padEnd(20)} ERROR ${msg.slice(0, 120)}${hint}`)
  }
}

console.log(`OCTUPUS local scheduler -> ${APP_URL}`)
console.log(`mode: ${ONCE ? "single pass" : FAST ? "fast (30s, debug only)" : "production cadences"}\n`)
for (const j of JOBS) {
  console.log(`  ${j.name.padEnd(20)} every ${FAST ? 30 : j.everySeconds}s  ${j.path}`)
  console.log(`  ${" ".repeat(20)} ${j.why}`)
}
console.log("")

if (ONCE) {
  // Sequential: a single pass is for verifying each endpoint answers, and
  // overlapping them would make a failure harder to attribute.
  for (const job of JOBS) await runJob(job)
  console.log("\nsingle pass complete.")
  process.exit(0)
}

// Each job keeps its own timer, so a slow job delays only itself.
for (const job of JOBS) {
  const period = (FAST ? 30 : job.everySeconds) * 1000
  void runJob(job)
  setInterval(() => { void runJob(job) }, period)
}
console.log("running — Ctrl+C to stop\n")
