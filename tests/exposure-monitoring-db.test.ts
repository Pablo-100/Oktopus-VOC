/**
 * PERIODIC EXPOSURE MONITORING — database-backed behaviour.
 *
 * These exercise the real Postgres claim/lease logic, which cannot be proven
 * in memory: atomic claiming, mutual exclusion between concurrent scheduler
 * invocations, and state surviving a process restart.
 *
 * Skips itself cleanly when no database is reachable, matching the project's
 * existing hermetic-test convention. Uses a dedicated `test:` asset-key prefix
 * and removes its own rows, so it never touches real monitoring state.
 */
import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { sql, initDb } from "@/lib/db"
import {

  claimDueAssets, isAssetLocked, setMonitoring, getMonitoring, monitoringOverview,
  MONITORING_INTERVALS,
} from "@/lib/exposure/monitoring"

/**
 * Tenancy fixtures. Every DB suite runs as an explicit tenant so a query that
 * forgets its user filter shows up as a cross-tenant leak rather than passing
 * silently. `OTHER` exists to prove isolation, not just to satisfy a signature.
 */
const TENANT = "test-tenant-a"
const OTHER = "test-tenant-b"

const PREFIX = "test:monitor:"
const KEY_A = `${PREFIX}a`
const KEY_B = `${PREFIX}b`
const KEY_FUTURE = `${PREFIX}future`
const KEY_DISABLED = `${PREFIX}disabled`

let dbAvailable = false

async function cleanup() {
  if (!dbAvailable) return
  await sql`DELETE FROM exposure_monitoring WHERE asset_key LIKE ${PREFIX + "%"}`
  await sql`DELETE FROM exposure_monitoring_runs WHERE asset_key LIKE ${PREFIX + "%"}`
}

// The schema migration in `initDb()` runs many statements against a REMOTE
// database, so first-run setup can exceed bun's 5s hook default. This is setup
// cost, not an assertion — the timeout is raised rather than the check weakened.
beforeAll(async () => {
  if (!HAS_TEST_DB) return
  try {
    await initDb()
    await sql`SELECT 1`
    dbAvailable = true
  } catch {
    dbAvailable = false
  }
  await cleanup()
}, 60_000)

afterAll(async () => {
  if (!HAS_TEST_DB) return
  await cleanup()
})

/** Seed a monitoring row with an explicit next_run_at. */
async function seed(assetKey: string, opts: { enabled: boolean; dueSecondsAgo?: number; intervalSeconds?: number }) {
  await setMonitoring(assetKey, "203.0.113.10", TENANT, {
    enabled: opts.enabled,
    intervalSeconds: opts.intervalSeconds ?? MONITORING_INTERVALS.every6h,
  })
  const offset = opts.dueSecondsAgo ?? 0
  await sql`
    UPDATE exposure_monitoring
    SET next_run_at = now() - (${offset}::text || ' seconds')::interval, locked_at = NULL, locked_by = NULL
    WHERE asset_key = ${assetKey}
  `
}

describe.skipIf(!process.env.DATABASE_URL)("Scheduling eligibility", () => {
  test("a DISABLED asset is never claimed", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_DISABLED, { enabled: false, dueSecondsAgo: 3600 })
    const claimed = await claimDueAssets("run-test-1", 10)
    expect(claimed.some((c) => c.asset_key === KEY_DISABLED)).toBe(false)
  })

  test("an enabled asset with a FUTURE next_run_at is not claimed", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_FUTURE, { enabled: true, dueSecondsAgo: -3600 }) // due in 1h
    const claimed = await claimDueAssets("run-test-2", 10)
    expect(claimed.some((c) => c.asset_key === KEY_FUTURE)).toBe(false)
  })

  test("a DUE enabled asset IS claimed", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 60 })
    const claimed = await claimDueAssets("run-test-3", 10)
    expect(claimed.some((c) => c.asset_key === KEY_A)).toBe(true)
  })

  test("the batch is bounded by the requested limit", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 120 })
    await seed(KEY_B, { enabled: true, dueSecondsAgo: 60 })
    const claimed = await claimDueAssets("run-test-4", 1)
    expect(claimed).toHaveLength(1)
  })

  /**
   * REGRESSION — the batch bound must not depend on the query planner.
   *
   * The original claim used `WHERE asset_key IN (SELECT … LIMIT n FOR UPDATE
   * SKIP LOCKED)`. `FOR UPDATE` makes that subquery non-hashable, so the
   * planner is free to re-execute it once per candidate outer row; each
   * re-execution skips the rows just locked and returns a different one, and a
   * single statement then claims more than `limit` assets. It was observed
   * claiming 2 rows under `LIMIT 1`, which silently breaks the per-run cost
   * bound that protects provider quota and the 60s function limit.
   *
   * Repeated because the faulty plan was only chosen intermittently — a single
   * attempt could pass against the broken implementation.
   */
  test("the limit holds across repeated claims, whatever plan Postgres picks", async () => {
    if (!dbAvailable) return
    await cleanup()
    const keys = Array.from({ length: 6 }, (_, i) => `${PREFIX}bound${i}`)
    for (const [i, k] of keys.entries()) await seed(k, { enabled: true, dueSecondsAgo: 60 + i })

    let maxClaimed = 0
    for (let i = 0; i < 12; i++) {
      // Release everything so each attempt sees the full candidate set.
      await sql`UPDATE exposure_monitoring SET locked_at = NULL, locked_by = NULL WHERE asset_key LIKE ${PREFIX + "%"}`
      const claimed = await claimDueAssets(`bound-${i}`, 2)
      maxClaimed = Math.max(maxClaimed, claimed.length)
    }
    expect(maxClaimed).toBeLessThanOrEqual(2)
    // 12 iterations x 2 statements against a REMOTE database: the wall-clock
    // budget is raised, the assertion is unchanged.
  }, 30_000)

  test("fairness: the OLDEST next_run_at is claimed first", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 600 }) // older
    await seed(KEY_B, { enabled: true, dueSecondsAgo: 60 })
    const claimed = await claimDueAssets("run-test-5", 1)
    expect(claimed[0]?.asset_key).toBe(KEY_A)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Concurrency — two invocations cannot claim the same asset", () => {
  test("a second scheduler run does not re-claim an already-claimed asset", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 60 })

    const first = await claimDueAssets("run-A", 10)
    const second = await claimDueAssets("run-B", 10)

    expect(first.some((c) => c.asset_key === KEY_A)).toBe(true)
    // The lease is still live, so run B must not see it.
    expect(second.some((c) => c.asset_key === KEY_A)).toBe(false)
  })

  test("TRULY concurrent claims never hand the same asset to two runs", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 60 })
    await seed(KEY_B, { enabled: true, dueSecondsAgo: 60 })

    // Fire several claim attempts simultaneously.
    const results = await Promise.all([
      claimDueAssets("race-1", 5),
      claimDueAssets("race-2", 5),
      claimDueAssets("race-3", 5),
    ])
    const allKeys = results.flat().map((r) => r.asset_key)
    const unique = new Set(allKeys)
    // Every claimed key must appear exactly once across all runs.
    expect(allKeys.length).toBe(unique.size)
  })

  test("a claimed asset reports as locked, which is what blocks manual refresh", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 60 })
    expect(await isAssetLocked(KEY_A, TENANT)).toBe(false)
    await claimDueAssets("run-lock", 10)
    expect(await isAssetLocked(KEY_A, TENANT)).toBe(true)
  })

  test("a STALE lease is reclaimable — a crashed run cannot block an asset forever", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 60 })
    // Simulate an invocation that claimed the asset and then died an hour ago.
    await sql`UPDATE exposure_monitoring SET locked_at = now() - interval '1 hour', locked_by = 'dead-run' WHERE asset_key = ${KEY_A}`
    expect(await isAssetLocked(KEY_A, TENANT)).toBe(false) // lease expired
    const claimed = await claimDueAssets("run-recover", 10)
    expect(claimed.some((c) => c.asset_key === KEY_A)).toBe(true)
  })
})

describe.skipIf(!process.env.DATABASE_URL)("Monitoring configuration", () => {
  test("monitoring is OPT-IN — a new row can be created disabled", async () => {
    if (!dbAvailable) return
    await cleanup()
    const row = await setMonitoring(KEY_A, "203.0.113.10", TENANT, { enabled: false })
    expect(row.enabled).toBe(false)
    const claimed = await claimDueAssets("run-optin", 10)
    expect(claimed.some((c) => c.asset_key === KEY_A)).toBe(false)
  })

  test("monitoring can be paused and resumed", async () => {
    if (!dbAvailable) return
    await cleanup()
    await setMonitoring(KEY_A, "203.0.113.10", TENANT, { enabled: true, intervalSeconds: MONITORING_INTERVALS.hourly })
    expect((await getMonitoring(KEY_A, TENANT))?.enabled).toBe(true)

    await setMonitoring(KEY_A, "203.0.113.10", TENANT, { enabled: false })
    expect((await getMonitoring(KEY_A, TENANT))?.enabled).toBe(false)
    // Paused assets are never claimed.
    expect((await claimDueAssets("run-paused", 10)).some((c) => c.asset_key === KEY_A)).toBe(false)

    await setMonitoring(KEY_A, "203.0.113.10", TENANT, { enabled: true })
    expect((await getMonitoring(KEY_A, TENANT))?.enabled).toBe(true)
  })

  test("interval is persisted in seconds and survives re-reading (process restart equivalent)", async () => {
    if (!dbAvailable) return
    await cleanup()
    await setMonitoring(KEY_A, "203.0.113.10", TENANT, { enabled: true, intervalSeconds: MONITORING_INTERVALS.daily })
    // Re-read through a fresh query — state lives in Postgres, not memory.
    const reread = await getMonitoring(KEY_A, TENANT)
    expect(reread?.interval_seconds).toBe(MONITORING_INTERVALS.daily)
    expect(reread?.enabled).toBe(true)
  })

  test("an absurdly short interval is floored (no accidental hammering)", async () => {
    if (!dbAvailable) return
    await cleanup()
    const row = await setMonitoring(KEY_A, "203.0.113.10", TENANT, { enabled: true, intervalSeconds: 1 })
    expect(row.interval_seconds).toBeGreaterThanOrEqual(300)
  })

  test("the overview reports enabled/paused/due counts", async () => {
    if (!dbAvailable) return
    await cleanup()
    await seed(KEY_A, { enabled: true, dueSecondsAgo: 60 })
    await seed(KEY_DISABLED, { enabled: false })
    const o = await monitoringOverview(TENANT)
    const mine = o.assets.filter((a) => a.asset_key.startsWith(PREFIX))
    expect(mine.some((a) => a.enabled)).toBe(true)
    expect(mine.some((a) => !a.enabled)).toBe(true)
  })
})

describe.skipIf(!HAS_TEST_DB)("cross-tenant isolation", () => {
  test("the overview reports only the caller's own monitored assets", async () => {
    const mine = await monitoringOverview(TENANT)
    const theirs = await monitoringOverview(OTHER)
    const myKeys = new Set(mine.assets.map((a) => a.asset_key))
    for (const a of theirs.assets) {
      // Two tenants may legitimately monitor the SAME host, so identity is
      // (user_id, asset_key) — a row of theirs must never carry my user id.
      expect(a.user_id).toBe(OTHER)
      if (myKeys.has(a.asset_key)) expect(a.user_id).not.toBe(TENANT)
    }
  }, 30_000)
})
