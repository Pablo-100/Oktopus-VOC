/**
 * PERIODIC EXPOSURE MONITORING — scheduler logic.
 *
 * Pure/logic tests (no DB, no network) covering the scheduling decisions:
 * classification, backoff, batch bounds, interval handling. DB-dependent
 * behaviour (atomic claiming, lock exclusivity, persistence across restart) is
 * covered by tests/exposure-monitoring-db.test.ts, which skips itself when no
 * database is reachable.
 */
import { describe, test, expect } from "bun:test"
import {
  classifyRefresh, backoffSeconds, maxAssetsPerRun,
  MONITORING_INTERVALS, DEFAULT_INTERVAL_SECONDS,
} from "@/lib/exposure/monitoring"
import type { ProviderName, ProviderOutcome, ProviderStatus } from "@/lib/exposure/types"
import { redactSecrets } from "@/lib/exposure/providers/_base"

function outcome(provider: ProviderName, status: ProviderStatus): ProviderOutcome {
  return {
    provider, role: "enrichment", status, retryable: false, query: "x",
    latencyMs: 10, observationCount: status === "success" ? 1 : 0,
    fetchedAt: new Date().toISOString(),
  }
}

describe("Refresh classification — partial success is NOT failure (item 12)", () => {
  test("all providers succeeding => success", () => {
    const r = classifyRefresh([outcome("censys", "success"), outcome("netlas", "success")])
    expect(r.status).toBe("success")
  })

  test("mixed success + failure => PARTIAL, and names what failed", () => {
    // Exactly the scenario in the brief: Censys ok, LeakIX ok, Netlas 429,
    // FOFA/ZoomEye unavailable, GreyNoise ok. Must not become TOTAL FAILURE.
    const r = classifyRefresh([
      outcome("censys", "success"),
      outcome("leakix", "success"),
      outcome("netlas", "rate_limited"),
      outcome("fofa", "quota_exhausted"),
      outcome("zoomeye", "provider_unavailable"),
      outcome("greynoise", "success"),
    ])
    expect(r.status).toBe("partial")
    expect(r.status).not.toBe("failed")
    expect(r.error).toContain("netlas")
  })

  test("every provider quota-blocked => quota_deferred, never failed", () => {
    const r = classifyRefresh([
      outcome("censys", "quota_exhausted"),
      outcome("netlas", "rate_limited"),
    ])
    expect(r.status).toBe("quota_deferred")
    expect(r.status).not.toBe("failed")
  })

  test("genuine provider errors => failed", () => {
    const r = classifyRefresh([
      outcome("censys", "provider_unavailable"),
      outcome("netlas", "authentication_failed"),
    ])
    expect(r.status).toBe("failed")
  })

  test("unconfigured providers do not make a run look failed", () => {
    const r = classifyRefresh([outcome("censys", "success"), outcome("fofa", "not_configured")])
    expect(r.status).toBe("success")
  })

  test("no providers contacted at all => no_provider (a deferral, not a failure)", () => {
    expect(classifyRefresh([]).status).toBe("no_provider")
    expect(classifyRefresh([outcome("fofa", "not_configured")]).status).toBe("no_provider")
  })
})

describe("Backoff (item 11) — bounded, never a retry storm", () => {
  const interval = MONITORING_INTERVALS.every6h

  test("no failures => the normal interval", () => {
    expect(backoffSeconds(0, interval)).toBe(interval)
  })

  test("backoff grows with consecutive failures", () => {
    const b1 = backoffSeconds(1, interval)
    const b2 = backoffSeconds(2, interval)
    const b3 = backoffSeconds(3, interval)
    expect(b2).toBeGreaterThan(b1)
    expect(b3).toBeGreaterThan(b2)
  })

  test("backoff is capped — a long outage cannot produce an unbounded delay", () => {
    const huge = backoffSeconds(999, interval)
    expect(huge).toBeLessThanOrEqual(6 * 3600)
    expect(Number.isFinite(huge)).toBe(true)
  })

  test("first backoff is never shorter than a few minutes (no hammering)", () => {
    expect(backoffSeconds(1, 60)).toBeGreaterThanOrEqual(5 * 60)
  })
})

describe("Batch bounds (item 26) — cost protection", () => {
  const KEY = "EXPOSURE_MONITOR_MAX_ASSETS_PER_RUN"
  const saved = process.env[KEY]
  const restore = () => { if (saved === undefined) delete process.env[KEY]; else process.env[KEY] = saved }

  test("defaults to a small conservative batch", () => {
    delete process.env[KEY]
    try { expect(maxAssetsPerRun()).toBe(5) } finally { restore() }
  })

  test("configurable via environment", () => {
    process.env[KEY] = "3"
    try { expect(maxAssetsPerRun()).toBe(3) } finally { restore() }
  })

  test("an absurd value is clamped — config cannot exhaust provider quota", () => {
    process.env[KEY] = "100000"
    try { expect(maxAssetsPerRun()).toBeLessThanOrEqual(25) } finally { restore() }
  })

  test("garbage config falls back to the safe default rather than 0 or NaN", () => {
    process.env[KEY] = "not-a-number"
    try { expect(maxAssetsPerRun()).toBe(5) } finally { restore() }
    process.env[KEY] = "-5"
    try { expect(maxAssetsPerRun()).toBe(5) } finally { restore() }
  })
})

describe("Intervals are configurable, not hardcoded (item 4)", () => {
  test("the documented cadences exist and are expressed in seconds", () => {
    expect(MONITORING_INTERVALS.hourly).toBe(3600)
    expect(MONITORING_INTERVALS.every6h).toBe(6 * 3600)
    expect(MONITORING_INTERVALS.daily).toBe(24 * 3600)
    expect(MONITORING_INTERVALS.weekly).toBe(7 * 24 * 3600)
  })

  test("the default is conservative (not every-5-minutes)", () => {
    expect(DEFAULT_INTERVAL_SECONDS).toBe(MONITORING_INTERVALS.every6h)
    expect(DEFAULT_INTERVAL_SECONDS).toBeGreaterThanOrEqual(3600)
  })
})

describe("Credential containment — error text is a real egress path", () => {
  const KEY = "FOFA_API_KEY"
  const saved = process.env[KEY]
  const restore = () => { if (saved === undefined) delete process.env[KEY]; else process.env[KEY] = saved }

  test("an exact credential value never survives into a message", () => {
    process.env[KEY] = "abcdef0123456789abcdef0123456789"
    try {
      // FOFA authenticates through the query string, so any message quoting the
      // request URL carries the key. Both passes fire here: the value is
      // replaced, then the query-param pass relabels it — either way the
      // secret is gone, which is the property that matters.
      const leaked = "Network error: request to https://fofa.info/api/v1/search/all?email=a@b.c&key=abcdef0123456789abcdef0123456789 failed"
      const safe = redactSecrets(leaked)
      expect(safe).not.toContain("abcdef0123456789abcdef0123456789")
      expect(safe).toContain("[redacted]")

      // Outside a URL there is no parameter to strip, so the env-name marker
      // is what identifies WHICH credential leaked.
      const bare = redactSecrets("provider rejected token abcdef0123456789abcdef0123456789 outright")
      expect(bare).not.toContain("abcdef0123456789abcdef0123456789")
      expect(bare).toContain("[FOFA_API_KEY]")
    } finally { restore() }
  })

  test("sensitive query parameters are stripped even when the value is unknown to us", () => {
    // A credential that never came from our env (rotated key, another tenant)
    // must still not be echoed back out of an error body.
    const safe = redactSecrets("provider said: GET /v1/search?token=SOMETHING_SECRET_XYZ&q=nginx failed")
    expect(safe).not.toContain("SOMETHING_SECRET_XYZ")
    expect(safe).toContain("[redacted]")
    expect(safe).toContain("q=nginx") // non-sensitive params are preserved
  })

  test("ordinary error text is left intact", () => {
    const msg = "HTTP 422 — provider rejected this query shape."
    expect(redactSecrets(msg)).toBe(msg)
  })

  test("a short or empty credential value cannot blank out the whole message", () => {
    process.env[KEY] = "x"
    try { expect(redactSecrets("an error mentioning x elsewhere")).toContain("elsewhere") }
    finally { restore() }
  })

  test("the monitoring module redacts before persisting", async () => {
    const src = await Bun.file("lib/exposure/monitoring.ts").text()
    expect(src).toContain("redactSecrets")
  })
})

describe("Architecture invariants — one implementation of everything", () => {
  test("the scheduler calls refreshAsset, it does not re-implement provider orchestration", async () => {
    const src = await Bun.file("lib/exposure/monitoring.ts").text()
    expect(src).toContain("refreshAsset")
    // It must never talk to providers or the quota table directly.
    expect(src).not.toContain("https://")
    expect(src).not.toMatch(/fetch\(/)
    expect(src).not.toContain("reserveQuota(")   // quota lives inside the adapters
    expect(src).not.toContain("detectChanges(")  // snapshots live in recordAssetChanges
  })

  test("the scheduler never touches provider credentials", async () => {
    const src = await Bun.file("lib/exposure/monitoring.ts").text()
    for (const k of ["CENSYS_API_TOKEN", "LEAKIX_API_KEY", "NETLAS_API_KEY", "FOFA_API_KEY", "ZOOMEYE_API_KEY", "GREYNOISE_API_KEY"]) {
      expect(src).not.toContain(k)
    }
  })

  test("no in-memory scheduling primitives — the runtime is serverless", async () => {
    const src = await Bun.file("lib/exposure/monitoring.ts").text()
    expect(src).not.toMatch(/setInterval\(/)
    expect(src).not.toMatch(/setTimeout\(/)
  })

  test("claiming uses SKIP LOCKED so two invocations cannot take the same asset", async () => {
    const src = await Bun.file("lib/exposure/monitoring.ts").text()
    expect(src).toContain("FOR UPDATE SKIP LOCKED")
  })

  test("the scheduler endpoint is authenticated with the existing cron secret", async () => {
    const src = await Bun.file("app/api/exposure/monitoring/run/route.ts").text()
    expect(src).toContain("authorized(req)")
    expect(src).toContain("401")
    // It must NOT be reachable without the secret.
    expect(src).not.toMatch(/export async function (GET|POST)[^)]*\)\s*\{\s*const result/)
  })

  test("manual refresh refuses to run while the scheduler holds the asset", async () => {
    const src = await Bun.file("app/api/exposure/refresh/route.ts").text()
    expect(src).toContain("isAssetLocked")
    expect(src).toContain("already in progress")
    expect(src).toContain("409")
  })
})
