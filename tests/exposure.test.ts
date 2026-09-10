/**
 * Provider query-builder tests for the consolidated `lib/exposure/` module.
 * No DB, no network.
 *
 * B1: this file previously tested `lib/exposure-providers.ts`, the parallel
 * EASM implementation that has since been removed. Coverage is preserved
 * against the surviving adapters so nothing was silently dropped in the merge.
 */
import { describe, test, expect } from "bun:test"
import { buildCensysQuery, buildCensysCveQuery } from "@/lib/exposure/providers/censys"
import { buildFofaQuery } from "@/lib/exposure/providers/fofa"
import { buildZoomeyeQuery } from "@/lib/exposure/providers/zoomeye"
import { providerConfiguration } from "@/lib/exposure/orchestrator"

describe("Query builders — per-vendor DSL", () => {
  test("Censys wraps the product in its services.software.product field", () => {
    expect(buildCensysQuery("Apache")).toBe('services.software.product="Apache"')
  })

  test("FOFA and ZoomEye use their app= product fields", () => {
    expect(buildFofaQuery("vCenter", "product")).toBe('app="vCenter"')
    expect(buildZoomeyeQuery("nginx", "product")).toBe('app="nginx"')
  })

  test("ip / domain / port map to the vendor's dedicated fields, not free text", () => {
    expect(buildFofaQuery("1.2.3.4", "ip")).toBe('ip="1.2.3.4"')
    expect(buildFofaQuery("example.com", "domain")).toBe('domain="example.com"')
    expect(buildFofaQuery("443", "port")).toBe('port="443"')
    expect(buildZoomeyeQuery("1.2.3.4", "ip")).toBe('ip="1.2.3.4"')
  })

  test("quoted DSLs escape embedded double quotes (no injection into vendor syntax)", () => {
    expect(buildCensysQuery('Foo"Bar')).toBe('services.software.product="Foo\\"Bar"')
    expect(buildFofaQuery('Foo"Bar', "product")).toBe('app="Foo\\"Bar"')
    expect(buildZoomeyeQuery('Foo"Bar', "product")).toBe('app="Foo\\"Bar"')
    expect(buildCensysCveQuery('CVE-2021"44228')).toBe('vulnerabilities.cve_id="CVE-2021\\"44228"')
  })
})

describe("providerConfiguration() — reflects env vars and declares roles", () => {
  // Every credential the configuration reads. A key missing from this list is
  // not cleared by clearAll(), so the "nothing configured" case would silently
  // test a half-configured environment instead.
  const KEYS = ["CENSYS_API_TOKEN", "LEAKIX_API_KEY", "NETLAS_API_KEY", "FOFA_EMAIL", "FOFA_API_KEY", "ZOOMEYE_API_KEY", "GREYNOISE_API_KEY", "SHODAN_API_KEY", "ABUSEIPDB_API_KEY"] as const
  const saved: Record<string, string | undefined> = {}
  for (const k of KEYS) saved[k] = process.env[k]
  const clearAll = () => { for (const k of KEYS) delete process.env[k] }
  const restore = () => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k] } }

  test("no keys set -> every provider reports unconfigured, and nothing throws", () => {
    clearAll()
    try {
      const cfg = providerConfiguration()
      // Asserted by name rather than by count alone: a bare number tells you a
      // provider was added but not which, and passes if one is swapped for
      // another.
      expect(cfg.map((c) => c.provider).sort()).toEqual(
        ["abuseipdb", "censys", "fofa", "greynoise", "leakix", "netlas", "shodan", "zoomeye"],
      )
      expect(cfg.every((c) => c.configured === false)).toBe(true)
    } finally { restore() }
  })

  test("FOFA requires BOTH email and key — one alone does not activate it", () => {
    clearAll()
    process.env.FOFA_API_KEY = "x"
    try {
      expect(providerConfiguration().find((c) => c.provider === "fofa")?.configured).toBe(false)
      process.env.FOFA_EMAIL = "a@b.com"
      expect(providerConfiguration().find((c) => c.provider === "fofa")?.configured).toBe(true)
    } finally { restore() }
  })

  test("each provider declares the role it is actually used for", () => {
    const roles = Object.fromEntries(providerConfiguration().map((c) => [c.provider, c.role]))
    expect(roles.leakix).toBe("discovery")
    expect(roles.fofa).toBe("discovery")
    expect(roles.zoomeye).toBe("discovery")
    expect(roles.censys).toBe("enrichment")
    expect(roles.netlas).toBe("enrichment")
    expect(roles.greynoise).toBe("threat")
    expect(roles.shodan).toBe("enrichment")
    // Reputation, not observation: AbuseIPDB must never be treated as a source
    // of what is running on a host.
    expect(roles.abuseipdb).toBe("threat")
  })
})
