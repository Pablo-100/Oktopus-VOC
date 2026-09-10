/**
 * FRESHNESS & CHANGE DETECTION (data-lifecycle audit).
 *
 * The invariant these protect:
 *
 *   `fetchedAt` (when OCTUPUS retrieved) and `observedAt` (when the PROVIDER
 *   saw the host) are different facts and must never be collapsed. Measured
 *   during the audit: LeakIX observations ~98 days old, Netlas 9–42 days,
 *   Censys ~0.1–0.4 days. Presenting any of that as "real-time" would be false.
 */
import { describe, test, expect } from "bun:test"
import { correlate } from "@/lib/exposure/correlate"
import { makeFreshness, freshnessStateFor, FRESHNESS_THRESHOLDS } from "@/lib/exposure/types"
import { detectChanges, snapshotOf, isEscalation, type AssetSnapshot } from "@/lib/exposure/changes"
import { PROVIDER_CAPABILITIES, capabilityFor } from "@/lib/exposure/capabilities"
import { makeVulnerability } from "@/lib/exposure/normalize"
import { netlasObservedAt, netlasScanWindow } from "@/lib/exposure/providers/netlas"
import type { ExposureAsset, ExposureService, ProviderName, ProviderObservation } from "@/lib/exposure/types"

const HOUR = 3600
const DAY = 24 * HOUR
/** Milliseconds helpers — Date.now() is ms, while HOUR/DAY above are SECONDS
 *  (they feed freshnessStateFor). Keeping the units explicit avoids the classic
 *  off-by-1000 that makes a 10-day-old timestamp look 14 minutes old. */
const MS_HOUR = HOUR * 1000
const MS_DAY = DAY * 1000

function obs(provider: ProviderName | null, ip: string, over: Partial<ProviderObservation> = {}): ProviderObservation {
  return {
    provider, ip, domain: null, hostname: null, asn: null, organization: null,
    country: null, city: null, latitude: null, longitude: null,
    services: [], technologies: [], certificates: [], vulnerabilities: [],
    notes: null, firstSeen: null, lastSeen: null, observedAt: null, raw: null,
    ...over,
  }
}

function svc(port: number, source: ProviderName, product: string | null = null, version: string | null = null): ExposureService {
  return {
    port, transport: "tcp", protocol: null, product, vendor: null, version,
    banner: null, httpStatus: null, httpTitle: null, httpServer: null,
    sources: [source], claims: [{ source, product, vendor: null, version, protocol: null }],
  }
}

describe("fetchedAt vs observedAt are never conflated", () => {
  test("a 10-day-old provider observation is NOT reported as fresh just because we fetched now", () => {
    const observedAt = new Date(Date.now() - 10 * MS_DAY).toISOString()
    const f = makeFreshness(observedAt)
    expect(f.observedAt).toBe(observedAt)
    // fetchedAt is ~now, but the STATE is driven by the observation age.
    expect(Date.now() - Date.parse(f.fetchedAt)).toBeLessThan(5000)
    expect(f.state).toBe("stale")
    expect(f.observationAgeSeconds).toBeGreaterThan(9 * DAY)
  })

  test("a provider supplying NO timestamp yields state 'unknown', never a fabricated one", () => {
    const f = makeFreshness(null)
    expect(f.observedAt).toBeNull()
    expect(f.observationAgeSeconds).toBeNull()
    expect(f.state).toBe("unknown")
    // Critically: fetchedAt must NOT be copied into observedAt.
    expect(f.observedAt).not.toBe(f.fetchedAt)
  })

  test("an unparseable provider timestamp degrades to unknown rather than throwing", () => {
    const f = makeFreshness("not-a-date")
    expect(f.state).toBe("unknown")
    expect(f.observedAt).toBeNull()
  })

  test("state thresholds key off observation age only", () => {
    expect(freshnessStateFor(null)).toBe("unknown")
    expect(freshnessStateFor(HOUR)).toBe("fresh")
    expect(freshnessStateFor(FRESHNESS_THRESHOLDS.freshSeconds - 1)).toBe("fresh")
    expect(freshnessStateFor(FRESHNESS_THRESHOLDS.freshSeconds + 1)).toBe("recent")
    expect(freshnessStateFor(FRESHNESS_THRESHOLDS.recentSeconds + 1)).toBe("stale")
    // The real measured ages from the audit:
    expect(freshnessStateFor(98 * DAY)).toBe("stale")  // LeakIX
    expect(freshnessStateFor(20 * DAY)).toBe("stale")  // Netlas
    expect(freshnessStateFor(6 * HOUR)).toBe("fresh")  // Censys
  })

  test("'live' is never produced by the freshness calculator", () => {
    // No configured provider scans on demand, so `live` must be unreachable.
    const samples = [null, 0, 1, HOUR, DAY, 30 * DAY, 365 * DAY]
    for (const s of samples) expect(freshnessStateFor(s)).not.toBe("live")
  })
})

describe("Correlation propagates provider observation times", () => {
  test("asset freshness reflects the FRESHEST provider observation", () => {
    const old = new Date(Date.now() - 90 * MS_DAY).toISOString()
    const recent = new Date(Date.now() - 2 * MS_HOUR).toISOString()
    const [a] = correlate([
      obs("leakix", "203.0.113.20", { observedAt: old }),
      obs("censys", "203.0.113.20", { observedAt: recent }),
    ])
    expect(a.freshness?.observedAt).toBe(recent)
    expect(a.freshness?.state).toBe("fresh")
  })

  test("per-provider freshness keeps the stale contributor visible", () => {
    const old = new Date(Date.now() - 90 * MS_DAY).toISOString()
    const recent = new Date(Date.now() - 2 * MS_HOUR).toISOString()
    const [a] = correlate([
      obs("leakix", "203.0.113.21", { observedAt: old }),
      obs("censys", "203.0.113.21", { observedAt: recent }),
    ])
    const leakix = a.providerFreshness?.find((p) => p.provider === "leakix")
    const censys = a.providerFreshness?.find((p) => p.provider === "censys")
    expect(leakix?.freshness.state).toBe("stale")   // not hidden by the aggregate
    expect(censys?.freshness.state).toBe("fresh")
  })

  test("a provider with a real timestamp outranks one with none", () => {
    const recent = new Date(Date.now() - 1 * MS_HOUR).toISOString()
    const [a] = correlate([
      obs("fofa", "203.0.113.22"),                        // no timestamp
      obs("censys", "203.0.113.22", { observedAt: recent }),
    ])
    // "unknown" must never win over a real measurement.
    expect(a.freshness?.observedAt).toBe(recent)
    expect(a.freshness?.state).toBe("fresh")
  })

  test("when NO provider supplies a timestamp the asset freshness is unknown", () => {
    const [a] = correlate([obs("fofa", "203.0.113.23"), obs("zoomeye", "203.0.113.23")])
    expect(a.freshness?.state).toBe("unknown")
    expect(a.freshness?.observedAt).toBeNull()
  })

  test("a query-target contributes no freshness (it is not an observation)", () => {
    const [a] = correlate([obs(null, "203.0.113.24", { origin: "query-target" })])
    expect(a.providerFreshness ?? []).toHaveLength(0)
    expect(a.freshness).toBeNull()
  })
})

describe("Change detection", () => {
  const base = (over: Partial<ExposureAsset> = {}): ExposureAsset => ({
    id: "ip:203.0.113.30", ip: "203.0.113.30", domain: null, domains: [], hostnames: [],
    asn: null, organization: null, country: null, city: null, latitude: null, longitude: null,
    services: [], technologies: [], certificates: [], vulnerabilities: [], threat: null,
    sources: ["censys"], sourceCount: 1, confidence: "low", confidenceScore: 12, evidence: [],
    enrichmentStatus: "enriched", isQueryTarget: false,
    firstSeen: null, lastSeen: null, exposureRisk: null, raw: [], ...over,
  })

  test("FIRST observation produces no changes (nothing actually changed)", () => {
    const current = snapshotOf(base({ services: [svc(443, "censys", "nginx")] }))
    expect(detectChanges(null, current)).toEqual([])
  })

  test("a new service is detected with its port and product", () => {
    const before = snapshotOf(base({ services: [svc(80, "censys", "Apache", "2.4.49")] }))
    const after = snapshotOf(base({ services: [svc(80, "censys", "Apache", "2.4.49"), svc(443, "censys", "nginx", "1.24")] }))
    const changes = detectChanges(before, after)
    const added = changes.find((c) => c.kind === "service_added")
    expect(added).toBeTruthy()
    expect(added!.detail).toContain("443")
    expect(added!.detail).toContain("nginx")
  })

  test("a closed port is detected as service_removed", () => {
    const before = snapshotOf(base({ services: [svc(80, "censys"), svc(443, "censys")] }))
    const after = snapshotOf(base({ services: [svc(80, "censys")] }))
    expect(detectChanges(before, after).some((c) => c.kind === "service_removed" && c.detail.includes("443"))).toBe(true)
  })

  test("a version bump on a stable product reports version_changed, not product_changed", () => {
    const before = snapshotOf(base({ services: [svc(443, "censys", "Apache", "2.4.49")] }))
    const after = snapshotOf(base({ services: [svc(443, "censys", "Apache", "2.4.62")] }))
    const changes = detectChanges(before, after)
    expect(changes.some((c) => c.kind === "version_changed")).toBe(true)
    expect(changes.some((c) => c.kind === "product_changed")).toBe(false)
  })

  test("a new CVE and a provider appearing are both first-class events", () => {
    const before = snapshotOf(base())
    const after = snapshotOf(base({
      vulnerabilities: [makeVulnerability({ cveId: "CVE-2021-41773", matchType: "version", sources: ["netlas"] })],
      sources: ["censys", "netlas"], sourceCount: 2,
    }))
    const changes = detectChanges(before, after)
    expect(changes.some((c) => c.kind === "vulnerability_added" && c.detail === "CVE-2021-41773")).toBe(true)
    expect(changes.some((c) => c.kind === "provider_appeared" && c.detail === "netlas")).toBe(true)
  })

  test("a risk change is REPORTED, carrying before and after", () => {
    const before: AssetSnapshot = { ...snapshotOf(base()), riskScore: 42 }
    const after: AssetSnapshot = { ...snapshotOf(base()), riskScore: 67 }
    const c = detectChanges(before, after).find((x) => x.kind === "risk_changed")
    expect(c).toBeTruthy()
    expect(c!.before).toBe("42")
    expect(c!.after).toBe("67")
  })

  test("an identical snapshot yields zero changes (no phantom events)", () => {
    const snap = snapshotOf(base({ services: [svc(443, "censys", "nginx", "1.24")], domains: ["a.example"] }))
    expect(detectChanges(snap, snap)).toEqual([])
  })

  test("escalations are distinguishable from reductions", () => {
    expect(isEscalation({ kind: "service_added", detail: "443/tcp" })).toBe(true)
    expect(isEscalation({ kind: "vulnerability_added", detail: "CVE-x" })).toBe(true)
    expect(isEscalation({ kind: "risk_changed", detail: "", before: "10", after: "80" })).toBe(true)
    expect(isEscalation({ kind: "risk_changed", detail: "", before: "80", after: "10" })).toBe(false)
    expect(isEscalation({ kind: "service_removed", detail: "443/tcp" })).toBe(false)
  })

  test("the snapshot stores only normalized fields — no raw provider payloads", () => {
    const asset = base({ services: [svc(443, "censys", "nginx")], raw: [{ provider: "censys", data: { huge: "x".repeat(10000) } }] })
    const snap = snapshotOf(asset)
    expect(JSON.stringify(snap)).not.toContain("xxxxxxxxxx")
    expect(Object.keys(snap).sort()).toEqual(["certificateFingerprints", "cveIds", "domains", "riskScore", "services", "sources"])
  })
})

describe("Provider capability matrix is honest", () => {
  test("every configured provider has a capability entry", () => {
    const names: ProviderName[] = ["censys", "leakix", "netlas", "fofa", "zoomeye", "greynoise"]
    for (const n of names) expect(capabilityFor(n)).toBeTruthy()
  })

  test("a provider claiming an observation timestamp must name the field it reads", () => {
    for (const c of PROVIDER_CAPABILITIES) {
      if (c.observationTimestamp) expect(c.observationTimestampField).toBeTruthy()
      else expect(c.observationTimestampField).toBeNull()
    }
  })

  test("providers we verified as timestamp-bearing are marked so", () => {
    expect(capabilityFor("leakix")!.observationTimestamp).toBe(true)
    expect(capabilityFor("censys")!.observationTimestamp).toBe(true)
    expect(capabilityFor("netlas")!.observationTimestamp).toBe(true)
    // FOFA/ZoomEye were never reachable, so we must NOT claim a capability.
    expect(capabilityFor("fofa")!.observationTimestamp).toBe(false)
    expect(capabilityFor("zoomeye")!.observationTimestamp).toBe(false)
  })

  test("no provider claims search where the adapter cannot search", () => {
    // Verified live: Censys search is 403 without a paid org, Netlas search 400.
    expect(capabilityFor("censys")!.search).toBe(false)
    expect(capabilityFor("netlas")!.search).toBe(false)
    expect(capabilityFor("leakix")!.search).toBe(true)
  })

  test("LeakIX must not claim CVE search (verified to return unrelated hosts)", () => {
    expect(capabilityFor("leakix")!.cveSearch).toBe(false)
  })
})

describe("Netlas scan windows must not overstate freshness", () => {
  /**
   * Captured live 2026-08-31. `source[]` is a scan CAMPAIGN, not a per-host
   * probe: campaign 959 ran for ten days, and two unrelated hosts returned the
   * identical `scan_ended_at` to the millisecond because they came from the
   * same batch. Reporting the END made every Netlas asset look FRESH forever.
   */
  const CAMPAIGN = {
    source: [{
      scan_label: "2026-08-21",
      scan_started_at: "2026-08-21T00:00:00Z",
      scan_ended_at: "2026-08-31T00:39:57.754000Z",
    }],
  }

  test("the observation time is the window START, not the end", () => {
    // The host was seen at some unknown point inside the window; the start is
    // the only bound that cannot claim the data is fresher than it is.
    expect(netlasObservedAt(CAMPAIGN)).toBe("2026-08-21T00:00:00.000Z")
    expect(netlasObservedAt(CAMPAIGN)).not.toBe("2026-08-31T00:39:57.754Z")
  })

  test("a ten-day-old campaign is reported as STALE, not FRESH", () => {
    const observedAt = netlasObservedAt(CAMPAIGN)!
    const ageSeconds = (Date.parse("2026-08-31T00:43:00Z") - Date.parse(observedAt)) / 1000
    expect(freshnessStateFor(ageSeconds)).toBe("stale")
  })

  test("the full window is preserved so the uncertainty stays visible", () => {
    const w = netlasScanWindow(CAMPAIGN)
    expect(w.start).toBe("2026-08-21T00:00:00.000Z")
    expect(w.end).toBe("2026-08-31T00:39:57.754Z")
  })

  test("the most recent campaign wins, and its OWN start is used", () => {
    const two = {
      source: [
        { scan_started_at: "2026-01-01T00:00:00Z", scan_ended_at: "2026-01-10T00:00:00Z" },
        { scan_started_at: "2026-08-21T00:00:00Z", scan_ended_at: "2026-08-31T00:00:00Z" },
      ],
    }
    // Not the older campaign's start, and not the newer campaign's end.
    expect(netlasObservedAt(two)).toBe("2026-08-21T00:00:00.000Z")
  })

  test("no scan metadata yields null, which surfaces as UNKNOWN rather than a guess", () => {
    expect(netlasObservedAt({})).toBeNull()
    expect(netlasObservedAt(undefined)).toBeNull()
    expect(freshnessStateFor(null)).toBe("unknown")
  })

  test("a campaign with only an end still reports something rather than nothing", () => {
    expect(netlasObservedAt({ source: [{ scan_ended_at: "2026-08-31T00:00:00Z" }] })).toBe("2026-08-31T00:00:00.000Z")
  })
})
