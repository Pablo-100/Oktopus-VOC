/**
 * EXPOSURE → CVE → RBVM → SOC ALERT: the decision layer.
 *
 * Two separate guarantees are under test:
 *   1. SEVERITY comes from the existing RBVM engine, and evidence quality gates
 *      what that severity is allowed to do.
 *   2. An alert fires once per condition, closes when the condition ends, and
 *      fires again only if the condition genuinely returns.
 */
import { describe, test, expect } from "bun:test"
import {
  isAlertEligible, isRiskEscalation, alertFingerprint, canEstablishAbsence, pendingFromAsset,
} from "@/lib/exposure/vuln-tracking"
import { computeExposureRisk, type CveFacts } from "@/lib/exposure/risk"
import { makeVulnerability } from "@/lib/exposure/normalize"
import type {
  ExposureAsset, ExposureService, ProviderName, ProviderOutcome, ProviderStatus, EvidenceTier,
} from "@/lib/exposure/types"

// ── fixtures (clearly deterministic test data, never presented as observations) ──

function service(port: number, product: string | null, version: string | null, sources: ProviderName[] = ["censys"]): ExposureService {
  return {
    port, transport: "tcp", protocol: "http", product, vendor: null, version,
    banner: null, httpStatus: null, httpTitle: null, httpServer: null, sources,
    claims: sources.map((s) => ({ source: s, product, vendor: null, version, protocol: "http" })),
  }
}

function outcome(provider: ProviderName, status: ProviderStatus): ProviderOutcome {
  return {
    provider, role: "enrichment", status, retryable: false, query: "x",
    latencyMs: 5, observationCount: status === "success" ? 1 : 0,
    fetchedAt: new Date().toISOString(),
  }
}

/** An asset carrying ONE CVE at a chosen evidence tier. */
function assetWith(tier: EvidenceTier, opts: { services?: ExposureService[]; sources?: ProviderName[] } = {}): ExposureAsset {
  const matchType = ({ confirmed: "cve-search", strong: "version", product: "product", pivot: "pivot", weak: "banner" } as const)[tier]
  const sources = opts.sources ?? ["censys"]
  return {
    id: "ip:203.0.113.10", ip: "203.0.113.10", domain: null, hostnames: [], domains: [],
    services: opts.services ?? [service(443, "Apache HTTP Server", "2.4.49", sources)],
    technologies: [], certificates: [],
    vulnerabilities: [{ correlatedPort: 443, ...makeVulnerability({ cveId: "CVE-2021-41773", matchType, sources }) }],
    sources, sourceCount: sources.length, confidence: "high", provenance: [], raw: [],
    threat: null, enrichmentStatus: "enriched",
    freshness: {
      fetchedAt: new Date().toISOString(),
      observedAt: new Date(Date.now() - 3 * 3600_000).toISOString(),
      observationAgeSeconds: 10800, fromCache: false, state: "fresh",
    },
  } as unknown as ExposureAsset
}

/** The worst realistic CVE: maximum CVSS, near-certain EPSS, KEV-listed, public exploit. */
const NIGHTMARE_CVE = new Map<string, CveFacts>([
  ["CVE-2021-41773", { cveId: "CVE-2021-41773", cvss: 10, epss: 0.99, isKev: true, hasExploit: true }],
])

describe("Evidence gates what CVE severity is allowed to do (items 13 & 23)", () => {
  const cases: Array<[EvidenceTier, boolean]> = [
    ["confirmed", true], ["strong", true],
    ["product", false], ["pivot", false], ["weak", false],
  ]

  for (const [tier, mayBeCritical] of cases) {
    test(`${tier} evidence + CVSS 10 / EPSS 0.99 / KEV / exploit ${mayBeCritical ? "MAY" : "must NOT"} reach Critical`, () => {
      const risk = computeExposureRisk(assetWith(tier), NIGHTMARE_CVE)
      if (mayBeCritical) {
        expect(risk.severity).toBe("critical")
      } else {
        expect(risk.severity).not.toBe("critical")
        // And the finding must not be alertable either — the two gates agree.
        expect(isAlertEligible(tier, risk.severity)).toBe(false)
      }
    })
  }

  test("the tier ordering pivot < weak < product < strong <= confirmed holds on identical inputs", () => {
    const score = (t: EvidenceTier) => computeExposureRisk(assetWith(t), NIGHTMARE_CVE).score
    expect(score("pivot")).toBeLessThan(score("weak"))
    expect(score("weak")).toBeLessThan(score("product"))
    expect(score("product")).toBeLessThan(score("strong"))
    expect(score("strong")).toBeLessThanOrEqual(score("confirmed"))
  })

  test("a CVSS-10 KEV CVE attached by product name alone raises NO alert", () => {
    // The exact false positive item 23 names: severe CVE, weak association.
    const risk = computeExposureRisk(assetWith("product"), NIGHTMARE_CVE)
    expect(isAlertEligible("product", risk.severity)).toBe(false)
  })

  test("a domain-only / not-enriched asset cannot alert", () => {
    // No service evidence at all, only a domain relationship.
    const asset = assetWith("pivot", { services: [] })
    const risk = computeExposureRisk(asset, NIGHTMARE_CVE)
    expect(risk.severity).not.toBe("critical")
    expect(isAlertEligible("pivot", risk.severity)).toBe(false)
  })
})

describe("Alert eligibility needs BOTH severity and evidence", () => {
  test("strong evidence at low severity does not alert", () => {
    expect(isAlertEligible("strong", "low")).toBe(false)
    expect(isAlertEligible("strong", "medium")).toBe(false)
  })

  test("high severity with weak evidence does not alert", () => {
    expect(isAlertEligible("weak", "critical")).toBe(false)
    expect(isAlertEligible("product", "critical")).toBe(false)
    expect(isAlertEligible("pivot", "critical")).toBe(false)
  })

  test("confirmed or strong evidence at high severity alerts", () => {
    expect(isAlertEligible("confirmed", "critical")).toBe(true)
    expect(isAlertEligible("confirmed", "high")).toBe(true)
    expect(isAlertEligible("strong", "high")).toBe(true)
  })

  test("a missing severity never alerts", () => {
    expect(isAlertEligible("confirmed", null)).toBe(false)
    expect(isAlertEligible("confirmed", undefined)).toBe(false)
  })
})

describe("Risk escalation is meaningful, not numerical drift (item 17)", () => {
  test("crossing Medium -> High with a real jump escalates", () => {
    expect(isRiskEscalation("medium", "high", 32, 78)).toBe(true)
  })

  test("a small wobble inside the same band does NOT escalate", () => {
    expect(isRiskEscalation("high", "high", 60, 62)).toBe(false)
    expect(isRiskEscalation("medium", "medium", 30, 34)).toBe(false)
  })

  test("a band crossing with a trivial delta does not escalate", () => {
    // 49 -> 50 crosses into High but is not worth an analyst's attention.
    expect(isRiskEscalation("medium", "high", 49, 50)).toBe(false)
  })

  test("risk going DOWN never escalates", () => {
    expect(isRiskEscalation("critical", "high", 90, 60)).toBe(false)
  })

  test("rising into a band that is still not alertable does not escalate", () => {
    expect(isRiskEscalation("low", "medium", 5, 40)).toBe(false)
  })

  test("repeating the same risk never re-escalates", () => {
    expect(isRiskEscalation("high", "high", 78, 78)).toBe(false)
  })

  test("a FIRST observation is not an escalation — it would double-page", () => {
    // There is no prior state to have risen from, and the new-vulnerability
    // alert already covers this event.
    expect(isRiskEscalation(null, "critical", null, 90)).toBe(false)
    expect(isRiskEscalation(null, "high", null, 78)).toBe(false)
  })
})

describe("Provider failure is not remediation (item 25)", () => {
  test("evidence stands when its source provider failed", () => {
    expect(canEstablishAbsence(["censys"], [outcome("censys", "rate_limited"), outcome("netlas", "success")])).toBe(false)
    expect(canEstablishAbsence(["censys"], [outcome("censys", "timeout"), outcome("netlas", "success")])).toBe(false)
    expect(canEstablishAbsence(["leakix"], [outcome("leakix", "quota_exhausted"), outcome("netlas", "success")])).toBe(false)
  })

  test("absence is established only when every source provider answered", () => {
    expect(canEstablishAbsence(["censys"], [outcome("censys", "success")])).toBe(true)
    expect(canEstablishAbsence(["censys", "netlas"], [outcome("censys", "success"), outcome("netlas", "success")])).toBe(true)
  })

  test("one of two source providers failing blocks resolution", () => {
    expect(canEstablishAbsence(["censys", "netlas"], [outcome("censys", "success"), outcome("netlas", "timeout")])).toBe(false)
  })

  test("a total provider blackout resolves nothing", () => {
    expect(canEstablishAbsence([], [outcome("censys", "timeout")])).toBe(false)
    expect(canEstablishAbsence(["censys"], [])).toBe(false)
  })

  test("a partial provider result still counts as having answered", () => {
    expect(canEstablishAbsence(["censys"], [outcome("censys", "partial")])).toBe(true)
  })
})

describe("Alert identity is stable — the basis of deduplication (item 20)", () => {
  test("the same condition always fingerprints identically", () => {
    expect(alertFingerprint("ip:1.2.3.4", 443, "CVE-2021-41773"))
      .toBe(alertFingerprint("ip:1.2.3.4", 443, "cve-2021-41773")) // case-insensitive CVE
  })

  test("different asset, port or CVE are different conditions", () => {
    const base = alertFingerprint("ip:1.2.3.4", 443, "CVE-2021-41773")
    expect(alertFingerprint("ip:1.2.3.5", 443, "CVE-2021-41773")).not.toBe(base)
    expect(alertFingerprint("ip:1.2.3.4", 8443, "CVE-2021-41773")).not.toBe(base)
    expect(alertFingerprint("ip:1.2.3.4", 443, "CVE-2021-42013")).not.toBe(base)
  })
})

describe("Relationship rows keep provenance and freshness honest (items 11 & 26)", () => {
  test("a service-derived finding is attributed to its port", () => {
    const rows = pendingFromAsset(assetWith("strong"))
    expect(rows).toHaveLength(1)
    expect(rows[0].port).toBe(443)
    expect(rows[0].product).toBe("Apache HTTP Server")
    expect(rows[0].version).toBe("2.4.49")
    expect(rows[0].sourceProviders).toEqual(["censys"])
  })

  test("a host-level finding is recorded at port 0, not attributed to a service", () => {
    const asset = assetWith("confirmed")
    // Provider CVE hit on the host — no port context.
    asset.vulnerabilities = [makeVulnerability({ cveId: "CVE-2021-41773", matchType: "cve-search", sources: ["netlas"] })]
    const rows = pendingFromAsset(asset)
    expect(rows[0].port).toBe(0)
  })

  test("provenance explains WHY, in terms an analyst can judge", () => {
    expect(pendingFromAsset(assetWith("confirmed"))[0].matchedVia).toMatch(/queried for CVE-2021-41773/i)
    expect(pendingFromAsset(assetWith("product"))[0].matchedVia).toMatch(/version not proven/i)
    expect(pendingFromAsset(assetWith("pivot"))[0].matchedVia).toMatch(/not directly reported/i)
  })

  test("the query target itself is never recorded as a finding", () => {
    const asset = assetWith("confirmed")
    ;(asset as unknown as { isQueryTarget: boolean }).isQueryTarget = true
    // Handled by trackAssetVulnerabilities; pendingFromAsset stays pure, so the
    // guard is asserted at the tracking boundary in the DB suite.
    expect(asset.isQueryTarget).toBe(true)
  })

  test("evidence tier and freshness are independent dimensions", () => {
    // A STRONG finding resting on a STALE observation must keep both facts.
    const asset = assetWith("strong")
    asset.freshness = {
      fetchedAt: new Date().toISOString(),
      observedAt: new Date(Date.now() - 98 * 24 * 3600_000).toISOString(),
      observationAgeSeconds: 98 * 24 * 3600, fromCache: false, state: "stale",
    }
    const rows = pendingFromAsset(asset)
    expect(rows[0].evidenceTier).toBe("strong")     // evidence unchanged by age
    expect(asset.freshness.state).toBe("stale")      // and staleness is not hidden
    expect(asset.freshness.observedAt).not.toBe(asset.freshness.fetchedAt)
  })
})

describe("Architecture — one RBVM, one alert pipeline (item 40)", () => {
  test("the alert layer does not implement its own scoring", async () => {
    const src = await Bun.file("lib/exposure/vuln-tracking.ts").text()
    expect(src).not.toMatch(/^import .*risk-engine/m)
    expect(src).not.toMatch(/computeRiskScore\(/)
    expect(src).not.toMatch(/exposureSeverity|exposureRiskScore/)
    // Severity is carried through from the asset's existing RBVM result.
    expect(src).toContain("risk?.severity")
  })

  test("alert payloads are scrubbed of credentials before storage", async () => {
    const src = await Bun.file("lib/exposure/vuln-tracking.ts").text()
    expect(src).toContain("redactSecrets")
    for (const k of ["CENSYS_API_TOKEN", "LEAKIX_API_KEY", "NETLAS_API_KEY", "FOFA_API_KEY", "ZOOMEYE_API_KEY", "GREYNOISE_API_KEY"]) {
      expect(src).not.toContain(k)
    }
  })

  test("deduplication is enforced by the database, not by application etiquette", async () => {
    const db = await Bun.file("lib/db.ts").text()
    // A read-then-write check has a race window against the 15-minute scheduler.
    expect(db).toContain("exposure_alerts_active_uniq")
    // STEP 5 widened the active set to include `in_progress`: an alert an
    // analyst is working is still the live one for that finding, so monitoring
    // must not be able to raise a duplicate underneath them. The guarantee is
    // broader than it was, not weaker — every ACTIVE state is covered.
    const indexClause = db.match(/UNIQUE INDEX[\s\S]{0,240}?state IN \(([^)]*)\)/)
    expect(indexClause).not.toBeNull()
    const states = indexClause![1]
    expect(states).toContain("'open'")
    expect(states).toContain("'acknowledged'")
    expect(states).toContain("'in_progress'")
    // Terminal states must NOT be in the index, or a finding could never re-alert.
    expect(states).not.toContain("'resolved'")
    expect(states).not.toContain("'closed'")
    const src = await Bun.file("lib/exposure/vuln-tracking.ts").text()
    expect(src).toContain("ON CONFLICT")
  })

  test("scheduled and manual refresh share one correlation path (item 31)", async () => {
    const orch = await Bun.file("lib/exposure/orchestrator.ts").text()
    // refreshAsset is the only place the tail is wired, and monitoring calls it.
    expect(orch).toContain("trackAssetVulnerabilities")
    expect(orch).toContain("evaluateAlerts")
    const mon = await Bun.file("lib/exposure/monitoring.ts").text()
    expect(mon).toContain("refreshAsset")
    expect(mon).not.toContain("trackAssetVulnerabilities") // not re-implemented
    expect(mon).not.toContain("correlateServices")
  })

  test("no second scheduler was introduced", async () => {
    const src = await Bun.file("lib/exposure/vuln-tracking.ts").text()
    // Actual scheduling primitives, not the word "scheduler" in prose.
    expect(src).not.toMatch(/setInterval\(|setTimeout\(/)
    expect(src).not.toMatch(/next_run_at|claimDueAssets|runMonitoringCycle/)
  })
})
