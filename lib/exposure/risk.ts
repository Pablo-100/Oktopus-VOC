/**
 * Exposure-aware risk.
 *
 * DESIGN RULE: this does not replace or fork the RBVM engine. `computeRiskScore`
 * in lib/risk-engine.ts stays the single source of truth for CVE risk
 * (CVSS 40% + EPSS 40% + KEV 20%); this module takes that score as `baseRbvm`
 * and applies a documented, itemised multiplier for real-world exposure
 * evidence. Every contribution is returned in `factors[]` so the final number
 * is auditable rather than a black box.
 *
 *   exposureRisk = min(100, baseRbvm x exposureFactor)
 *   exposureFactor = 1.0 + sum(evidence bonuses)   (capped at 1.60)
 *
 * Rationale for the cap: exposure should be able to escalate a genuinely
 * dangerous CVE into "fix this now" territory, but must never manufacture a
 * critical out of a low-severity flaw — a 10.0-RBVM bug on an exposed host is
 * still a 16 at most, which stays Low. Exposure amplifies risk; it is not risk
 * by itself.
 */
import { computeRiskScore } from "@/lib/risk-engine"
import type { EvidenceTier, ExposureAsset, ExposureRisk } from "@/lib/exposure/types"

/** Authoritative CVE facts, sourced from OCTUPUS's own `cves` table — never from an EASM provider. */
export interface CveFacts {
  cveId: string
  cvss: number | null
  epss: number | null
  isKev: boolean
  hasExploit: boolean
}

const MAX_FACTOR = 1.6

/**
 * How much a CVE's own RBVM score counts, given HOW the CVE was linked to this
 * asset. Without this, a `pivot` lead ("this CVE affects a product we think we
 * saw here") scored identically to a provider directly confirming the host is
 * affected — observed live: a Cloudflare load balancer reached risk 100
 * CRITICAL off a Log4Shell product-name pivot.
 *
 * Evidence quality must gate risk, not just decorate it.
 */
const MATCH_QUALITY: Record<EvidenceTier, number> = {
  confirmed: 1.0,  // a provider, queried by CVE id, returned this host
  strong: 1.0,     // affected VERSION fingerprinted here
  product: 0.55,   // product name only — may not be an affected build
  weak: 0.5,       // banner/heuristic inference
  pivot: 0.3,      // locally derived lead, NOT confirmation
}

/**
 * Tiers permitted to escalate risk on KEV / public-exploit signals.
 *
 * Deliberately excludes `product`, `pivot` and `weak`: KEV means "this CVE is
 * exploited in the wild", which only raises THIS host's risk if we have real
 * evidence this host runs the affected build. Letting a product-name guess
 * inherit a KEV escalation is how a load balancer became a CRITICAL incident.
 */
const ESCALATION_TIERS: ReadonlySet<EvidenceTier> = new Set<EvidenceTier>(["confirmed", "strong"])

/** SLA mirrors the existing dashboard policy, including the KEV 24h override. */
function slaFor(severity: ExposureRisk["severity"], anyKev: boolean): number {
  if (anyKev) return 24
  switch (severity) {
    case "critical": return 24
    case "high": return 72
    case "medium": return 24 * 7
    default: return 24 * 30
  }
}

function severityFor(score: number): ExposureRisk["severity"] {
  if (score >= 75) return "critical"
  if (score >= 50) return "high"
  if (score >= 25) return "medium"
  return "low"
}

/**
 * Compute exposure-adjusted risk for one correlated asset.
 * `factsByCve` supplies authoritative CVSS/EPSS/KEV from the existing pipeline;
 * a CVE absent from it contributes only what the EASM provider asserted, and
 * that weaker evidence is reflected in the match-quality factor.
 */
export function computeExposureRisk(asset: ExposureAsset, factsByCve: Map<string, CveFacts>): ExposureRisk {
  const factors: ExposureRisk["factors"] = []

  // 1. Base: the worst RBVM score among this asset's correlated CVEs.
  let baseRbvm = 0
  let anyKev = false
  let anyExploit = false
  const scored: Array<{ cveId: string; score: number }> = []

  let weakestOnly = true // true while every CVE link is a mere pivot/product lead
  for (const v of asset.vulnerabilities) {
    const facts = factsByCve.get(v.cveId)
    let raw: number
    if (facts) {
      raw = computeRiskScore(facts.cvss, facts.epss, facts.isKev)
    } else {
      // No authoritative record — fall back to the provider's own score, and
      // deliberately do NOT infer KEV/exploit from an EASM provider.
      raw = computeRiskScore(v.providerScore ?? null, null, false)
    }
    // Keyed off the EXPLICIT evidence tier, not re-derived from matchType.
    const tier = v.evidenceTier ?? "weak"
    const quality = MATCH_QUALITY[tier] ?? 0.5
    const score = Math.round(raw * quality * 10) / 10

    // KEV/exploit escalation requires evidence the host really runs the
    // affected build — a product-name match or pivot is not that.
    if (ESCALATION_TIERS.has(tier)) {
      weakestOnly = false
      if (facts?.isKev) anyKev = true
      if (facts?.hasExploit) anyExploit = true
    }
    scored.push({ cveId: v.cveId, score })
    if (score > baseRbvm) baseRbvm = score
  }
  scored.sort((a, b) => b.score - a.score)

  if (baseRbvm > 0 && weakestOnly) {
    factors.push({
      label: "Potential match only",
      delta: 0,
      detail: "Every CVE here is linked by product name or local pivot, not by a confirmed version or provider CVE hit — treat as a lead to verify, not a confirmed finding.",
    })
  }

  if (baseRbvm === 0) {
    // No known vulnerability: exposure alone is not a vulnerability finding.
    return {
      score: 0, severity: "low", baseRbvm: 0, exposureFactor: 1,
      factors: [{ label: "No correlated CVE", delta: 0, detail: "Asset is exposed but no vulnerability was matched to it." }],
      slaHours: slaFor("low", false), drivingCves: [],
    }
  }
  const topTier = asset.vulnerabilities.find((v) => v.cveId === scored[0].cveId)?.evidenceTier ?? "weak"
  factors.push({
    label: "Base RBVM",
    delta: baseRbvm,
    detail: `Highest CVE risk on this asset (${scored[0].cveId}), weighted ×${MATCH_QUALITY[topTier] ?? 0.5} for "${topTier}" evidence`,
  })

  // 2. Exposure evidence multipliers.
  let factor = 1
  if (asset.services.length > 0) {
    factor += 0.15
    factors.push({ label: "Internet-facing service", delta: 0.15, detail: `${asset.services.length} exposed service(s) observed` })
  }
  if (asset.sourceCount >= 3) {
    factor += 0.12
    factors.push({ label: "Multi-provider confirmation", delta: 0.12, detail: `${asset.sourceCount} independent providers confirm this asset` })
  } else if (asset.sourceCount === 2) {
    factor += 0.06
    factors.push({ label: "Corroborated exposure", delta: 0.06, detail: "2 independent providers confirm this asset" })
  }
  if (anyKev) {
    factor += 0.15
    factors.push({ label: "CISA KEV", delta: 0.15, detail: "A CVE on this asset is in the KEV catalogue — confirmed exploited in the wild" })
  }
  if (anyExploit) {
    factor += 0.08
    factors.push({ label: "Public exploit", delta: 0.08, detail: "Exploit code is publicly referenced for a CVE on this asset" })
  }
  // Version-level matches are real evidence the vulnerable build is running;
  // product-name-only matches are not, and must not inflate risk.
  if (asset.vulnerabilities.some((v) => v.matchType === "version")) {
    factor += 0.10
    factors.push({ label: "Version-confirmed match", delta: 0.10, detail: "A vulnerable product VERSION was fingerprinted, not just the product name" })
  }
  // GreyNoise: malicious scanning observed against/from this host.
  if (asset.threat?.classification === "malicious") {
    factor += 0.10
    factors.push({ label: "Malicious activity (GreyNoise)", delta: 0.10, detail: "GreyNoise classifies this IP as malicious" })
  } else if (asset.threat?.noise) {
    factor += 0.04
    factors.push({ label: "Observed scanning (GreyNoise)", delta: 0.04, detail: "GreyNoise has observed this IP participating in internet scanning" })
  }
  // Low-confidence correlation should not drive an incident.
  if (asset.confidence === "low") {
    factor -= 0.10
    factors.push({ label: "Low correlation confidence", delta: -0.10, detail: "Weak evidence linking these observations — treat with caution" })
  }

  factor = Math.max(0.5, Math.min(MAX_FACTOR, factor))
  const score = Math.round(Math.min(100, baseRbvm * factor) * 10) / 10
  const severity = severityFor(score)

  return {
    score,
    severity,
    baseRbvm,
    exposureFactor: Math.round(factor * 100) / 100,
    factors,
    slaHours: slaFor(severity, anyKev),
    drivingCves: scored.slice(0, 5).map((s) => s.cveId),
  }
}
