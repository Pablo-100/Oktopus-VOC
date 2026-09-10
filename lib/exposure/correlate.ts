/**
 * Cross-provider correlation engine.
 *
 * Turns N provider observations into M canonical assets: the same real host
 * seen by Censys, Netlas, LeakIX and FOFA must become ONE asset carrying four
 * sources, not four duplicate rows.
 *
 * Merge policy — deliberately conservative, because a FALSE merge is worse than
 * a missed one (it would attribute one host's vulnerabilities to another):
 *
 *   MERGE on   exact IP            — globally unique at a point in time
 *   MERGE on   exact domain        — when neither side has an IP to contradict it
 *   MERGE on   cert fingerprint    — SHA-256 of the same cert implies same deployment
 *   NEVER merge on product/version/org/ASN alone — thousands of unrelated hosts
 *                                    share "Apache" or an ASN; that is a
 *                                    similarity signal, never an identity one.
 *
 * Confidence is evidence-weighted rather than a raw provider count: three
 * providers agreeing on an exact IP *and* the same open port is stronger
 * evidence than three providers that merely each saw the IP once.
 */
import type {
  ConfidenceLevel, CorrelationEvidence, ExposureAsset, ExposureCertificate, ExposureService,
  ExposureTechnology, ExposureVulnerability, ProviderName, ProviderObservation,
} from "@/lib/exposure/types"
import { syncEvidenceTier } from "@/lib/exposure/normalize"
import { makeFreshness, type Freshness } from "@/lib/exposure/types"

/**
 * The SINGLE identity key for one observation. Returns exactly one key (or
 * null) — never a set — which is what structurally prevents false merges.
 *
 * A1 REGRESSION GUARD. The previous implementation returned every identifier
 * as a co-equal key and union'd them together, so three different IPs behind
 * one domain (`example.com` -> 104.20.23.154 / 172.66.147.243 / 8.47.69.8)
 * collapsed into ONE asset and two hosts were silently destroyed. Any domain
 * on a CDN or load balancer hit this.
 *
 * Precedence, strongest first:
 *   1. IP           — globally unique at a point in time. When present it is
 *                     the ONLY identity; domain and certificate become
 *                     attributes, so two different IPs can never merge.
 *   2. domain       — only for observations that carry no IP at all.
 *   3. cert SHA-256 — only when there is neither IP nor domain.
 *
 * A certificate is deliberately NOT allowed to merge across IPs: the same
 * cert is routinely deployed on many load-balancer nodes, which are genuinely
 * distinct hosts. That costs us some true merges — acceptable, because a false
 * merge misattributes one host's vulnerabilities to another.
 */
function identityKey(o: ProviderObservation): string | null {
  if (o.ip?.trim()) return `ip:${o.ip.trim().toLowerCase()}`
  if (o.domain?.trim()) return `domain:${o.domain.trim().toLowerCase()}`
  for (const c of o.certificates) {
    if (c.fingerprint?.trim()) return `cert:${c.fingerprint.trim().toLowerCase()}`
  }
  return null
}

/**
 * Freshest observation across providers.
 *
 * A record WITH a provider timestamp always beats one without: "unknown" means
 * we have no evidence of age, which must never outrank a real measurement.
 * Returns a `fetchedAt`-only record when no provider supplied any timestamp —
 * honest "we retrieved this now, but nobody told us when they saw it".
 */
function freshestOf(entries: Array<{ provider: ProviderName; freshness: Freshness }>): Freshness | null {
  if (!entries.length) return null
  const withObserved = entries.filter((e) => e.freshness.observedAt)
  if (!withObserved.length) return makeFreshness(null, { fetchedAt: entries[0].freshness.fetchedAt })
  const best = withObserved.reduce((a, b) => (a.freshness.observedAt! > b.freshness.observedAt! ? a : b))
  return best.freshness
}

/** Normalize a product string for comparison only (display keeps the original). */
function normProduct(p?: string | null): string {
  return (p ?? "").trim().toLowerCase().replace(/[\s_-]+/g, "")
}

/**
 * Generic fingerprints that carry no vendor information. Censys reports these
 * for "something answered HTTP here", so they must not be treated as a real
 * product claim that contradicts a specific one like "Apache".
 */
const GENERIC_PRODUCTS = new Set(["httpserver", "http", "https", "server", "unknown", "authoritativeserver"])

/**
 * Merge services on the same port, PRESERVING every provider's claim (B3).
 *
 * The old `existing.product ??= svc.product` silently let whichever provider
 * happened to be merged first define the product, so a genuine disagreement
 * (Censys "http_server" vs LeakIX "Apache") became invisible. Conflicting
 * fingerprints matter: they change which CVEs a product matches.
 */
function mergeServices(target: ExposureService[], incoming: ExposureService[]): void {
  for (const svc of incoming) {
    // Match on port only — a provider labelling the same port "HTTP" vs "https"
    // is exactly the disagreement we want to record, not a reason to split.
    const existing = target.find((s) => s.port === svc.port)
    if (!existing) {
      target.push({ ...svc, sources: [...svc.sources], claims: [...(svc.claims ?? [])] })
      continue
    }
    for (const src of svc.sources) if (!existing.sources.includes(src)) existing.sources.push(src)
    for (const claim of svc.claims ?? []) {
      if (!existing.claims.some((c) => c.source === claim.source)) existing.claims.push(claim)
    }
    // Non-identifying fields: first non-null wins (no meaningful conflict).
    existing.banner ??= svc.banner
    existing.httpStatus ??= svc.httpStatus
    existing.httpTitle ??= svc.httpTitle
    existing.httpServer ??= svc.httpServer
    existing.transport ??= svc.transport
    existing.protocol ??= svc.protocol

    // Derive consensus + detect disagreement across the retained claims.
    const named = existing.claims.filter((c) => normProduct(c.product) && !GENERIC_PRODUCTS.has(normProduct(c.product)))
    const distinct = new Set(named.map((c) => normProduct(c.product)))
    existing.conflict = distinct.size > 1
    // Prefer a specific product over a generic one; otherwise keep the first specific claim.
    existing.product = named[0]?.product ?? existing.product ?? svc.product ?? null
    existing.vendor ??= svc.vendor
    // A version is only trustworthy when providers do not disagree on the product.
    const versions = new Set(existing.claims.map((c) => (c.version ?? "").trim()).filter(Boolean))
    if (versions.size > 1) existing.conflict = true
    existing.version ??= svc.version
  }
}

function mergeTechnologies(target: ExposureTechnology[], incoming: ExposureTechnology[]): void {
  for (const tech of incoming) {
    const existing = target.find((t) => t.name.toLowerCase() === tech.name.toLowerCase())
    if (!existing) {
      target.push({ ...tech, categories: [...tech.categories], sources: [...tech.sources] })
      continue
    }
    existing.version ??= tech.version
    for (const src of tech.sources) if (!existing.sources.includes(src)) existing.sources.push(src)
    for (const c of tech.categories) if (!existing.categories.includes(c)) existing.categories.push(c)
  }
}

function mergeCertificates(target: ExposureCertificate[], incoming: ExposureCertificate[]): void {
  for (const cert of incoming) {
    const existing = cert.fingerprint
      ? target.find((c) => c.fingerprint === cert.fingerprint)
      : target.find((c) => c.commonName && c.commonName === cert.commonName)
    if (!existing) {
      target.push({ ...cert, sans: [...cert.sans], sources: [...cert.sources] })
      continue
    }
    existing.commonName ??= cert.commonName
    existing.issuer ??= cert.issuer
    existing.fingerprint ??= cert.fingerprint
    existing.validFrom ??= cert.validFrom
    existing.validTo ??= cert.validTo
    existing.expired ??= cert.expired
    for (const s of cert.sans) if (!existing.sans.includes(s)) existing.sans.push(s)
    for (const src of cert.sources) if (!existing.sources.includes(src)) existing.sources.push(src)
  }
}

/**
 * Evidence strength for a CVE↔asset link, weakest to strongest. When two
 * providers link the same CVE, the STRONGEST evidence must survive the merge —
 * otherwise a locally-derived `pivot` lead could mask a provider's direct
 * `cve-search` assertion (or vice versa), which changes how an analyst triages.
 */
const MATCH_STRENGTH: Record<NonNullable<ExposureVulnerability["matchType"]>, number> = {
  unknown: 0,
  pivot: 1,
  product: 2,
  banner: 3,
  version: 4,
  "cve-search": 5,
}

function mergeVulnerabilities(target: ExposureVulnerability[], incoming: ExposureVulnerability[]): void {
  for (const v of incoming) {
    const existing = target.find((x) => x.cveId === v.cveId)
    if (!existing) {
      target.push({ ...v, sources: [...v.sources] })
      continue
    }
    for (const src of v.sources) if (!existing.sources.includes(src)) existing.sources.push(src)
    existing.providerScore ??= v.providerScore
    existing.providerSeverity ??= v.providerSeverity
    existing.matchedProduct ??= v.matchedProduct
    if (MATCH_STRENGTH[v.matchType ?? "unknown"] > MATCH_STRENGTH[existing.matchType ?? "unknown"]) {
      existing.matchType = v.matchType
      // Tier and `confirmed` must follow the promoted match type, never drift.
      syncEvidenceTier(existing)
    }
  }
}

/**
 * Evidence-weighted confidence.
 * Base: how many INDEPENDENT providers saw the asset.
 * Bonus: corroborating detail (agreeing services, certificate identity, deep enrichment).
 */
export function scoreConfidence(asset: ExposureAsset): { level: ConfidenceLevel; score: number } {
  // A2: an asset that exists only because the user searched for it has NO
  // evidence behind it. Zero, not "low" — there is nothing to be confident in.
  if (asset.sourceCount === 0) return { level: "low", score: 0 }

  let score = 0
  const n = asset.sourceCount
  if (n >= 4) score += 60
  else if (n === 3) score += 45
  else if (n === 2) score += 30
  else score += 12

  // Multiple providers agreeing on the SAME open port is much stronger than
  // merely both having heard of the IP.
  const corroboratedService = asset.services.some((s) => s.sources.length >= 2)
  if (corroboratedService) score += 18

  // A certificate fingerprint is a near-unique deployment identifier.
  if (asset.certificates.some((c) => c.fingerprint)) score += 10

  // Deep enrichment (ASN/org/geo resolved) means we truly identified the host.
  if (asset.asn != null || asset.organization) score += 6
  if (asset.services.length > 0) score += 6

  score = Math.min(100, score)
  const level: ConfidenceLevel = score >= 80 ? "very_high" : score >= 60 ? "high" : score >= 38 ? "medium" : "low"
  return { level, score }
}

/**
 * Correlate observations into canonical assets.
 *
 * Uses union-find over identity keys so a chain of observations (A shares an IP
 * with B, B shares a cert with C) collapses into one asset in a single pass.
 */
export function correlate(observations: ProviderObservation[]): ExposureAsset[] {
  // Grouping is now a direct bucket by single identity key. Union-find is gone
  // along with multi-key identity: with exactly one key per observation there
  // are no chains to resolve, and no path by which two different IPs could end
  // up in the same bucket (A1).
  const groups = new Map<string, ProviderObservation[]>()
  const orphans: ProviderObservation[] = []
  for (const o of observations) {
    const key = identityKey(o)
    if (!key) { orphans.push(o); continue }
    const g = groups.get(key) ?? []
    g.push(o)
    groups.set(key, g)
  }

  const assets: ExposureAsset[] = []
  for (const [key, group] of groups) {
    const sources: ProviderName[] = []
    const hostnames = new Set<string>()
    const domains = new Set<string>()
    const services: ExposureService[] = []
    const technologies: ExposureTechnology[] = []
    const certificates: ExposureCertificate[] = []
    const vulnerabilities: ExposureVulnerability[] = []
    const raw: Array<{ provider: ProviderName; data: unknown }> = []

    let ip: string | null = null
    let domain: string | null = null
    let asn: number | null = null
    let organization: string | null = null
    let country: string | null = null
    let city: string | null = null
    let latitude: number | null = null
    let longitude: number | null = null
    let firstSeen: string | null = null
    let lastSeen: string | null = null
    let sawProviderEvidence = false
    // Per-provider freshness, so an analyst can see WHICH source is stale
    // rather than only an aggregate.
    const providerFreshness: Array<{ provider: ProviderName; freshness: Freshness }> = []

    for (const o of group) {
      // A2: only real provider observations become evidence. A `query-target`
      // seed carries provider === null and must never inflate sources,
      // sourceCount, confidence or the provider-confirmation UI.
      if (o.provider) {
        sawProviderEvidence = true
        if (!sources.includes(o.provider)) sources.push(o.provider)
        if (o.raw != null) raw.push({ provider: o.provider, data: o.raw })
        // Record freshness per provider. `observedAt` is the PROVIDER's own
        // timestamp; when it supplies none the state is "unknown", never
        // silently backfilled with our fetch time.
        const existingFresh = providerFreshness.find((p) => p.provider === o.provider)
        const f = makeFreshness(o.observedAt ?? null)
        if (!existingFresh) providerFreshness.push({ provider: o.provider, freshness: f })
        else if (f.observedAt && (!existingFresh.freshness.observedAt || f.observedAt > existingFresh.freshness.observedAt)) {
          existingFresh.freshness = f
        }
      }
      ip ??= o.ip ?? null
      domain ??= o.domain ?? null
      if (o.domain?.trim()) domains.add(o.domain.trim())
      asn ??= o.asn ?? null
      organization ??= o.organization ?? null
      country ??= o.country ?? null
      city ??= o.city ?? null
      latitude ??= o.latitude ?? null
      longitude ??= o.longitude ?? null
      if (o.hostname) hostnames.add(o.hostname)
      mergeServices(services, o.services)
      mergeTechnologies(technologies, o.technologies)
      mergeCertificates(certificates, o.certificates)
      mergeVulnerabilities(vulnerabilities, o.vulnerabilities)
      if (o.firstSeen && (!firstSeen || o.firstSeen < firstSeen)) firstSeen = o.firstSeen
      if (o.lastSeen && (!lastSeen || o.lastSeen > lastSeen)) lastSeen = o.lastSeen
    }

    const evidence: CorrelationEvidence[] = []
    const providerObs = group.filter((o) => o.provider)
    if (ip && providerObs.filter((o) => o.ip === ip).length > 1) {
      evidence.push({ basis: "exact-ip", detail: `${providerObs.filter((o) => o.ip === ip).length} providers independently reported ${ip}` })
    }
    const sharedSvc = services.find((s) => s.sources.length >= 2)
    if (sharedSvc) {
      evidence.push({ basis: "service-agreement", detail: `Port ${sharedSvc.port} confirmed by ${sharedSvc.sources.join(", ")}` })
    }
    const fpCert = certificates.find((c) => c.fingerprint)
    if (fpCert) {
      evidence.push({ basis: "cert-fingerprint", detail: `Certificate ${fpCert.fingerprint?.slice(0, 16)}… observed on this asset` })
    }
    // A1: this is a RELATIONSHIP recorded as evidence, never a merge basis.
    if (domains.size > 0 && ip) {
      evidence.push({ basis: "domain-to-ip", detail: `${[...domains].join(", ")} resolves to ${ip}` })
    }
    const conflicted = services.find((s) => s.conflict)
    if (conflicted) {
      evidence.push({
        basis: "provider-disagreement",
        detail: `Port ${conflicted.port}: ${conflicted.claims.map((c) => `${c.source}=${c.product ?? "?"}${c.version ? " " + c.version : ""}`).join(" vs ")}`,
      })
    }

    const asset: ExposureAsset = {
      id: key,
      ip, domain,
      domains: [...domains],
      hostnames: [...hostnames],
      asn, organization, country, city, latitude, longitude,
      services, technologies, certificates, vulnerabilities,
      threat: null,
      sources,
      sourceCount: sources.length,
      confidence: "low",
      confidenceScore: 0,
      evidence,
      enrichmentStatus: "not_requested",
      isQueryTarget: !sawProviderEvidence,
      firstSeen, lastSeen,
      // Asset-level freshness = the FRESHEST provider observation backing it.
      // Optimistic by design: if any provider saw this host recently, the asset
      // is at least that fresh. Per-provider detail stays available so a stale
      // contributor is never hidden.
      freshness: freshestOf(providerFreshness),
      providerFreshness,
      exposureRisk: null,
      raw,
    }
    const { level, score } = scoreConfidence(asset)
    asset.confidence = level
    asset.confidenceScore = score
    assets.push(asset)
  }

  // Observations with no usable identifier can't be correlated — surfaced as
  // their own low-confidence assets rather than silently dropped.
  orphans.forEach((o, i) => {
    const asset: ExposureAsset = {
      id: `orphan:${o.provider ?? "query-target"}:${i}`,
      ip: null, domain: null, domains: [], hostnames: o.hostname ? [o.hostname] : [],
      asn: o.asn ?? null, organization: o.organization ?? null,
      country: o.country ?? null, city: o.city ?? null,
      latitude: o.latitude ?? null, longitude: o.longitude ?? null,
      services: o.services, technologies: o.technologies,
      certificates: o.certificates, vulnerabilities: o.vulnerabilities,
      threat: null,
      sources: o.provider ? [o.provider] : [],
      sourceCount: o.provider ? 1 : 0,
      confidence: "low", confidenceScore: o.provider ? 10 : 0, evidence: [],
      enrichmentStatus: "not_requested",
      isQueryTarget: !o.provider,
      firstSeen: o.firstSeen ?? null, lastSeen: o.lastSeen ?? null,
      exposureRisk: null,
      raw: o.provider && o.raw != null ? [{ provider: o.provider, data: o.raw }] : [],
    }
    assets.push(asset)
  })

  // Most-corroborated and most-detailed first.
  assets.sort((a, b) => b.confidenceScore - a.confidenceScore || b.services.length - a.services.length)
  return assets
}
