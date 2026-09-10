/**
 * Exposure → CVE relationship persistence, resolution, and SOC alerting.
 *
 * This is the layer between correlation and the analyst. It owns three things
 * and deliberately owns nothing else:
 *
 *   1. the durable `exposure_vulnerability` relationship (first/last seen,
 *      active/resolved) — the traceable answer to "why do we believe this?"
 *   2. lifecycle transitions driven by what a refresh ACTUALLY established
 *   3. `exposure_alerts` — deduplicated SOC alerts with an explicit lifecycle
 *
 * It does NOT score anything. Severity and risk come from `computeExposureRisk`
 * over `lib/risk-engine.ts`; there is no second engine here, and no
 * "exposure severity" concept. An alert carries the EXISTING RBVM severity and
 * reports evidence confidence as a separate, non-substitutable dimension.
 */
import { sql } from "@/lib/db"
import { redactSecrets } from "@/lib/exposure/providers/_base"
import { recordAlertEvent, escalateAlert } from "@/lib/exposure/alert-workflow"
import type {
  ExposureAsset, ExposureVulnerability, ProviderName, ProviderOutcome, EvidenceTier,
} from "@/lib/exposure/types"

export type VulnStatus = "active" | "resolved"
export type AlertState = "open" | "acknowledged" | "resolved" | "suppressed"
export type AlertKind = "new_exposed_vulnerability" | "risk_increased"

/**
 * Evidence tiers that may raise a SOC alert.
 *
 * `product`, `pivot` and `weak` are excluded. A product-name guess or a local
 * pivot is a LEAD, and paging an analyst on a lead — however severe the CVE
 * itself is — is exactly the false-positive failure mode item 23 forbids.
 * These leads remain fully visible in the UI and in
 * `exposure_vulnerability`; they simply do not become alerts.
 */
const ALERTABLE_TIERS: ReadonlySet<EvidenceTier> = new Set<EvidenceTier>(["confirmed", "strong"])

/**
 * Severities that may raise a SOC alert.
 *
 * Mirrors the EXISTING alert convention in `lib/collector.ts`
 * (`severity IN ('critical','high') OR is_kev OR epss >= 0.5`) rather than
 * inventing an incompatible policy. Severity here is the RBVM severity already
 * computed for the asset.
 */
const ALERTABLE_SEVERITIES: ReadonlySet<string> = new Set(["critical", "high"])

/**
 * Minimum risk delta worth an escalation alert.
 *
 * Without this the 15-minute scheduler would alert on every point of numerical
 * drift. Only a change that crosses into a higher severity band AND moves the
 * score materially is worth an analyst's attention.
 */
const RISK_ESCALATION_MIN_DELTA = 10

const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 }

/**
 * Alerts raised for one asset in a single evaluation.
 *
 * A version-level provider legitimately reports every CVE known for a detected
 * build: one unpatched Apache 2.4.7 produced 116 critical, correctly-evidenced
 * findings in testing. Every one is real, and paging an analyst 116 times is
 * still useless — alert fatigue is what makes a SOC miss the one that mattered.
 *
 * So the FINDINGS are all kept and remain visible in the vulnerability view;
 * only the number that becomes an ALERT is bounded, highest risk first. The
 * remainder is reported in `withheld` so the cap is visible rather than silent.
 */
const MAX_ALERTS_PER_ASSET_PER_RUN = 5

export interface VulnRow {
  asset_key: string
  port: number
  cve_id: string
  evidence_tier: EvidenceTier
  confirmed: boolean
  match_type: string | null
  source_providers: ProviderName[]
  product: string | null
  version: string | null
  matched_via: string | null
  observed_at: string | null
  fetched_at: string | null
  risk_score: number | null
  severity: string | null
  status: VulnStatus
  first_seen_at: string
  last_seen_at: string
  resolved_at: string | null
}

/**
 * Did this refresh actually establish ABSENCE, or did a provider merely fail?
 *
 * Item 25: a 429, a timeout or an exhausted quota is not evidence of
 * remediation. A vulnerability may only be resolved when EVERY provider that
 * supplied its evidence reported successfully this time — if any of them could
 * not answer, the correct conclusion is "unknown", and unknown must never be
 * rendered as "fixed".
 */
export function canEstablishAbsence(
  sourceProviders: readonly ProviderName[],
  providers: readonly ProviderOutcome[],
): boolean {
  const succeeded = new Set(
    providers.filter((p) => p.status === "success" || p.status === "partial").map((p) => p.provider),
  )
  if (!succeeded.size) return false // nothing answered at all

  // A locally-correlated finding with no provider attribution rides on the
  // service observation itself, so any successful refresh can retire it.
  if (!sourceProviders.length) return true

  return sourceProviders.every((p) => succeeded.has(p))
}

/** Stable identity for deduplication: the same condition must always hash the same. */
export function alertFingerprint(assetKey: string, port: number, cveId: string): string {
  return `${assetKey}|${port}|${cveId.toUpperCase()}`
}

/** Flatten an asset's vulnerabilities into per-service rows. */
export interface PendingVuln {
  port: number
  cveId: string
  evidenceTier: EvidenceTier
  confirmed: boolean
  matchType: string | null
  sourceProviders: ProviderName[]
  product: string | null
  version: string | null
  matchedVia: string
}

/**
 * Build the per-(port, CVE) rows for an asset.
 *
 * A vulnerability that belongs to the asset as a whole rather than to a
 * specific service (a provider CVE hit on the host, or a pivot) is recorded at
 * port 0 — inventing a port for it would fabricate provenance.
 */
export function pendingFromAsset(asset: ExposureAsset): PendingVuln[] {
  const out: PendingVuln[] = []
  const seen = new Set<string>()

  // Map each service's product/version so a per-service finding keeps its context.
  const serviceByPort = new Map(asset.services.map((s) => [s.port, s]))

  for (const v of asset.vulnerabilities) {
    // `correlatedPort` is set by the correlation step for service-derived
    // findings; anything else is asset-level.
    const port = v.correlatedPort ?? 0
    const key = `${port}|${v.cveId}`
    if (seen.has(key)) continue
    seen.add(key)
    const svc = serviceByPort.get(port)
    out.push({
      port,
      cveId: v.cveId,
      evidenceTier: v.evidenceTier,
      confirmed: v.confirmed,
      matchType: v.matchType ?? null,
      sourceProviders: [...v.sources],
      product: svc?.product ?? v.matchedProduct ?? null,
      version: svc?.version ?? null,
      matchedVia: describeMatch(v, Boolean(svc)),
    })
  }
  return out
}

/** Human-readable provenance — what an analyst reads to judge the finding. */
function describeMatch(v: ExposureVulnerability, fromService: boolean): string {
  switch (v.evidenceTier) {
    case "confirmed":
      return `Provider returned this host when queried for ${v.cveId}`
    case "strong":
      return fromService
        ? `Affected VERSION fingerprinted on this service (${v.matchedProduct ?? "product"})`
        : `Affected version reported for this host (${v.matchedProduct ?? "product"})`
    case "product":
      return `Product name matched CPE "${v.matchedProduct ?? "?"}" in OCTUPUS's CVE data — version not proven`
    case "pivot":
      return `Local CVE→product pivot; this host was not directly reported as affected`
    default:
      return `Banner/heuristic inference only`
  }
}

export interface TrackingResult {
  created: PendingVuln[]
  resolved: VulnRow[]
  /** Rows still present; used for risk-change evaluation. */
  active: number
  /** True when provider failures made absence undecidable, so nothing was resolved. */
  resolutionWithheld: boolean
}

/**
 * Reconcile an asset's correlated vulnerabilities against what is stored.
 *
 * Returns what genuinely CHANGED so the caller can raise events and alerts;
 * a steady state produces an empty result and therefore no alert noise.
 */
export async function trackAssetVulnerabilities(
  asset: ExposureAsset,
  providers: readonly ProviderOutcome[],
  userId: string,
): Promise<TrackingResult> {
  const assetKey = asset.id
  const empty: TrackingResult = { created: [], resolved: [], active: 0, resolutionWithheld: false }
  if (!assetKey || asset.isQueryTarget) return empty

  const pending = pendingFromAsset(asset)
  const risk = asset.exposureRisk
  const observedAt = asset.freshness?.observedAt ?? null
  const fetchedAt = asset.freshness?.fetchedAt ?? new Date().toISOString()

  // Tenant-scoped: another user's findings for the SAME host are a different
  // record set. Reading them here would let one user's remediation resolve
  // another user's alert.
  const existing = (await sql`
    SELECT * FROM exposure_vulnerability WHERE user_id = ${userId} AND asset_key = ${assetKey}
  `) as VulnRow[]
  const existingByKey = new Map(existing.map((r) => [`${r.port}|${r.cve_id}`, r]))

  const created: PendingVuln[] = []
  for (const p of pending) {
    const prior = existingByKey.get(`${p.port}|${p.cveId}`)
    // NEW when never seen, or when it had been resolved and has now returned.
    if (!prior || prior.status === "resolved") created.push(p)
  }

  // ── Upsert everything currently observed ──────────────────────────────────
  // `first_seen_at` is preserved on conflict: history is not rewritten by a
  // later sighting. A row returning from `resolved` re-opens with a fresh
  // `first_seen_at` because it is genuinely a new occurrence.
  for (const p of pending) {
    const prior = existingByKey.get(`${p.port}|${p.cveId}`)
    const reopening = prior?.status === "resolved"
    await sql`
      INSERT INTO exposure_vulnerability (
        user_id, asset_key, port, cve_id, evidence_tier, confirmed, match_type, source_providers,
        product, version, matched_via, observed_at, fetched_at, risk_score, severity,
        status, first_seen_at, last_seen_at, resolved_at
      ) VALUES (
        ${userId}, ${assetKey}, ${p.port}, ${p.cveId}, ${p.evidenceTier}, ${p.confirmed}, ${p.matchType},
        ${p.sourceProviders as unknown as string[]},
        ${p.product}, ${p.version}, ${p.matchedVia}, ${observedAt}::timestamptz, ${fetchedAt}::timestamptz,
        ${risk?.score ?? null}, ${risk?.severity ?? null},
        'active', now(), now(), NULL
      )
      ON CONFLICT (user_id, asset_key, port, cve_id) DO UPDATE SET
        evidence_tier = EXCLUDED.evidence_tier,
        confirmed     = EXCLUDED.confirmed,
        match_type    = EXCLUDED.match_type,
        source_providers = EXCLUDED.source_providers,
        product       = EXCLUDED.product,
        version       = EXCLUDED.version,
        matched_via   = EXCLUDED.matched_via,
        observed_at   = EXCLUDED.observed_at,
        fetched_at    = EXCLUDED.fetched_at,
        risk_score    = EXCLUDED.risk_score,
        severity      = EXCLUDED.severity,
        status        = 'active',
        resolved_at   = NULL,
        first_seen_at = CASE WHEN ${reopening} THEN now() ELSE exposure_vulnerability.first_seen_at END,
        last_seen_at  = now()
    `
  }

  // ── Resolution — only where absence is actually established ───────────────
  const presentKeys = new Set(pending.map((p) => `${p.port}|${p.cveId}`))
  const resolved: VulnRow[] = []
  let resolutionWithheld = false

  for (const row of existing) {
    if (row.status !== "active") continue
    if (presentKeys.has(`${row.port}|${row.cve_id}`)) continue

    if (!canEstablishAbsence(row.source_providers ?? [], providers)) {
      // Provider failure — NOT remediation. Leave the row active and untouched.
      resolutionWithheld = true
      continue
    }
    await sql`
      UPDATE exposure_vulnerability
      SET status = 'resolved', resolved_at = now()
      WHERE user_id = ${userId} AND asset_key = ${assetKey} AND port = ${row.port} AND cve_id = ${row.cve_id}
    `
    resolved.push(row)
  }

  return { created, resolved, active: pending.length, resolutionWithheld }
}

// ─────────────────────────── SOC alerts ───────────────────────────

export interface AlertInput {
  /** Owner of this finding. Alerts are never visible across tenants. */
  userId: string
  assetKey: string
  target: string
  port: number
  cveId: string
  kind: AlertKind
  severity: string
  riskScore: number | null
  previousRisk: number | null
  evidenceTier: EvidenceTier
  payload: Record<string, unknown>
}

/**
 * Is this finding worth waking a SOC analyst?
 *
 * Both gates must pass, and they are independent concepts (item 19):
 *   - SEVERITY comes from the existing RBVM engine
 *   - EVIDENCE is how sure we are the asset is really affected
 *
 * A CVSS-10 / EPSS-0.99 / KEV vulnerability attached by a product-name guess
 * fails the evidence gate and raises no alert, no matter how severe the CVE is.
 */
export function isAlertEligible(tier: EvidenceTier, severity: string | null | undefined): boolean {
  if (!ALERTABLE_TIERS.has(tier)) return false
  return ALERTABLE_SEVERITIES.has((severity ?? "").toLowerCase())
}

/**
 * Should a risk move raise an escalation alert?
 *
 * Requires BOTH a jump into a higher severity band and a material score delta,
 * so ordinary numerical drift between 15-minute runs stays silent.
 */
export function isRiskEscalation(
  previousSeverity: string | null,
  currentSeverity: string | null,
  previousScore: number | null,
  currentScore: number | null,
): boolean {
  // No prior state is not an escalation — there is nothing to have risen FROM.
  // A first observation is already covered by `new_exposed_vulnerability`, and
  // treating it as an escalation too would page twice for one event.
  if (previousScore == null && previousSeverity == null) return false

  const prevRank = SEVERITY_RANK[(previousSeverity ?? "").toLowerCase()] ?? -1
  const currRank = SEVERITY_RANK[(currentSeverity ?? "").toLowerCase()] ?? -1
  if (currRank <= prevRank) return false
  if (!ALERTABLE_SEVERITIES.has((currentSeverity ?? "").toLowerCase())) return false
  const delta = (currentScore ?? 0) - (previousScore ?? 0)
  return delta >= RISK_ESCALATION_MIN_DELTA
}

/**
 * Raise an alert, unless an identical condition is already open.
 *
 * Deduplication is enforced by the `exposure_alerts_active_uniq` partial unique
 * index rather than a read-then-write check: with a scheduler running every 15
 * minutes and manual refreshes possible at any moment, an application-level
 * check has a race window and the database does not. `ON CONFLICT DO NOTHING`
 * turns a duplicate into a no-op instead of an error.
 */
export async function raiseAlert(input: AlertInput): Promise<boolean> {
  const fingerprint = alertFingerprint(input.assetKey, input.port, input.cveId)
  // Alert payloads are read by humans and shipped to the browser: scrub before
  // storing, never after.
  const payload = JSON.parse(redactSecrets(JSON.stringify(input.payload))) as Record<string, unknown>

  const rows = (await sql`
    INSERT INTO exposure_alerts (
      user_id, fingerprint, asset_key, port, cve_id, kind, state, severity,
      risk_score, previous_risk, evidence_tier, payload
    ) VALUES (
      ${input.userId}, ${fingerprint}, ${input.assetKey}, ${input.port}, ${input.cveId}, ${input.kind}, 'open',
      ${input.severity}, ${input.riskScore}, ${input.previousRisk}, ${input.evidenceTier},
      ${JSON.stringify(payload)}::jsonb
    )
    ON CONFLICT (user_id, fingerprint) WHERE state IN ('open','acknowledged','in_progress') DO NOTHING
    RETURNING id
  `) as Array<{ id: number }>

  // STEP 5: the alert's own audit trail starts here. Best-effort, so a lost
  // audit line never prevents the alert itself from existing.
  if (rows.length) {
    await recordAlertEvent(rows[0].id, input.userId, "alert_created", "system", input.kind, {
      severity: input.severity, riskScore: input.riskScore,
      evidenceTier: input.evidenceTier, cveId: input.cveId,
    })
  }
  return rows.length > 0
}

/** Close any active alert for a condition that no longer holds. */
export async function resolveAlerts(assetKey: string, port: number, cveId: string, userId: string): Promise<number> {
  const rows = (await sql`
    UPDATE exposure_alerts
    SET state = 'resolved', resolved_at = now(), updated_at = now()
    WHERE user_id = ${userId}
      AND fingerprint = ${alertFingerprint(assetKey, port, cveId)}
      -- in_progress is included: when the finding genuinely disappears the
      -- alert must close for the analyst working it too, otherwise it stays
      -- active forever and blocks the finding from ever re-alerting.
      AND state IN ('open','acknowledged','in_progress')
    RETURNING id, state
  `) as Array<{ id: number; state: string }>
  // Auto-resolution is an event in the alert's life; without this the timeline
  // simply stops and an analyst cannot tell why the alert closed.
  for (const r of rows) {
    await recordAlertEvent(r.id, userId, "alert_resolved", "system",
      "Finding no longer observed; auto-resolved.", { auto: true })
  }
  return rows.length
}

/**
 * Direct state write, tenant-scoped.
 *
 * NOT the analyst path: `transitionAlert()` in alert-workflow.ts owns lifecycle
 * changes and enforces the state machine, the suppression reason and the audit
 * trail. This exists only for internal transitions that have already been
 * validated, and it deliberately cannot touch another tenant's alert.
 */
export async function setAlertState(id: number, state: AlertState, userId: string): Promise<boolean> {
  const rows = (await sql`
    UPDATE exposure_alerts
    SET state = ${state},
        resolved_at = CASE WHEN ${state} = 'resolved' THEN now() ELSE resolved_at END,
        updated_at = now()
    WHERE id = ${id} AND user_id = ${userId}
    RETURNING id
  `) as unknown[]
  return rows.length > 0
}

// ───────────────────── alert evaluation (the pipeline tail) ─────────────────

export interface AlertEvaluation {
  raised: Array<{ cveId: string; port: number; kind: AlertKind; severity: string }>
  closed: number
  /** Findings that were suppressed by the evidence gate, with the reason. */
  suppressed: Array<{ cveId: string; tier: EvidenceTier; reason: string }>
  /**
   * Eligible findings NOT alerted because the per-asset cap was reached.
   * They exist as vulnerability records and are visible in the UI; they simply
   * did not each raise their own alert.
   */
  withheld: number
  /**
   * Ids of the alerts this evaluation raised or escalated.
   *
   * Carried so the caller can attempt IMMEDIATE delivery once everything has
   * been written. Delivery is deliberately not performed here: this function
   * decides what is actionable, and an HTTP call to Telegram has no business
   * inside that decision.
   */
  alertIds: number[]
}

/**
 * Decide what an asset's CHANGES mean for the SOC.
 *
 * Runs strictly AFTER correlation and RBVM: an alert must have a vulnerability
 * and a risk basis, never "a service appeared" (item 18).
 */
export async function evaluateAlerts(
  asset: ExposureAsset,
  tracking: TrackingResult,
  userId: string,
  previous: { severity: string | null; score: number | null },
): Promise<AlertEvaluation> {
  const out: AlertEvaluation = { raised: [], closed: 0, suppressed: [], alertIds: [], withheld: 0 }
  const assetKey = asset.id
  if (!assetKey || asset.isQueryTarget) return out

  const risk = asset.exposureRisk
  const target = asset.ip ?? asset.domain ?? assetKey
  const severity = risk?.severity ?? "low"

  // ── New exposed vulnerabilities ──
  // Highest risk first, so the capped set is the set worth waking someone for.
  const ordered = [...tracking.created].sort((a, b) => {
    const rank = (t: EvidenceTier) => (t === "confirmed" ? 2 : t === "strong" ? 1 : 0)
    return rank(b.evidenceTier) - rank(a.evidenceTier)
  })
  for (const p of ordered) {
    if (!isAlertEligible(p.evidenceTier, severity)) {
      out.suppressed.push({
        cveId: p.cveId,
        tier: p.evidenceTier,
        reason: !ALERTABLE_TIERS.has(p.evidenceTier)
          ? `evidence is "${p.evidenceTier}" — a lead, not a confirmed finding`
          : `RBVM severity is "${severity}", below the alerting threshold`,
      })
      continue
    }
    // Cap reached: the finding is already recorded, it just does not page.
    if (out.raised.length >= MAX_ALERTS_PER_ASSET_PER_RUN) {
      out.withheld++
      continue
    }
    const created = await raiseAlert({
      userId, assetKey, target, port: p.port, cveId: p.cveId,
      kind: "new_exposed_vulnerability",
      severity,
      riskScore: risk?.score ?? null,
      previousRisk: previous.score,
      evidenceTier: p.evidenceTier,
      payload: {
        asset: target,
        service: p.port > 0 ? `${p.port}/tcp` : "host-level",
        product: p.product,
        version: p.version,
        cveId: p.cveId,
        evidence: p.evidenceTier,
        providers: p.sourceProviders,
        why: p.matchedVia,
        // Freshness is reported as its own dimension — a STRONG finding can
        // still rest on a STALE observation, and collapsing the two would
        // present old data as current proof.
        observedAt: asset.freshness?.observedAt ?? null,
        fetchedAt: asset.freshness?.fetchedAt ?? null,
        freshness: asset.freshness?.state ?? "unknown",
        previousRisk: previous.score,
        currentRisk: risk?.score ?? null,
        slaHours: risk?.slaHours ?? null,
      },
    })
    if (created) out.raised.push({ cveId: p.cveId, port: p.port, kind: "new_exposed_vulnerability", severity })
  }

  // ── Resolutions ──
  for (const r of tracking.resolved) {
    out.closed += await resolveAlerts(assetKey, r.port, r.cve_id, userId)
  }

  // ── Risk escalation ──
  if (isRiskEscalation(previous.severity, severity, previous.score, risk?.score ?? null)) {
    // Attribute the escalation to the CVE actually driving it, and only when
    // that CVE's evidence is strong enough to alert on.
    const driver = risk?.drivingCves?.[0]
    const vuln = driver ? asset.vulnerabilities.find((v) => v.cveId === driver) : undefined
    if (vuln && isAlertEligible(vuln.evidenceTier, severity)) {
      const port = vuln.correlatedPort ?? 0

      // A live alert for this exact finding already exists: its fingerprint is
      // identical, so `raiseAlert` would hit ON CONFLICT DO NOTHING and the
      // escalation would be silently lost. Update it in place instead — one
      // alert per finding, with the escalation recorded and re-queued for
      // notification.
      const escalated = await escalateAlert(
        alertFingerprint(assetKey, port, vuln.cveId),
        userId,
        { severity, riskScore: risk?.score ?? null, evidenceTier: vuln.evidenceTier },
      )
      if (escalated.escalated) {
        out.raised.push({ cveId: vuln.cveId, port, kind: "risk_increased", severity })
        if (escalated.alertId) out.alertIds.push(Number(escalated.alertId))
        return await withAlertIds(out, assetKey, userId)
      }

      const created = await raiseAlert({
        userId, assetKey, target, port, cveId: vuln.cveId,
        kind: "risk_increased",
        severity,
        riskScore: risk?.score ?? null,
        previousRisk: previous.score,
        evidenceTier: vuln.evidenceTier,
        payload: {
          asset: target,
          cveId: vuln.cveId,
          evidence: vuln.evidenceTier,
          providers: vuln.sources,
          previousRisk: previous.score,
          previousSeverity: previous.severity,
          currentRisk: risk?.score ?? null,
          currentSeverity: severity,
          why: "Exposure-adjusted RBVM risk crossed into a higher severity band.",
          observedAt: asset.freshness?.observedAt ?? null,
          fetchedAt: asset.freshness?.fetchedAt ?? null,
        },
      })
      if (created) out.raised.push({ cveId: vuln.cveId, port, kind: "risk_increased", severity })
    } else if (vuln) {
      out.suppressed.push({
        cveId: vuln.cveId, tier: vuln.evidenceTier,
        reason: `risk rose but the driving CVE's evidence is "${vuln.evidenceTier}"`,
      })
    }
  }

  return await withAlertIds(out, assetKey, userId)
}

/**
 * Resolve the ids of the alerts this evaluation raised.
 *
 * One query for the whole batch rather than changing `raiseAlert`'s contract:
 * its boolean return ("did this create a new alert?") is what callers and the
 * existing tests depend on, and widening it to carry an id would be a change to
 * the alert engine for the benefit of the delivery layer.
 */
async function withAlertIds(out: AlertEvaluation, assetKey: string, userId: string): Promise<AlertEvaluation> {
  if (!out.raised.length) return out
  try {
    const fingerprints = out.raised.map((r) => alertFingerprint(assetKey, r.port, r.cveId))
    const rows = (await sql`
      SELECT id FROM exposure_alerts
      WHERE user_id = ${userId}
        AND fingerprint = ANY(${fingerprints}::text[])
        AND state IN ('open','acknowledged','in_progress')
    `) as Array<{ id: number }>
    for (const r of rows) {
      const id = Number(r.id)
      if (Number.isFinite(id) && !out.alertIds.includes(id)) out.alertIds.push(id)
    }
  } catch (e) {
    // Losing the ids only costs the immediate attempt; the scheduler still
    // delivers from the outbox.
    console.error("[alerts] could not resolve raised alert ids:", e instanceof Error ? e.message : String(e))
  }
  return out
}
