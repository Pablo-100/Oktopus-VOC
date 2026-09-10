/**
 * Normalization helpers shared by every provider adapter.
 *
 * The point of centralising this: `evidenceTier` and `confirmed` must ALWAYS
 * agree with `matchType`. If each adapter set them by hand, one adapter could
 * mark a product-name guess as `confirmed` and the whole evidence hierarchy
 * would quietly stop meaning anything. Adapters call `makeVulnerability()` and
 * cannot get it wrong.
 */
import { evidenceTierFor, type ExposureVulnerability, type ProviderName, type VulnMatchType } from "@/lib/exposure/types"

export function makeVulnerability(input: {
  cveId: string
  matchType: VulnMatchType
  sources: ProviderName[]
  providerScore?: number | null
  providerSeverity?: string | null
  matchedProduct?: string | null
}): ExposureVulnerability {
  const tier = evidenceTierFor(input.matchType)
  return {
    cveId: input.cveId.toUpperCase(),
    matchType: input.matchType,
    evidenceTier: tier,
    // Derived, never passed in: only a direct provider CVE hit is a confirmation.
    confirmed: tier === "confirmed",
    providerScore: input.providerScore ?? null,
    providerSeverity: input.providerSeverity ?? null,
    matchedProduct: input.matchedProduct ?? null,
    sources: [...input.sources],
  }
}

/**
 * Re-derive tier/confirmed after a merge changed `matchType`. Used by the
 * correlation engine so promoting a pivot to a confirmed hit also promotes the
 * tier — the two can never drift apart.
 */
export function syncEvidenceTier(v: ExposureVulnerability): void {
  v.evidenceTier = evidenceTierFor(v.matchType)
  v.confirmed = v.evidenceTier === "confirmed"
}
