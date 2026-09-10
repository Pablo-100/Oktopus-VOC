/**
 * Verify a user's provider credentials by actually using them.
 *
 * A key is only worth storing if it works, and "works" is not something a
 * regex can decide: a well-formed Censys token whose account has no credits
 * left fails exactly like a valid one until you spend a call. Saving without
 * checking is how a user ends up with a green "configured" badge and an empty
 * result set — the precise failure this codebase already went to some trouble
 * to eliminate for platform keys.
 *
 * So each check performs ONE real, minimal request against a benign public
 * target, then reports what the provider said. The distinction that matters to
 * the user is preserved: a rejected key is their problem to fix, an exhausted
 * quota is their account's billing state, and a network failure is neither.
 */
import { runWithCredentials, PROVIDER_CREDENTIAL_FIELDS, type CredentialProvider } from "@/lib/exposure/credentials"
import { redactSecrets } from "@/lib/exposure/providers/_base"
import type { ProviderOutcome } from "@/lib/exposure/types"
import { lookupShodan } from "@/lib/exposure/providers/shodan"
import { lookupAbuseIPDB } from "@/lib/exposure/providers/abuseipdb"
import { lookupCensys } from "@/lib/exposure/providers/censys"
import { lookupNetlas } from "@/lib/exposure/providers/netlas"
import { lookupGreyNoise } from "@/lib/exposure/providers/greynoise"
import { searchLeakix } from "@/lib/exposure/providers/leakix"
import { searchFofa } from "@/lib/exposure/providers/fofa"
import { searchZoomeye } from "@/lib/exposure/providers/zoomeye"

/**
 * Probe target for the lookup-style providers.
 *
 * A Google public resolver: unambiguously public, owned by a party that expects
 * to be looked up, and certain to exist in every provider's dataset — so an
 * empty answer means the credential failed, not that the target is obscure.
 */
const PROBE_IP = "8.8.8.8"

/** Probe term for the search-style providers. Common enough to always match. */
const PROBE_TERM = "nginx"

export type CredentialStatus = "valid" | "invalid" | "quota_exhausted" | "unreachable"

export interface CredentialCheck {
  status: CredentialStatus
  message: string
}

/** Map a provider outcome onto the four states a user can act on. */
function fromOutcome(outcome: ProviderOutcome): CredentialCheck {
  const message = redactSecrets(outcome.message ?? "").slice(0, 300)
  switch (outcome.status) {
    case "success":
    case "partial":
      return { status: "valid", message: message || "Key accepted and returned data." }
    case "authentication_failed":
      return { status: "invalid", message: message || "The provider rejected these credentials." }
    case "quota_exhausted":
    case "rate_limited":
      // The credential itself is fine — the account behind it has nothing left
      // to spend. Storing it is correct; the user needs to top up, not retype.
      return {
        status: "quota_exhausted",
        message: message || "Credentials are valid, but this account has no remaining quota.",
      }
    case "not_configured":
      return { status: "invalid", message: "Credentials were not supplied." }
    default:
      return {
        status: "unreachable",
        message: message || "Could not reach the provider. The credentials were not verified.",
      }
  }
}

/** One real call per provider, using the smallest request that proves the key. */
async function probe(provider: CredentialProvider): Promise<ProviderOutcome> {
  switch (provider) {
    case "shodan":
      return (await lookupShodan(PROBE_IP)).outcome
    case "abuseipdb":
      return (await lookupAbuseIPDB(PROBE_IP)).outcome
    case "censys":
      return (await lookupCensys(PROBE_IP)).outcome
    case "netlas":
      return (await lookupNetlas(PROBE_IP)).outcome
    case "greynoise":
      return (await lookupGreyNoise(PROBE_IP)).outcome
    case "leakix":
      return (await searchLeakix(PROBE_TERM)).outcome
    case "fofa":
      return (await searchFofa(PROBE_TERM)).outcome
    case "zoomeye":
      return (await searchZoomeye(PROBE_TERM)).outcome
  }
}

/**
 * Check candidate credentials WITHOUT storing them or touching the caller's
 * own context.
 *
 * The values are placed in a throwaway credential context for the duration of
 * the probe, so they are never written to the environment (which is process
 * global and would leak one user's key into every concurrent request) and are
 * unreachable the moment the call returns.
 */
export async function checkCredentials(
  provider: CredentialProvider,
  values: Record<string, string>,
): Promise<CredentialCheck> {
  const required = PROVIDER_CREDENTIAL_FIELDS[provider]
  const missing = required.filter((f) => !values[f]?.trim())
  if (missing.length) {
    return { status: "invalid", message: `Missing required field(s): ${missing.join(", ")}.` }
  }

  try {
    const outcome = await runWithCredentials(
      { values, userProvided: new Set([provider]), userId: null },
      () => probe(provider),
    )
    return fromOutcome(outcome)
  } catch (e) {
    return {
      status: "unreachable",
      message: redactSecrets(e instanceof Error ? e.message : String(e)).slice(0, 300),
    }
  }
}
