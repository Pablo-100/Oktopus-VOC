/**
 * ABUSEIPDB — threat context.
 *
 * MEASURED CAPABILITY (probed live 2026-09-03): `/api/v2/check` returns
 * `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`, `isTor`,
 * `usageType`, `isp`, `domain`, `hostnames` and `lastReportedAt`.
 *
 * This is a REPUTATION signal, not exposure discovery: it says how often an
 * address has been REPORTED for abuse, which is a statement about the address's
 * behaviour, not about what is running on it. It therefore contributes threat
 * context only, and never services, products or CVEs.
 *
 * It sits alongside GreyNoise rather than replacing it: GreyNoise answers
 * "is this address scanning the internet", AbuseIPDB answers "has this address
 * been reported by others". Both are kept — collapsing them would lose the
 * distinction.
 */
import type { ProviderOutcome, ThreatContext } from "@/lib/exposure/types"
import { getJson, outcome, errorOutcome, ProviderError, isValidIp, isPrivateIp } from "./_base"
import { credential } from "@/lib/exposure/credentials"

const NAME = "abuseipdb" as const
const ROLE = "threat" as const

/**
 * Reports needed before an address is called malicious.
 *
 * AbuseIPDB's own guidance treats a high confidence score as actionable and a
 * low one as noise; a single angry reporter is not evidence. 50 is the
 * threshold AbuseIPDB itself uses for "likely malicious" in its UI.
 */
const MALICIOUS_SCORE = 50
const SUSPICIOUS_SCORE = 25

interface AbuseResponse {
  data?: {
    ipAddress?: string
    abuseConfidenceScore?: number
    totalReports?: number
    numDistinctUsers?: number
    isTor?: boolean
    isWhitelisted?: boolean
    usageType?: string | null
    isp?: string | null
    domain?: string | null
    countryCode?: string | null
    lastReportedAt?: string | null
  }
}

function key(): string {
  const k = credential("ABUSEIPDB_API_KEY")
  if (!k) throw new ProviderError("not_configured", "ABUSEIPDB_API_KEY is not set.", false)
  return k
}

/**
 * Map the confidence score onto the shared classification vocabulary.
 *
 * A score of 0 with no reports is genuinely "benign"; a score of 0 that simply
 * means nobody has looked is "unknown". The two are distinguished by whether
 * any report exists, because reporting them the same way would turn absence of
 * evidence into evidence of absence.
 */
export function classifyAbuse(score: number, totalReports: number, whitelisted: boolean): string {
  if (whitelisted) return "benign"
  if (score >= MALICIOUS_SCORE) return "malicious"
  if (score >= SUSPICIOUS_SCORE) return "suspicious"
  if (totalReports > 0) return "reported"
  return "unknown"
}

/** Reputation lookup for one public IP. */
export async function lookupAbuseIPDB(ip: string): Promise<{ threat: ThreatContext | null; outcome: ProviderOutcome }> {
  const started = Date.now()
  const t = ip.trim()
  try {
    if (!isValidIp(t)) throw new ProviderError("query_unsupported", "AbuseIPDB accepts only an IP address.", false)
    if (isPrivateIp(t)) throw new ProviderError("query_unsupported", "Refusing to look up a private/reserved address.", false)

    const res = await getJson<AbuseResponse>(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(t)}&maxAgeInDays=90`,
      { Key: key(), Accept: "application/json" },
    )
    const d = res?.data
    if (!d) return { threat: null, outcome: outcome(NAME, ROLE, t, started, "success", 0, "No reputation record.") }

    const score = Number(d.abuseConfidenceScore ?? 0)
    const reports = Number(d.totalReports ?? 0)
    const classification = classifyAbuse(score, reports, Boolean(d.isWhitelisted))

    return {
      threat: {
        ip: t,
        classification,
        // `noise` here means "seen misbehaving by multiple independent
        // reporters" — deliberately not the same claim GreyNoise makes about
        // internet-wide scanning, so it needs more than one reporter.
        noise: (d.numDistinctUsers ?? 0) > 1,
        riot: Boolean(d.isWhitelisted),
        actor: d.isp ?? d.domain ?? null,
        lastSeen: d.lastReportedAt ?? null,
        link: `https://www.abuseipdb.com/check/${encodeURIComponent(t)}`,
      },
      outcome: outcome(NAME, ROLE, t, started, "success", 1,
        `Abuse confidence ${score}% from ${reports} report(s).`),
    }
  } catch (e) {
    return { threat: null, outcome: errorOutcome(NAME, ROLE, t, started, e) }
  }
}
