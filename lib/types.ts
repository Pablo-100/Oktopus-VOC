/** Types du domaine OCTUPUS (portés depuis le frontend vanilla). */

export type Severity = "critical" | "high" | "medium" | "low";
export type RiskTone = Severity;

export interface CveRef {
  url: string;
  tags: string[];
}

export interface Vuln {
  cveId: string;
  description: string;
  cvssV2: number | "-";
  cvssV3: number | "-";
  severity: Severity;
  cwes: string[];
  attackVector: string;
  references: CveRef[];
  hasExploit: boolean;
  vendors: string[];
  products: string[];
  vector: string;
  complexity: string;
  impactC: string; // NONE | LOW | HIGH (confidentialité)
  impactI: string; // intégrité
  impactA: string; // disponibilité
  publishedDate: string; // affichage (fr-FR)
  sortDate: Date | null;
  lastModified: string | null;
  epss: number | null;
  epssPercentile: number | null;
  isKev: boolean;
  riskScore: number | null;
  riskLevel: string;
}

export type ZeroDayKind = "reserved" | "prepub_exploited" | "advisory";

export type ZeroDayExploitState = "kev-confirmed" | "source-reported" | "poc-published" | "none" | null;

export interface ZeroDay {
  id: string
  source: "nvd-reserved" | "kev" | "defend" | "github" | "news" | "p0"
  kind: ZeroDayKind
  cveId: string | null
  ghsaId: string | null
  title: string
  product: string | null
  exploitState: ZeroDayExploitState
  verification: "verified" | "partial" | null
  isKev: boolean
  hasExploit: boolean
  riskScore: number
  severity: string
  cvss: number | null
  epss: number | null
  firstSeenAt: string | null
  lastSeenAt: string | null
  becameCve: boolean
  resolvedAt: string | null
  description?: string | null
  /** Plain-language explanation (see lib/zero-day-explain.ts), computed at read time
   *  by /api/zero-days for every row — unlike `description`, which can be null (KEV)
   *  or a dense technical writeup (GitHub advisories), this is written for a reader
   *  with no security background. Optional here because it's a derived display field,
   *  not raw collected data — collector-side ZeroDay objects never set it. */
  plainSummary?: string
  permalink?: string | null
  references: string[]
  data: unknown
}

/**
 * Legacy provider-name union used by the per-product / per-CVE panels in the
 * CVE and 0-day detail dialogs. Kept in sync with `ProviderName` in
 * lib/exposure/types.ts (which is the canonical definition since the B1
 * consolidation) — `greynoise` was added when the two GreyNoise clients merged.
 */
export type ExposureProviderName =
  | "censys" | "leakix" | "netlas" | "fofa" | "zoomeye" | "greynoise"
  | "shodan" | "abuseipdb"

export interface ExposureResult {
  provider: ExposureProviderName
  query: string
  ok: boolean
  /** Authoritative total when the provider's API exposes one; a sample size otherwise (see `approximate`). */
  count: number | null
  /** true when `count` is capped by a page size rather than a true total (e.g. LeakIX has no total-count field on its free API). */
  approximate: boolean
  error?: string
  fetchedAt: string
}

/**
 * GreyNoise CVE exploitation-activity signal — distinct from ExposureResult:
 * keyed by CVE ID (not product name), and it answers "is this being actively
 * mass-exploited on the internet right now", not "how many instances exist".
 */
export interface CveExploitationActivity {
  cveId: string
  ok: boolean
  /** GreyNoise `exploitation_details.exploit_found` — a known exploit exists for this CVE. */
  exploited: boolean | null
  /** GreyNoise's own KEV corroboration (`exploitation_registered_in_kev`) — independent of your own CISA KEV pull. */
  inKev: boolean | null
  /** GreyNoise `exploitation_details.epss_score` — a second EPSS reading, independent of the one from FIRST.org. */
  epssScore: number | null
  /** `details.vulnerability_name` — short human label, e.g. "Apache Log4j2 Remote Code Execution Vulnerability". */
  summary: string | null
  error?: string
  fetchedAt: string
}
