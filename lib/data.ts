/**
 * Pipeline de données OCTUPUS (porté depuis dashboard.js + risk-engine.js).
 * Côté client/front : lecture de la BASE uniquement (instantané) + mapping NVD.
 * Le pipeline réseau (NVD, EPSS, KEV) vit côté serveur : lib/collector.ts,
 * lib/kev-cache.ts, lib/nvd-archive.ts (Tier A), lib/nvd-search.ts (Tier B).
 */
import type { Vuln, ZeroDay, Severity } from "./types";
import { severityFromCvss } from "./risk-engine";

/**
 * The subset of the NVD 2.0 CVE object this module consumes.
 *
 * Deliberately all-optional: the feed omits whatever does not apply to a given
 * record, so anything not marked optional would be a lie about the wire format.
 * These replace `any`, which silently accepted a rename or a shape change in the
 * upstream feed and turned it into `undefined` at runtime instead of an error.
 */
interface NvdCvssData {
  baseScore?: number
  vectorString?: string
  // v3.x names
  attackVector?: string
  attackComplexity?: string
  confidentialityImpact?: string
  integrityImpact?: string
  availabilityImpact?: string
  // v2 names for the same concepts
  accessVector?: string
  accessComplexity?: string
}
interface NvdMetricEntry { cvssData?: NvdCvssData }
interface NvdDescription { lang?: string; value?: string }
interface NvdWeakness { description?: NvdDescription[] }
interface NvdReference { url?: string; tags?: string[] }
interface NvdCpeMatch { criteria?: string }
interface NvdNode { cpeMatch?: NvdCpeMatch[] }
interface NvdConfiguration { nodes?: NvdNode[] }

interface NvdCve {
  id?: string
  published?: string
  lastModified?: string
  descriptions?: NvdDescription[]
  weaknesses?: NvdWeakness[]
  references?: NvdReference[]
  configurations?: NvdConfiguration[]
  metrics?: {
    cvssMetricV31?: NvdMetricEntry[]
    cvssMetricV30?: NvdMetricEntry[]
    cvssMetricV2?: NvdMetricEntry[]
  }
}

/** One row of the FIRST EPSS API response. */
interface EpssRow { cve?: string; epss?: string; percentile?: string }

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

export function processNvd(data: { vulnerabilities?: unknown[] }): Vuln[] {
  const items = (data.vulnerabilities ?? []) as Array<{ cve: NvdCve }>;
  return items.map(({ cve }) => {
    const metrics = cve.metrics ?? {};
    const v3 =
      metrics.cvssMetricV31?.[0]?.cvssData ??
      metrics.cvssMetricV30?.[0]?.cvssData ??
      {};
    const v2 = metrics.cvssMetricV2?.[0]?.cvssData ?? {};
    // `?? null` rather than letting `undefined` through: a CVE that is still
    // awaiting analysis carries no CVSS metric at all, and the scorer's contract
    // is an explicit null for "unscored".
    const severity: Severity = severityFromCvss(v3.baseScore ?? v2.baseScore ?? null);

    const cweSet = new Set<string>();
    (cve.weaknesses ?? []).forEach((w) =>
      (w.description ?? []).forEach((d) => {
        if (d.value && /^CWE-\d+$/i.test(d.value)) cweSet.add(String(d.value).toUpperCase());
      }),
    );

    const references = (cve.references ?? []).map((r) => ({
      url: r.url ?? "",
      tags: r.tags ?? [],
    }));
    const hasExploit = references.some((r) => (r.tags ?? []).includes("Exploit"));

    const vendorSet = new Set<string>();
    const productSet = new Set<string>();
    (cve.configurations ?? []).forEach((cfg) =>
      (cfg.nodes ?? []).forEach((node) =>
        (node.cpeMatch ?? []).forEach((cpe) => {
          const parts = String(cpe.criteria ?? "").split(":");
          if (parts.length > 4) {
            if (parts[3] && parts[3] !== "*" && parts[3] !== "-")
              vendorSet.add(parts[3].replace(/_/g, " "));
            if (parts[4] && parts[4] !== "*" && parts[4] !== "-")
              productSet.add(parts[4].replace(/_/g, " "));
          }
        }),
      ),
    );

    // Guarded: a record with no `published` produced an Invalid Date, which
    // rendered literally as "Invalid Date" and sorted unpredictably.
    const pub = cve.published ? new Date(cve.published) : null;
    const pubValid = pub && !Number.isNaN(pub.getTime()) ? pub : null;

    return {
      cveId: cve.id ?? "",
      description:
        cve.descriptions?.find((d) => d.lang === "en")?.value ??
        "No description available",
      cvssV2: v2.baseScore ?? "-",
      cvssV3: v3.baseScore ?? "-",
      severity,
      cwes: [...cweSet],
      attackVector: v3.attackVector ?? v2.accessVector ?? "-",
      references,
      hasExploit,
      vendors: [...vendorSet].slice(0, 8),
      products: [...productSet].slice(0, 8),
      vector: v3.vectorString ?? v2.vectorString ?? "-",
      complexity: v3.attackComplexity ?? v2.accessComplexity ?? "-",
      impactC: v3.confidentialityImpact ?? v2.confidentialityImpact ?? "-",
      impactI: v3.integrityImpact ?? v2.integrityImpact ?? "-",
      impactA: v3.availabilityImpact ?? v2.availabilityImpact ?? "-",
      publishedDate: pubValid ? pubValid.toLocaleDateString("en-US") : "-",
      sortDate: pubValid,
      lastModified: cve.lastModified ?? null,
      epss: null,
      epssPercentile: null,
      isKev: false,
      riskScore: null,
      riskLevel: "",
    } satisfies Vuln;
  });
}

// ---------------------------------------------------------------- EPSS
export async function fetchEpss(
  cveIds: string[],
): Promise<Map<string, { epss: number; percentile: number }>> {
  const result = new Map<string, { epss: number; percentile: number }>();
  const ids = [...new Set(cveIds.filter((id) => id && CVE_REGEX.test(id)))];
  const BATCH = 100;
  for (let i = 0; i < ids.length; i += BATCH) {
    const chunk = ids.slice(i, i + BATCH);
    try {
      const res = await fetch(
        `https://api.first.org/data/v1/epss?cve=${chunk.join(",")}&pretty=false`,
      );
      if (!res.ok) continue;
      const json = await res.json();
      const payload = json as { data?: EpssRow[] };
      (payload.data ?? []).forEach((row) =>
        result.set(String(row.cve ?? "").toUpperCase(), {
          epss: parseFloat(row.epss ?? "0"),
          percentile: parseFloat(row.percentile ?? "0"),
        }),
      );
      if (i + BATCH < ids.length) await new Promise((r) => setTimeout(r, 250));
    } catch {
      /* on continue */
    }
  }
  return result;
}

/**
 * Charge les CVE depuis la BASE (déjà traitées & enrichies par le collecteur serveur).
 * AUCUN appel NVD côté navigateur -> chargement instantané.
 * Signature/contrat inchangés (Vuln[] trié récent -> ancien) : le dashboard ne change pas.
 */
export async function loadCves(keyword = ""): Promise<Vuln[]> {
  const url = keyword ? `/api/cves?search=${encodeURIComponent(keyword)}` : "/api/cves";
  const res = await fetch(url);
  if (!res.ok) throw new Error(`CVE load failed: ${res.status} (database unavailable?)`);
  const { cves } = await res.json();
  const list = (cves as Vuln[]).map((v) => ({
    ...v,
    sortDate: v.sortDate ? new Date(v.sortDate) : null,
  }));
  list.sort((a, b) => (b.sortDate?.getTime() ?? 0) - (a.sortDate?.getTime() ?? 0));
  return list;
}

/**
 * Charge les 0-day depuis la BASE (déjà traités & enrichis par le collecteur serveur).
 * AUCUN appel externe côté navigateur -> chargement instantané.
 * ?kind= reserved|prepub_exploited|advisory|resolved (became_cve=true)
 * ?search= filtre titre/cve_id/ghsa_id/product
 * ?active= true -> became_cve=false (par défaut)
 */
export async function loadZeroDays(params: { kind?: string; search?: string; active?: string } = {}): Promise<ZeroDay[]> {
  const sp = new URLSearchParams()
  if (params.kind) sp.set("kind", params.kind)
  if (params.search) sp.set("search", params.search)
  if (params.active) sp.set("active", params.active)
  const url = sp.toString() ? `/api/zero-days?${sp.toString()}` : "/api/zero-days"
  const res = await fetch(url)
  if (!res.ok) throw new Error(`0-day load failed: ${res.status} (database unavailable?)`)
  const { zeroDays } = await res.json()
  const list = (zeroDays as ZeroDay[]).map((z) => ({
    ...z,
    firstSeenAt: z.firstSeenAt ? z.firstSeenAt : null,
    lastSeenAt: z.lastSeenAt ? z.lastSeenAt : null,
    resolvedAt: z.resolvedAt ? z.resolvedAt : null,
  }))
  list.sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
  return list
}
