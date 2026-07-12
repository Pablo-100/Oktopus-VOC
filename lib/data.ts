/**
 * Pipeline de données OCTUPUS (porté depuis dashboard.js + risk-engine.js).
 * Tout est récupéré côté navigateur (CORS ouvert) : NVD, EPSS (FIRST.org),
 * CISA KEV (fichier local /kev.json). Puis enrichissement RBVM.
 */
import type { Vuln, Severity } from "./types";
import { computeRiskScore, riskLevel, severityFromCvss } from "./risk-engine";

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

// ---------------------------------------------------------------- NVD
// Passe par le proxy serveur /api/nvd (clé côté serveur, pas de CORS/rate-limit keyless)
export async function fetchNvd(keyword = ""): Promise<Vuln[]> {
  const p = new URLSearchParams();
  p.set("resultsPerPage", "2000");
  if (keyword) {
    p.set("keywordSearch", keyword);
  } else {
    const end = new Date();
    const start = new Date();
    start.setDate(end.getDate() - 7); // fenêtre large -> plus de CVE filtrables
    p.set("pubStartDate", start.toISOString());
    p.set("pubEndDate", end.toISOString());
  }
  const res = await fetch(`/api/nvd?${p.toString()}`);
  if (!res.ok) throw new Error(`NVD ${res.status} (réessaie dans 1 min)`);
  const data = await res.json();
  return processNvd(data);
}

export function processNvd(data: { vulnerabilities?: unknown[] }): Vuln[] {
  const items = (data.vulnerabilities ?? []) as Array<{ cve: Record<string, any> }>;
  return items.map(({ cve }) => {
    const metrics = cve.metrics ?? {};
    const v3 =
      metrics.cvssMetricV31?.[0]?.cvssData ??
      metrics.cvssMetricV30?.[0]?.cvssData ??
      {};
    const v2 = metrics.cvssMetricV2?.[0]?.cvssData ?? {};
    const severity: Severity = severityFromCvss(v3.baseScore ?? v2.baseScore);

    const cweSet = new Set<string>();
    (cve.weaknesses ?? []).forEach((w: any) =>
      (w.description ?? []).forEach((d: any) => {
        if (/^CWE-\d+$/i.test(d.value)) cweSet.add(String(d.value).toUpperCase());
      }),
    );

    const references = (cve.references ?? []).map((r: any) => ({
      url: r.url,
      tags: r.tags ?? [],
    }));
    const hasExploit = references.some((r: any) => (r.tags ?? []).includes("Exploit"));

    const vendorSet = new Set<string>();
    const productSet = new Set<string>();
    (cve.configurations ?? []).forEach((cfg: any) =>
      (cfg.nodes ?? []).forEach((node: any) =>
        (node.cpeMatch ?? []).forEach((cpe: any) => {
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

    const pub = new Date(cve.published);

    return {
      cveId: cve.id,
      description:
        cve.descriptions?.find((d: any) => d.lang === "en")?.value ??
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
      publishedDate: pub.toLocaleDateString("fr-FR"),
      sortDate: pub,
      lastModified: cve.lastModified ?? null,
      epss: null,
      epssPercentile: null,
      isKev: false,
      riskScore: null,
      riskLevel: "",
    } satisfies Vuln;
  });
}

// ---------------------------------------------------------------- KEV
export async function loadKev(): Promise<Set<string>> {
  try {
    const res = await fetch("/kev.json");
    if (!res.ok) return new Set();
    const data = await res.json();
    return new Set((data.cves ?? []).map((id: string) => id.toUpperCase()));
  } catch {
    return new Set();
  }
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
      (json.data ?? []).forEach((row: any) =>
        result.set(String(row.cve).toUpperCase(), {
          epss: parseFloat(row.epss),
          percentile: parseFloat(row.percentile),
        }),
      );
      if (i + BATCH < ids.length) await new Promise((r) => setTimeout(r, 250));
    } catch {
      /* on continue */
    }
  }
  return result;
}

// ---------------------------------------------------- enrichissement RBVM
export async function enrich(vulns: Vuln[]): Promise<Vuln[]> {
  const [kev, epssMap] = await Promise.all([
    loadKev(),
    fetchEpss(vulns.map((v) => v.cveId)),
  ]);
  for (const v of vulns) {
    const key = v.cveId.toUpperCase();
    const isKev = kev.has(key);
    const epssData = epssMap.get(key);
    const epss = epssData ? epssData.epss : null;
    const bestCvss =
      v.cvssV3 !== "-" ? v.cvssV3 : v.cvssV2 !== "-" ? v.cvssV2 : 0;
    v.epss = epss;
    v.epssPercentile = epssData ? epssData.percentile : null;
    v.isKev = isKev;
    if (isKev) v.hasExploit = true;
    v.riskScore = computeRiskScore(bestCvss, epss, isKev);
    v.riskLevel = riskLevel(v.riskScore).level;
  }
  return vulns;
}

/**
 * Charge les CVE depuis la BASE (déjà traitées & enrichies par le collecteur serveur).
 * AUCUN appel NVD côté navigateur -> chargement instantané.
 * Signature/contrat inchangés (Vuln[] trié récent -> ancien) : le dashboard ne change pas.
 */
export async function loadCves(keyword = ""): Promise<Vuln[]> {
  const url = keyword ? `/api/cves?search=${encodeURIComponent(keyword)}` : "/api/cves";
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Chargement CVE ${res.status} (base indisponible ?)`);
  const { cves } = await res.json();
  const list = (cves as Vuln[]).map((v) => ({
    ...v,
    sortDate: v.sortDate ? new Date(v.sortDate) : null,
  }));
  list.sort((a, b) => (b.sortDate?.getTime() ?? 0) - (a.sortDate?.getTime() ?? 0));
  return list;
}
