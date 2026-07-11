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
