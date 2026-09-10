/**
 * Moteur de scoring RBVM (porté depuis risk-engine.js).
 * Risk = CVSS×0.4 + EPSS×0.4 + KEV×0.2, chaque signal normalisé sur 0–100.
 */
import type { RiskTone, ZeroDayKind, ZeroDayExploitState } from "./types";

export const RISK_WEIGHTS = { cvss: 0.4, epss: 0.4, kev: 0.2 } as const;

export function computeRiskScore(
  cvss: number | string | null,
  epss: number | null,
  isKev: boolean,
): number {
  const cvssVal = parseFloat(String(cvss));
  const cvssNorm = isNaN(cvssVal) ? 0 : cvssVal * 10; // 0-10 -> 0-100
  const epssNorm = epss == null || isNaN(epss) ? 0 : epss * 100; // 0-1 -> 0-100
  const kevBoost = isKev ? 100 : 0;

  const risk =
    cvssNorm * RISK_WEIGHTS.cvss +
    epssNorm * RISK_WEIGHTS.epss +
    kevBoost * RISK_WEIGHTS.kev;

  return Math.round(risk * 10) / 10;
}

export function riskLevel(score: number | null): { level: string; tone: RiskTone } {
  const s = score ?? 0;
  if (s >= 75) return { level: "Critical", tone: "critical" };
  if (s >= 50) return { level: "High", tone: "high" };
  if (s >= 25) return { level: "Medium", tone: "medium" };
  return { level: "Low", tone: "low" };
}

/** Classes Tailwind par niveau de risque / sévérité. */
export const TONE_CLASS: Record<RiskTone, string> = {
  critical: "bg-zinc-900 text-white border-zinc-700",
  high: "bg-red-600 text-white border-red-500",
  medium: "bg-amber-500 text-black border-amber-400",
  low: "bg-emerald-600 text-white border-emerald-500",
};

export function severityFromCvss(score: number | string | null): RiskTone {
  const s = parseFloat(String(score));
  if (isNaN(s) || s === 0) return "low";
  if (s >= 9) return "critical";
  if (s >= 7) return "high";
  if (s >= 4) return "medium";
  return "low";
}

export function computeZeroDayRisk(
  kind: ZeroDayKind,
  exploitState: ZeroDayExploitState,
  isKev: boolean,
  hasExploit: boolean,
  cvss?: number | null,
  epss?: number | null
): number {
  const base = { reserved: 30, advisory: 50, prepub_exploited: 70 }[kind];
  let boost = 0;
  if (exploitState === "kev-confirmed") {
    boost = 25;
  } else if (exploitState === "source-reported") {
    boost = 20;
  } else if (exploitState === "poc-published") {
    boost = 10;
  }
  let risk = base + boost + (isKev ? 10 : 0) + (hasExploit ? 5 : 0);
  if (cvss) {
    risk += Math.min(15, cvss);
  }
  if (epss) {
    risk += Math.round((epss * 100) / 6);
  }
  if (kind === "prepub_exploited" && risk < 70) {
    risk = 70;
  }
  if (exploitState === "kev-confirmed" && risk < 80) {
    risk = 80;
  }
  if (exploitState === "source-reported" && risk < 70) {
    risk = 70;
  }
  risk = Math.max(0, Math.min(100, risk));
  return Math.round(risk * 10) / 10;
}

export function zeroDaySeverity(risk: number): RiskTone {
  return riskLevel(risk).tone;
}
