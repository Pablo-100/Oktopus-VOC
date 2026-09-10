/**
 * Plain-language explanation for a 0-day entry — written for a reader with no
 * security background. Always produced server-side (never null/missing), unlike
 * `description` which is null for KEV-sourced entries and a dense technical
 * writeup for GitHub advisories. Deterministic (no AI call, no API key needed,
 * no cost) so every single entry gets one, not just the ones an AI happens to run for.
 */
import type { ZeroDay, ZeroDayKind, ZeroDayExploitState } from "@/lib/types"

function kindClause(kind: ZeroDayKind, exploitState: ZeroDayExploitState): string {
  if (kind === "prepub_exploited") {
    let s = "This is a confirmed zero-day: attackers were already using this weakness before it had an official public record, so defenders had no advance warning."
    if (exploitState === "kev-confirmed") {
      s += " CISA — the U.S. government's cybersecurity agency — has confirmed real-world attacks and added it to its official list of Known Exploited Vulnerabilities."
    } else if (exploitState === "source-reported") {
      s += " Independent security researchers have reported real-world attacks exploiting it."
    } else if (exploitState === "poc-published") {
      s += " A working proof-of-concept exploit is already public, so attackers have what they need even though no live attack has been confirmed yet."
    }
    return s
  }
  if (kind === "reserved") {
    return "An identifier for this vulnerability has been reserved, but full public details haven't been released yet — usually because the vendor or researcher is still finishing a fix before going public."
  }
  return "This is a documented security issue that was published without an official CVE number, and it may never get one — it's tracked outside the usual CVE system, but the vulnerability itself is real."
}

function impactClause(product: string | null): string {
  return product ? ` It affects ${product}.` : ""
}

function urgencyClause(severity: string, riskScore: number): string {
  const sev = severity.toLowerCase()
  if (sev === "critical" || sev === "high") {
    return ` Given its ${sev} severity (risk score ${riskScore}/100), if you use this software you should treat it as urgent — check for a vendor patch or workaround right away.`
  }
  if (sev === "medium") {
    return ` Its risk score (${riskScore}/100) is moderate — patch it as part of your normal update cycle, no need to panic.`
  }
  return ` Its risk score (${riskScore}/100) is currently low — worth tracking, but not urgent.`
}

function resolutionClause(becameCve: boolean): string {
  return becameCve
    ? " It has since been assigned an official CVE number — search for it in the CVE Dashboard for full technical details."
    : ""
}

export function explainZeroDay(z: Pick<ZeroDay, "kind" | "exploitState" | "product" | "severity" | "riskScore" | "becameCve">): string {
  return (
    kindClause(z.kind, z.exploitState) +
    impactClause(z.product) +
    urgencyClause(z.severity, z.riskScore) +
    resolutionClause(z.becameCve)
  )
}
