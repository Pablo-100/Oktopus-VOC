/** Helpers Threat Intelligence (CAPEC/ATT&CK depuis CWE, source d'exploit, CWE info). */
import { THREAT_MAP } from "./threat-map"
import { CWE_INFO } from "./cwe-info"
import type { Vuln } from "./types"

export const digits = (id: string) => id.replace(/\D/g, "")

export function cweName(id: string) {
  return CWE_INFO[digits(id)] ?? null
}

export function threatFor(v: Vuln) {
  const capec = new Map<string, string>()
  const attack = new Map<string, string>()
  for (const c of v.cwes ?? []) {
    const e = THREAT_MAP[digits(c)]
    if (e) {
      e.capec.forEach((x) => capec.set(x.id, x.name))
      e.attack.forEach((x) => attack.set(x.id, x.name))
    }
  }
  return {
    capec: [...capec.entries()],
    attack: [...attack.entries()],
  }
}

export function hostOf(url: string) {
  try {
    return new URL(url).hostname.replace(/^www\./, "")
  } catch {
    return url
  }
}

export function exploitSource(url: string) {
  const h = hostOf(url).toLowerCase()
  if (h.includes("exploit-db")) return "ExploitDB"
  if (h.includes("github")) return "GitHub PoC"
  if (h.includes("metasploit") || h.includes("rapid7")) return "Metasploit"
  if (h.includes("packetstorm")) return "Packet Storm"
  return h
}

export const SLA_DAYS: Record<string, number> = { critical: 1, high: 3, medium: 7, low: 30 }
export function slaDays(v: Vuln) {
  if (v.isKev) return 1
  return SLA_DAYS[v.severity] ?? 30
}
