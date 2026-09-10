/**
 * Tests purs pour lib/greynoise.ts — pas de DB, pas de réseau.
 * The parser here is locked to the REAL GreyNoise /v1/cve/{id} schema,
 * verified live 2026-08-26 (see scripts/test-exposure.ts and the comment
 * at the top of lib/greynoise.ts) against CVE-2021-44228.
 */
import { describe, test, expect } from "bun:test"
import { parseGreyNoiseCveResponse } from "@/lib/exposure/providers/greynoise"

const REAL_LOG4SHELL_RESPONSE = {
  id: "CVE-2021-44228",
  details: {
    vulnerability_name: "Apache Log4j2 Remote Code Execution Vulnerability",
    vulnerability_description: "Apache Log4j2 2.0-beta9 through 2.15.0 ...",
    cve_cvss_score: 10,
    product: "Log4j2",
    vendor: "Apache",
    published_to_nist_nvd: true,
  },
  timeline: {
    cve_published_date: "2021-12-10T10:15:09Z",
    cisa_kev_date_added: "2021-12-10T00:00:00Z",
  },
  exploitation_details: {
    attack_vector: "NETWORK",
    exploit_found: true,
    exploitation_registered_in_kev: true,
    epss_score: 0.99999,
  },
}

describe("parseGreyNoiseCveResponse — matches the real GreyNoise schema", () => {
  test("extracts exploited/inKev/epssScore/summary from a real Log4Shell response", () => {
    const r = parseGreyNoiseCveResponse("CVE-2021-44228", REAL_LOG4SHELL_RESPONSE)
    expect(r.ok).toBe(true)
    expect(r.exploited).toBe(true)
    expect(r.inKev).toBe(true)
    expect(r.epssScore).toBeCloseTo(0.99999, 5)
    expect(r.summary).toBe("Apache Log4j2 Remote Code Execution Vulnerability")
  })

  test("exploit_found=false -> exploited=false, not null", () => {
    const r = parseGreyNoiseCveResponse("CVE-2026-0001", { exploitation_details: { exploit_found: false, exploitation_registered_in_kev: false } })
    expect(r.exploited).toBe(false)
    expect(r.inKev).toBe(false)
  })

  test("completely unexpected shape -> nulls, never throws", () => {
    const r = parseGreyNoiseCveResponse("CVE-2026-0002", { totally: "unexpected", shape: 123 })
    expect(r.ok).toBe(true)
    expect(r.exploited).toBeNull()
    expect(r.inKev).toBeNull()
    expect(r.epssScore).toBeNull()
    expect(r.summary).toBeNull()
  })

  test("empty object -> nulls, never throws", () => {
    expect(() => parseGreyNoiseCveResponse("CVE-2026-0003", {})).not.toThrow()
  })

  test("wrong-typed fields are rejected rather than coerced", () => {
    const r = parseGreyNoiseCveResponse("CVE-2026-0004", {
      exploitation_details: { exploit_found: "yes", epss_score: "0.5" },
      details: { vulnerability_name: 42 },
    })
    expect(r.exploited).toBeNull()
    expect(r.epssScore).toBeNull()
    expect(r.summary).toBeNull()
  })
})
