import { describe, test, expect } from "bun:test"
import { candidates } from "@/app/api/assets/suggestions/route"

/**
 * Mapping what the providers OBSERVED onto the vocabulary the CVE data uses.
 *
 * These are two different naming systems that nobody reconciled: Shodan and
 * Netlas report marketing names ("Apache HTTP Server"), NVD stores CPE names
 * ("http_server"). Neither is derivable from the other, so several plausible
 * forms are generated and the caller keeps whichever has real CVE coverage.
 */
describe("observed-product → CPE candidate generation", () => {
  test("a single-word product yields itself", () => {
    expect(candidates("OpenSSH")).toContain("openssh")
    expect(candidates("Exim")).toContain("exim")
  })

  test("a multi-word product yields the forms CPE actually uses", () => {
    const c = candidates("Apache HTTP Server")
    // The vendor is usually the first token, the product the last, and CPE
    // joins the rest with underscores — all three are real possibilities and
    // guessing only one would under-report.
    expect(c).toContain("apache")
    expect(c).toContain("server")
    expect(c).toContain("apache_http_server")
    expect(c).toContain("http_server")
  })

  test("case and surrounding whitespace never produce distinct candidates", () => {
    expect(candidates("  OpenSSH  ")).toEqual(candidates("openssh"))
  })

  test("candidates are deduplicated", () => {
    const c = candidates("Dovecot")
    expect(new Set(c).size).toBe(c.length)
  })

  test("fragments too short to be meaningful are dropped", () => {
    // A two-character token would match an enormous, meaningless slice of the
    // CVE corpus and present it as the user's exposure.
    expect(candidates("Go")).not.toContain("go")
    for (const c of candidates("IBM DB2 v9")) expect(c.length).toBeGreaterThanOrEqual(3)
  })

  test("an absurdly long banner string cannot become a candidate", () => {
    // Provider "product" fields carry raw banner text often enough that this is
    // a real input, not a hypothetical.
    for (const c of candidates("x".repeat(200))) expect(c.length).toBeLessThanOrEqual(60)
  })

  test("empty input yields nothing usable", () => {
    expect(candidates("").every((c) => c.length >= 3)).toBe(true)
  })
})
