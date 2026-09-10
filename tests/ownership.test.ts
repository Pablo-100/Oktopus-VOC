import { HAS_TEST_DB } from "./_db-guard"
import { describe, test, expect, afterAll, beforeAll } from "bun:test"
import {
  isDomain,
  isIpv4,
  isIpv6,
  isIpAddress,
  normalizeTarget,
  issueVerification,
  checkVerification,
  isTargetAuthorized,
  removeOwnership,
  listOwnership,
  TXT_PREFIX,
} from "@/lib/exposure/ownership"
import { sql, initDb } from "@/lib/db"

/**
 * Entitlement to MONITOR a target.
 *
 * Search and enrichment stay open — every provider is passive, so a lookup only
 * reads what was already collected. Monitoring schedules repeated queries,
 * accumulates history and pages a human, so it requires a DNS TXT record only
 * the domain's controller can publish.
 */

describe("target shape — telling an address from a domain", () => {
  test("an IPv4 address is NOT a domain", () => {
    // The bug this pins: `1.2.3.4` satisfies the label-and-dot pattern, so a
    // naive domain check calls it a domain. Because the authorisation function
    // tested domains first, every IP took the domain branch and the address
    // logic below was unreachable — the transitive rule never ran at all.
    expect(isDomain("1.2.3.4")).toBe(false)
    expect(isDomain("45.33.32.156")).toBe(false)
    expect(isIpv4("45.33.32.156")).toBe(true)
    expect(isIpAddress("45.33.32.156")).toBe(true)
  })

  test("a numeric final label is rejected, since no real TLD is all digits", () => {
    expect(isDomain("example.123")).toBe(false)
  })

  test("real domains still pass", () => {
    for (const d of ["example.com", "app.example.com", "a-b.co.uk", "xn--80ak6aa92e.com"]) {
      expect(isDomain(d)).toBe(true)
    }
  })

  test("malformed input is rejected rather than coerced", () => {
    for (const bad of ["", "localhost", "-bad.com", "bad-.com", "no_underscores.com", "a..b.com", "has space.com"]) {
      expect(isDomain(bad)).toBe(false)
    }
  })

  test("IPv6 is recognised, because the provider layer accepts IPv6 targets", () => {
    expect(isIpv6("2001:db8::1")).toBe(true)
    expect(isIpAddress("2001:db8::1")).toBe(true)
    expect(isDomain("2001:db8::1")).toBe(false)
  })

  test("normalisation collapses case and the trailing root dot", () => {
    // Otherwise "Example.COM." and "example.com" become two records, one
    // verified and one not.
    expect(normalizeTarget("Example.COM.")).toBe("example.com")
    expect(normalizeTarget("  EXAMPLE.com  ")).toBe("example.com")
  })
})

describe.skipIf(!HAS_TEST_DB)("verification lifecycle", () => {
  const U = "ownership-suite-user"
  const OTHER = "ownership-suite-other"

  // The first DB call runs the whole migration against a cold branch, which
  // exceeds bun's 5s default. Paying it once here keeps the per-test budgets
  // measuring the code rather than the connection.
  beforeAll(async () => { await initDb() }, 120_000)

  afterAll(async () => {
    await sql`DELETE FROM target_ownership WHERE user_id IN (${U}, ${OTHER})`
  })

  test("an unverified domain is not authorised", async () => {
    const a = await isTargetAuthorized(U, "example.com")
    expect(a.allowed).toBe(false)
  }, 30_000)

  test("issuing produces a pending record with an unguessable token", async () => {
    const r = await issueVerification(U, "example.com")
    expect(r.status).toBe("pending")
    expect(r.token.startsWith("octupus-verify=")).toBe(true)
    // 16 random bytes as hex.
    expect(r.token.length).toBeGreaterThan(30)
  })

  test("re-issuing ROTATES the token so an old record cannot be replayed", async () => {
    const first = await issueVerification(U, "example.com")
    const second = await issueVerification(U, "example.com")
    expect(second.token).not.toBe(first.token)
    expect(second.status).toBe("pending")
  })

  test("a check against a domain with no matching record does not verify it", async () => {
    // example.com exists and answers DNS, but publishes no token of ours.
    const r = await checkVerification(U, "example.com")
    expect(r.status).toBe("pending")
    expect(r.lastError).toBeTruthy()
    expect((await isTargetAuthorized(U, "example.com")).allowed).toBe(false)
  }, 30_000)

  test("an IP address cannot be submitted for direct verification", async () => {
    // No DNS record asserts control of an address, so offering to verify one
    // would be a promise the mechanism cannot keep.
    await expect(issueVerification(U, "45.33.32.156")).rejects.toThrow()
  })

  test("checking a target that was never started is refused", async () => {
    await expect(checkVerification(U, "never-started-here.com")).rejects.toThrow()
  })
})

describe.skipIf(!HAS_TEST_DB)("authorisation, once verified", () => {
  const U = "ownership-auth-user"
  const OTHER = "ownership-auth-other"

  afterAll(async () => {
    await sql`DELETE FROM target_ownership WHERE user_id IN (${U}, ${OTHER})`
  })

  async function verify(user: string, domain: string) {
    await issueVerification(user, domain)
    await sql`UPDATE target_ownership SET status='verified', verified_at=now() WHERE user_id=${user} AND target=${domain}`
  }

  test("the verified domain itself is authorised", async () => {
    await verify(U, "example.com")
    const a = await isTargetAuthorized(U, "example.com")
    expect(a.allowed).toBe(true)
    expect(a.via).toBe("example.com")
  }, 30_000)

  test("subdomains inherit, because only the zone owner can delegate them", async () => {
    const a = await isTargetAuthorized(U, "deep.app.example.com")
    expect(a.allowed).toBe(true)
    expect(a.via).toBe("example.com")
  }, 30_000)

  test("a look-alike domain is REJECTED, not matched by suffix confusion", async () => {
    // The classic bug in this shape of check: `endsWith("example.com")` would
    // wrongly authorise both of these. The dot in `.example.com` is what makes
    // it a delegation test rather than a string test.
    for (const evil of ["notexample.com", "evil-example.com", "example.com.attacker.net"]) {
      expect((await isTargetAuthorized(U, evil)).allowed).toBe(false)
    }
  }, 30_000)

  test("another user's verification grants this user nothing", async () => {
    expect((await isTargetAuthorized(OTHER, "example.com")).allowed).toBe(false)
  })

  test("removing the claim revokes authorisation immediately", async () => {
    await removeOwnership(U, "example.com")
    expect((await isTargetAuthorized(U, "example.com")).allowed).toBe(false)
  })

  test("an IP is authorised only while a verified domain resolves to it", async () => {
    await verify(U, "example.com")
    // example.com's real A records are whatever they are; the point is that the
    // ADDRESS branch runs at all and reaches a decision. Before the shape fix
    // this returned the domain branch's answer and never consulted DNS.
    const a = await isTargetAuthorized(U, "203.0.113.99")
    expect(a.allowed).toBe(false)
    expect(a.reason).toContain("resolves")
    await removeOwnership(U, "example.com")
  }, 30_000)

  test("with nothing verified, every target is refused", async () => {
    expect((await listOwnership(U)).length).toBe(0)
    const a = await isTargetAuthorized(U, "anything.com")
    expect(a.allowed).toBe(false)
  })

  test("the TXT name is namespaced so it cannot collide with SPF or DMARC", () => {
    expect(TXT_PREFIX.startsWith("_")).toBe(true)
    expect(TXT_PREFIX).not.toBe("_dmarc")
  })
})
