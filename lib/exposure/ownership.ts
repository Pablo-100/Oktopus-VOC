/**
 * Proof that a user is entitled to monitor a target.
 *
 * OCTUPUS never scans anything: every observation comes from a provider that
 * already crawled the internet, so a one-off lookup is no different from
 * visiting Shodan's own website and is left open. CONTINUOUS monitoring is
 * different in kind — it schedules repeated queries against a host, stores a
 * history of it, and pages someone when it changes. Doing that to infrastructure
 * you have no relationship with is not something a hosted product should let a
 * stranger do, so it requires proof.
 *
 * The proof is a DNS TXT record, which is the standard mechanism precisely
 * because only someone with control of the domain can publish one.
 *
 * IP targets cannot be proven this way — no DNS record asserts control of an
 * address. Rather than inventing a weak check, an IP is accepted only when a
 * domain the user HAS verified currently resolves to it. That is a real,
 * re-checkable link, and it fails closed when it stops being true.
 */
import { promises as dns } from "dns"
import { randomBytes } from "crypto"
import { sql, initDb } from "@/lib/db"

/** Where the record must be published. A dedicated name avoids colliding with SPF/DMARC. */
export const TXT_PREFIX = "_octupus-verify"

export type OwnershipStatus = "pending" | "verified" | "failed"

export interface OwnershipRecord {
  target: string
  token: string
  status: OwnershipStatus
  method: string
  verifiedAt: string | null
  lastCheckedAt: string | null
  lastError: string | null
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/

export function isIpv4(value: string): boolean {
  const parts = value.trim().split(".")
  return (
    parts.length === 4 &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255)
  )
}

/** Matches the conservative IPv6 form the provider layer already accepts. */
export function isIpv6(value: string): boolean {
  const v = value.trim()
  return /^[0-9a-fA-F:]+$/.test(v) && v.includes(":") && v.length <= 45
}

export function isIpAddress(value: string): boolean {
  return isIpv4(value) || isIpv6(value)
}

/**
 * A DOMAIN, and specifically not an IP address.
 *
 * The label-and-dot shape alone is not enough: `1.2.3.4` satisfies it, so a
 * naive check reports an IPv4 address as a domain. That mattered twice — the
 * API would offer to "verify" an address by a DNS record that can never exist,
 * and `isTargetAuthorized` tested domains first, which sent every IP down the
 * domain branch and left the address logic unreachable.
 *
 * A final label of pure digits is the discriminator: no real TLD is numeric.
 */
export function isDomain(value: string): boolean {
  const v = value.trim().toLowerCase()
  if (isIpAddress(v)) return false
  if (!DOMAIN_RE.test(v)) return false
  const tld = v.slice(v.lastIndexOf(".") + 1)
  return !/^\d+$/.test(tld)
}

/**
 * Canonical form of a target.
 *
 * Verification is looked up by exact string, so `Example.COM.` and
 * `example.com` must not become two different records — one verified and one
 * not.
 */
export function normalizeTarget(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, "")
}

/**
 * Start (or restart) verification for a domain.
 *
 * The token is regenerated on every call so that a record published for an
 * earlier attempt cannot be replayed after the user has removed their claim.
 */
export async function issueVerification(userId: string, rawTarget: string): Promise<OwnershipRecord> {
  const target = normalizeTarget(rawTarget)
  if (!isDomain(target)) {
    throw new Error("Only a domain can be verified directly. An IP is authorised through a verified domain that resolves to it.")
  }
  await initDb()
  const token = `octupus-verify=${randomBytes(16).toString("hex")}`
  const rows = (await sql`
    INSERT INTO target_ownership (user_id, target, token, status, method, created_at, updated_at)
    VALUES (${userId}, ${target}, ${token}, 'pending', 'dns_txt', now(), now())
    ON CONFLICT (user_id, target) DO UPDATE SET
      token = EXCLUDED.token, status = 'pending', last_error = NULL, updated_at = now()
    RETURNING target, token, status, method, verified_at, last_checked_at, last_error
  `) as Array<Record<string, unknown>>
  return toRecord(rows[0])
}

function toRecord(r: Record<string, unknown>): OwnershipRecord {
  return {
    target: String(r.target),
    token: String(r.token),
    status: String(r.status) as OwnershipStatus,
    method: String(r.method),
    verifiedAt: r.verified_at ? String(r.verified_at) : null,
    lastCheckedAt: r.last_checked_at ? String(r.last_checked_at) : null,
    lastError: r.last_error ? String(r.last_error) : null,
  }
}

/**
 * Look for the token in DNS and record the outcome.
 *
 * Both `_octupus-verify.<domain>` and the apex are accepted: some registrars
 * make subdomain TXT records awkward, and refusing the apex would block those
 * users for no security gain — the token is unguessable either way.
 */
export async function checkVerification(userId: string, rawTarget: string): Promise<OwnershipRecord> {
  const target = normalizeTarget(rawTarget)
  await initDb()
  const rows = (await sql`
    SELECT target, token, status, method, verified_at, last_checked_at, last_error
    FROM target_ownership WHERE user_id = ${userId} AND target = ${target}
  `) as Array<Record<string, unknown>>
  if (!rows[0]) throw new Error("No verification has been started for this target.")
  const record = toRecord(rows[0])

  let found = false
  let error: string | null = null
  try {
    const names = [`${TXT_PREFIX}.${target}`, target]
    const chunks: string[] = []
    for (const name of names) {
      try {
        const txt = await dns.resolveTxt(name)
        // A TXT answer arrives as an array of string segments that must be
        // joined: records longer than 255 bytes are split by the protocol.
        for (const entry of txt) chunks.push(entry.join(""))
      } catch {
        // NXDOMAIN on one name is expected when the user chose the other.
      }
    }
    found = chunks.some((c) => c.trim() === record.token)
    if (!found) {
      error = chunks.length
        ? "The TXT record was found but does not contain the current token. If you rotated it, publish the new value."
        : "No TXT record found yet. DNS changes can take a few minutes to propagate."
    }
  } catch (e) {
    error = e instanceof Error ? e.message : "DNS lookup failed."
  }

  const updated = (await sql`
    UPDATE target_ownership SET
      status = ${found ? "verified" : "pending"},
      verified_at = ${found ? new Date().toISOString() : null}::timestamptz,
      last_checked_at = now(),
      last_error = ${error},
      updated_at = now()
    WHERE user_id = ${userId} AND target = ${target}
    RETURNING target, token, status, method, verified_at, last_checked_at, last_error
  `) as Array<Record<string, unknown>>
  return toRecord(updated[0])
}

/** Every target this user has a verification record for. */
export async function listOwnership(userId: string): Promise<OwnershipRecord[]> {
  await initDb()
  const rows = (await sql`
    SELECT target, token, status, method, verified_at, last_checked_at, last_error
    FROM target_ownership WHERE user_id = ${userId} ORDER BY target
  `) as Array<Record<string, unknown>>
  return rows.map(toRecord)
}

export async function removeOwnership(userId: string, rawTarget: string): Promise<void> {
  await initDb()
  await sql`DELETE FROM target_ownership WHERE user_id = ${userId} AND target = ${normalizeTarget(rawTarget)}`
}

/**
 * May this user monitor this target?
 *
 * Fails CLOSED: any error resolving the question is treated as "no". An
 * authorisation check that degrades to "allow" under load is not a check.
 */
export async function isTargetAuthorized(
  userId: string,
  rawTarget: string,
): Promise<{ allowed: boolean; reason: string; via?: string }> {
  const target = normalizeTarget(rawTarget)
  try {
    await initDb()
    const verified = (await sql`
      SELECT target FROM target_ownership
      WHERE user_id = ${userId} AND status = 'verified'
    `) as Array<{ target: string }>

    if (!verified.length) {
      return { allowed: false, reason: "You have not verified any domain yet." }
    }

    // Addresses FIRST. An IP is authorised only while a verified domain actually
    // resolves to it, re-checked on every call rather than cached, so the
    // authorisation disappears when the DNS record does. Both A and AAAA are
    // consulted because the provider layer accepts IPv6 targets.
    if (isIpAddress(target)) {
      for (const v of verified) {
        try {
          const addrs = isIpv6(target) ? await dns.resolve6(v.target) : await dns.resolve4(v.target)
          if (addrs.map((a) => a.toLowerCase()).includes(target)) {
            return { allowed: true, reason: "A verified domain resolves to this address.", via: v.target }
          }
        } catch {
          // This domain has no such record; try the next.
        }
      }
      return { allowed: false, reason: `No domain you have verified currently resolves to ${target}.` }
    }

    // A domain is authorised by its own record, or by a verified parent: proving
    // example.com demonstrates control of app.example.com, since only the zone
    // owner can delegate it.
    if (isDomain(target)) {
      const match = verified.find((v) => v.target === target || target.endsWith(`.${v.target}`))
      return match
        ? { allowed: true, reason: "Verified domain.", via: match.target }
        : { allowed: false, reason: `'${target}' is not covered by any domain you have verified.` }
    }

    return { allowed: false, reason: "Unrecognised target format." }
  } catch (e) {
    console.error("[ownership] authorization check failed:", e instanceof Error ? e.message : e)
    return { allowed: false, reason: "Could not verify authorisation for this target." }
  }
}
