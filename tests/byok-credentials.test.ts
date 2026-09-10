import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { encryptSecret, decryptSecret, maskSecret, vaultAvailable, VaultError } from "@/lib/crypto-vault"
import {
  credential,
  runWithCredentials,
  activeSecretValues,
  cacheScope,
  resultScope,
  usingOwnKey,
  isSecretField,
  asCredentialProvider,
  PROVIDER_CREDENTIAL_FIELDS,
  CREDENTIAL_PROVIDERS,
} from "@/lib/exposure/credentials"
import { redactSecrets } from "@/lib/exposure/providers/_base"

/**
 * BYOK is the point at which this platform starts holding OTHER PEOPLE'S
 * secrets. These tests cover the properties that make that acceptable: a
 * database dump is inert on its own, a row cannot be moved between users, one
 * user's key never reaches another user's request, and a key cannot escape into
 * stored error text.
 */

const REAL_KEY = process.env.CREDENTIAL_ENCRYPTION_KEY
// A fixed 32-byte key so the crypto tests do not depend on deployment config.
const TEST_KEY = Buffer.alloc(32, 7).toString("base64")

beforeAll(() => { process.env.CREDENTIAL_ENCRYPTION_KEY = TEST_KEY })
afterAll(() => {
  if (REAL_KEY === undefined) delete process.env.CREDENTIAL_ENCRYPTION_KEY
  else process.env.CREDENTIAL_ENCRYPTION_KEY = REAL_KEY
})

describe("crypto-vault — sealing user credentials", () => {
  test("round-trips a secret for the user and provider it was sealed with", () => {
    const packed = encryptSecret("shodan-live-key-abcdef", "user-1", "shodan")
    expect(decryptSecret(packed, "user-1", "shodan")).toBe("shodan-live-key-abcdef")
  })

  test("the ciphertext never contains the plaintext", () => {
    // Shaped like a real provider key, but not one. A test fixture is source
    // code: putting a live credential here would publish it.
    const secret = "K3yF1xtur3NotARealCredential0000"
    const packed = encryptSecret(secret, "user-1", "shodan")
    expect(packed.includes(secret)).toBe(false)
    // Nor as base64 of itself, which a naive "encoding" would produce.
    expect(packed.includes(Buffer.from(secret).toString("base64"))).toBe(false)
  })

  test("a row copied to ANOTHER USER does not decrypt", () => {
    // The whole point of binding owner into the AAD: stealing a ciphertext from
    // the table and pasting it into your own row must not yield a usable key.
    const packed = encryptSecret("victim-key-123456", "victim", "shodan")
    expect(() => decryptSecret(packed, "attacker", "shodan")).toThrow(VaultError)
  })

  test("a row moved to another PROVIDER column does not decrypt", () => {
    const packed = encryptSecret("some-key-123456", "user-1", "shodan")
    expect(() => decryptSecret(packed, "user-1", "censys")).toThrow(VaultError)
  })

  test("tampering with the ciphertext is detected rather than silently accepted", () => {
    const packed = encryptSecret("some-key-123456", "user-1", "shodan")
    const parts = packed.split(".")
    const body = Buffer.from(parts[3], "base64")
    body[0] ^= 0xff
    parts[3] = body.toString("base64")
    expect(() => decryptSecret(parts.join("."), "user-1", "shodan")).toThrow(VaultError)
  })

  test("a different master key cannot decrypt — a stolen DB dump alone is inert", () => {
    const packed = encryptSecret("some-key-123456", "user-1", "shodan")
    process.env.CREDENTIAL_ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64")
    try {
      expect(() => decryptSecret(packed, "user-1", "shodan")).toThrow(VaultError)
    } finally {
      process.env.CREDENTIAL_ENCRYPTION_KEY = TEST_KEY
    }
  })

  test("each encryption uses a fresh IV — identical inputs produce different ciphertext", () => {
    // IV reuse under GCM is a silent, catastrophic break, so this is asserted
    // rather than assumed.
    const a = encryptSecret("same-secret-value", "user-1", "shodan")
    const b = encryptSecret("same-secret-value", "user-1", "shodan")
    expect(a).not.toBe(b)
    expect(a.split(".")[1]).not.toBe(b.split(".")[1])
  })

  test("rejects a master key of the wrong length instead of padding it", () => {
    process.env.CREDENTIAL_ENCRYPTION_KEY = Buffer.alloc(16, 1).toString("base64")
    try {
      expect(vaultAvailable()).toBe(false)
      expect(() => encryptSecret("x-123456", "u", "shodan")).toThrow(VaultError)
    } finally {
      process.env.CREDENTIAL_ENCRYPTION_KEY = TEST_KEY
    }
  })

  test("accepts hex as well as base64, so operators are not forced into one encoding", () => {
    process.env.CREDENTIAL_ENCRYPTION_KEY = Buffer.alloc(32, 3).toString("hex")
    try {
      const packed = encryptSecret("hex-keyed-secret", "u", "shodan")
      expect(decryptSecret(packed, "u", "shodan")).toBe("hex-keyed-secret")
    } finally {
      process.env.CREDENTIAL_ENCRYPTION_KEY = TEST_KEY
    }
  })

  test("refuses to encrypt an empty secret", () => {
    expect(() => encryptSecret("", "u", "shodan")).toThrow(VaultError)
  })

  test("maskSecret reveals at most the last four characters, and nothing for short values", () => {
    expect(maskSecret("K3yF1xtur3NotARealCredential0000")).toBe("••••0000")
    expect(maskSecret("short")).toBe("••••")
  })
})

describe("credential context — whose key is in play", () => {
  const ctxA = { values: { SHODAN_API_KEY: "aaaa-user-a-key-aaaa" }, userProvided: new Set(["shodan"]), userId: "user-a" }
  const ctxB = { values: { SHODAN_API_KEY: "bbbb-user-b-key-bbbb" }, userProvided: new Set(["shodan"]), userId: "user-b" }

  test("a user's key is visible only inside their own context", async () => {
    const seenA = await runWithCredentials(ctxA, async () => credential("SHODAN_API_KEY"))
    const seenB = await runWithCredentials(ctxB, async () => credential("SHODAN_API_KEY"))
    expect(seenA).toBe("aaaa-user-a-key-aaaa")
    expect(seenB).toBe("bbbb-user-b-key-bbbb")
  })

  test("concurrent contexts do not bleed into each other", async () => {
    // The realistic failure mode for a serverless app: two requests in flight
    // at once. If credentials were held in a module variable rather than
    // AsyncLocalStorage, one of these would win and serve the wrong key.
    const [a, b] = await Promise.all([
      runWithCredentials(ctxA, async () => {
        await new Promise((r) => setTimeout(r, 10))
        return credential("SHODAN_API_KEY")
      }),
      runWithCredentials(ctxB, async () => credential("SHODAN_API_KEY")),
    ])
    expect(a).toBe("aaaa-user-a-key-aaaa")
    expect(b).toBe("bbbb-user-b-key-bbbb")
  })

  test("falls back to the platform environment when the user supplied nothing", async () => {
    process.env.NETLAS_API_KEY = "platform-netlas-key"
    try {
      const seen = await runWithCredentials(ctxA, async () => credential("NETLAS_API_KEY"))
      expect(seen).toBe("platform-netlas-key")
    } finally { delete process.env.NETLAS_API_KEY }
  })

  test("outside any context it reads the environment, so existing callers are unchanged", () => {
    process.env.NETLAS_API_KEY = "platform-netlas-key"
    try { expect(credential("NETLAS_API_KEY")).toBe("platform-netlas-key") }
    finally { delete process.env.NETLAS_API_KEY }
  })
})

describe("cache and quota scoping — who paid for this result", () => {
  const own = { values: { SHODAN_API_KEY: "own-key-value-1234" }, userProvided: new Set(["shodan"]), userId: "user-a" }
  const platformOnly = { values: {}, userProvided: new Set<string>(), userId: "user-a" }

  test("a result fetched with the user's own key is scoped to that user", async () => {
    expect(await runWithCredentials(own, async () => cacheScope("shodan"))).toBe("u:user-a")
  })

  test("a result fetched with a platform key stays shared", async () => {
    expect(await runWithCredentials(platformOnly, async () => cacheScope("shodan"))).toBe("platform")
  })

  test("scoping is per provider — the user's Shodan key does not privatise GreyNoise", async () => {
    // GreyNoise still runs on the platform key here, so its cached answer is
    // legitimately shareable even though this request also used a private key.
    expect(await runWithCredentials(own, async () => cacheScope("greynoise"))).toBe("platform")
  })

  test("a MIXED multi-provider result is private to the user who part-paid for it", async () => {
    // resultScope covers the correlated search, which cannot be attributed to a
    // single provider: if any of the user's own credentials contributed, the
    // combined answer is not reproducible by anyone else.
    expect(await runWithCredentials(own, async () => resultScope())).toBe("u:user-a")
    expect(await runWithCredentials(platformOnly, async () => resultScope())).toBe("platform")
  })

  test("usingOwnKey reflects only providers the user actually configured", async () => {
    await runWithCredentials(own, async () => {
      expect(usingOwnKey("shodan")).toBe(true)
      expect(usingOwnKey("censys")).toBe(false)
    })
  })
})

describe("redaction — a user's key must never reach stored text", () => {
  test("scrubs the active user's secret from provider error text", async () => {
    const key = "Sh0danSh4pedFixtureNotReal123456"
    const ctx = { values: { SHODAN_API_KEY: key }, userProvided: new Set(["shodan"]), userId: "user-a" }
    // Shodan authenticates in the QUERY STRING, so its own error text can quote
    // the key back at us — this is the realistic leak path, not a hypothetical.
    const raw = `Request failed: https://api.shodan.io/shodan/host/8.8.8.8?key=${key}`
    const cleaned = await runWithCredentials(ctx, async () => redactSecrets(raw))
    expect(cleaned).not.toContain(key)
  })

  test("scrubs a user key even when it appears without a recognisable parameter name", async () => {
    // The pattern rules only catch `?key=`-style occurrences. A provider that
    // echoes the bare value in a message would otherwise leak it verbatim.
    const key = "abcdefgh12345678ijklmnop"
    const ctx = { values: { NETLAS_API_KEY: key }, userProvided: new Set(["netlas"]), userId: "user-a" }
    const cleaned = await runWithCredentials(ctx, async () => redactSecrets(`Invalid token ${key} supplied`))
    expect(cleaned).not.toContain(key)
    expect(cleaned).toContain("[user-credential]")
  })

  test("non-secret identifying fields are not treated as secrets", async () => {
    // FOFA's email is an identifier, not a credential; scrubbing it would make
    // error messages unreadable for no security gain.
    const ctx = {
      values: { FOFA_EMAIL: "analyst@example.com", FOFA_API_KEY: "fofa-key-abcdef123456" },
      userProvided: new Set(["fofa"]), userId: "user-a",
    }
    const values = await runWithCredentials(ctx, async () => activeSecretValues())
    expect(values).toContain("fofa-key-abcdef123456")
    expect(values).not.toContain("analyst@example.com")
  })

  test("outside a context there is nothing to leak", () => {
    expect(activeSecretValues()).toEqual([])
  })
})

describe("provider field declarations", () => {
  test("every provider that can be configured declares at least one field", () => {
    for (const p of CREDENTIAL_PROVIDERS) {
      expect(PROVIDER_CREDENTIAL_FIELDS[p].length).toBeGreaterThan(0)
    }
  })

  test("FOFA requires both an email and a key", () => {
    expect([...PROVIDER_CREDENTIAL_FIELDS.fofa].sort()).toEqual(["FOFA_API_KEY", "FOFA_EMAIL"])
  })

  test("identifier fields are marked non-secret so the UI can show them", () => {
    expect(isSecretField("FOFA_EMAIL")).toBe(false)
    expect(isSecretField("CENSYS_ORG_ID")).toBe(false)
    expect(isSecretField("SHODAN_API_KEY")).toBe(true)
  })

  test("only known providers are accepted from request bodies", () => {
    expect(asCredentialProvider("shodan")).toBe("shodan")
    expect(asCredentialProvider("../../etc/passwd")).toBeNull()
    expect(asCredentialProvider("DATABASE_URL")).toBeNull()
    expect(asCredentialProvider(42)).toBeNull()
    expect(asCredentialProvider(null)).toBeNull()
  })
})
