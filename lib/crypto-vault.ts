/**
 * Symmetric vault for third-party credentials that users entrust to us.
 *
 * These are not our secrets. A user pasting their Shodan or Censys key is
 * handing over something that can be billed against and, on some providers,
 * used to scan on their behalf — so the storage rules are stricter than for our
 * own configuration:
 *
 *   - AES-256-GCM, so a tampered ciphertext fails to decrypt rather than
 *     silently returning altered bytes.
 *   - The encryption key lives in the environment, never in the database. An
 *     attacker who exfiltrates the database alone gets nothing usable.
 *   - Each record carries its own random IV. Reusing an IV under GCM is a
 *     catastrophic, silent break, so it is generated per encryption and never
 *     derived from the plaintext or the user id.
 *   - Additional authenticated data binds a ciphertext to its owner and
 *     provider, so a row copied between users or between provider columns fails
 *     authentication instead of decrypting into the wrong context.
 */
import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "crypto"

const ALGORITHM = "aes-256-gcm"
const IV_BYTES = 12 // GCM's standard nonce length.
const KEY_BYTES = 32
const VERSION = "v1"

export class VaultError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "VaultError"
  }
}

/**
 * The master key, accepted as base64 or hex so operators are not forced into
 * one encoding. Read on every call rather than cached at module load: caching
 * would freeze a rotated key for the life of a warm serverless instance.
 */
function masterKey(): Buffer {
  const raw = process.env.CREDENTIAL_ENCRYPTION_KEY?.trim()
  if (!raw) {
    throw new VaultError(
      "CREDENTIAL_ENCRYPTION_KEY is not set. Generate one with: openssl rand -base64 32",
    )
  }
  let key: Buffer
  if (/^[0-9a-f]{64}$/i.test(raw)) key = Buffer.from(raw, "hex")
  else key = Buffer.from(raw, "base64")

  if (key.length !== KEY_BYTES) {
    throw new VaultError(
      `CREDENTIAL_ENCRYPTION_KEY must decode to ${KEY_BYTES} bytes, got ${key.length}. Generate one with: openssl rand -base64 32`,
    )
  }
  return key
}

/** True when a usable master key is configured — lets callers degrade instead of throwing. */
export function vaultAvailable(): boolean {
  try {
    masterKey()
    return true
  } catch {
    return false
  }
}

/**
 * Binds a ciphertext to the row that owns it. A ciphertext moved to another
 * user's row, or to a different provider's column, will not authenticate.
 */
function aad(userId: string, provider: string): Buffer {
  return Buffer.from(`${userId}:${provider}`, "utf8")
}

/** Encrypt one credential. Returns an opaque, self-describing string. */
export function encryptSecret(plaintext: string, userId: string, provider: string): string {
  if (!plaintext) throw new VaultError("Refusing to encrypt an empty secret.")
  const iv = randomBytes(IV_BYTES)
  const cipher = createCipheriv(ALGORITHM, masterKey(), iv)
  cipher.setAAD(aad(userId, provider))
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()
  return [VERSION, iv.toString("base64"), tag.toString("base64"), ct.toString("base64")].join(".")
}

/**
 * Decrypt one credential.
 *
 * Throws on any tampering, on a wrong master key, and on a row whose owner or
 * provider does not match the one it was sealed with.
 */
export function decryptSecret(packed: string, userId: string, provider: string): string {
  const parts = packed.split(".")
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new VaultError("Stored credential is malformed or uses an unsupported format version.")
  }
  const [, ivB64, tagB64, ctB64] = parts
  try {
    const decipher = createDecipheriv(ALGORITHM, masterKey(), Buffer.from(ivB64, "base64"))
    decipher.setAAD(aad(userId, provider))
    decipher.setAuthTag(Buffer.from(tagB64, "base64"))
    return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]).toString("utf8")
  } catch (e) {
    // Never echo the underlying OpenSSL text: it varies with the failure mode
    // and would tell an attacker which part of the record they got wrong.
    if (e instanceof VaultError) throw e
    throw new VaultError("Credential could not be decrypted. The encryption key may have changed.")
  }
}

/**
 * The only part of a secret that is ever safe to show back to its owner.
 *
 * Enough to recognise which key is stored, too little to use. Short secrets
 * reveal nothing at all rather than a usable fraction of themselves.
 */
export function maskSecret(plaintext: string): string {
  if (plaintext.length < 8) return "••••"
  return `••••${plaintext.slice(-4)}`
}

/** Constant-time comparison, for callers checking a secret without leaking length-independent timing. */
export function secretsEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8")
  const bb = Buffer.from(b, "utf8")
  if (ba.length !== bb.length) return false
  return timingSafeEqual(ba, bb)
}
