/**
 * Per-user provider credentials (BYOK), with a platform fallback.
 *
 * The EASM providers are paid; the CVE feeds are not. So users bring their own
 * EASM keys and spend their own credits, while CVE/0-day data stays free and
 * shared. That change makes three things true that were not true when every key
 * came from `process.env`:
 *
 *   1. A request must carry WHOSE keys it is using. Providers used to read the
 *      environment directly from module scope, which has no notion of a user.
 *   2. Secrets now originate in the DATABASE, not the environment, so the
 *      redaction that protected us before (matching known env values) is blind
 *      to them unless the active values are registered somewhere it can see.
 *   3. Results fetched with one user's key must not be served from cache to
 *      another user, who did not pay for them.
 *
 * All three are handled by putting the resolved credentials in an
 * AsyncLocalStorage context for the duration of the work. Providers ask this
 * module for a value instead of reading the environment; redaction asks it for
 * the active secrets; the cache asks it who owns the result.
 */
import { AsyncLocalStorage } from "async_hooks"
import { sql, initDb } from "@/lib/db"
import { decryptSecret, vaultAvailable } from "@/lib/crypto-vault"

/**
 * The environment variable names each provider authenticates with.
 *
 * This is the single source of truth for what a user may store, what the
 * account UI renders, and what the vault seals. A provider missing from here
 * simply cannot be configured per-user — it keeps using platform credentials.
 */
export const PROVIDER_CREDENTIAL_FIELDS = {
  shodan: ["SHODAN_API_KEY"],
  censys: ["CENSYS_API_TOKEN", "CENSYS_ORG_ID"],
  netlas: ["NETLAS_API_KEY"],
  leakix: ["LEAKIX_API_KEY"],
  fofa: ["FOFA_EMAIL", "FOFA_API_KEY"],
  zoomeye: ["ZOOMEYE_API_KEY"],
  greynoise: ["GREYNOISE_API_KEY"],
  abuseipdb: ["ABUSEIPDB_API_KEY"],
} as const satisfies Record<string, readonly string[]>

export type CredentialProvider = keyof typeof PROVIDER_CREDENTIAL_FIELDS

export const CREDENTIAL_PROVIDERS = Object.keys(PROVIDER_CREDENTIAL_FIELDS) as CredentialProvider[]

/** Fields that are identifiers rather than secrets — safe to display in full. */
const NON_SECRET_FIELDS = new Set(["FOFA_EMAIL", "CENSYS_ORG_ID"])

export function isSecretField(field: string): boolean {
  return !NON_SECRET_FIELDS.has(field)
}

export interface CredentialContext {
  /** Resolved values, keyed by environment variable name. */
  values: Readonly<Record<string, string>>
  /** Providers for which the USER supplied credentials (not the platform's). */
  userProvided: ReadonlySet<string>
  /** Owner of the user-supplied credentials, or null when running on platform keys only. */
  userId: string | null
}

const store = new AsyncLocalStorage<CredentialContext>()

/**
 * Resolve one credential field.
 *
 * Providers call this instead of reading `process.env` so that the same code
 * serves a web request (user's keys), a cron run (the asset owner's keys), and
 * a test (the environment). Falling back to the environment is deliberate: it
 * keeps the platform's own keys working as a free tier and keeps every existing
 * test valid without a context.
 */
export function credential(field: string): string | undefined {
  const ctx = store.getStore()
  const fromUser = ctx?.values[field]
  if (fromUser) return fromUser
  return process.env[field] || undefined
}

/** Whether the active context is using the USER's own key for this provider. */
export function usingOwnKey(provider: string): boolean {
  return store.getStore()?.userProvided.has(provider) ?? false
}

/**
 * Identity to scope cached provider responses and quota by.
 *
 * A result fetched with a user's own key is theirs: another user must not read
 * it from cache, both because they did not pay for it and because plans differ
 * in what they return. Results fetched with the platform's key are shared,
 * which is what makes the free tier affordable.
 */
export function cacheScope(provider: string): string {
  const ctx = store.getStore()
  if (ctx?.userId && ctx.userProvided.has(provider)) return `u:${ctx.userId}`
  return "platform"
}

/**
 * Scope for a result built from SEVERAL providers at once.
 *
 * A correlated search may mix the user's own Censys key with the platform's
 * GreyNoise key, and the combined answer is only reproducible by that user. If
 * ANY of their own credentials contributed, the whole result is theirs and must
 * not be served from cache to anyone else. Only a result built entirely on
 * platform keys is shareable.
 */
export function resultScope(): string {
  const ctx = store.getStore()
  if (ctx?.userId && ctx.userProvided.size > 0) return `u:${ctx.userId}`
  return "platform"
}

/**
 * Every secret value active right now, for redaction.
 *
 * `redactSecrets` cannot match user keys against a list of environment
 * variables because they never appear in the environment. Without this, a
 * provider that echoes its request back — Shodan authenticates in the QUERY
 * STRING — could persist another person's API key into our stored error text.
 */
export function activeSecretValues(): string[] {
  const ctx = store.getStore()
  if (!ctx) return []
  return Object.entries(ctx.values)
    .filter(([field, value]) => isSecretField(field) && value.length >= 8)
    .map(([, value]) => value)
}

/** Run `fn` with these credentials in scope. */
export function runWithCredentials<T>(ctx: CredentialContext, fn: () => Promise<T>): Promise<T> {
  return store.run(ctx, fn)
}

interface CredentialRow {
  provider: string
  field: string
  ciphertext: string
}

/**
 * Load and decrypt one user's stored credentials.
 *
 * A record that fails to decrypt is SKIPPED rather than thrown, so one damaged
 * row (a rotated master key, a partially restored backup) degrades that single
 * provider to the platform fallback instead of breaking the user's whole
 * session. The failure is logged without the ciphertext.
 */
export async function loadUserCredentials(userId: string): Promise<CredentialContext> {
  const empty: CredentialContext = { values: {}, userProvided: new Set(), userId }
  if (!vaultAvailable()) return empty

  await initDb()
  const rows = (await sql`
    SELECT provider, field, ciphertext
    FROM user_provider_credentials
    WHERE user_id = ${userId}
  `) as CredentialRow[]

  const values: Record<string, string> = {}
  const userProvided = new Set<string>()
  for (const row of rows) {
    try {
      values[row.field] = decryptSecret(row.ciphertext, userId, row.provider)
      userProvided.add(row.provider)
    } catch (e) {
      console.error(
        `[credentials] Skipping undecryptable credential for provider=${row.provider} field=${row.field}:`,
        e instanceof Error ? e.message : "unknown error",
      )
    }
  }

  // A provider is only "user provided" when EVERY field it needs is present.
  // FOFA needs an email as well as a key; a half-configured provider would
  // otherwise claim the user's own quota scope while failing every call.
  for (const provider of [...userProvided]) {
    const required = PROVIDER_CREDENTIAL_FIELDS[provider as CredentialProvider] ?? []
    if (!required.every((f) => values[f])) {
      userProvided.delete(provider)
      for (const f of required) delete values[f]
    }
  }

  return { values, userProvided, userId }
}

/**
 * Run `fn` as `userId`, with that user's stored credentials in scope.
 *
 * Re-entrant: nested calls for the SAME user reuse the context already active
 * rather than decrypting the same rows again. That matters because the public
 * entry points call one another — refreshAsset() calls enrichSingleAsset() —
 * and each one establishes the context so that none of them can be reached
 * without it, whichever is the outermost caller.
 */
export async function withUserCredentials<T>(userId: string | null, fn: () => Promise<T>): Promise<T> {
  if (!userId) return fn()
  const active = store.getStore()
  if (active?.userId === userId) return fn()
  const ctx = await loadUserCredentials(userId)
  return runWithCredentials(ctx, fn)
}

/**
 * Which providers this user can actually reach, and on whose credentials.
 *
 * Drives the account page and the exposure status strip. Never returns secret
 * values — only whether one is present and where it came from.
 */
export async function credentialSummary(
  userId: string,
): Promise<Array<{ provider: CredentialProvider; source: "user" | "platform" | "none"; fields: string[] }>> {
  const ctx = await loadUserCredentials(userId)
  return CREDENTIAL_PROVIDERS.map((provider) => {
    const fields = PROVIDER_CREDENTIAL_FIELDS[provider]
    if (ctx.userProvided.has(provider)) return { provider, source: "user" as const, fields: [...fields] }
    const platform = fields.every((f) => Boolean(process.env[f]))
    return { provider, source: platform ? ("platform" as const) : ("none" as const), fields: [...fields] }
  })
}

/** Narrow an arbitrary string to a provider we accept credentials for. */
export function asCredentialProvider(value: unknown): CredentialProvider | null {
  return typeof value === "string" && (CREDENTIAL_PROVIDERS as string[]).includes(value)
    ? (value as CredentialProvider)
    : null
}
