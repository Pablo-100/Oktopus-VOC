import { NextResponse } from "next/server"
import { sql, initDb } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { rateLimited, keyFrom } from "@/lib/rate-limit"
import { encryptSecret, maskSecret, vaultAvailable } from "@/lib/crypto-vault"
import { checkCredentials } from "@/lib/exposure/credential-check"
import {
  PROVIDER_CREDENTIAL_FIELDS,
  CREDENTIAL_PROVIDERS,
  asCredentialProvider,
  isSecretField,
} from "@/lib/exposure/credentials"

export const dynamic = "force-dynamic"

/**
 * BYOK credential management.
 *
 * The EASM providers are paid, so users bring their own keys and spend their
 * own credits; the CVE and 0-day feeds stay free and shared. That makes this
 * route custodian of OTHER PEOPLE'S secrets, which sets the rules it follows:
 *
 *   - A stored secret is NEVER returned. Not to its owner, not masked-but-
 *     recoverable, not in an error. The only thing that comes back is the last
 *     four characters, enough to recognise which key is stored.
 *   - Values are sealed with AES-256-GCM before they reach the database, under
 *     a key held in the environment, so a database dump alone is inert.
 *   - Saving performs one REAL provider call first. A key that cannot be used
 *     is worth knowing about now, not on the user's first empty search.
 */

interface CredentialRow {
  provider: string
  field: string
  last4: string | null
  status: string
  status_note: string | null
  verified_at: string | null
  updated_at: string
}

/** What the account page renders. Contains no secret material. */
async function summary(userId: string) {
  await initDb()
  const rows = (await sql`
    SELECT provider, field, last4, status, status_note, verified_at, updated_at
    FROM user_provider_credentials
    WHERE user_id = ${userId}
  `) as CredentialRow[]

  return CREDENTIAL_PROVIDERS.map((provider) => {
    const fields = PROVIDER_CREDENTIAL_FIELDS[provider]
    const stored = rows.filter((r) => r.provider === provider)
    const complete = fields.every((f) => stored.some((r) => r.field === f))
    const first = stored[0]
    return {
      provider,
      fields: fields.map((field) => {
        const row = stored.find((r) => r.field === field)
        return { field, secret: isSecretField(field), hint: row?.last4 ?? null, stored: Boolean(row) }
      }),
      // A provider is only usable when every field it needs is present — FOFA
      // needs an email as well as a key, and a half-filled entry would claim to
      // work while failing every call.
      configured: complete,
      status: complete ? (first?.status ?? "unverified") : "incomplete",
      statusNote: first?.status_note ?? null,
      verifiedAt: first?.verified_at ?? null,
      // Whether the PLATFORM could serve this provider if the user stores
      // nothing. Drives the "you can try it without a key" hint.
      platformFallback: fields.every((f) => Boolean(process.env[f])),
    }
  })
}

export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  try {
    return NextResponse.json(
      { providers: await summary(gate.user.id), vaultReady: vaultAvailable() },
      { headers: { "Cache-Control": "no-store" } },
    )
  } catch (e) {
    return apiError(e, "account-credentials-get")
  }
}

/** Save (or replace) one provider's credentials, after verifying them for real. */
export async function PUT(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // Tight: each call spends a real provider request, so this is an abuse path
  // as well as a credential path.
  const denied = rateLimited(keyFrom(req, gate.user.id), 10, 60_000)
  if (denied) return denied

  try {
    if (!vaultAvailable()) {
      return NextResponse.json(
        {
          error:
            "Credential storage is not configured on this deployment (CREDENTIAL_ENCRYPTION_KEY is missing). Keys cannot be stored safely, so they are not accepted.",
        },
        { status: 503 },
      )
    }

    const body = (await req.json().catch(() => null)) as {
      provider?: unknown
      values?: unknown
    } | null

    const provider = asCredentialProvider(body?.provider)
    if (!provider) return NextResponse.json({ error: "Unknown provider." }, { status: 400 })

    const raw = body?.values
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return NextResponse.json({ error: "Missing 'values'." }, { status: 400 })
    }

    const allowed = PROVIDER_CREDENTIAL_FIELDS[provider]
    const values: Record<string, string> = {}
    for (const field of allowed) {
      const v = (raw as Record<string, unknown>)[field]
      if (typeof v !== "string" || !v.trim()) {
        return NextResponse.json({ error: `Missing value for ${field}.` }, { status: 400 })
      }
      // A pasted key with stray whitespace is the single most common cause of a
      // "wrong key" that is actually correct.
      const trimmed = v.trim()
      if (trimmed.length > 512) {
        return NextResponse.json({ error: `Value for ${field} is too long.` }, { status: 400 })
      }
      values[field] = trimmed
    }

    // Verify BEFORE storing. An unusable key is reported now rather than
    // discovered later as a mysteriously empty result set.
    const check = await checkCredentials(provider, values)
    if (check.status === "invalid") {
      return NextResponse.json({ error: check.message, status: check.status }, { status: 400 })
    }

    const now = new Date().toISOString()
    for (const field of allowed) {
      const plaintext = values[field]
      await sql`
        INSERT INTO user_provider_credentials
          (user_id, provider, field, ciphertext, last4, status, status_note, verified_at, created_at, updated_at)
        VALUES (
          ${gate.user.id}, ${provider}, ${field},
          ${encryptSecret(plaintext, gate.user.id, provider)},
          ${isSecretField(field) ? maskSecret(plaintext) : plaintext},
          ${check.status}, ${check.message}, ${now}::timestamptz, now(), now()
        )
        ON CONFLICT (user_id, provider, field) DO UPDATE SET
          ciphertext = EXCLUDED.ciphertext,
          last4 = EXCLUDED.last4,
          status = EXCLUDED.status,
          status_note = EXCLUDED.status_note,
          verified_at = EXCLUDED.verified_at,
          updated_at = now()
      `
    }

    return NextResponse.json({
      ok: true,
      // `quota_exhausted` and `unreachable` are STORED, not rejected: the key
      // is valid, the account is simply empty or the provider was briefly
      // unavailable. Saying so is more useful than refusing the save.
      status: check.status,
      message: check.message,
      providers: await summary(gate.user.id),
    })
  } catch (e) {
    return apiError(e, "account-credentials-put")
  }
}

/** Remove one provider's credentials. The user falls back to platform keys, if any. */
export async function DELETE(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  const denied = rateLimited(keyFrom(req, gate.user.id), 20, 60_000)
  if (denied) return denied

  try {
    const body = (await req.json().catch(() => null)) as { provider?: unknown } | null
    const provider = asCredentialProvider(body?.provider)
    if (!provider) return NextResponse.json({ error: "Unknown provider." }, { status: 400 })

    await initDb()
    // Scoped to the caller: a user can only ever delete their own rows.
    await sql`
      DELETE FROM user_provider_credentials
      WHERE user_id = ${gate.user.id} AND provider = ${provider}
    `
    return NextResponse.json({ ok: true, providers: await summary(gate.user.id) })
  } catch (e) {
    return apiError(e, "account-credentials-delete")
  }
}
