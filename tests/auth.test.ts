import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { existsSync, readFileSync } from "fs"
import { Pool } from "pg"

// ── Charge .env.local s'il existe (dev local). En CI, TEST_DATABASE_URL + secrets
//    sont injectés par le workflow — ce fichier n'a besoin d'exister nulle part. ──
if (existsSync(".env.local")) {
  for (const line of readFileSync(".env.local", "utf8").split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/)
    if (m) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "")
  }
}
// Base de TESTS dédiée (jamais la base de prod). Prioritaire sur .env.local.
if (process.env.TEST_DATABASE_URL) process.env.DATABASE_URL = process.env.TEST_DATABASE_URL
// Envoi d'email inerte pendant les tests (pas d'appel SMTP/Resend réel)
delete process.env.GMAIL_USER
delete process.env.GMAIL_APP_PASSWORD
delete process.env.RESEND_API_KEY

// Les suites "base réelle" nécessitent une vraie URL (jamais le placeholder des tests isolés).
const HAS_DB = Boolean(
  process.env.DATABASE_URL &&
    !process.env.DATABASE_URL.startsWith("postgresql://placeholder"),
)

type AuthModule = typeof import("../lib/auth")
type ApiAuthModule = typeof import("../lib/api-auth")
let auth: AuthModule["auth"]
let requireUser: ApiAuthModule["requireUser"]

const TEST_DOMAIN = "@octupus-test.local"
const email = `test-${Date.now()}${TEST_DOMAIN}`
const password = "Test12345!"

function pool() {
  return new Pool({
    connectionString: (process.env.DATABASE_URL || "").replace(/&?channel_binding=require/, ""),
    // Jamais de blocage si la base est indisponible en test.
    //
    // 15s, pas 5s : la base de test est une branche Neon distante qui doit
    // sortir de veille au premier appel. Un démarrage à froid dépasse
    // régulièrement 5s, ce qui faisait échouer un test d'inscription pour une
    // raison purement réseau — le suivant, sur une connexion déjà chaude,
    // passait. Une latence rapportée comme une erreur de logique est pire
    // qu'un test lent.
    connectionTimeoutMillis: 15000,
  })
}
// Convertit un en-tête Set-Cookie en en-tête Cookie (paires name=value uniquement)
function cookieHeaderFrom(setCookie: string) {
  return setCookie.split(/,(?=[^ ;]+=)/).map((c) => c.split(";")[0].trim()).join("; ")
}

beforeAll(async () => {
  auth = (await import("../lib/auth")).auth
  requireUser = (await import("../lib/api-auth")).requireUser
})

afterAll(async () => {
  if (!HAS_DB) return
  const p = pool()
  await p.query(`DELETE FROM session  WHERE "userId" IN (SELECT id FROM "user" WHERE email LIKE $1)`, ["%" + TEST_DOMAIN])
  await p.query(`DELETE FROM account  WHERE "userId" IN (SELECT id FROM "user" WHERE email LIKE $1)`, ["%" + TEST_DOMAIN])
  await p.query(`DELETE FROM verification WHERE identifier LIKE $1`, ["%" + TEST_DOMAIN])
  await p.query(`DELETE FROM "user"   WHERE email LIKE $1`, ["%" + TEST_DOMAIN])
  await p.end()
})

describe("Configuration Better Auth", () => {
  test("Email/mot de passe activé", () => {
    expect(auth.options.emailAndPassword?.enabled).toBe(true)
  })
  test("Vérification email OBLIGATOIRE (mode strict)", () => {
    expect(auth.options.emailAndPassword?.requireEmailVerification).toBe(true)
  })
  test("Providers Google + GitHub configurés quand les secrets sont présents", () => {
    // buildSocialProviders() n'enregistre que les providers dont les secrets existent.
    // Le test est donc valide qu'avec un secret réel (prod/CI avec secrets > dev sans .env.local).
    if (process.env.GITHUB_CLIENT_ID || process.env.GOOGLE_CLIENT_ID) {
      expect(auth.options.socialProviders?.google ?? auth.options.socialProviders?.github).toBeDefined()
    }
  })
  test("Account linking activé (UN user par email) avec providers de confiance", () => {
    const al = auth.options.account?.accountLinking
    expect(al?.enabled).toBe(true)
    expect(al?.trustedProviders).toContain("google")
    expect(al?.trustedProviders).toContain("github")
    expect(al?.trustedProviders).toContain("email-password")
  })
  test("Sessions : expiration + rotation configurées", () => {
    expect(auth.options.session?.expiresIn).toBeGreaterThan(0)
    expect(auth.options.session?.updateAge).toBeGreaterThan(0)
  })
  test("Rate limiting activé", () => {
    expect(auth.options.rateLimit?.enabled).toBe(true)
  })
})

describe.skipIf(!HAS_DB)("Flux email/mot de passe — mode strict (base réelle)", () => {
  test("Inscription : crée un utilisateur SANS session (email non vérifié)", async () => {
    const res = await auth.api.signUpEmail({ body: { name: "Test User", email, password } })
    expect(res.user?.email).toBe(email)
    // requireEmailVerification -> aucune session tant que l'email n'est pas vérifié
    expect(res.token).toBeFalsy()
  })

  test("Un seul utilisateur en base pour cet email (pas de doublon)", async () => {
    const p = pool()
    const r = await p.query(`SELECT COUNT(*)::int AS n FROM "user" WHERE email = $1`, [email])
    await p.end()
    expect(r.rows[0].n).toBe(1)
  })

  test("Connexion BLOQUÉE tant que l'email n'est pas vérifié (pas de session)", async () => {
    let blocked = false
    try {
      const r = await auth.api.signInEmail({ body: { email, password }, asResponse: true })
      blocked = !/session/i.test(r.headers.get("set-cookie") || "")
    } catch {
      blocked = true
    }
    expect(blocked).toBe(true)
  })

  test("Une fois l'email vérifié, la connexion réussit et la session est valide", async () => {
    const p = pool()
    await p.query(`UPDATE "user" SET "emailVerified" = true WHERE email = $1`, [email])
    await p.end()
    const signIn = await auth.api.signInEmail({ body: { email, password }, asResponse: true })
    const setCookie = signIn.headers.get("set-cookie")
    expect(setCookie).toBeTruthy()
    const session = await auth.api.getSession({ headers: new Headers({ cookie: cookieHeaderFrom(setCookie!) }) })
    expect(session?.user.email).toBe(email)
  })
})

describe("Sécurité des routes", () => {
  test("getSession renvoie null sans cookie", async () => {
    const s = await auth.api.getSession({ headers: new Headers() })
    expect(s).toBeNull()
  })
  test("requireUser refuse (401) une requête non authentifiée", async () => {
    const gate = await requireUser(new Request("http://localhost:3000/api/assets"))
    expect(gate.user).toBeNull()
    expect(gate.deny?.status).toBe(401)
  })
})