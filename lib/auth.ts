import { betterAuth } from "better-auth"
import { emailOTP } from "better-auth/plugins"
import { Pool } from "pg"
import { dash } from "@better-auth/infra"
import { sendOtpEmail } from "@/lib/mailer"

/**
 * Système d'authentification OCTUPUS-VOC — Better Auth (source de vérité unique).
 *
 * Règle métier centrale : UN SEUL utilisateur par adresse email.
 *   Google, GitHub et Email/Mot de passe partageant le même email sont
 *   toujours rattachés au MÊME compte (account linking) — jamais de doublon.
 *
 * Sécurité : cookies HttpOnly + SameSite=Lax, Secure en production, CSRF/state
 *   OAuth + PKCE (natifs Better Auth), rate limiting, rotation de session,
 *   cache de session signé. Aligné OWASP.
 */

const APP_NAME = "OCTUPUS"
const isProd = process.env.NODE_ENV === "production"
const baseURL = process.env.BETTER_AUTH_URL || "http://localhost:3000"

// Neon via node-postgres ('pg' ne gère pas channel_binding -> on le retire de l'URL)
const connectionString = (process.env.DATABASE_URL || "").replace(/&?channel_binding=require/, "")

// Providers sociaux activés uniquement si leurs secrets sont présents (sinon Better Auth planterait au boot)
function buildSocialProviders() {
  const providers: Record<string, { clientId: string; clientSecret: string }> = {}
  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    providers.github = { clientId: process.env.GITHUB_CLIENT_ID, clientSecret: process.env.GITHUB_CLIENT_SECRET }
  }
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    providers.google = { clientId: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET }
  }
  return providers
}

export const auth = betterAuth({
  appName: APP_NAME,
  baseURL,
  secret: process.env.BETTER_AUTH_SECRET,
  database: new Pool({ connectionString }),
  trustedOrigins: [baseURL],

  // ── Email / Mot de passe ────────────────────────────────────────────────
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 8,
    autoSignIn: true,
    // STRICT : aucune session tant que l'email n'est pas vérifié.
    // -> inscription = pas de session (proxy bloque tout), connexion non-vérifiée = refusée.
    requireEmailVerification: true,
  },

  // ── Providers OAuth ─────────────────────────────────────────────────────
  socialProviders: buildSocialProviders(),

  // ── Account linking : UN utilisateur par email ──────────────────────────
  account: {
    accountLinking: {
      enabled: true,
      // Google/GitHub fournissent des emails vérifiés -> liés au compte existant du même email.
      // "email-password" est traité comme fiable pour lier un login OAuth à un compte email.
      trustedProviders: ["google", "github", "email-password"],
      // allowDifferentEmails reste false (défaut) : on ne lie JAMAIS des emails différents (anti-takeover).
    },
  },

  // ── Cycle de vie du compte ──────────────────────────────────────────────
  user: {
    deleteUser: { enabled: true },
  },

  // ── Sessions : persistance, rotation, rafraîchissement ──────────────────
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 jours
    updateAge: 60 * 60 * 24,     // rotation : l'expiration est repoussée à chaque jour d'activité
    freshAge: 60 * 60 * 24,      // fenêtre "récente" exigée pour les actions sensibles (unlink / delete)
    cookieCache: { enabled: true, maxAge: 5 * 60 }, // getSession lit un cookie signé -> pas de hit DB à chaque requête
  },

  // ── Cookies & CSRF (OWASP) ──────────────────────────────────────────────
  advanced: {
    useSecureCookies: isProd, // Secure=on uniquement en prod (sinon OAuth casse sur http://localhost)
    defaultCookieAttributes: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProd,
    },
  },

  // ── Rate limiting (anti brute-force / abus) ─────────────────────────────
  rateLimit: {
    enabled: true, // activé aussi en dev (défaut Better Auth = prod uniquement)
    window: 60,
    max: 100,
  },

  // ── Plugins ─────────────────────────────────────────────────────────────
  plugins: [
    // Vérification d'email par CODE OTP à 6 chiffres, envoyé via Gmail SMTP.
    emailOTP({
      otpLength: 6,
      expiresIn: 60 * 5,                    // 5 minutes
      allowedAttempts: 3,                   // 3 essais max avant invalidation
      storeOTP: "hashed",                   // OTP jamais stocké en clair (OWASP)
      sendVerificationOnSignUp: true,       // envoi auto du code à l'inscription
      overrideDefaultEmailVerification: true, // la vérif d'email passe par l'OTP (pas le lien)
      async sendVerificationOTP({ email, otp, type }) {
        try {
          await sendOtpEmail(email, otp, type, 5)
        } catch (e) {
          // Un échec d'envoi ne doit jamais bloquer l'inscription/connexion.
          console.error("[email-otp] envoi échoué:", e)
        }
      },
    }),
    // Dashboard hébergé Better Auth (@better-auth/infra)
    dash(),
  ],
})
