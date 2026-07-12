import nodemailer, { type Transporter } from "nodemailer"
import { Resend } from "resend"

/**
 * Emails transactionnels OCTUPUS-VOC (serveur uniquement), double fournisseur :
 *  - "gmail"  : Gmail SMTP (nodemailer) — gratuit, envoie à tous (~500/j).
 *  - "resend" : ESP HTTP — nécessite un domaine vérifié pour envoyer à tous.
 * Sélection via EMAIL_PROVIDER, sinon auto-détection. Sinon no-op propre.
 *
 * Design des emails : professionnel, sans emoji, logo en en-tête, thème clair.
 */
const APP_NAME = "OCTUPUS-VOC"
const APP_URL = (process.env.BETTER_AUTH_URL || "https://octupus-voc.vercel.app").replace(/\/$/, "")
const LOGO_URL = `${APP_URL}/logo.png`

const GMAIL_USER = process.env.GMAIL_USER
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD
const RESEND_API_KEY = process.env.RESEND_API_KEY
const RESEND_FROM = process.env.RESEND_FROM || "OCTUPUS <onboarding@resend.dev>"

function activeProvider(): "gmail" | "resend" | "none" {
  const forced = process.env.EMAIL_PROVIDER
  if (forced === "gmail") return GMAIL_USER && GMAIL_APP_PASSWORD ? "gmail" : "none"
  if (forced === "resend") return RESEND_API_KEY ? "resend" : "none"
  if (GMAIL_USER && GMAIL_APP_PASSWORD) return "gmail"
  if (RESEND_API_KEY) return "resend"
  return "none"
}

let gmailTransport: Transporter | null = null
function getGmail(): Transporter {
  if (!gmailTransport) gmailTransport = nodemailer.createTransport({ service: "gmail", auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD } })
  return gmailTransport
}
let resendClient: Resend | null = null
function getResend(): Resend {
  if (!resendClient) resendClient = new Resend(RESEND_API_KEY)
  return resendClient
}

/** Enveloppe HTML commune (en-tête logo + pied de page) — thème clair pro. */
function shell(body: string): string {
  return `
  <div style="margin:0;padding:24px 12px;background:#eef1f6;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
    <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #e5e8ee;">
      <div style="background:#0a0e1a;padding:24px 28px;text-align:center;">
        <img src="${LOGO_URL}" width="42" height="42" alt="${APP_NAME}" style="display:inline-block;border:0;outline:none;" />
        <div style="margin-top:8px;font-size:18px;font-weight:800;color:#ffffff;letter-spacing:1px;">OCTUPUS<span style="color:#22d3ee;">-VOC</span></div>
        <div style="margin-top:2px;font-size:10px;color:#8b95a7;letter-spacing:2px;text-transform:uppercase;">Vulnerability Operations Center</div>
      </div>
      <div style="padding:32px 28px;color:#1f2733;">
        ${body}
      </div>
      <div style="padding:18px 28px;background:#f7f8fa;border-top:1px solid #e5e8ee;color:#98a1b0;font-size:11px;line-height:1.6;text-align:center;">
        Message automatique d'${APP_NAME} — merci de ne pas répondre.<br />
        &copy; 2026 ${APP_NAME}. Tous droits réservés.
      </div>
    </div>
  </div>`
}

function button(href: string, label: string): string {
  return `<div style="text-align:center;margin:26px 0 4px;"><a href="${href}" style="display:inline-block;padding:12px 28px;background:#6d28d9;color:#ffffff;text-decoration:none;border-radius:10px;font-size:14px;font-weight:600;">${label}</a></div>`
}

// ─────────────────────────────────────────────────────────── OTP ───────────
type OtpType = "sign-in" | "email-verification" | "forget-password" | "change-email"

const COPY: Record<OtpType, { subject: string; title: string; intro: string }> = {
  "email-verification": { subject: `${APP_NAME} — Vérification de votre email`, title: "Vérifiez votre adresse email", intro: "Saisissez ce code de sécurité pour activer votre compte OCTUPUS-VOC." },
  "sign-in": { subject: `${APP_NAME} — Code de connexion`, title: "Votre code de connexion", intro: "Utilisez ce code à usage unique pour vous connecter à OCTUPUS-VOC." },
  "forget-password": { subject: `${APP_NAME} — Réinitialisation du mot de passe`, title: "Réinitialisez votre mot de passe", intro: "Utilisez ce code pour définir un nouveau mot de passe sur votre compte." },
  "change-email": { subject: `${APP_NAME} — Confirmation du nouvel email`, title: "Confirmez votre nouvel email", intro: "Saisissez ce code pour confirmer cette nouvelle adresse email." },
}

function otpBody(otp: string, type: OtpType, minutes: number): string {
  const c = COPY[type]
  return `
    <h1 style="margin:0 0 10px;font-size:20px;font-weight:700;color:#0f172a;">${c.title}</h1>
    <p style="margin:0 0 26px;font-size:14px;line-height:1.6;color:#5b6472;">${c.intro}</p>
    <div style="text-align:center;margin:0 0 24px;">
      <div style="display:inline-block;padding:16px 26px;background:#f3f5fb;border:1px solid #dfe3f0;border-radius:12px;font-size:30px;font-weight:800;letter-spacing:9px;color:#6d28d9;">${otp}</div>
    </div>
    <p style="margin:0;font-size:13px;line-height:1.6;color:#98a1b0;">Ce code expire dans <b style="color:#5b6472;">${minutes} minutes</b>. Si vous n'êtes pas à l'origine de cette demande, ignorez cet email en toute sécurité.</p>`
}

// ─────────────────────────────────────────────────────── Welcome ──────────
function welcomeBody(name?: string): string {
  const hello = name ? `Bienvenue, ${name}` : "Bienvenue"
  return `
    <h1 style="margin:0 0 10px;font-size:20px;font-weight:700;color:#0f172a;">${hello}</h1>
    <p style="margin:0 0 18px;font-size:14px;line-height:1.6;color:#5b6472;">
      Votre compte OCTUPUS-VOC est prêt. La plateforme priorise les vulnérabilités (CVE) par le <b>risque réel</b> — en fusionnant CVSS, EPSS et CISA KEV — pour vous indiquer quoi corriger en premier.
    </p>
    <table role="presentation" style="width:100%;border-collapse:collapse;margin:0 0 8px;">
      <tr><td style="padding:6px 0;font-size:13px;color:#5b6472;">&bull;&nbsp; Suivez les CVE priorisées par Risk Score (RBVM)</td></tr>
      <tr><td style="padding:6px 0;font-size:13px;color:#5b6472;">&bull;&nbsp; Déclarez vos actifs pour un risque contextualisé</td></tr>
      <tr><td style="padding:6px 0;font-size:13px;color:#5b6472;">&bull;&nbsp; Recevez les alertes critiques en temps réel</td></tr>
    </table>
    ${button(`${APP_URL}/dashboard`, "Ouvrir le tableau de bord")}`
}

// ─────────────────────────────────────────────────────── envoi ────────────
async function deliver(to: string, subject: string, html: string, text: string): Promise<boolean> {
  const provider = activeProvider()
  if (provider === "gmail") {
    await getGmail().sendMail({ from: `"${APP_NAME}" <${GMAIL_USER}>`, to, subject, text, html })
    return true
  }
  if (provider === "resend") {
    const { error } = await getResend().emails.send({ from: RESEND_FROM, to, subject, text, html })
    if (error) { console.error("[mailer] Resend:", error); return false }
    return true
  }
  console.warn("[mailer] Aucun fournisseur email configuré — email non envoyé.")
  return false
}

export async function sendOtpEmail(to: string, otp: string, type: OtpType, expiresMinutes = 5): Promise<boolean> {
  const c = COPY[type]
  const text = `${c.title}\n\n${c.intro}\n\nCode : ${otp}\n\nCe code expire dans ${expiresMinutes} minutes.`
  return deliver(to, c.subject, shell(otpBody(otp, type, expiresMinutes)), text)
}

export async function sendWelcomeEmail(to: string, name?: string): Promise<boolean> {
  const text = `Bienvenue sur ${APP_NAME}. Votre compte est prêt : ${APP_URL}/dashboard`
  return deliver(to, `${APP_NAME} — Bienvenue`, shell(welcomeBody(name)), text)
}
