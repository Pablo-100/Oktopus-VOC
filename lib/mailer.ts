import nodemailer, { type Transporter } from "nodemailer"
import { Resend } from "resend"
import { getAppUrl } from "@/lib/app-url"

/**
 * Emails transactionnels OCTUPUS-VOC (serveur uniquement), double fournisseur :
 *  - "gmail"  : Gmail SMTP (nodemailer) — gratuit, envoie à tous (~500/j).
 *  - "resend" : ESP HTTP — nécessite un domaine vérifié pour envoyer à tous.
 * Sélection via EMAIL_PROVIDER, sinon auto-détection. Sinon no-op propre.
 *
 * Design des emails : professionnel, sans emoji, logo en en-tête, thème clair.
 */
const APP_NAME = "OCTUPUS-VOC"
// Resolved from BETTER_AUTH_URL / Vercel env — never a hardcoded deployment.
// See lib/app-url.ts for why (emails used to link to the original author's site).
const APP_URL = getAppUrl()
const LOGO_URL = `${APP_URL}/logo.png`

const GMAIL_USER = process.env.GMAIL_USER
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD
const RESEND_API_KEY = process.env.RESEND_API_KEY
const RESEND_FROM = process.env.RESEND_FROM || "OCTUPUS <onboarding@resend.dev>"

/**
 * Whether a provider is configured at all.
 *
 * Exported so the sign-up flow can say "this deployment cannot send email"
 * instead of leaving the user waiting for a code that will never arrive.
 * Returns only a boolean — never which provider, never any credential.
 */
export function mailProviderConfigured(): boolean {
  return activeProvider() !== "none"
}

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
        Automated message from ${APP_NAME} — please do not reply.<br />
        &copy; 2026 ${APP_NAME}. All rights reserved.
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
  "email-verification": { subject: `${APP_NAME} — Verify your email`, title: "Verify your email address", intro: "Enter this security code to activate your OCTUPUS-VOC account." },
  "sign-in": { subject: `${APP_NAME} — Sign-in code`, title: "Your sign-in code", intro: "Use this one-time code to sign in to OCTUPUS-VOC." },
  "forget-password": { subject: `${APP_NAME} — Reset your password`, title: "Reset your password", intro: "Use this code to set a new password on your account." },
  "change-email": { subject: `${APP_NAME} — Confirm your new email`, title: "Confirm your new email", intro: "Enter this code to confirm your new email address." },
}

function otpBody(otp: string, type: OtpType, minutes: number): string {
  const c = COPY[type]
  return `
    <h1 style="margin:0 0 10px;font-size:20px;font-weight:700;color:#0f172a;">${c.title}</h1>
    <p style="margin:0 0 26px;font-size:14px;line-height:1.6;color:#5b6472;">${c.intro}</p>
    <div style="text-align:center;margin:0 0 24px;">
      <div style="display:inline-block;padding:16px 26px;background:#f3f5fb;border:1px solid #dfe3f0;border-radius:12px;font-size:30px;font-weight:800;letter-spacing:9px;color:#6d28d9;">${otp}</div>
    </div>
    <p style="margin:0;font-size:13px;line-height:1.6;color:#98a1b0;">This code expires in <b style="color:#5b6472;">${minutes} minutes</b>. If you did not request it, you can safely ignore this email.</p>`
}

// ─────────────────────────────────────────────────────── Welcome ──────────
function welcomeBody(name?: string): string {
  const hello = name ? `Welcome, ${name}` : "Welcome"
  return `
    <h1 style="margin:0 0 10px;font-size:20px;font-weight:700;color:#0f172a;">${hello}</h1>
    <p style="margin:0 0 18px;font-size:14px;line-height:1.6;color:#5b6472;">
      Your OCTUPUS-VOC account is ready. The platform ranks vulnerabilities (CVEs) by <b>real exploitation risk</b> — combining CVSS, EPSS and CISA KEV — so you know what to fix first.
    </p>
    <table role="presentation" style="width:100%;border-collapse:collapse;margin:0 0 8px;">
      <tr><td style="padding:6px 0;font-size:13px;color:#5b6472;">&bull;&nbsp; Track CVEs ranked by risk score</td></tr>
      <tr><td style="padding:6px 0;font-size:13px;color:#5b6472;">&bull;&nbsp; Declare your assets for contextualized risk</td></tr>
      <tr><td style="padding:6px 0;font-size:13px;color:#5b6472;">&bull;&nbsp; Get critical alerts in real time</td></tr>
    </table>
    ${button(`${APP_URL}/dashboard`, "Open the dashboard")}`
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
  console.warn("[mailer] No email provider configured — email not sent. Sign-up verification codes cannot be delivered; run `bun run doctor` for setup help.")
  return false
}

export async function sendOtpEmail(to: string, otp: string, type: OtpType, expiresMinutes = 5): Promise<boolean> {
  const c = COPY[type]
  const text = `${c.title}

${c.intro}

Code: ${otp}

This code expires in ${expiresMinutes} minutes.`
  const sent = await deliver(to, c.subject, shell(otpBody(otp, type, expiresMinutes)), text)

  // Last-resort fallback for a deployment with no mail provider.
  //
  // In that state the code is undeliverable, registration can never complete,
  // and the instance is unusable by anyone — including its operator. Printing
  // the code to the server log is the difference between a fixable setup and a
  // dead install, and it discloses nothing that is not already lost: whoever
  // reads these logs already controls the deployment.
  //
  // Deliberately narrow: it fires ONLY when no provider is configured, never
  // when delivery merely failed. A transient Resend error must not start
  // spilling one-time codes into a production log.
  if (!sent && activeProvider() === "none") {
    console.warn(
      `[mailer] INSECURE FALLBACK — no email provider is configured, so this ${type} code for ${to} ` +
        `could not be delivered and is printed here instead: ${otp} (expires in ${expiresMinutes} min). ` +
        "Configure RESEND_API_KEY or GMAIL_USER + GMAIL_APP_PASSWORD and run `bun run doctor`. " +
        "One-time codes must never reach logs on a real deployment.",
    )
  }
  return sent
}

export async function sendWelcomeEmail(to: string, name?: string): Promise<boolean> {
  const text = `Bienvenue sur ${APP_NAME}. Votre compte est prêt : ${APP_URL}/dashboard`
  return deliver(to, `${APP_NAME} — Bienvenue`, shell(welcomeBody(name)), text)
}
