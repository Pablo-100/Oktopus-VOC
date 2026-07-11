import nodemailer, { type Transporter } from "nodemailer"
import { Resend } from "resend"

/**
 * Envoi d'emails transactionnels (codes OTP), à double fournisseur :
 *
 *  - "gmail"  : Gmail SMTP via nodemailer — GRATUIT, envoie à n'importe qui
 *               (~500/jour). Requiert GMAIL_USER + GMAIL_APP_PASSWORD.
 *  - "resend" : ESP HTTP — nécessite un domaine vérifié pour envoyer à tous
 *               (sinon mode test = seulement l'email du compte). Requiert RESEND_API_KEY.
 *
 * Sélection via EMAIL_PROVIDER ("gmail" | "resend"), sinon auto-détection
 * (Gmail prioritaire car il envoie à tous gratuitement). Si rien n'est
 * configuré, l'envoi est ignoré proprement (no-op).
 */
const APP_NAME = "OCTUPUS"

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
  if (!gmailTransport) {
    gmailTransport = nodemailer.createTransport({ service: "gmail", auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD } })
  }
  return gmailTransport
}
let resendClient: Resend | null = null
function getResend(): Resend {
  if (!resendClient) resendClient = new Resend(RESEND_API_KEY)
  return resendClient
}

type OtpType = "sign-in" | "email-verification" | "forget-password" | "change-email"

const COPY: Record<OtpType, { subject: string; title: string; intro: string }> = {
  "email-verification": { subject: `${APP_NAME} — Vérifie ton email`, title: "Vérifie ton adresse email", intro: "Saisis ce code pour activer ton compte OCTUPUS :" },
  "sign-in": { subject: `${APP_NAME} — Code de connexion`, title: "Connexion à OCTUPUS", intro: "Voici ton code de connexion à usage unique :" },
  "forget-password": { subject: `${APP_NAME} — Réinitialisation du mot de passe`, title: "Réinitialise ton mot de passe", intro: "Utilise ce code pour définir un nouveau mot de passe :" },
  "change-email": { subject: `${APP_NAME} — Confirme ton nouvel email`, title: "Confirme ton nouvel email", intro: "Saisis ce code pour confirmer ce nouvel email :" },
}

function otpHtml(otp: string, type: OtpType, expiresMinutes: number) {
  const c = COPY[type]
  const digits = otp.split("").map((d) => `<span style="display:inline-block;min-width:44px;margin:0 4px;padding:14px 0;background:#0b1220;border:1px solid #22304a;border-radius:12px;font-size:30px;font-weight:800;color:#67e8f9;letter-spacing:2px;">${d}</span>`).join("")
  return `
  <div style="margin:0;padding:32px 16px;background:#060913;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
    <div style="max-width:520px;margin:0 auto;background:#0a0e1a;border:1px solid #1b2740;border-radius:20px;overflow:hidden;">
      <div style="padding:24px 28px;background:linear-gradient(135deg,#7c3aed22,#ec489922);border-bottom:1px solid #1b2740;">
        <span style="font-size:20px;font-weight:800;color:#e2e8f0;letter-spacing:1px;">🐙 ${APP_NAME}</span>
        <span style="float:right;color:#64748b;font-size:12px;">Vulnerability Operations Center</span>
      </div>
      <div style="padding:32px 28px;">
        <h1 style="margin:0 0 8px;font-size:20px;color:#f1f5f9;">${c.title}</h1>
        <p style="margin:0 0 24px;font-size:14px;color:#94a3b8;line-height:1.6;">${c.intro}</p>
        <div style="text-align:center;margin:8px 0 20px;">${digits}</div>
        <p style="margin:0;font-size:13px;color:#64748b;">Ce code expire dans <strong style="color:#94a3b8;">${expiresMinutes} minutes</strong>. Si tu n'es pas à l'origine de cette demande, ignore cet email.</p>
      </div>
      <div style="padding:16px 28px;border-top:1px solid #1b2740;color:#475569;font-size:11px;">Envoyé automatiquement par OCTUPUS — ne réponds pas à cet email.</div>
    </div>
  </div>`
}

export async function sendOtpEmail(to: string, otp: string, type: OtpType, expiresMinutes = 5): Promise<boolean> {
  const provider = activeProvider()
  const c = COPY[type]
  const html = otpHtml(otp, type, expiresMinutes)
  const text = `${c.title}\n\n${c.intro}\n\nCode : ${otp}\n\nCe code expire dans ${expiresMinutes} minutes.`

  if (provider === "gmail") {
    await getGmail().sendMail({ from: `"${APP_NAME} Security" <${GMAIL_USER}>`, to, subject: c.subject, text, html })
    return true
  }
  if (provider === "resend") {
    const { error } = await getResend().emails.send({ from: RESEND_FROM, to, subject: c.subject, text, html })
    if (error) { console.error("[mailer] Resend a renvoyé une erreur:", error); return false }
    return true
  }
  console.warn("[mailer] Aucun fournisseur email configuré (GMAIL_* ou RESEND_API_KEY) — email non envoyé.")
  return false
}
