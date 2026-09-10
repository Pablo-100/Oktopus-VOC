import { Card } from "@/components/ui/card"

export const metadata = { title: "Privacy Policy — OCTUPUS-VOC" }

export default function PrivacyPage() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-12">
      <h1 className="text-3xl font-bold tracking-tight">Privacy Policy</h1>
      <p className="mt-2 text-sm text-muted-foreground">Last updated: August 22, 2026</p>

      <Card className="glass mt-6 space-y-6 p-6 text-sm leading-relaxed sm:p-8">
        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">1. Visiting the public feed</h2>
          <p>
            Reading the 0-day tracker, the CVE dashboard&apos;s public pages, or calling the public API requires no
            account and no personal data. We log your IP address transiently, in memory only, purely to enforce rate
            limits — it is never persisted to a database or shared with third parties.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">2. If you create an account</h2>
          <p>We store:</p>
          <ul className="ml-5 mt-2 list-disc space-y-1">
            <li><strong>Identity</strong>: email address, name, and — if you sign in with Google or GitHub — the profile fields those providers share (name, email, avatar).</li>
            <li><strong>Session data</strong>: signed session cookies, session expiry and rotation timestamps, active-session metadata (for the &ldquo;active sessions&rdquo; revocation feature).</li>
            <li><strong>Product data you create</strong>: your asset inventory, CVE triage notes/assignees, and imports you trigger.</li>
          </ul>
          <p className="mt-2">
            Passwords are never stored in plain text. Email-verification codes are hashed before being stored and
            expire after 5 minutes.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">3. Third parties we rely on</h2>
          <ul className="ml-5 mt-2 list-disc space-y-1">
            <li><strong>Google / GitHub OAuth</strong> — only if you choose those sign-in methods.</li>
            <li><strong>Gmail SMTP or Resend</strong> — to deliver verification-code and account emails.</li>
            <li><strong>OpenRouter</strong> — if you use the AI analysis feature, the CVE&apos;s public description (not your personal data) is sent to generate the analysis.</li>
            <li><strong>Telegram Bot API</strong> — only for the alerting feature, which sends CVE/0-day content, never account data.</li>
            <li><strong>Neon (PostgreSQL hosting)</strong> and <strong>Vercel</strong> — infrastructure providers who host the database and the application.</li>
          </ul>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">4. Your rights</h2>
          <p>
            Wherever you are, you can ask us to access, export, correct, or delete your account data. The account
            page includes self-service session revocation and account deletion. For anything not self-service,
            email us — see Contact below. If you are in the EU/EEA or UK, this covers your rights under the GDPR;
            if you are a California resident, it covers your rights under the CCPA.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">5. Data retention</h2>
          <p>
            Account data is kept for as long as your account exists. Deleting your account removes your profile,
            asset inventory, and triage assignments tied to you. Aggregated, de-identified CVE/0-day data (which is
            public data, not personal data) is retained indefinitely as the core dataset of the Service.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">6. Cookies</h2>
          <p>
            We use one essential, <code>HttpOnly</code>, signed session cookie to keep you logged in. We do not use
            third-party advertising or tracking cookies.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">7. Children</h2>
          <p>The Service is not directed at children under 16 and we do not knowingly collect their data.</p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">8. Contact</h2>
          <p>
            Privacy questions or data requests:{" "}
            <a href="mailto:mustaphaamintbini@gmail.com" className="underline decoration-dotted">
              mustaphaamintbini@gmail.com
            </a>
            .
          </p>
        </section>

        <p className="border-t border-border pt-4 text-xs text-muted-foreground">
          This is a draft policy written to accompany the public launch of the 0-day feed; it has not been reviewed
          by a lawyer. Treat it as a starting point, not final legal advice.
        </p>
      </Card>
    </main>
  )
}
