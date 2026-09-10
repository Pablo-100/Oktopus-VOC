import Link from "next/link"
import { Card } from "@/components/ui/card"

export const metadata = { title: "Terms of Service — OCTUPUS-VOC" }

export default function TermsPage() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-12">
      <h1 className="text-3xl font-bold tracking-tight">Terms of Service</h1>
      <p className="mt-2 text-sm text-muted-foreground">Last updated: August 22, 2026</p>

      <Card className="glass mt-6 space-y-6 p-6 text-sm leading-relaxed sm:p-8">
        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">1. What OCTUPUS-VOC is</h2>
          <p>
            OCTUPUS-VOC (&ldquo;the Service&rdquo;) is a Vulnerability Operations Center: a 0-day / pre-CVE tracker,
            a CVE risk-prioritization dashboard, internet-exposure intelligence over assets you have verified you
            control, and a SOC alert workflow. All of it requires an account. It is operated by Tbini Mustapha Amin
            (&ldquo;the Author&rdquo;, &ldquo;we&rdquo;).
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">2. The public data feed</h2>
          <p>
            The 0-day tracker (<Link href="/zero-days" className="underline decoration-dotted">/zero-days</Link>) and
            the read-only CVE endpoints are made available <strong>free of charge, without an account</strong>, as a
            public service to developers and security practitioners. You may read, display, and cite this data,
            including via the API, <strong>provided you keep attribution to OCTUPUS-VOC and to the original data
            sources</strong> (see <Link href="/sources" className="underline decoration-dotted">Data Sources &amp;
            Attribution</Link>). This is the one explicit exception to the proprietary license that otherwise covers
            the Software; it does not grant any right to the underlying source code, design, or branding.
          </p>
          <p className="mt-2">
            This exception does not cover: automated bulk scraping intended to republish or resell the feed as a
            competing product, reverse-engineering the Service, or any use prohibited under Section 5 below.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">3. Accounts</h2>
          <p>
            Creating an account (email/password, Google, or GitHub) unlocks the CVE dashboard, asset inventory,
            triage workflow, and alerts. One email address maps to exactly one account regardless of sign-in method.
            You are responsible for keeping your credentials secure and for activity under your account.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">4. Data accuracy &amp; no warranty</h2>
          <p>
            CVE, EPSS, KEV, and 0-day data is aggregated from third-party sources (NVD, FIRST.org, CISA, GitHub,
            Google Project Zero, defend.network, and security news) and enriched with a computed risk score. It is
            provided <strong>&ldquo;as is&rdquo;, without warranty of accuracy, completeness, or timeliness</strong>.
            It does not constitute security, legal, or compliance advice, and must not be the sole basis for a
            security decision. Verify against the original advisory before acting.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">5. Acceptable use</h2>
          <p>You agree not to:</p>
          <ul className="ml-5 mt-2 list-disc space-y-1">
            <li>Exceed the published rate limits or attempt to circumvent them (multiple IPs, key rotation, etc.);</li>
            <li>Use the Service to attack, scan, or target systems without authorization;</li>
            <li>Resell or republish the feed as a competing aggregation product without written permission;</li>
            <li>Attempt to access another user&apos;s account, assets, or triage data.</li>
          </ul>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">6. Limitation of liability</h2>
          <p>
            To the maximum extent permitted by law, the Author is not liable for any indirect, incidental, or
            consequential damages arising from use of, or reliance on, the Service or its data.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">7. Changes</h2>
          <p>
            These Terms may be updated as the Service evolves internationally; material changes will be reflected by
            the &ldquo;Last updated&rdquo; date above. Continued use after a change constitutes acceptance.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold text-foreground">8. Contact</h2>
          <p>
            Questions about these Terms:{" "}
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
