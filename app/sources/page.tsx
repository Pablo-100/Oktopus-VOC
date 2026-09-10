import { Card } from "@/components/ui/card"
import { PipelineHealthCard } from "@/components/pipeline-health-card"

export const metadata = { title: "Data Sources & Attribution — OCTUPUS-VOC" }

type Source = { name: string; url: string; usage: string; license: string }

const CVE_SOURCES: Source[] = [
  { name: "NVD 2.0 (NIST)", url: "https://nvd.nist.gov", usage: "CVE records, CVSS, CWE, CPE, references", license: "Public domain (US government work)" },
  { name: "FIRST.org EPSS", url: "https://www.first.org/epss/", usage: "Exploitation probability score", license: "Free API, attribution appreciated" },
  { name: "CISA KEV Catalog", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", usage: "Confirmed-exploited flag", license: "Public domain (US government work)" },
  { name: "MITRE CWE / CAPEC / ATT&CK", url: "https://attack.mitre.org", usage: "Weakness → attack-pattern → technique mapping", license: "MITRE terms of use — free for this kind of derivative mapping" },
]

const ZERO_DAY_SOURCES: Source[] = [
  { name: "CISA KEV (pre-publication join)", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", usage: "Flaws confirmed exploited before their CVE was ever published — the only source verified date-against-date, not just tagged", license: "Public domain" },
  { name: "GitHub Security Advisories", url: "https://github.com/advisories", usage: "Reviewed advisories published without a CVE ID assigned", license: "GitHub API terms" },
  { name: "Google Project Zero — 0-day tracker", url: "https://googleprojectzero.blogspot.com", usage: "In-the-wild 0-day exploitation history", license: "Public spreadsheet, attribution appreciated" },
  { name: "BleepingComputer / The Hacker News (RSS)", url: "https://www.bleepingcomputer.com", usage: "Filtered by 0-day / exploited-in-the-wild keywords, headline + link only", license: "Fair-use excerpt, links back to the original article" },
]

const SERVICE_PROVIDERS: Source[] = [
  { name: "OpenRouter", url: "https://openrouter.ai", usage: "AI-generated CVE analysis (optional feature)", license: "Commercial API" },
  { name: "Telegram Bot API", url: "https://core.telegram.org/bots/api", usage: "Optional High/Critical alert delivery", license: "Telegram terms" },
]

function SourceTable({ title, rows }: { title: string; rows: Source[] }) {
  return (
    <section>
      <h2 className="mb-3 text-lg font-semibold text-foreground">{title}</h2>
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full min-w-[560px] text-sm">
          <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left">Source</th>
              <th className="px-3 py-2 text-left">Used for</th>
              <th className="px-3 py-2 text-left">License / terms</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.name} className="border-t border-border">
                <td className="px-3 py-2 font-medium">
                  <a href={s.url} target="_blank" rel="noopener noreferrer" className="underline decoration-dotted hover:text-cyan-400">{s.name}</a>
                </td>
                <td className="px-3 py-2 text-muted-foreground">{s.usage}</td>
                <td className="px-3 py-2 text-muted-foreground">{s.license}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default function SourcesPage() {
  return (
    <main className="mx-auto max-w-4xl px-4 py-12">
      <h1 className="text-3xl font-bold tracking-tight">Data Sources &amp; Attribution</h1>
      <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
        OCTUPUS-VOC does not originate vulnerability data — it aggregates, normalizes, and risk-scores it from the
        sources below. We credit every one of them, and where a license requires attribution (notably defend.network,
        CC BY 4.0), that credit also appears directly on the page displaying the data.
      </p>

      {/* Attribution says where data COULD come from. This says whether it is
          actually arriving — the question an operator has when a page looks
          suspiciously quiet. */}
      <div className="mt-8">
        <PipelineHealthCard />
      </div>

      <div className="mt-8 space-y-8">
        <SourceTable title="CVE Dashboard" rows={CVE_SOURCES} />
        <SourceTable title="0-Day / Pre-CVE Tracker" rows={ZERO_DAY_SOURCES} />
        <SourceTable title="Optional service providers" rows={SERVICE_PROVIDERS} />
      </div>

      <Card className="glass mt-10 p-6 text-sm text-muted-foreground">
        Spotted an attribution that&apos;s missing or wrong? Tell us at{" "}
        <a href="mailto:mustaphaamintbini@gmail.com" className="underline decoration-dotted hover:text-foreground">
          mustaphaamintbini@gmail.com
        </a>{" "}
        and we&apos;ll fix it.
      </Card>
    </main>
  )
}
