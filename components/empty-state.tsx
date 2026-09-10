import Link from "next/link"

/**
 * Two different empty tables that must not look the same.
 *
 * "No rows" has two completely different causes, and collapsing them into one
 * message is why a freshly hosted instance looks broken: the dashboard says
 * "No CVE matches" whether the user's filters excluded everything, or the
 * database has simply never been synced. The first is the user's own doing and
 * needs no explanation; the second is a setup step nobody told them about, and
 * on day one it is the *only* thing they see.
 *
 * So the dataset being empty is stated as such, with the actual next step.
 */

export function NoDataYet({
  what,
  syncPath,
  colSpan,
}: {
  /** What has not arrived yet, e.g. "CVE data". */
  what: string
  /** The cron endpoint that fills it, shown verbatim so it can be copied. */
  syncPath: string
  colSpan: number
}) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-12 text-center">
        <div className="mx-auto max-w-lg">
          <div className="mb-2 text-2xl">🗃️</div>
          <p className="mb-1 font-medium text-foreground">No {what} yet</p>
          <p className="mb-4 text-sm leading-relaxed text-muted-foreground">
            This is a fresh installation, not a fault. {what} arrives from the scheduled synchronisation, which has not
            run against this database yet — nothing is broken and no filter is hiding anything.
          </p>
          <div className="mb-4 rounded-lg border border-border bg-white/5 p-3 text-left">
            <p className="mb-2 text-xs font-medium text-foreground">To fill it:</p>
            <ol className="list-inside list-decimal space-y-1 text-xs text-muted-foreground">
              <li>
                Set <code className="text-foreground">CRON_SECRET</code> and <code className="text-foreground">APP_URL</code> in
                your deployment, then point a scheduler at{" "}
                <code className="break-all text-foreground">{syncPath}</code> with an{" "}
                <code className="text-foreground">Authorization: Bearer</code> header.
              </li>
              <li>
                Or trigger it once by hand — the repository ships a local runner:{" "}
                <code className="text-foreground">bun run scripts/local-cron.ts --once</code>
              </li>
            </ol>
          </div>
          <p className="text-xs text-muted-foreground">
            <Link href="/sources" className="text-primary hover:underline">
              Sources &amp; Health
            </Link>{" "}
            shows whether each pipeline has run and how old its newest record is.
          </p>
        </div>
      </td>
    </tr>
  )
}

/**
 * The other case: data exists, the current filters just exclude all of it.
 * Kept beside `NoDataYet` so the distinction stays obvious to whoever edits
 * either one.
 */
export function NoMatches({ what, colSpan }: { what: string; colSpan: number }) {
  return (
    <tr>
      <td colSpan={colSpan} className="py-10 text-center text-muted-foreground">
        No {what} matches these filters.
      </td>
    </tr>
  )
}
