"use client"

import { useCallback, useEffect, useState } from "react"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"

/**
 * Domain ownership panel.
 *
 * Explains the boundary rather than just enforcing it: search and enrichment
 * are open to any target because they only read what providers already
 * collected, while monitoring schedules repeated queries and pages a human, so
 * it needs proof. A user told only "not authorised" would reasonably conclude
 * the product is broken.
 */

interface OwnedTarget {
  target: string
  token: string
  status: "pending" | "verified" | "failed"
  method: string
  verifiedAt: string | null
  lastCheckedAt: string | null
  lastError: string | null
}

export function VerifiedDomainsCard() {
  const [targets, setTargets] = useState<OwnedTarget[] | null>(null)
  const [txtPrefix, setTxtPrefix] = useState("_octupus-verify")
  const [draft, setDraft] = useState("")
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(async () => {
    const res = await fetch("/api/exposure/ownership")
    if (!res.ok) return
    const d = (await res.json()) as { targets: OwnedTarget[]; txtPrefix: string }
    setTargets(d.targets)
    setTxtPrefix(d.txtPrefix)
  }, [])

  useEffect(() => { void load() }, [load])

  async function post(action: "start" | "check", target: string) {
    setBusy(target)
    try {
      const res = await fetch("/api/exposure/ownership", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, target }),
      })
      const d = (await res.json()) as { error?: string; target?: OwnedTarget }
      if (!res.ok) { toast.error(d.error ?? "Request failed."); return }
      if (action === "start") { setDraft(""); toast.success("Token issued. Publish it, then check.") }
      else if (d.target?.status === "verified") toast.success(`${target} verified.`)
      // A failed check is the normal case for the first minute or two after a
      // DNS change, so it is reported as information rather than an error.
      else toast.info(d.target?.lastError ?? "Not found yet.")
      await load()
    } finally { setBusy(null) }
  }

  async function remove(target: string) {
    setBusy(target)
    try {
      const res = await fetch("/api/exposure/ownership", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      })
      if (!res.ok) { toast.error("Could not remove."); return }
      toast.success("Removed.")
      await load()
    } finally { setBusy(null) }
  }

  if (!targets) return null

  return (
    <Card className="glass mb-5 p-6">
      <h2 className="mb-1 text-lg font-semibold">Verified domains</h2>
      <p className="mb-4 text-sm leading-relaxed text-muted-foreground">
        <b className="text-foreground">Search and enrichment work on any target</b> — those only read data the providers
        already collected, exactly like visiting Shodan&apos;s own site. <b className="text-foreground">Continuous
        monitoring</b> is different: it re-queries a host on a schedule, keeps its history and raises alerts. That
        requires proving you control the domain. Once a domain is verified, its subdomains and any IP address it
        currently resolves to are covered too.
      </p>

      <div className="mb-4 flex flex-wrap gap-2">
        <Input
          placeholder="example.com"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && draft.trim()) void post("start", draft.trim()) }}
          className="max-w-xs"
          autoComplete="off"
          spellCheck={false}
        />
        <Button onClick={() => void post("start", draft.trim())} disabled={!draft.trim() || busy !== null}>
          Add domain
        </Button>
      </div>

      {targets.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No domains verified yet, so monitoring is unavailable. Everything else works.
        </p>
      ) : (
        <div className="grid gap-3">
          {targets.map((t) => (
            <div key={t.target} className="rounded-lg border border-border bg-white/5 p-4">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="font-medium">{t.target}</span>
                {t.status === "verified" ? (
                  <Badge className="bg-emerald-500/20 text-emerald-300">Verified</Badge>
                ) : (
                  <Badge className="bg-amber-500/20 text-amber-300">Awaiting DNS</Badge>
                )}
                {t.verifiedAt && (
                  <span className="text-[11px] text-muted-foreground">
                    {new Date(t.verifiedAt).toLocaleDateString()}
                  </span>
                )}
              </div>

              {t.status !== "verified" && (
                <div className="mb-3 rounded border border-border bg-black/20 p-3 text-xs">
                  <p className="mb-2 text-muted-foreground">
                    Publish this TXT record, then check. Either name works — use whichever your registrar makes easier.
                  </p>
                  <div className="overflow-x-auto">
                    <table className="text-[11px]">
                      <tbody>
                        <tr>
                          <td className="pr-3 text-muted-foreground">Name</td>
                          <td className="font-mono">{txtPrefix}.{t.target}</td>
                        </tr>
                        <tr>
                          <td className="pr-3 text-muted-foreground">or</td>
                          <td className="font-mono">{t.target}</td>
                        </tr>
                        <tr>
                          <td className="pr-3 text-muted-foreground">Type</td>
                          <td className="font-mono">TXT</td>
                        </tr>
                        <tr>
                          <td className="pr-3 align-top text-muted-foreground">Value</td>
                          <td className="break-all font-mono text-emerald-300">{t.token}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  {t.lastError && <p className="mt-2 text-amber-300/90">{t.lastError}</p>}
                </div>
              )}

              <div className="flex flex-wrap gap-2">
                {t.status !== "verified" && (
                  <>
                    <Button size="sm" onClick={() => void post("check", t.target)} disabled={busy === t.target}>
                      {busy === t.target ? "Checking DNS…" : "Check now"}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => void post("start", t.target)} disabled={busy === t.target}>
                      New token
                    </Button>
                  </>
                )}
                <Button size="sm" variant="outline" onClick={() => void remove(t.target)} disabled={busy === t.target}>
                  Remove
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
