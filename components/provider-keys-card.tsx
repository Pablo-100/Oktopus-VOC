"use client"

import { useCallback, useEffect, useState } from "react"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { cn } from "@/lib/utils"

/**
 * BYOK panel: the user's own exposure-provider API keys.
 *
 * Deliberately explicit about three things users get wrong with BYOK products:
 * where to obtain each key, that the free CVE data needs none of them, and what
 * happens when they store nothing. It also never displays a stored secret — the
 * server only ever returns the last four characters, so there is nothing here to
 * accidentally leak into a screenshot.
 */

interface FieldState {
  field: string
  secret: boolean
  hint: string | null
  stored: boolean
}

interface ProviderState {
  provider: string
  fields: FieldState[]
  configured: boolean
  status: string
  statusNote: string | null
  verifiedAt: string | null
  platformFallback: boolean
}

/** Where to get each key, and what the free tier actually allows. */
const PROVIDER_INFO: Record<string, { label: string; role: string; url: string; note: string }> = {
  shodan: {
    label: "Shodan", role: "Enrichment",
    url: "https://account.shodan.io/",
    note: "The only provider that reports a service VERSION, which is what lets a finding reach 'strong' evidence and raise an alert. The free plan allows host lookups.",
  },
  censys: {
    label: "Censys", role: "Enrichment",
    url: "https://search.censys.io/account/api",
    note: "Rich host and certificate data. The free tier is small and runs out quickly.",
  },
  netlas: {
    label: "Netlas", role: "Enrichment",
    url: "https://app.netlas.io/profile/",
    note: "Ports, software and certificates. Generous free tier.",
  },
  leakix: {
    label: "LeakIX", role: "Discovery",
    url: "https://leakix.net/settings/api",
    note: "Finds hosts by product or keyword.",
  },
  fofa: {
    label: "FOFA", role: "Discovery",
    url: "https://en.fofa.info/userInfo",
    note: "Search by product. Needs both the account email and the API key.",
  },
  zoomeye: {
    label: "ZoomEye", role: "Discovery",
    url: "https://www.zoomeye.hk/profile",
    note: "Search by product. Queries cost credits.",
  },
  greynoise: {
    label: "GreyNoise", role: "Threat",
    url: "https://viz.greynoise.io/account/",
    note: "Tells you whether an address is scanning the internet right now.",
  },
  abuseipdb: {
    label: "AbuseIPDB", role: "Threat",
    url: "https://www.abuseipdb.com/account/api",
    note: "Reputation only — how often an address has been reported. Never reports services or CVEs.",
  },
}

const FIELD_LABEL: Record<string, string> = {
  SHODAN_API_KEY: "API key",
  CENSYS_API_TOKEN: "API token",
  CENSYS_ORG_ID: "Organization ID",
  NETLAS_API_KEY: "API key",
  LEAKIX_API_KEY: "API key",
  FOFA_EMAIL: "Account email",
  FOFA_API_KEY: "API key",
  ZOOMEYE_API_KEY: "API key",
  GREYNOISE_API_KEY: "API key",
  ABUSEIPDB_API_KEY: "API key",
}

function StatusBadge({ p }: { p: ProviderState }) {
  if (!p.configured) {
    return p.platformFallback ? (
      <Badge className="bg-white/10 text-muted-foreground">Using shared key</Badge>
    ) : (
      <Badge className="bg-white/10 text-muted-foreground">Not set</Badge>
    )
  }
  const map: Record<string, { text: string; cls: string }> = {
    valid: { text: "Working", cls: "bg-emerald-500/20 text-emerald-300" },
    quota_exhausted: { text: "No credits left", cls: "bg-amber-500/20 text-amber-300" },
    unreachable: { text: "Unverified", cls: "bg-amber-500/20 text-amber-300" },
    invalid: { text: "Rejected", cls: "bg-red-500/20 text-red-300" },
    unverified: { text: "Unverified", cls: "bg-white/10 text-muted-foreground" },
  }
  const s = map[p.status] ?? map.unverified
  return <Badge className={s.cls}>{s.text}</Badge>
}

export function ProviderKeysCard() {
  const [providers, setProviders] = useState<ProviderState[] | null>(null)
  const [vaultReady, setVaultReady] = useState(true)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(async () => {
    const res = await fetch("/api/account/credentials")
    if (!res.ok) return
    const d = (await res.json()) as { providers: ProviderState[]; vaultReady: boolean }
    setProviders(d.providers)
    setVaultReady(d.vaultReady)
  }, [])

  useEffect(() => { void load() }, [load])

  async function save(p: ProviderState) {
    const values: Record<string, string> = {}
    for (const f of p.fields) {
      const v = drafts[`${p.provider}.${f.field}`]?.trim()
      if (!v) { toast.error(`${FIELD_LABEL[f.field] ?? f.field} is required.`); return }
      values[f.field] = v
    }
    setBusy(p.provider)
    try {
      const res = await fetch("/api/account/credentials", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: p.provider, values }),
      })
      const d = (await res.json()) as { error?: string; status?: string; message?: string; providers?: ProviderState[] }
      if (!res.ok) { toast.error(d.error ?? "Could not save."); return }
      // The key is stored even when the account has no credits — say which it is
      // rather than a flat "saved", since the two mean very different things.
      if (d.status === "valid") toast.success(`${PROVIDER_INFO[p.provider]?.label ?? p.provider} verified and saved.`)
      else toast.warning(d.message ?? "Saved, but could not be verified.")
      if (d.providers) setProviders(d.providers)
      // Clear the inputs: the value is stored now and must not linger in the DOM.
      setDrafts((prev) => {
        const next = { ...prev }
        for (const f of p.fields) delete next[`${p.provider}.${f.field}`]
        return next
      })
    } finally { setBusy(null) }
  }

  async function remove(p: ProviderState) {
    setBusy(p.provider)
    try {
      const res = await fetch("/api/account/credentials", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: p.provider }),
      })
      const d = (await res.json()) as { error?: string; providers?: ProviderState[] }
      if (!res.ok) { toast.error(d.error ?? "Could not remove."); return }
      toast.success("Removed.")
      if (d.providers) setProviders(d.providers)
    } finally { setBusy(null) }
  }

  if (!providers) return null

  return (
    <Card className="glass mb-5 p-6">
      <h2 className="mb-1 text-lg font-semibold">Exposure provider keys</h2>
      <p className="mb-4 text-sm leading-relaxed text-muted-foreground">
        CVE and 0-day data is free and needs no key. The internet-exposure providers below are paid services, so you
        use <b className="text-foreground">your own accounts</b> and your own credits — nothing you search here is
        billed to anyone else, and no one else can spend your quota. Keys are encrypted before storage and are never
        shown again after you save them.
      </p>

      {!vaultReady && (
        <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-200">
          Credential storage is not configured on this deployment, so keys cannot be stored safely and are not being
          accepted. This is a server setting (<code>CREDENTIAL_ENCRYPTION_KEY</code>), not something you can fix here.
        </div>
      )}

      <div className="grid gap-3">
        {providers.map((p) => {
          const info = PROVIDER_INFO[p.provider]
          return (
            <div key={p.provider} className="rounded-lg border border-border bg-white/5 p-4">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="font-medium">{info?.label ?? p.provider}</span>
                <Badge className="bg-white/5 text-[10px] text-muted-foreground">{info?.role}</Badge>
                <StatusBadge p={p} />
                {info && (
                  <a href={info.url} target="_blank" rel="noreferrer"
                     className="ml-auto text-xs text-primary underline-offset-2 hover:underline">
                    Get a key ↗
                  </a>
                )}
              </div>

              <p className="mb-3 text-xs leading-relaxed text-muted-foreground">{info?.note}</p>

              {p.configured && p.statusNote && p.status !== "valid" && (
                <p className="mb-3 rounded border border-amber-500/30 bg-amber-500/10 p-2 text-xs text-amber-200">
                  {p.statusNote}
                </p>
              )}

              <div className="grid gap-2 sm:grid-cols-2">
                {p.fields.map((f) => (
                  <div key={f.field} className="grid gap-1">
                    <label className="text-[11px] text-muted-foreground">
                      {FIELD_LABEL[f.field] ?? f.field}
                      {f.stored && f.hint && <span className="ml-1 opacity-70">(stored: {f.hint})</span>}
                    </label>
                    <Input
                      type={f.secret ? "password" : "text"}
                      // A stored key is unrecoverable by design, so the field is
                      // for REPLACING it, not editing it.
                      placeholder={f.stored ? "Replace with a new value…" : "Paste your key…"}
                      value={drafts[`${p.provider}.${f.field}`] ?? ""}
                      onChange={(e) =>
                        setDrafts((prev) => ({ ...prev, [`${p.provider}.${f.field}`]: e.target.value }))
                      }
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </div>
                ))}
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Button size="sm" onClick={() => save(p)} disabled={busy === p.provider}>
                  {busy === p.provider ? "Checking…" : p.configured ? "Replace key" : "Save & verify"}
                </Button>
                {p.configured && (
                  <Button size="sm" variant="outline" onClick={() => remove(p)} disabled={busy === p.provider}>
                    Remove
                  </Button>
                )}
                <span className={cn("text-[11px] text-muted-foreground", !p.configured && p.platformFallback && "text-amber-300/80")}>
                  {p.configured
                    ? p.verifiedAt
                      ? `Checked ${new Date(p.verifiedAt).toLocaleDateString()}`
                      : ""
                    : p.platformFallback
                      ? "Currently using the shared demo key — limited and shared with everyone."
                      : "No key available, so this provider returns nothing."}
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}
