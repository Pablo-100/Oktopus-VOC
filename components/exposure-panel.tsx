"use client"

import { useEffect, useState } from "react"
import { Badge } from "@/components/ui/badge"
import type { ExposureResult } from "@/lib/types"

const PROVIDER_LABEL: Record<string, string> = { censys: "Censys", leakix: "LeakIX", netlas: "Netlas", fofa: "FOFA", zoomeye: "ZoomEye" }

function fmt(r: ExposureResult): string {
  if (!r.ok || r.count == null) return "—"
  return `${r.approximate ? "~" : ""}${r.count.toLocaleString("en-US")}`
}

/** Internet-exposure signal for a product — how many internet-facing instances the configured EASM providers see right now. */
export function ExposurePanel({ product }: { product: string | null }) {
  const [results, setResults] = useState<ExposureResult[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!product) return
    let cancelled = false
    setLoading(true)
    setError(null)
    fetch(`/api/exposure?product=${encodeURIComponent(product)}`)
      .then((r) => r.json())
      .then((d) => {
        if (cancelled) return
        if (d.error) throw new Error(d.error)
        setResults(d.results ?? [])
      })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [product])

  if (!product) return null

  return (
    <div className="rounded-lg border border-border bg-muted/20 p-4">
      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Internet exposure — {product}
      </p>
      {loading && <p className="text-sm text-muted-foreground">Checking exposure scanners…</p>}
      {error && <p className="text-sm text-destructive">{error}</p>}
      {results && results.length === 0 && (
        <p className="text-sm text-muted-foreground">No exposure providers configured — see docs/exposure-providers-setup.md.</p>
      )}
      {results && results.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {results.map((r) => (
            <Badge
              key={r.provider}
              variant={r.ok ? "secondary" : "outline"}
              title={r.ok ? `Query: ${r.query}` : r.error}
              className={!r.ok ? "opacity-50" : undefined}
            >
              {PROVIDER_LABEL[r.provider] ?? r.provider}: {fmt(r)}
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}
