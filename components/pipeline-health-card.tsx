"use client"

import { useCallback, useEffect, useState } from "react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

/**
 * Ingestion health, stated as a verdict rather than a timestamp.
 *
 * This exists because of a real outage: the zero-day sync was starved of its
 * time budget for twelve days while every indicator read healthy, because
 * `last_status` records whether the last call THREW, not whether it produced
 * anything. A feed can run successfully forever and store nothing.
 *
 * So the two numbers that actually matter are shown: how long since the
 * pipeline ran, and how old the newest record it holds is. A source that is
 * succeeding and producing nothing is named as such.
 */

interface Pipeline {
  name: string
  status: "ok" | "stale" | "never"
  hoursSinceRun: number | null
  expectedWithinHours: number
  lastStatus: string | null
  records: number
}

interface SourceHealth {
  source: string
  records: number
  newest: string | null
  newestAgeHours: number | null
  consecutiveFailures: number
  consecutiveEmpty: number
  lastError: string | null
  status: string
}

const TONE: Record<string, string> = {
  ok: "bg-emerald-500/15 text-emerald-300",
  stale: "bg-red-500/15 text-red-300",
  never: "bg-white/5 text-muted-foreground",
  failing: "bg-red-500/15 text-red-300",
  "producing nothing": "bg-amber-500/15 text-amber-300",
}

function age(hours: number | null): string {
  if (hours === null) return "never"
  if (hours < 1) return "under an hour ago"
  if (hours < 48) return `${Math.round(hours)}h ago`
  return `${Math.round(hours / 24)}d ago`
}

export function PipelineHealthCard() {
  const [data, setData] = useState<{ pipelines: Pipeline[]; sources: SourceHealth[]; checkedAt: string } | null>(null)
  const [failed, setFailed] = useState(false)

  const load = useCallback(async () => {
    const res = await fetch("/api/health")
    if (!res.ok) { setFailed(true); return }
    setData(await res.json())
  }, [])

  useEffect(() => { void load() }, [load])

  // Signed-out visitors get nothing rather than a broken card.
  if (failed || !data) return null

  const degraded = data.pipelines.filter((p) => p.status !== "ok")

  return (
    <Card className="glass mb-6 p-5">
      <h2 className="mb-1 text-lg font-semibold">Pipeline health</h2>
      <p className="mb-4 text-sm leading-relaxed text-muted-foreground">
        Whether the data behind this platform is actually arriving.{" "}
        <b className="text-foreground">A feed can run without error and still store nothing</b>, so what is reported
        here is how long since each pipeline ran and how old the newest record it holds is — not merely whether the
        last call succeeded.
      </p>

      {degraded.length > 0 && (
        <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-100">
          <b>{degraded.map((d) => d.name).join(" and ")}</b>{" "}
          {degraded.length === 1 ? "has" : "have"} not run recently. Data on the affected pages is older than it
          appears — the age shown is real, the freshness is not.
        </div>
      )}

      <div className="mb-4 grid gap-2 sm:grid-cols-2">
        {data.pipelines.map((p) => (
          <div key={p.name} className="rounded-lg border border-border bg-white/5 p-3">
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-sm font-medium">{p.name}</span>
              <Badge className={cn("text-[10px]", TONE[p.status])}>{p.status}</Badge>
            </div>
            <div className="text-xs text-muted-foreground">
              Last run {age(p.hoursSinceRun)} · expected every {p.expectedWithinHours}h ·{" "}
              {p.records.toLocaleString("en-US")} records
            </div>
          </div>
        ))}
      </div>

      {data.sources.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-muted-foreground">
              <tr className="text-left">
                <th className="py-1 pr-3 font-medium">Source</th>
                <th className="py-1 pr-3 font-medium">Held</th>
                <th className="py-1 pr-3 font-medium">Newest</th>
                <th className="py-1 pr-3 font-medium">State</th>
              </tr>
            </thead>
            <tbody>
              {data.sources.map((s) => (
                <tr key={s.source} className="border-t border-border/60">
                  <td className="py-1.5 pr-3 font-mono">{s.source}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{s.records}</td>
                  <td className="py-1.5 pr-3">{age(s.newestAgeHours)}</td>
                  <td className="py-1.5 pr-3">
                    <Badge className={cn("text-[10px]", TONE[s.status] ?? TONE.never)}>{s.status}</Badge>
                    {s.consecutiveEmpty > 0 && s.status === "ok" && (
                      <span className="ml-1 text-muted-foreground" title="Ran without error but returned no records">
                        ({s.consecutiveEmpty} empty)
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}
