"use client"

import { useMemo, useState } from "react"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export type Facet = { name: string; count: number }

/**
 * Sélecteur searchable + scrollable (multi-sélection) alimenté par les vraies
 * valeurs de la base -> l'utilisateur coche, il ne tape jamais -> zéro faute.
 */
export function FacetPicker({
  label,
  placeholder,
  options,
  selected,
  onToggle,
}: {
  label: string
  placeholder: string
  options: Facet[]
  selected: Set<string>
  onToggle: (name: string) => void
}) {
  const [q, setQ] = useState("")
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    return (s ? options.filter((o) => o.name.toLowerCase().includes(s)) : options).slice(0, 250)
  }, [q, options])

  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium">{label} {selected.size > 0 && <span className="text-cyan-400">({selected.size})</span>}</label>

      {selected.size > 0 && (
        <div className="mb-2 flex flex-wrap gap-1.5">
          {[...selected].map((s) => (
            <Badge key={s} onClick={() => onToggle(s)} className="cursor-pointer bg-primary/20 text-foreground hover:bg-primary/30" title="Retirer">
              {s} ✕
            </Badge>
          ))}
        </div>
      )}

      <Input placeholder={placeholder} value={q} onChange={(e) => setQ(e.target.value)} />

      <div className="mt-2 max-h-56 overflow-y-auto rounded-lg border border-border bg-background/40">
        {filtered.length === 0 ? (
          <p className="p-3 text-center text-xs text-muted-foreground">Aucun résultat</p>
        ) : (
          filtered.map((o) => {
            const on = selected.has(o.name)
            return (
              <button
                type="button"
                key={o.name}
                onClick={() => onToggle(o.name)}
                className={cn(
                  "flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-sm transition-colors hover:bg-white/5",
                  on && "bg-primary/15 text-foreground",
                )}
              >
                <span className="truncate">{on ? "✓ " : ""}{o.name}</span>
                <span className="shrink-0 rounded-full bg-white/5 px-1.5 text-[11px] text-muted-foreground">{o.count}</span>
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}
