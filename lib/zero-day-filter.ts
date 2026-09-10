/**
 * Construction SÛRE du filtre WHERE de la table `zero_days`.
 *
 * Antécédent : la route /api/zero-days concaténait des chaînes SQL à partir de
 * l'entrée utilisateur (`?search=`) puis passait le résultat à `sql.unsafe()`
 * -> injection SQL possible (CVE). Ici AUCUNE valeur utilisateur n'est
 * interpolée dans le texte : `kind` est mappé par une liste blanche stricte et
 * `search` est lié en paramètre. La composition utilise des fragments Neon
 * (tagged templates imbriqués) — Neon renumérote les placeholders $n à plat.
 *
 * Exporté séparément pour être testable en isolation (pas de DB, pas de réseau) :
 * les tests vérifient que le texte généré ne contient jamais l'entrée brute.
 */
import { sql } from "@/lib/db"
import type { ZeroDayKind } from "@/lib/types"

export type ZeroDayFilterInput = {
  kind?: string | null
  search?: string | null
  active?: string | null
}

/** liste blanche stricte des valeurs autorisées pour `kind`. */
const ALLOWED_KINDS: ReadonlySet<string> = new Set(["reserved", "prepub_exploited", "advisory"])

/**
 * Construit le fragment `WHERE` (sans le mot-clé) ou `null` quand aucun filtre.
 * - kind === "resolved"              -> became_cve = true
 * - kind ∈ ALLOWED_KINDS           -> kind = <enum>            (param lié)
 * - active === "true" (sans kind)  -> became_cve = false
 * - search                         -> ILIKE sur title/cve_id/ghsa_id/product (params liés)
 */
export function buildZeroDayWhere(input: ZeroDayFilterInput): ReturnType<typeof sql> | null {
  let clause: ReturnType<typeof sql> | null = null

  const kind = input.kind?.trim()
  if (kind === "resolved") {
    clause = sql`became_cve = true`
  } else if (kind && ALLOWED_KINDS.has(kind as ZeroDayKind)) {
    clause = sql`kind = ${kind as ZeroDayKind}` // enum validé, jamais l'entrée brute
  } else if (input.active?.trim() === "true") {
    clause = sql`became_cve = false`
  }

  const search = input.search?.trim()
  if (search) {
    const term = `%${search}%`
    const searchClause = sql`(title ILIKE ${term} OR cve_id ILIKE ${term} OR ghsa_id ILIKE ${term} OR product ILIKE ${term})`
    clause = clause ? sql`${clause} AND ${searchClause}` : searchClause
  }

  return clause
}

/**
 * Rendu SQL final d'un fragment (pour les tests) — le texte ne doit JAMAIS
 * contenir l'entrée brute, uniquement des placeholders $n.
 * (introspection via queryData.toParameterizedQuery : objet Neon).
 */
export function fragmentText(fragment: ReturnType<typeof sql> | null): string {
  if (fragment == null) return ""
  const qd = (fragment as unknown as { queryData?: { toParameterizedQuery?: () => { query: string } } }).queryData
  const rendered = qd?.toParameterizedQuery?.()
  return rendered?.query ?? ""
}

/** Paramètres liés d'un fragment (pour les tests). */
export function fragmentParams(fragment: ReturnType<typeof sql> | null): unknown[] {
  if (fragment == null) return []
  const qd = (fragment as unknown as { queryData?: { toParameterizedQuery?: () => { params: unknown[] } } }).queryData
  const rendered = qd?.toParameterizedQuery?.()
  return rendered?.params ?? []
}