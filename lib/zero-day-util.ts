/**
 * Utilitaires 0-day partagés (déduplication multi-sources).
 *
 * Ici uniquement : par déplacement de `normalizeKey` hors du collecteur pour
 * que les sources additionnelles (RSS news, Google P0) puissent l'importer
 * SANS cycle d'import (collector -> news -> collector).
 */
export function normalizeKey(cveId?: string, ghsaId?: string, source?: string, id?: string): string {
  if (cveId) return cveId.toUpperCase()
  if (ghsaId) return `GHSA:${ghsaId.toUpperCase()}`
  return `SRC:${source}:${id}`
}

/** True si le texte contient un identifiant CVE canonique (CVE-YYYY-NNNN...). */
export function extractCveId(text: string): string | null {
  const m = /CVE-\d{4}-\d{4,7}/i.exec(text ?? "")
  return m ? m[0].toUpperCase() : null
}