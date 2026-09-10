/**
 * HttpClient serveur minimal (fetch + retry avec backoff).
 * Factorisé hors de collector.ts pour éviter les cycles d'imports
 * (collector ↔ kev-cache ↔ archive partagent ce module).
 */
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** fetch JSON avec retry (429 / 5xx) + backoff. `resolveText` : renvoyer du texte brut pour les flux gzip. */
export async function fetchJson<T = Record<string, unknown>>(
  url: string,
  headers: Record<string, string> = {},
  retries = 4,
): Promise<T> {
  let lastErr: unknown
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { headers })
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return (await res.json()) as T
    } catch (e) {
      lastErr = e
      if (attempt < retries) await sleep(1500 * (attempt + 1))
    }
  }
  throw lastErr
}