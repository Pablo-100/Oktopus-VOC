import { NextResponse } from "next/server"
import { requireUser } from "@/lib/api-auth"

const SYSTEM_PROMPT =
  "Tu es un analyste Cyber Threat Intelligence dans un VOC. " +
  "Analyse UNIQUEMENT les données de la CVE fournies en JSON. " +
  "N'invente AUCUN fait : si une information manque, dis-le. " +
  "Réponds en français, en Markdown, concis, avec ces sections :\n" +
  "### Résumé en clair\n### Comment c'est exploité\n### Impact\n### Recommandation de remédiation\n### Scénario d'attaque\n" +
  "Termine par une ligne « Priorité : » cohérente avec le Risk Score."

export async function POST(req: Request) {
  const gate = await requireUser(req); if (gate.deny) return gate.deny
  const apiKey = process.env.OPENROUTER_API_KEY
  if (!apiKey) return NextResponse.json({ error: "OPENROUTER_API_KEY manquante (.env.local)" }, { status: 503 })

  let context: unknown
  try {
    context = (await req.json()).context
  } catch {
    return NextResponse.json({ error: "JSON invalide" }, { status: 400 })
  }
  if (!context) return NextResponse.json({ error: "Champ context requis" }, { status: 400 })

  const models = [
    process.env.OPENROUTER_MODEL || "openai/gpt-oss-120b:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "openrouter/free",
  ].filter((m, i, a) => a.indexOf(m) === i)

  let lastErr = "Aucun modèle disponible"
  for (const model of models) {
    try {
      const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json", "X-Title": "OCTUPUS VOC" },
        body: JSON.stringify({
          model,
          temperature: 0.2,
          max_tokens: 900,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: "Données de la CVE (JSON) :\n" + JSON.stringify(context, null, 2) },
          ],
        }),
      })
      const data = await r.json()
      if (!r.ok || data.error) { lastErr = data.error?.message || `HTTP ${r.status}`; continue }
      const text = data.choices?.[0]?.message?.content
      if (text) return NextResponse.json({ text, model })
      lastErr = "Réponse vide"
    } catch (e) {
      lastErr = (e as Error).message
    }
  }
  return NextResponse.json({ error: lastErr }, { status: 502 })
}
