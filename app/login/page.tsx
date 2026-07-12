"use client"

import { Suspense, useState } from "react"
import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { authClient } from "@/lib/auth-client"
import { friendlyAuthError } from "@/lib/auth-errors"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

function LoginForm() {
  const router = useRouter()
  const params = useSearchParams()
  const dest = params.get("redirect") || "/dashboard"
  const urlError = params.get("error")
  const justVerified = params.get("verified") === "1"
  const justReset = params.get("reset") === "1"

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [social, setSocial] = useState<"github" | "google" | null>(null)

  const shownError = err || (urlError ? friendlyAuthError(urlError) : null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true); setErr(null)
    const { error } = await authClient.signIn.email({ email, password })
    setLoading(false)
    if (error) setErr(friendlyAuthError(error.code || error.message))
    else router.push(dest)
  }

  async function withProvider(provider: "github" | "google") {
    setSocial(provider); setErr(null)
    const { error } = await authClient.signIn.social({ provider, callbackURL: dest, errorCallbackURL: "/login" })
    if (error) { setSocial(null); setErr(friendlyAuthError(error.code || error.message)) }
  }

  return (
    <Card className="glass p-6">
      <h1 className="mb-1 text-2xl font-bold">Connexion</h1>
      <p className="mb-5 text-sm text-muted-foreground">Accède à ton poste de commande OCTUPUS</p>

      {justVerified && <p className="mb-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-300">✅ Email vérifié — connecte-toi pour accéder à ton espace.</p>}
      {justReset && <p className="mb-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-300">✅ Mot de passe réinitialisé — connecte-toi avec ton nouveau mot de passe.</p>}

      <div className="grid gap-2">
        <Button variant="outline" disabled={!!social} onClick={() => withProvider("github")}>
          {social === "github" ? "Redirection…" : "Continuer avec GitHub"}
        </Button>
        <Button variant="outline" disabled={!!social} onClick={() => withProvider("google")}>
          {social === "google" ? "Redirection…" : "Continuer avec Google"}
        </Button>
      </div>
      <div className="my-4 flex items-center gap-3 text-xs text-muted-foreground"><span className="h-px flex-1 bg-border" /> ou <span className="h-px flex-1 bg-border" /></div>

      <form onSubmit={submit} className="grid gap-3">
        <Input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
        <Input type="password" placeholder="Mot de passe" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
        {shownError && <p className="text-sm text-red-400">⚠️ {shownError}</p>}
        <Button type="submit" disabled={loading}>{loading ? "Connexion…" : "Se connecter"}</Button>
        <Link href="/forgot-password" className="text-center text-xs text-muted-foreground underline hover:text-foreground">Mot de passe oublié ?</Link>
      </form>

      <p className="mt-4 text-sm text-muted-foreground">Pas de compte ? <Link href="/signup" className="text-cyan-400 underline">S&apos;inscrire</Link></p>
    </Card>
  )
}

export default function LoginPage() {
  return (
    <main className="mx-auto flex min-h-[82vh] max-w-md flex-col justify-center px-4">
      <Suspense fallback={<Card className="glass p-6 text-muted-foreground">Chargement…</Card>}>
        <LoginForm />
      </Suspense>
    </main>
  )
}
