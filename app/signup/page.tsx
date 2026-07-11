"use client"

import { Suspense, useState } from "react"
import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { authClient } from "@/lib/auth-client"
import { friendlyAuthError } from "@/lib/auth-errors"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

function SignupForm() {
  const router = useRouter()
  const params = useSearchParams()
  const urlError = params.get("error")

  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [social, setSocial] = useState<"github" | "google" | null>(null)

  const shownError = err || (urlError ? friendlyAuthError(urlError) : null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true); setErr(null)
    const { error } = await authClient.signUp.email({ name, email, password })
    setLoading(false)
    // Un code OTP a été envoyé (sendVerificationOnSignUp) -> écran de saisie du code
    if (error) setErr(friendlyAuthError(error.code || error.message))
    else router.push(`/verify-email?email=${encodeURIComponent(email)}`)
  }

  async function withProvider(provider: "github" | "google") {
    setSocial(provider); setErr(null)
    const { error } = await authClient.signIn.social({ provider, callbackURL: "/dashboard", errorCallbackURL: "/signup" })
    if (error) { setSocial(null); setErr(friendlyAuthError(error.code || error.message)) }
  }

  return (
    <Card className="glass p-6">
      <h1 className="mb-1 text-2xl font-bold">Créer un compte</h1>
      <p className="mb-5 text-sm text-muted-foreground">Rejoins ton VOC OCTUPUS</p>

      <div className="grid gap-2">
        <Button variant="outline" disabled={!!social} onClick={() => withProvider("github")}>
          {social === "github" ? "Redirection…" : "S'inscrire avec GitHub"}
        </Button>
        <Button variant="outline" disabled={!!social} onClick={() => withProvider("google")}>
          {social === "google" ? "Redirection…" : "S'inscrire avec Google"}
        </Button>
      </div>
      <div className="my-4 flex items-center gap-3 text-xs text-muted-foreground"><span className="h-px flex-1 bg-border" /> ou <span className="h-px flex-1 bg-border" /></div>

      <form onSubmit={submit} className="grid gap-3">
        <Input placeholder="Nom" value={name} onChange={(e) => setName(e.target.value)} required autoComplete="name" />
        <Input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
        <Input type="password" placeholder="Mot de passe (8+ caractères)" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} autoComplete="new-password" />
        {shownError && <p className="text-sm text-red-400">⚠️ {shownError}</p>}
        <Button type="submit" disabled={loading}>{loading ? "Création…" : "Créer le compte"}</Button>
      </form>

      <p className="mt-4 text-sm text-muted-foreground">Déjà un compte ? <Link href="/login" className="text-cyan-400 underline">Se connecter</Link></p>
    </Card>
  )
}

export default function SignupPage() {
  return (
    <main className="mx-auto flex min-h-[82vh] max-w-md flex-col justify-center px-4">
      <Suspense fallback={<Card className="glass p-6 text-muted-foreground">Chargement…</Card>}>
        <SignupForm />
      </Suspense>
    </main>
  )
}
