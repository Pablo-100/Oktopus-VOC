"use client"

import { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { authClient } from "@/lib/auth-client"
import { friendlyAuthError } from "@/lib/auth-errors"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { toast } from "sonner"

export default function ForgotPasswordPage() {
  const router = useRouter()
  const [step, setStep] = useState<"email" | "reset">("email")
  const [email, setEmail] = useState("")
  const [otp, setOtp] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function sendCode(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true); setErr(null)
    const { error } = await authClient.forgetPassword.emailOtp({ email })
    setLoading(false)
    if (error) setErr(friendlyAuthError(error.code || error.message))
    else { toast.success("Code envoyé — vérifie ta boîte (et les spams)"); setStep("reset") }
  }

  async function resend() {
    const { error } = await authClient.forgetPassword.emailOtp({ email })
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else toast.success("Nouveau code envoyé")
  }

  async function reset(e: React.FormEvent) {
    e.preventDefault()
    if (password.length < 8) { setErr("Le mot de passe doit faire 8 caractères minimum."); return }
    setLoading(true); setErr(null)
    const { error } = await authClient.emailOtp.resetPassword({ email, otp, password })
    setLoading(false)
    if (error) setErr(friendlyAuthError(error.code || error.message))
    else { toast.success("Mot de passe réinitialisé"); router.push("/login?reset=1") }
  }

  return (
    <main className="mx-auto flex min-h-[82vh] max-w-md flex-col justify-center px-4">
      <Card className="glass p-6">
        <h1 className="mb-1 text-2xl font-bold">Mot de passe oublié</h1>

        {step === "email" ? (
          <>
            <p className="mb-5 text-sm text-muted-foreground">Entre ton email : on t&apos;envoie un code à 6 chiffres pour réinitialiser ton mot de passe.</p>
            <form onSubmit={sendCode} className="grid gap-3">
              <Input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
              {err && <p className="text-sm text-red-400">⚠️ {err}</p>}
              <Button type="submit" disabled={loading}>{loading ? "Envoi…" : "Envoyer le code"}</Button>
            </form>
          </>
        ) : (
          <>
            <p className="mb-5 text-sm text-muted-foreground">Code envoyé à <strong className="text-foreground">{email}</strong>. Saisis-le et choisis un nouveau mot de passe.</p>
            <form onSubmit={reset} className="grid gap-3">
              <Input inputMode="numeric" maxLength={6} placeholder="Code à 6 chiffres" value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))} required autoComplete="one-time-code" className="text-center text-lg tracking-[0.4em]" />
              <Input type="password" placeholder="Nouveau mot de passe (8+ caractères)" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} autoComplete="new-password" />
              {err && <p className="text-sm text-red-400">⚠️ {err}</p>}
              <Button type="submit" disabled={loading || otp.length !== 6}>{loading ? "Réinitialisation…" : "Réinitialiser le mot de passe"}</Button>
            </form>
            <p className="mt-4 text-center text-sm text-muted-foreground">
              Pas reçu ? <button onClick={resend} className="text-cyan-400 underline">Renvoyer le code</button>
            </p>
          </>
        )}

        <p className="mt-4 text-sm text-muted-foreground"><Link href="/login" className="text-cyan-400 underline">← Retour à la connexion</Link></p>
      </Card>
    </main>
  )
}
