"use client"

import { Suspense, useRef, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { authClient } from "@/lib/auth-client"
import { friendlyAuthError } from "@/lib/auth-errors"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { toast } from "sonner"

function VerifyForm() {
  const router = useRouter()
  const params = useSearchParams()
  const email = params.get("email") || ""
  const dest = params.get("redirect") || "/dashboard"

  const [digits, setDigits] = useState<string[]>(["", "", "", "", "", ""])
  const [verifying, setVerifying] = useState(false)
  const [resending, setResending] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const inputs = useRef<Array<HTMLInputElement | null>>([])

  const code = digits.join("")

  function setDigit(i: number, v: string) {
    const clean = v.replace(/\D/g, "")
    if (!clean) { setDigits((d) => d.map((x, j) => (j === i ? "" : x))); return }
    const chars = clean.split("")
    setDigits((d) => {
      const next = [...d]
      for (let k = 0; k < chars.length && i + k < 6; k++) next[i + k] = chars[k]
      return next
    })
    const focusTo = Math.min(i + clean.length, 5)
    inputs.current[focusTo]?.focus()
  }

  function onKeyDown(i: number, e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Backspace" && !digits[i] && i > 0) inputs.current[i - 1]?.focus()
  }

  async function verify(fullCode?: string) {
    const otp = fullCode || code
    if (otp.length !== 6) return
    setVerifying(true); setErr(null)
    const { error } = await authClient.emailOtp.verifyEmail({ email, otp })
    if (error) {
      setVerifying(false)
      setErr(friendlyAuthError(error.code || error.message)); setDigits(["", "", "", "", "", ""]); inputs.current[0]?.focus()
      return
    }
    toast.success("Email vérifié ✅")
    // En mode strict, la vérif ne crée pas forcément de session -> on vérifie et sinon on renvoie à la connexion
    const { data } = await authClient.getSession()
    setVerifying(false)
    if (data?.user) router.push(dest)
    else router.push(`/login?verified=1&redirect=${encodeURIComponent(dest)}`)
  }

  async function resend() {
    setResending(true); setErr(null)
    const { error } = await authClient.emailOtp.sendVerificationOtp({ email, type: "email-verification" })
    setResending(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else toast.success("Nouveau code envoyé — vérifie ta boîte (et les spams)")
  }

  if (!email) {
    return (
      <Card className="glass p-6 text-center">
        <p className="text-sm text-muted-foreground">Adresse email manquante. Reviens depuis l&apos;inscription ou ton compte.</p>
        <Button className="mt-4" onClick={() => router.push("/login")}>Retour</Button>
      </Card>
    )
  }

  return (
    <Card className="glass p-6">
      <h1 className="mb-1 text-2xl font-bold">Vérifie ton email</h1>
      <p className="mb-5 text-sm text-muted-foreground">On a envoyé un code à 6 chiffres à <strong className="text-foreground">{email}</strong>. Saisis-le ci-dessous.</p>

      <div className="mb-4 flex justify-center gap-2" onPaste={(e) => { const t = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6); if (t) { e.preventDefault(); setDigit(0, t); if (t.length === 6) verify(t) } }}>
        {digits.map((d, i) => (
          <input
            key={i}
            ref={(el) => { inputs.current[i] = el }}
            value={d}
            inputMode="numeric"
            maxLength={1}
            autoComplete={i === 0 ? "one-time-code" : "off"}
            autoFocus={i === 0}
            onChange={(e) => setDigit(i, e.target.value)}
            onKeyDown={(e) => onKeyDown(i, e)}
            className="h-14 w-12 rounded-xl border border-border bg-background text-center text-2xl font-bold text-cyan-300 outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/40"
          />
        ))}
      </div>

      {err && <p className="mb-3 text-center text-sm text-red-400">⚠️ {err}</p>}

      <Button className="w-full" disabled={verifying || code.length !== 6} onClick={() => verify()}>
        {verifying ? "Vérification…" : "Vérifier"}
      </Button>

      <p className="mt-4 text-center text-sm text-muted-foreground">
        Pas reçu ?{" "}
        <button onClick={resend} disabled={resending} className="text-cyan-400 underline disabled:opacity-50">
          {resending ? "Envoi…" : "Renvoyer le code"}
        </button>
      </p>
    </Card>
  )
}

export default function VerifyEmailPage() {
  return (
    <main className="mx-auto flex min-h-[82vh] max-w-md flex-col justify-center px-4">
      <Suspense fallback={<Card className="glass p-6 text-muted-foreground">Chargement…</Card>}>
        <VerifyForm />
      </Suspense>
    </main>
  )
}
