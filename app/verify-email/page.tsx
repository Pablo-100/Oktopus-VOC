"use client"

import { Suspense, useRef, useState, useEffect } from "react"
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
  // `null` while unknown, so the warning never flashes before the answer
  // arrives and never claims a working deployment is broken.
  const [mailConfigured, setMailConfigured] = useState<boolean | null>(null)
  useEffect(() => {
    fetch("/api/mail-status")
      .then((r) => (r.ok ? r.json() : { configured: true }))
      .then((d) => setMailConfigured(Boolean(d.configured)))
      // On failure assume it works: telling someone their email is broken when
      // it is not would be worse than staying quiet.
      .catch(() => setMailConfigured(true))
  }, [])
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
    toast.success("Email verified ✅")
    // In strict mode, verifying doesn't necessarily create a session -> check and fall back to sign-in
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
    else toast.success("New code sent — check your inbox (and spam folder)")
  }

  if (!email) {
    return (
      <Card className="glass p-6 text-center">
        <p className="text-sm text-muted-foreground">Missing email address. Go back through sign-up or your account.</p>
        <Button className="mt-4" onClick={() => router.push("/login")}>Back</Button>
      </Card>
    )
  }

  return (
    <Card className="glass p-6">
      <h1 className="mb-1 text-2xl font-bold">Verify your email</h1>

      {mailConfigured === false ? (
        <div className="mb-5 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm leading-relaxed text-amber-100">
          <p className="mb-2 font-medium">This deployment cannot send email, so no code was delivered.</p>
          <p className="mb-2">
            The account was created and the code was generated — it just has nowhere to go. This is a server
            configuration gap, not something you can fix from this page.
          </p>
          <p className="text-xs">
            Whoever operates this instance should set <code>RESEND_API_KEY</code> (or{" "}
            <code>GMAIL_USER</code> + <code>GMAIL_APP_PASSWORD</code>) and run{" "}
            <code>bun run doctor</code>, which lists exactly what is missing. The code is written to the server logs
            in the meantime.
          </p>
        </div>
      ) : (
        <p className="mb-5 text-sm text-muted-foreground">
          We sent a 6-digit code to <strong className="text-foreground">{email}</strong>. Enter it below.
        </p>
      )}

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
        {verifying ? "Verifying…" : "Verify"}
      </Button>

      <p className="mt-4 text-center text-sm text-muted-foreground">
        Didn&apos;t get it?{" "}
        <button onClick={resend} disabled={resending} className="text-cyan-400 underline disabled:opacity-50">
          {resending ? "Sending…" : "Resend code"}
        </button>
      </p>
    </Card>
  )
}

export default function VerifyEmailPage() {
  return (
    <main className="mx-auto flex min-h-[82vh] max-w-md flex-col justify-center px-4">
      <Suspense fallback={<Card className="glass p-6 text-muted-foreground">Loading…</Card>}>
        <VerifyForm />
      </Suspense>
    </main>
  )
}
