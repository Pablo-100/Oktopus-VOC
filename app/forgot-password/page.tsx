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
    else { toast.success("Code sent — check your inbox (and spam folder)"); setStep("reset") }
  }

  async function resend() {
    const { error } = await authClient.forgetPassword.emailOtp({ email })
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else toast.success("New code sent")
  }

  async function reset(e: React.FormEvent) {
    e.preventDefault()
    if (password.length < 8) { setErr("Password must be at least 8 characters."); return }
    setLoading(true); setErr(null)
    const { error } = await authClient.emailOtp.resetPassword({ email, otp, password })
    setLoading(false)
    if (error) setErr(friendlyAuthError(error.code || error.message))
    else { toast.success("Password reset"); router.push("/login?reset=1") }
  }

  return (
    <main className="mx-auto flex min-h-[82vh] max-w-md flex-col justify-center px-4">
      <Card className="glass p-6">
        <h1 className="mb-1 text-2xl font-bold">Forgot password</h1>

        {step === "email" ? (
          <>
            <p className="mb-5 text-sm text-muted-foreground">Enter your email: we&apos;ll send a 6-digit code to reset your password.</p>
            <form onSubmit={sendCode} className="grid gap-3">
              <Input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
              {err && <p className="text-sm text-red-400">⚠️ {err}</p>}
              <Button type="submit" disabled={loading}>{loading ? "Sending…" : "Send code"}</Button>
            </form>
          </>
        ) : (
          <>
            <p className="mb-5 text-sm text-muted-foreground">Code sent to <strong className="text-foreground">{email}</strong>. Enter it and choose a new password.</p>
            <form onSubmit={reset} className="grid gap-3">
              <Input inputMode="numeric" maxLength={6} placeholder="6-digit code" value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))} required autoComplete="one-time-code" className="text-center text-lg tracking-[0.4em]" />
              <Input type="password" placeholder="New password (8+ characters)" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} autoComplete="new-password" />
              {err && <p className="text-sm text-red-400">⚠️ {err}</p>}
              <Button type="submit" disabled={loading || otp.length !== 6}>{loading ? "Resetting…" : "Reset password"}</Button>
            </form>
            <p className="mt-4 text-center text-sm text-muted-foreground">
              Didn&apos;t get it? <button onClick={resend} className="text-cyan-400 underline">Resend code</button>
            </p>
          </>
        )}

        <p className="mt-4 text-sm text-muted-foreground"><Link href="/login" className="text-cyan-400 underline">← Back to sign in</Link></p>
      </Card>
    </main>
  )
}
