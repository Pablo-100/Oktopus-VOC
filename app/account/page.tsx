"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { authClient } from "@/lib/auth-client"
import { friendlyAuthError } from "@/lib/auth-errors"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { TelegramQR, BOT_USERNAME } from "@/components/telegram-qr"
import { ProviderKeysCard } from "@/components/provider-keys-card"
import { VerifiedDomainsCard } from "@/components/verified-domains-card"
import { toast } from "sonner"

// Providers offered (excluding "credential" = email/password, handled separately)
const SOCIALS = [
  { id: "google", label: "🔵 Google" },
  { id: "github", label: "⚫ GitHub" },
] as const

type Account = { id: string; providerId: string; accountId: string; createdAt?: string | Date }
type Session = { id: string; token: string; createdAt?: string | Date; updatedAt?: string | Date; ipAddress?: string | null; userAgent?: string | null }

function fmt(d?: string | Date | null) {
  if (!d) return "—"
  const date = new Date(d)
  return isNaN(date.getTime()) ? "—" : date.toLocaleString("en-US")
}

// Extracts a readable "Browser · OS" label from the user-agent
function deviceOf(ua?: string | null) {
  if (!ua) return "Unknown device"
  const browser = /Edg/.test(ua) ? "Edge" : /Chrome/.test(ua) ? "Chrome" : /Firefox/.test(ua) ? "Firefox" : /Safari/.test(ua) ? "Safari" : "Browser"
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : ""
  return [browser, os].filter(Boolean).join(" · ")
}

export default function AccountPage() {
  const router = useRouter()
  const { data: session, isPending } = authClient.useSession()

  const [nameEdit, setNameEdit] = useState<string | null>(null)
  const [savingName, setSavingName] = useState(false)
  const [curPw, setCurPw] = useState("")
  const [newPw, setNewPw] = useState("")
  const [savingPw, setSavingPw] = useState(false)
  const [delPw, setDelPw] = useState("")
  const [confirmDel, setConfirmDel] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [sendingVerif, setSendingVerif] = useState(false)

  const [accounts, setAccounts] = useState<Account[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [busyProvider, setBusyProvider] = useState<string | null>(null)

  const loadAccounts = useCallback(async () => {
    const { data } = await authClient.listAccounts()
    if (data) setAccounts(data as Account[])
  }, [])
  const loadSessions = useCallback(async () => {
    const { data } = await authClient.listSessions()
    if (data) setSessions(data as Session[])
  }, [])

  useEffect(() => {
    if (!isPending && !session?.user) router.replace("/login")
  }, [isPending, session, router])
  useEffect(() => {
    if (!session?.user) return
    // Chargement asynchrone (le setState a lieu après await, dans loadAccounts/loadSessions)
    void (async () => { await loadAccounts(); await loadSessions() })()
  }, [session?.user, loadAccounts, loadSessions])

  if (isPending || !session?.user) {
    return <main className="mx-auto flex min-h-[70vh] max-w-md items-center justify-center px-4 text-muted-foreground">Loading…</main>
  }

  const u = session.user
  const name = nameEdit ?? (u.name || "") // dérivé de la session tant que l'utilisateur n'a pas édité
  const currentToken = session.session?.token
  const initial = (u.name || u.email || "?").charAt(0).toUpperCase()
  const hasPassword = accounts.some((a) => a.providerId === "credential")
  const linkedIds = new Set(accounts.map((a) => a.providerId))
  const loginMethodsCount = accounts.length
  const lastLogin = sessions.map((s) => new Date(s.createdAt || 0).getTime()).sort((a, b) => b - a)[0]

  async function saveName() {
    setSavingName(true)
    const { error } = await authClient.updateUser({ name })
    setSavingName(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { setNameEdit(null); toast.success("Name updated") }
  }

  async function changePassword() {
    if (newPw.length < 8) return toast.error("The new password must be at least 8 characters")
    setSavingPw(true)
    const { error } = await authClient.changePassword({ currentPassword: curPw, newPassword: newPw, revokeOtherSessions: true })
    setSavingPw(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Password changed — other sessions signed out"); setCurPw(""); setNewPw(""); loadSessions() }
  }

  async function linkProvider(provider: string) {
    setBusyProvider(provider)
    const { error } = await authClient.linkSocial({ provider: provider as "google" | "github", callbackURL: "/account" })
    if (error) { setBusyProvider(null); toast.error(friendlyAuthError(error.code || error.message)) }
    // success -> OAuth redirect to the provider
  }

  async function unlinkProvider(providerId: string, accountId: string) {
    if (loginMethodsCount <= 1) return toast.error("You can't remove your last sign-in method.")
    setBusyProvider(providerId)
    const { error } = await authClient.unlinkAccount({ providerId, accountId })
    setBusyProvider(null)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Provider unlinked"); loadAccounts() }
  }

  async function revokeSession(token: string) {
    const { error } = await authClient.revokeSession({ token })
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Session revoked"); loadSessions() }
  }
  async function revokeOthers() {
    const { error } = await authClient.revokeOtherSessions()
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Other devices signed out"); loadSessions() }
  }

  async function startVerification() {
    setSendingVerif(true)
    const { error } = await authClient.emailOtp.sendVerificationOtp({ email: u.email, type: "email-verification" })
    setSendingVerif(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Code sent"); router.push(`/verify-email?email=${encodeURIComponent(u.email)}&redirect=/account`) }
  }

  async function deleteAccount() {
    setDeleting(true)
    const { error } = await authClient.deleteUser({ password: delPw || undefined })
    setDeleting(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Account deleted"); router.replace("/") }
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">My Account</h1>
          <p className="text-sm text-muted-foreground">Profile, sign-in methods, sessions and security</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => authClient.signOut().then(() => { router.replace("/"); router.refresh() })}>
          Log out
        </Button>
      </div>

      {/* Profile */}
      <Card className="glass mb-5 p-6">
        <div className="flex items-center gap-4">
          {u.image ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={u.image} alt="" className="h-16 w-16 rounded-full ring-2 ring-primary/40" />
          ) : (
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-violet-600 to-pink-500 text-2xl font-bold text-white">{initial}</div>
          )}
          <div className="min-w-0">
            <p className="truncate text-lg font-semibold">{u.name || "No name"}</p>
            <p className="truncate text-sm text-muted-foreground">{u.email}</p>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <Badge variant={u.emailVerified ? "default" : "outline"}>{u.emailVerified ? "Email verified" : "Email not verified"}</Badge>
              {!u.emailVerified && (
                <Button size="sm" variant="outline" disabled={sendingVerif} onClick={startVerification}>
                  {sendingVerif ? "Sending…" : "Verify my email"}
                </Button>
              )}
            </div>
            <p className="mt-2 font-mono text-xs text-muted-foreground">ID: {u.id}</p>
          </div>
        </div>

        <Separator className="my-5" />

        <div className="grid gap-2">
          <Label htmlFor="name">Display name</Label>
          <div className="flex gap-2">
            <Input id="name" value={name} onChange={(e) => setNameEdit(e.target.value)} placeholder="Your name" />
            <Button onClick={saveName} disabled={savingName || name === u.name || !name.trim()}>{savingName ? "…" : "Save"}</Button>
          </div>
        </div>
      </Card>

      {/* Sign-in methods */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-1 text-lg font-semibold">Sign-in methods</h2>
        <p className="mb-4 text-sm text-muted-foreground">One account, several ways to sign in. You can&apos;t remove the last one.</p>
        <ul className="grid gap-2">
          <li className="flex items-center justify-between rounded-lg border border-border p-3">
            <span className="text-sm">✉️ Email + password</span>
            <Badge variant={hasPassword ? "default" : "outline"}>{hasPassword ? "Enabled" : "Not set"}</Badge>
          </li>
          {SOCIALS.map((p) => {
            const acc = accounts.find((a) => a.providerId === p.id)
            const linked = linkedIds.has(p.id)
            return (
              <li key={p.id} className="flex items-center justify-between rounded-lg border border-border p-3">
                <span className="text-sm">{p.label} {linked && <span className="text-muted-foreground">· linked</span>}</span>
                {linked ? (
                  <Button size="sm" variant="outline" disabled={busyProvider === p.id || loginMethodsCount <= 1}
                    onClick={() => acc && unlinkProvider(p.id, acc.accountId)}
                    title={loginMethodsCount <= 1 ? "Last sign-in method — can't be removed" : ""}>
                    {busyProvider === p.id ? "…" : "Unlink"}
                  </Button>
                ) : (
                  <Button size="sm" disabled={busyProvider === p.id} onClick={() => linkProvider(p.id)}>
                    {busyProvider === p.id ? "…" : "Link"}
                  </Button>
                )}
              </li>
            )
          })}
        </ul>
      </Card>

      {/* Security (password) */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-1 text-lg font-semibold">Security</h2>
        <p className="mb-4 text-sm text-muted-foreground">Change your password (email accounts). Accounts using only GitHub/Google don&apos;t have one.</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="cur">Current password</Label>
            <Input id="cur" type="password" value={curPw} onChange={(e) => setCurPw(e.target.value)} autoComplete="current-password" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="new">New password</Label>
            <Input id="new" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} autoComplete="new-password" minLength={8} />
          </div>
        </div>
        <Button className="mt-4" onClick={changePassword} disabled={savingPw || !curPw || !newPw}>{savingPw ? "Changing…" : "Change password"}</Button>
      </Card>

      <ProviderKeysCard />

      <VerifiedDomainsCard />

      {/* Active sessions */}
      <Card className="glass mb-5 p-6">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Active sessions</h2>
          {sessions.length > 1 && <Button size="sm" variant="outline" onClick={revokeOthers}>Sign out other devices</Button>}
        </div>
        <ul className="grid gap-2">
          {sessions.length === 0 ? (
            <li className="text-sm text-muted-foreground">No sessions listed.</li>
          ) : sessions.map((s) => {
            const current = s.token === currentToken
            return (
              <li key={s.id} className="flex items-center justify-between rounded-lg border border-border p-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium">{deviceOf(s.userAgent)} {current && <Badge className="ml-1">This device</Badge>}</div>
                  <div className="text-xs text-muted-foreground">{s.ipAddress || "Unknown IP"} · signed in on {fmt(s.createdAt)}</div>
                </div>
                {!current && <Button size="sm" variant="ghost" className="text-red-400 hover:text-red-300" onClick={() => revokeSession(s.token)}>Revoke</Button>}
              </li>
            )
          })}
        </ul>
      </Card>

      {/* Account info */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-3 text-lg font-semibold">Account information</h2>
        <dl className="grid gap-2 text-sm sm:grid-cols-2">
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Account created</dt><dd>{fmt(u.createdAt)}</dd></div>
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Last sign-in</dt><dd>{lastLogin ? fmt(new Date(lastLogin)) : "—"}</dd></div>
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Email verified</dt><dd>{u.emailVerified ? "Yes" : "No"}</dd></div>
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Sign-in methods</dt><dd>{loginMethodsCount}</dd></div>
        </dl>
      </Card>

      {/* Telegram alerts */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-1 text-lg font-semibold">🔔 Telegram alerts</h2>
        <p className="mb-5 text-sm text-muted-foreground">Scan this QR to open the bot <strong>@{BOT_USERNAME}</strong> and receive Critical/High CVEs in real time.</p>
        <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-start">
          <TelegramQR size={168} />
          <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
            <li>Scan the QR (or click the button) to open the bot in Telegram.</li>
            <li>Press <strong>Start</strong>.</li>
            <li>OCTUPUS pushes every detected <span className="text-rose-400">Critical</span> / <span className="text-orange-400">High</span> CVE.</li>
          </ol>
        </div>
      </Card>

      {/* Danger zone */}
      <Card className="mb-10 border-rose-500/40 bg-rose-500/5 p-6">
        <h2 className="mb-1 text-lg font-semibold text-rose-400">Danger zone</h2>
        <p className="mb-4 text-sm text-muted-foreground">Deleting your account is <strong>permanent</strong>: profile, sessions and personal data are erased.</p>
        {!confirmDel ? (
          <Button variant="outline" className="border-rose-500/50 text-rose-400 hover:bg-rose-500/10" onClick={() => setConfirmDel(true)}>Delete my account</Button>
        ) : (
          <div className="grid gap-3">
            <div className="grid gap-2">
              <Label htmlFor="delpw">Confirm with your password (email accounts)</Label>
              <Input id="delpw" type="password" value={delPw} onChange={(e) => setDelPw(e.target.value)} placeholder="Password" autoComplete="current-password" />
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => { setConfirmDel(false); setDelPw("") }}>Cancel</Button>
              <Button className="bg-rose-600 text-white hover:bg-rose-700" onClick={deleteAccount} disabled={deleting}>{deleting ? "Deleting…" : "Yes, delete permanently"}</Button>
            </div>
          </div>
        )}
      </Card>
    </main>
  )
}
