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
import { toast } from "sonner"

// Fournisseurs proposés (hors "credential" = email/mot de passe, traité à part)
const SOCIALS = [
  { id: "google", label: "🔵 Google" },
  { id: "github", label: "⚫ GitHub" },
] as const

type Account = { id: string; providerId: string; accountId: string; createdAt?: string | Date }
type Session = { id: string; token: string; createdAt?: string | Date; updatedAt?: string | Date; ipAddress?: string | null; userAgent?: string | null }

function fmt(d?: string | Date | null) {
  if (!d) return "—"
  const date = new Date(d)
  return isNaN(date.getTime()) ? "—" : date.toLocaleString("fr-FR")
}

// Extrait un libellé lisible "Navigateur · OS" depuis le user-agent
function deviceOf(ua?: string | null) {
  if (!ua) return "Appareil inconnu"
  const browser = /Edg/.test(ua) ? "Edge" : /Chrome/.test(ua) ? "Chrome" : /Firefox/.test(ua) ? "Firefox" : /Safari/.test(ua) ? "Safari" : "Navigateur"
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
    return <main className="mx-auto flex min-h-[70vh] max-w-md items-center justify-center px-4 text-muted-foreground">Chargement…</main>
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
    else { setNameEdit(null); toast.success("Nom mis à jour") }
  }

  async function changePassword() {
    if (newPw.length < 8) return toast.error("Le nouveau mot de passe doit faire 8+ caractères")
    setSavingPw(true)
    const { error } = await authClient.changePassword({ currentPassword: curPw, newPassword: newPw, revokeOtherSessions: true })
    setSavingPw(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Mot de passe changé — autres sessions déconnectées"); setCurPw(""); setNewPw(""); loadSessions() }
  }

  async function linkProvider(provider: string) {
    setBusyProvider(provider)
    const { error } = await authClient.linkSocial({ provider: provider as "google" | "github", callbackURL: "/account" })
    if (error) { setBusyProvider(null); toast.error(friendlyAuthError(error.code || error.message)) }
    // succès -> redirection OAuth vers le provider
  }

  async function unlinkProvider(providerId: string, accountId: string) {
    if (loginMethodsCount <= 1) return toast.error("Impossible de retirer ta dernière méthode de connexion.")
    setBusyProvider(providerId)
    const { error } = await authClient.unlinkAccount({ providerId, accountId })
    setBusyProvider(null)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Fournisseur délié"); loadAccounts() }
  }

  async function revokeSession(token: string) {
    const { error } = await authClient.revokeSession({ token })
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Session révoquée"); loadSessions() }
  }
  async function revokeOthers() {
    const { error } = await authClient.revokeOtherSessions()
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Autres appareils déconnectés"); loadSessions() }
  }

  async function startVerification() {
    setSendingVerif(true)
    const { error } = await authClient.emailOtp.sendVerificationOtp({ email: u.email, type: "email-verification" })
    setSendingVerif(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Code envoyé"); router.push(`/verify-email?email=${encodeURIComponent(u.email)}&redirect=/account`) }
  }

  async function deleteAccount() {
    setDeleting(true)
    const { error } = await authClient.deleteUser({ password: delPw || undefined })
    setDeleting(false)
    if (error) toast.error(friendlyAuthError(error.code || error.message))
    else { toast.success("Compte supprimé"); router.replace("/") }
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Mon compte</h1>
          <p className="text-sm text-muted-foreground">Profil, connexions, sessions et sécurité</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => authClient.signOut().then(() => { router.replace("/"); router.refresh() })}>
          Déconnexion
        </Button>
      </div>

      {/* Profil */}
      <Card className="glass mb-5 p-6">
        <div className="flex items-center gap-4">
          {u.image ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={u.image} alt="" className="h-16 w-16 rounded-full ring-2 ring-primary/40" />
          ) : (
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-violet-600 to-pink-500 text-2xl font-bold text-white">{initial}</div>
          )}
          <div className="min-w-0">
            <p className="truncate text-lg font-semibold">{u.name || "Sans nom"}</p>
            <p className="truncate text-sm text-muted-foreground">{u.email}</p>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <Badge variant={u.emailVerified ? "default" : "outline"}>{u.emailVerified ? "Email vérifié" : "Email non vérifié"}</Badge>
              {!u.emailVerified && (
                <Button size="sm" variant="outline" disabled={sendingVerif} onClick={startVerification}>
                  {sendingVerif ? "Envoi…" : "Vérifier mon email"}
                </Button>
              )}
            </div>
            <p className="mt-2 font-mono text-xs text-muted-foreground">ID : {u.id}</p>
          </div>
        </div>

        <Separator className="my-5" />

        <div className="grid gap-2">
          <Label htmlFor="name">Nom affiché</Label>
          <div className="flex gap-2">
            <Input id="name" value={name} onChange={(e) => setNameEdit(e.target.value)} placeholder="Ton nom" />
            <Button onClick={saveName} disabled={savingName || name === u.name || !name.trim()}>{savingName ? "…" : "Enregistrer"}</Button>
          </div>
        </div>
      </Card>

      {/* Méthodes de connexion */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-1 text-lg font-semibold">Méthodes de connexion</h2>
        <p className="mb-4 text-sm text-muted-foreground">Un seul compte, plusieurs façons de te connecter. Tu ne peux pas retirer la dernière.</p>
        <ul className="grid gap-2">
          <li className="flex items-center justify-between rounded-lg border border-border p-3">
            <span className="text-sm">✉️ Email + mot de passe</span>
            <Badge variant={hasPassword ? "default" : "outline"}>{hasPassword ? "Activé" : "Non défini"}</Badge>
          </li>
          {SOCIALS.map((p) => {
            const acc = accounts.find((a) => a.providerId === p.id)
            const linked = linkedIds.has(p.id)
            return (
              <li key={p.id} className="flex items-center justify-between rounded-lg border border-border p-3">
                <span className="text-sm">{p.label} {linked && <span className="text-muted-foreground">· lié</span>}</span>
                {linked ? (
                  <Button size="sm" variant="outline" disabled={busyProvider === p.id || loginMethodsCount <= 1}
                    onClick={() => acc && unlinkProvider(p.id, acc.accountId)}
                    title={loginMethodsCount <= 1 ? "Dernière méthode de connexion — non retirable" : ""}>
                    {busyProvider === p.id ? "…" : "Délier"}
                  </Button>
                ) : (
                  <Button size="sm" disabled={busyProvider === p.id} onClick={() => linkProvider(p.id)}>
                    {busyProvider === p.id ? "…" : "Lier"}
                  </Button>
                )}
              </li>
            )
          })}
        </ul>
      </Card>

      {/* Sécurité (mot de passe) */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-1 text-lg font-semibold">Sécurité</h2>
        <p className="mb-4 text-sm text-muted-foreground">Change ton mot de passe (comptes email). Les comptes purement GitHub/Google n&apos;en ont pas.</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="cur">Mot de passe actuel</Label>
            <Input id="cur" type="password" value={curPw} onChange={(e) => setCurPw(e.target.value)} autoComplete="current-password" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="new">Nouveau mot de passe</Label>
            <Input id="new" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} autoComplete="new-password" minLength={8} />
          </div>
        </div>
        <Button className="mt-4" onClick={changePassword} disabled={savingPw || !curPw || !newPw}>{savingPw ? "Changement…" : "Changer le mot de passe"}</Button>
      </Card>

      {/* Sessions actives */}
      <Card className="glass mb-5 p-6">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Sessions actives</h2>
          {sessions.length > 1 && <Button size="sm" variant="outline" onClick={revokeOthers}>Déconnecter les autres</Button>}
        </div>
        <ul className="grid gap-2">
          {sessions.length === 0 ? (
            <li className="text-sm text-muted-foreground">Aucune session listée.</li>
          ) : sessions.map((s) => {
            const current = s.token === currentToken
            return (
              <li key={s.id} className="flex items-center justify-between rounded-lg border border-border p-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium">{deviceOf(s.userAgent)} {current && <Badge className="ml-1">Cet appareil</Badge>}</div>
                  <div className="text-xs text-muted-foreground">{s.ipAddress || "IP inconnue"} · connectée le {fmt(s.createdAt)}</div>
                </div>
                {!current && <Button size="sm" variant="ghost" className="text-red-400 hover:text-red-300" onClick={() => revokeSession(s.token)}>Révoquer</Button>}
              </li>
            )
          })}
        </ul>
      </Card>

      {/* Infos compte */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-3 text-lg font-semibold">Informations du compte</h2>
        <dl className="grid gap-2 text-sm sm:grid-cols-2">
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Compte créé</dt><dd>{fmt(u.createdAt)}</dd></div>
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Dernière connexion</dt><dd>{lastLogin ? fmt(new Date(lastLogin)) : "—"}</dd></div>
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Email vérifié</dt><dd>{u.emailVerified ? "Oui" : "Non"}</dd></div>
          <div className="flex justify-between rounded-lg border border-border p-3"><dt className="text-muted-foreground">Méthodes de connexion</dt><dd>{loginMethodsCount}</dd></div>
        </dl>
      </Card>

      {/* Alertes Telegram */}
      <Card className="glass mb-5 p-6">
        <h2 className="mb-1 text-lg font-semibold">🔔 Alertes Telegram</h2>
        <p className="mb-5 text-sm text-muted-foreground">Scanne ce QR pour ouvrir le bot <strong>@{BOT_USERNAME}</strong> et recevoir les CVE critiques/élevées en temps réel.</p>
        <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-start">
          <TelegramQR size={168} />
          <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
            <li>Scanne le QR (ou clique le bouton) pour ouvrir le bot dans Telegram.</li>
            <li>Appuie sur <strong>Démarrer / Start</strong>.</li>
            <li>OCTUPUS pousse chaque CVE <span className="text-rose-400">Critique</span> / <span className="text-orange-400">Élevée</span> détectée.</li>
          </ol>
        </div>
      </Card>

      {/* Zone dangereuse */}
      <Card className="mb-10 border-rose-500/40 bg-rose-500/5 p-6">
        <h2 className="mb-1 text-lg font-semibold text-rose-400">Zone dangereuse</h2>
        <p className="mb-4 text-sm text-muted-foreground">La suppression de ton compte est <strong>définitive</strong> : profil, sessions et données personnelles effacés.</p>
        {!confirmDel ? (
          <Button variant="outline" className="border-rose-500/50 text-rose-400 hover:bg-rose-500/10" onClick={() => setConfirmDel(true)}>Supprimer mon compte</Button>
        ) : (
          <div className="grid gap-3">
            <div className="grid gap-2">
              <Label htmlFor="delpw">Confirme avec ton mot de passe (comptes email)</Label>
              <Input id="delpw" type="password" value={delPw} onChange={(e) => setDelPw(e.target.value)} placeholder="Mot de passe" autoComplete="current-password" />
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => { setConfirmDel(false); setDelPw("") }}>Annuler</Button>
              <Button className="bg-rose-600 text-white hover:bg-rose-700" onClick={deleteAccount} disabled={deleting}>{deleting ? "Suppression…" : "Oui, supprimer définitivement"}</Button>
            </div>
          </div>
        )}
      </Card>
    </main>
  )
}
