"use client"

import Link from "next/link"
import Image from "next/image"
import { usePathname, useRouter } from "next/navigation"
import { useTheme } from "next-themes"
import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { authClient } from "@/lib/auth-client"

const LINKS = [
  { href: "/", label: "Accueil" },
  { href: "/dashboard", label: "CVE Dashboard" },
  { href: "/assets", label: "Actifs" },
  { href: "/statistics", label: "Statistiques" },
]

export function Navbar() {
  const pathname = usePathname()
  const router = useRouter()
  const { theme, setTheme } = useTheme()
  const { data: session } = authClient.useSession()

  // Déconnexion -> on éjecte vers l'accueil public (replace = pas de retour arrière vers la page protégée)
  async function handleLogout() {
    await authClient.signOut()
    router.replace("/")
    router.refresh()
  }
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])

  // Horloge système en temps réel
  const [now, setNow] = useState("")
  useEffect(() => {
    const upd = () => setNow(new Date().toLocaleTimeString("fr-FR"))
    upd()
    const id = setInterval(upd, 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <nav className="sticky top-0 z-50 border-b border-border bg-background/70 backdrop-blur-xl">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-wide">
          <Image src="/logo.png" alt="OCTUPUS" width={30} height={30} className="drop-shadow-[0_2px_10px_rgba(139,92,246,0.7)]" />
          <span className="neon-text">OCTUPUS</span>
        </Link>

        <div className="flex items-center gap-1">
          {LINKS.filter((l) => l.href === "/" || (mounted && session?.user)).map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={cn(
                "relative rounded-full px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground",
                pathname === l.href && "text-foreground",
              )}
            >
              {pathname === l.href && (
                <span className="absolute inset-0 -z-10 rounded-full bg-primary/15 ring-1 ring-primary/40" />
              )}
              {l.label}
            </Link>
          ))}
          <span className="mx-2 hidden items-center gap-1.5 rounded-full border border-border bg-white/5 px-3 py-1 font-mono text-sm tabular-nums text-foreground md:inline-flex" title="Heure locale">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
            {mounted ? now : "--:--:--"}
          </span>
          {mounted && (session?.user ? (
            <div className="ml-1 flex items-center gap-2">
              <Link href="/account" title="Mon compte" className="hidden max-w-[140px] items-center gap-1.5 truncate rounded-full border border-border bg-white/5 px-2.5 py-1 text-sm text-foreground hover:border-primary/50 md:inline-flex">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-violet-600 to-pink-500 text-[11px] font-bold text-white">
                  {(session.user.name || session.user.email || "?").charAt(0).toUpperCase()}
                </span>
                <span className="truncate">{session.user.name || session.user.email}</span>
              </Link>
              <Button size="sm" variant="outline" onClick={handleLogout}>Déconnexion</Button>
            </div>
          ) : (
            <Link href="/login" className="ml-1 rounded-full bg-gradient-to-r from-violet-600 to-pink-500 px-3 py-1.5 text-sm font-semibold text-white">Connexion</Link>
          ))}
          <Button
            variant="ghost"
            size="icon"
            aria-label="Basculer le thème"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            className="ml-1"
          >
            {mounted && theme === "dark" ? "☀️" : "🌙"}
          </Button>
        </div>
      </div>
    </nav>
  )
}
