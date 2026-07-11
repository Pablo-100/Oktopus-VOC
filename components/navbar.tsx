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

  const [mounted, setMounted] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  useEffect(() => setMounted(true), [])

  // Horloge système en temps réel
  const [now, setNow] = useState("")
  useEffect(() => {
    const upd = () => setNow(new Date().toLocaleTimeString("fr-FR"))
    upd()
    const id = setInterval(upd, 1000)
    return () => clearInterval(id)
  }, [])

  async function handleLogout() {
    setMenuOpen(false)
    await authClient.signOut()
    router.replace("/")
    router.refresh()
  }
  function toggleTheme() {
    setTheme(theme === "dark" ? "light" : "dark")
  }

  const links = LINKS.filter((l) => l.href === "/" || (mounted && session?.user))
  const user = mounted ? session?.user : null
  const avatarInitial = (user?.name || user?.email || "?").charAt(0).toUpperCase()

  return (
    <nav className="sticky top-0 z-50 border-b border-border bg-background/70 backdrop-blur-xl">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-wide" onClick={() => setMenuOpen(false)}>
          <Image src="/logo.png" alt="OCTUPUS" width={30} height={30} className="drop-shadow-[0_2px_10px_rgba(139,92,246,0.7)]" />
          <span className="neon-text">OCTUPUS</span>
        </Link>

        {/* ─── Desktop (md+) ─── */}
        <div className="hidden items-center gap-1 md:flex">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={cn(
                "relative rounded-full px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground",
                pathname === l.href && "text-foreground",
              )}
            >
              {pathname === l.href && <span className="absolute inset-0 -z-10 rounded-full bg-primary/15 ring-1 ring-primary/40" />}
              {l.label}
            </Link>
          ))}
          <span className="mx-2 inline-flex items-center gap-1.5 rounded-full border border-border bg-white/5 px-3 py-1 font-mono text-sm tabular-nums text-foreground" title="Heure locale">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
            {mounted ? now : "--:--:--"}
          </span>
          {user ? (
            <div className="ml-1 flex items-center gap-2">
              <Link href="/account" title="Mon compte" className="inline-flex max-w-[140px] items-center gap-1.5 truncate rounded-full border border-border bg-white/5 px-2.5 py-1 text-sm text-foreground hover:border-primary/50">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-violet-600 to-pink-500 text-[11px] font-bold text-white">{avatarInitial}</span>
                <span className="truncate">{user.name || user.email}</span>
              </Link>
              <Button size="sm" variant="outline" onClick={handleLogout}>Déconnexion</Button>
            </div>
          ) : (
            <Link href="/login" className="ml-1 rounded-full bg-gradient-to-r from-violet-600 to-pink-500 px-3 py-1.5 text-sm font-semibold text-white">Connexion</Link>
          )}
          <Button variant="ghost" size="icon" aria-label="Basculer le thème" onClick={toggleTheme} className="ml-1">
            {mounted && theme === "dark" ? "☀️" : "🌙"}
          </Button>
        </div>

        {/* ─── Mobile (<md) : thème + hamburger ─── */}
        <div className="flex items-center gap-1 md:hidden">
          <Button variant="ghost" size="icon" aria-label="Basculer le thème" onClick={toggleTheme}>
            {mounted && theme === "dark" ? "☀️" : "🌙"}
          </Button>
          <Button variant="ghost" size="icon" aria-label="Menu" aria-expanded={menuOpen} onClick={() => setMenuOpen((o) => !o)}>
            {menuOpen ? "✕" : "☰"}
          </Button>
        </div>
      </div>

      {/* ─── Panneau mobile déroulant ─── */}
      {menuOpen && (
        <div className="border-t border-border bg-background/95 px-4 py-3 backdrop-blur-xl md:hidden">
          <div className="grid gap-1">
            {links.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                onClick={() => setMenuOpen(false)}
                className={cn(
                  "rounded-lg px-3 py-2 text-sm text-muted-foreground hover:bg-white/5 hover:text-foreground",
                  pathname === l.href && "bg-primary/15 text-foreground ring-1 ring-primary/40",
                )}
              >
                {l.label}
              </Link>
            ))}
          </div>
          <div className="mt-3 border-t border-border pt-3">
            {user ? (
              <div className="grid gap-2">
                <Link href="/account" onClick={() => setMenuOpen(false)} className="flex items-center gap-2 rounded-lg border border-border bg-white/5 px-3 py-2 text-sm text-foreground">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-violet-600 to-pink-500 text-xs font-bold text-white">{avatarInitial}</span>
                  <span className="truncate">{user.name || user.email}</span>
                </Link>
                <Button variant="outline" size="sm" onClick={handleLogout}>Déconnexion</Button>
              </div>
            ) : (
              <Link href="/login" onClick={() => setMenuOpen(false)} className="block rounded-lg bg-gradient-to-r from-violet-600 to-pink-500 px-3 py-2 text-center text-sm font-semibold text-white">
                Connexion
              </Link>
            )}
          </div>
        </div>
      )}
    </nav>
  )
}
