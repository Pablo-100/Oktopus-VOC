"use client"

import Link from "next/link"
import Image from "next/image"
import { usePathname, useRouter } from "next/navigation"
import { useTheme } from "next-themes"
import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { authClient } from "@/lib/auth-client"

// "0-days" is public (no auth required) — it stays visible to every visitor.
// The rest only appear once signed in (filtered below by `session?.user`).
/**
 * Links shown while signed out.
 *
 * Must contain ONLY pages the proxy actually leaves public. `/zero-days` used
 * to sit here because the 0-day tracker was the public flagship; it is now
 * gated, so advertising it to a signed-out visitor promised a page that
 * immediately bounced them to the login screen.
 */
const PUBLIC_LINKS = [{ href: "/", label: "Home" }]

/** Everything behind authentication, in the order an analyst works through it. */
const AUTH_LINKS = [
  { href: "/dashboard", label: "CVE Dashboard" },
  { href: "/zero-days", label: "0-Days" },
  { href: "/exposure", label: "Exposure" },
  { href: "/assets", label: "My Assets" },
  { href: "/statistics", label: "Statistics" },
  // Where the ingestion pipelines report whether data is actually arriving.
  { href: "/sources", label: "Sources" },
]

export function Navbar() {
  const pathname = usePathname()
  const router = useRouter()
  const { theme, setTheme } = useTheme()
  const { data: session } = authClient.useSession()

  const [mounted, setMounted] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  useEffect(() => setMounted(true), [])

  // Live system clock
  const [now, setNow] = useState("")
  useEffect(() => {
    const upd = () => setNow(new Date().toLocaleTimeString("en-US"))
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

  const links = [...PUBLIC_LINKS, ...(mounted && session?.user ? AUTH_LINKS : [])]
  const user = mounted ? session?.user : null
  const avatarInitial = (user?.name || user?.email || "?").charAt(0).toUpperCase()

  return (
    <nav className="sticky top-0 z-50 border-b border-border bg-background/70 backdrop-blur-xl">
      {/* `flex-nowrap` and a wider container: six links plus the clock, the user
          chip, a log-out button and the theme toggle no longer fit in
          max-w-6xl, and the row was wrapping onto a second line. */}
      <div className="mx-auto flex h-14 max-w-7xl flex-nowrap items-center justify-between gap-2 px-4">
        {/* Logo */}
        {/* One line. The wordmark and its tagline were stacked, which made the
            brand block two rows tall and forced the whole bar to reserve that
            height. The tagline now sits inline and disappears on narrow screens
            rather than pushing anything to a second row. */}
        <Link href="/" className="flex shrink-0 items-center gap-2 whitespace-nowrap" onClick={() => setMenuOpen(false)}>
          <Image src="/logo.png" alt="OCTUPUS VOC" width={30} height={30} className="drop-shadow-[0_2px_10px_rgba(139,92,246,0.7)]" />
          <span className="flex items-baseline gap-1.5 leading-none">
            <span className="text-sm font-extrabold tracking-tight sm:text-base">
              <span className="bg-gradient-to-r from-violet-400 via-fuchsia-400 to-cyan-400 bg-clip-text text-transparent">OCTUPUS</span>{" "}
              <span className="bg-gradient-to-r from-pink-500 to-orange-400 bg-clip-text text-transparent">VOC</span>
            </span>
            <span className="hidden text-[9px] font-semibold uppercase tracking-[0.18em] text-muted-foreground xl:inline">
              By OCTUPUS
            </span>
          </span>
        </Link>

        {/* ─── Desktop (md+) ─── */}
        <div className="hidden min-w-0 flex-1 items-center justify-center gap-0.5 overflow-x-auto whitespace-nowrap md:flex [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={cn(
                "relative shrink-0 rounded-full px-2.5 py-1.5 text-sm whitespace-nowrap text-muted-foreground transition-colors hover:text-foreground",
                pathname === l.href && "text-foreground",
              )}
            >
              {pathname === l.href && <span className="absolute inset-0 -z-10 rounded-full bg-primary/15 ring-1 ring-primary/40" />}
              {l.label}
            </Link>
          ))}
          <span className="mx-1 hidden shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-border bg-white/5 px-2.5 py-1 font-mono text-sm tabular-nums text-foreground lg:inline-flex" title="Local time">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
            {mounted ? now : "--:--:--"}
          </span>
          {user ? (
            <div className="ml-1 flex shrink-0 items-center gap-2 whitespace-nowrap">
              <Link href="/account" title="My account" className="inline-flex max-w-[120px] shrink-0 items-center gap-1.5 truncate rounded-full border border-border bg-white/5 px-2.5 py-1 text-sm text-foreground hover:border-primary/50">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-violet-600 to-pink-500 text-[11px] font-bold text-white">{avatarInitial}</span>
                <span className="truncate">{user.name || user.email}</span>
              </Link>
              <Button size="sm" variant="outline" onClick={handleLogout}>Log out</Button>
            </div>
          ) : (
            <Link href="/login" className="ml-1 rounded-full bg-gradient-to-r from-violet-600 to-pink-500 px-3 py-1.5 text-sm font-semibold text-white">Sign in</Link>
          )}
          <Button variant="ghost" size="icon" aria-label="Toggle theme" onClick={toggleTheme} className="ml-1 shrink-0">
            {mounted && theme === "dark" ? "☀️" : "🌙"}
          </Button>
        </div>

        {/* ─── Mobile (<md): theme + hamburger ─── */}
        <div className="flex items-center gap-1 md:hidden">
          <Button variant="ghost" size="icon" aria-label="Toggle theme" onClick={toggleTheme}>
            {mounted && theme === "dark" ? "☀️" : "🌙"}
          </Button>
          <Button variant="ghost" size="icon" aria-label="Menu" aria-expanded={menuOpen} onClick={() => setMenuOpen((o) => !o)}>
            {menuOpen ? "✕" : "☰"}
          </Button>
        </div>
      </div>

      {/* ─── Mobile dropdown panel ─── */}
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
                <Button variant="outline" size="sm" onClick={handleLogout}>Log out</Button>
              </div>
            ) : (
              <Link href="/login" onClick={() => setMenuOpen(false)} className="block rounded-lg bg-gradient-to-r from-violet-600 to-pink-500 px-3 py-2 text-center text-sm font-semibold text-white">
                Sign in
              </Link>
            )}
          </div>
        </div>
      )}
    </nav>
  )
}
