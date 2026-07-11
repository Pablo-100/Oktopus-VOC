import Link from "next/link"
import Image from "next/image"

const NAV = [
  { href: "/", label: "Accueil" },
  { href: "/dashboard", label: "CVE Dashboard" },
  { href: "/statistics", label: "Statistiques" },
  { href: "/assets", label: "Actifs" },
]

const RESOURCES = [
  { href: "https://nvd.nist.gov", label: "NVD" },
  { href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", label: "CISA KEV" },
  { href: "https://www.first.org/epss/", label: "FIRST EPSS" },
  { href: "https://attack.mitre.org", label: "MITRE ATT&CK" },
]

const SOCIALS = [
  {
    label: "LinkedIn",
    href: "https://www.linkedin.com/in/mustapha-amin-tbini/",
    icon: (
      <path d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.85 0-2.14 1.45-2.14 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.63-1.85 3.36-1.85 3.59 0 4.25 2.36 4.25 5.44v6.3zM5.34 7.43a2.06 2.06 0 110-4.13 2.06 2.06 0 010 4.13zM7.12 20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.22.79 24 1.77 24h20.45c.98 0 1.78-.78 1.78-1.73V1.73C24 .77 23.2 0 22.22 0z" />
    ),
  },
  {
    label: "Email",
    href: "mailto:mustaphaamintbini@gmail.com",
    icon: (
      <path d="M22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6zm-2 0-8 5-8-5h16zm0 12H4V8l8 5 8-5v10z" />
    ),
  },
  {
    label: "WhatsApp",
    href: "https://wa.me/21646345226",
    icon: (
      <path d="M17.47 14.38c-.3-.15-1.76-.87-2.03-.97-.27-.1-.47-.15-.67.15-.2.3-.77.97-.94 1.17-.17.2-.35.22-.65.07-.3-.15-1.26-.46-2.4-1.48-.89-.79-1.49-1.77-1.66-2.07-.17-.3-.02-.46.13-.61.13-.13.3-.35.45-.52.15-.17.2-.3.3-.5.1-.2.05-.37-.02-.52-.07-.15-.67-1.62-.92-2.22-.24-.58-.49-.5-.67-.51l-.57-.01c-.2 0-.52.07-.8.37-.27.3-1.04 1.02-1.04 2.48 0 1.46 1.07 2.88 1.22 3.08.15.2 2.1 3.2 5.08 4.49.71.3 1.26.48 1.69.62.71.22 1.36.19 1.87.12.57-.09 1.76-.72 2-1.41.25-.7.25-1.29.17-1.42-.07-.13-.27-.2-.57-.35zM12.04 21.5a9.5 9.5 0 01-4.85-1.33l-.35-.2-3.6.94.96-3.5-.23-.36a9.46 9.46 0 01-1.45-5.05c0-5.23 4.26-9.49 9.5-9.49 2.54 0 4.92.99 6.71 2.79a9.42 9.42 0 012.78 6.71c0 5.24-4.26 9.5-9.49 9.5zM20.3 3.7A11.44 11.44 0 0012.04.25C5.72.25.57 5.4.57 11.72c0 2.02.53 3.99 1.53 5.73L.5 23.75l6.44-1.69a11.45 11.45 0 005.1 1.3h.01c6.32 0 11.47-5.15 11.47-11.47 0-3.06-1.19-5.94-3.36-8.1z" />
    ),
  },
  {
    label: "GitHub",
    href: "https://github.com/Pablo-100",
    icon: (
      <path d="M12 .5C5.37.5 0 5.87 0 12.5c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58v-2.03c-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.21.09 1.84 1.24 1.84 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.67-.3-5.47-1.34-5.47-5.96 0-1.32.47-2.4 1.24-3.24-.12-.3-.54-1.52.12-3.17 0 0 1.01-.32 3.3 1.24a11.5 11.5 0 016 0c2.29-1.56 3.3-1.24 3.3-1.24.66 1.65.24 2.87.12 3.17.77.84 1.24 1.92 1.24 3.24 0 4.63-2.81 5.65-5.49 5.95.43.37.81 1.1.81 2.22v3.29c0 .32.22.7.83.58C20.56 22.29 24 17.79 24 12.5 24 5.87 18.63.5 12 .5z" />
    ),
  },
]

function FooterColumn({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-4 text-xs font-semibold uppercase tracking-[0.15em] text-muted-foreground">{title}</h3>
      <ul className="space-y-2.5 text-sm">{children}</ul>
    </div>
  )
}

export function Footer() {
  return (
    <footer className="mt-20 border-t border-border/70 bg-background/50">
      {/* fine ligne d'accent en haut */}
      <div className="h-px w-full bg-gradient-to-r from-transparent via-primary/40 to-transparent" />

      <div className="mx-auto max-w-6xl px-4 py-14">
        <div className="grid grid-cols-1 gap-10 sm:grid-cols-2 lg:grid-cols-12">
          {/* Marque */}
          <div className="lg:col-span-5">
            <Link href="/" className="flex items-center gap-2.5">
              <Image src="/logo.png" alt="OCTUPUS-VOC" width={34} height={34} className="drop-shadow-[0_2px_10px_rgba(139,92,246,0.6)]" />
              <span className="neon-text text-lg font-bold tracking-wide">OCTUPUS-VOC</span>
            </Link>
            <p className="mt-4 max-w-sm text-sm leading-relaxed text-muted-foreground">
              Vulnerability Operations Center — priorisation des vulnérabilités par le <span className="text-foreground">risque réel</span>, en fusionnant CVSS, EPSS et CISA KEV.
            </p>
          </div>

          {/* Navigation */}
          <div className="lg:col-span-2">
            <FooterColumn title="Navigation">
              {NAV.map((l) => (
                <li key={l.href}>
                  <Link href={l.href} className="text-muted-foreground transition-colors hover:text-foreground">{l.label}</Link>
                </li>
              ))}
            </FooterColumn>
          </div>

          {/* Ressources */}
          <div className="lg:col-span-2">
            <FooterColumn title="Ressources">
              {RESOURCES.map((l) => (
                <li key={l.href}>
                  <a href={l.href} target="_blank" rel="noopener noreferrer" className="text-muted-foreground transition-colors hover:text-foreground">{l.label}</a>
                </li>
              ))}
            </FooterColumn>
          </div>

          {/* Contact */}
          <div className="lg:col-span-3">
            <h3 className="mb-4 text-xs font-semibold uppercase tracking-[0.15em] text-muted-foreground">Contact</h3>
            <div className="flex gap-2.5">
              {SOCIALS.map((s) => (
                <a
                  key={s.label}
                  href={s.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={s.label}
                  title={s.label}
                  className="flex h-10 w-10 items-center justify-center rounded-full border border-border bg-white/[0.03] text-muted-foreground transition-all hover:-translate-y-0.5 hover:border-primary/50 hover:text-foreground"
                >
                  <svg viewBox="0 0 24 24" fill="currentColor" className="h-[18px] w-[18px]">{s.icon}</svg>
                </a>
              ))}
            </div>
          </div>
        </div>

        {/* Bas de page */}
        <div className="mt-12 flex flex-col items-center justify-between gap-3 border-t border-border/70 pt-6 text-sm text-muted-foreground sm:flex-row">
          <span>© 2026 OCTUPUS-VOC. Tous droits réservés.</span>
          <span>
            Developed by: <span className="font-medium text-foreground">TBINI Mustapha Amin</span> — <span className="neon-text font-semibold">OCTUPUS</span>
          </span>
        </div>
      </div>
    </footer>
  )
}
