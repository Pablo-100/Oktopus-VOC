import type { Metadata, Viewport } from "next"
import { Geist_Mono, Noto_Sans, Outfit } from "next/font/google"

import "./globals.css"
import { ThemeProvider } from "@/components/theme-provider"
import { Navbar } from "@/components/navbar"
import { Footer } from "@/components/footer"
import { cn } from "@/lib/utils"

const outfitHeading = Outfit({ subsets: ["latin"], variable: "--font-heading" })
const notoSans = Noto_Sans({ subsets: ["latin"], variable: "--font-sans" })
const fontMono = Geist_Mono({ subsets: ["latin"], variable: "--font-mono" })

export const metadata: Metadata = {
  title: "OCTUPUS — Rise from the deep. Crush every threat",
  description:
    "Vulnerability Operations Center : priorisation des CVE par le risque réel (CVSS · EPSS · CISA KEV), threat intelligence et analytics.",
  icons: { icon: "/logo.png", apple: "/logo.png" },
}

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#0a0e1a",
}

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="fr"
      suppressHydrationWarning
      className={cn(
        "antialiased",
        fontMono.variable,
        "font-sans",
        notoSans.variable,
        outfitHeading.variable,
      )}
    >
      <body>
        <ThemeProvider>
          <div className="octo-bg" aria-hidden />
          <Navbar />
          {children}
          <Footer />
        </ThemeProvider>
      </body>
    </html>
  )
}
