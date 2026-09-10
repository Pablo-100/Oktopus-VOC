import type { Metadata, Viewport } from "next"
import { Geist_Mono, Noto_Sans, Outfit } from "next/font/google"

import "./globals.css"
import { SpeedInsights } from "@vercel/speed-insights/next"
import { Analytics } from "@vercel/analytics/next"
import { ThemeProvider } from "@/components/theme-provider"
import { Navbar } from "@/components/navbar"
import { Footer } from "@/components/footer"
import { cn } from "@/lib/utils"
import { Toaster } from "@/components/ui/sonner"

const outfitHeading = Outfit({ subsets: ["latin"], variable: "--font-heading" })
const notoSans = Noto_Sans({ subsets: ["latin"], variable: "--font-sans" })
const fontMono = Geist_Mono({ subsets: ["latin"], variable: "--font-mono" })

export const metadata: Metadata = {
  title: "OCTUPUS — Rise from the deep. Crush every threat",
  // What search results and link previews show. It described the 0-day tracker
  // as public, which stopped being true when the tracker was gated — a promise
  // made in the one place a visitor reads before they can check it.
  description:
    "Vulnerability Operations Center: real-world risk prioritization for CVEs (CVSS · EPSS · CISA KEV), internet-exposure intelligence on your own assets, 0-day tracking and a SOC alert workflow.",
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
      lang="en"
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
          {/* Mounts sonner's render target. Without it every `toast.*` call in
              the app is a silent no-op: eight pages — account, assets,
              dashboard, password reset, email verification — were reporting
              both success and failure into nothing. */}
          <Toaster richColors closeButton position="top-right" />
        </ThemeProvider>
        <SpeedInsights />
        <Analytics />
      </body>
    </html>
  )
}
