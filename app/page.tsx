"use client"

import Link from "next/link"
import Image from "next/image"
import { useEffect, useRef, useState } from "react"
import { Card } from "@/components/ui/card"

/* ------------------------------------------------------------------ 3D bg */
function useThreeBackground(canvasRef: React.RefObject<HTMLCanvasElement | null>) {
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return

    let cleanup: (() => void) | undefined
    let cancelled = false
    // Three.js chargé dynamiquement -> hors du bundle initial de l'accueil (perf)
    import("three").then((THREE) => {
      if (cancelled || !canvasRef.current) return
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(72, innerWidth / innerHeight, 0.1, 200)
    camera.position.z = 34
    const group = new THREE.Group()
    scene.add(group)

    const N = 900
    const pos = new Float32Array(N * 3)
    for (let i = 0; i < N; i++) {
      const r = 16 + Math.random() * 12
      const t = Math.random() * Math.PI * 2
      const p = Math.acos(2 * Math.random() - 1)
      pos[i * 3] = r * Math.sin(p) * Math.cos(t)
      pos[i * 3 + 1] = r * Math.sin(p) * Math.sin(t)
      pos[i * 3 + 2] = r * Math.cos(p)
    }
    const pg = new THREE.BufferGeometry()
    pg.setAttribute("position", new THREE.BufferAttribute(pos, 3))
    group.add(new THREE.Points(pg, new THREE.PointsMaterial({ color: 0x8b5cf6, size: 0.18, transparent: true, opacity: 0.85 })))

    const ico1 = new THREE.Mesh(new THREE.IcosahedronGeometry(11, 1), new THREE.MeshBasicMaterial({ color: 0x22d3ee, wireframe: true, transparent: true, opacity: 0.22 }))
    const ico2 = new THREE.Mesh(new THREE.IcosahedronGeometry(7, 0), new THREE.MeshBasicMaterial({ color: 0xfb7185, wireframe: true, transparent: true, opacity: 0.18 }))
    group.add(ico1, ico2)

    let mx = 0, my = 0
    const onMove = (e: MouseEvent) => { mx = e.clientX / innerWidth - 0.5; my = e.clientY / innerHeight - 0.5 }
    window.addEventListener("mousemove", onMove)
    const resize = () => { camera.aspect = innerWidth / innerHeight; camera.updateProjectionMatrix(); renderer.setSize(innerWidth, innerHeight) }
    window.addEventListener("resize", resize)
    resize()

    let raf = 0
    const animate = () => {
      raf = requestAnimationFrame(animate)
      group.rotation.y += 0.0016
      group.rotation.x += 0.0007
      ico1.rotation.z -= 0.0012
      ico2.rotation.x += 0.002
      camera.position.x += (mx * 8 - camera.position.x) * 0.04
      camera.position.y += (-my * 8 - camera.position.y) * 0.04
      camera.lookAt(scene.position)
      renderer.render(scene, camera)
    }
    animate()

      cleanup = () => {
        cancelAnimationFrame(raf)
        window.removeEventListener("mousemove", onMove)
        window.removeEventListener("resize", resize)
        renderer.dispose()
      }
    })
    return () => { cancelled = true; cleanup?.() }
  }, [canvasRef])
}

/* ------------------------------------------------------------------ data */
/**
 * The product's entry points.
 *
 * `/exposure` was missing entirely — the largest feature in the platform was
 * unreachable from the landing page. The 0-day card also promised "public, no
 * account needed", which stopped being true when the tracker was gated; a
 * landing page that advertises access the product refuses is the worst place
 * for a stale claim.
 */
const MODULES = [
  { href: "/exposure", icon: "🛰️", title: "Exposure Intelligence", desc: "What of yours is reachable from the internet, which CVEs it correlates to, and how strong the evidence is — from passive provider data, never a scan." },
  { href: "/dashboard", icon: "🐛", title: "CVE Dashboard", desc: "RBVM prioritization, triage, SLA, advanced filters and alerts." },
  { href: "/zero-days", icon: "☠️", title: "0-Day Tracker", desc: "Pre-CVE and zero-day intelligence, merged from 4 independent sources." },
  { href: "/assets", icon: "⭐", title: "My Assets", desc: "Declare your stack — or accept what the providers already detected on your hosts — and see only the CVEs that reach you." },
  { href: "/statistics", icon: "📊", title: "Statistics", desc: "CVE trends, CVSS & EPSS distributions, top vendors / products / CWE." },
]
const STEPS = [
  { n: "1", t: "Severity (CVSS)", d: "The technical severity of the flaw, on a 0–10 scale." },
  { n: "2", t: "Probability (EPSS)", d: "The likelihood it gets exploited within 30 days." },
  { n: "3", t: "Reality (CISA KEV)", d: "Is it already being exploited in the wild?" },
]
/**
 * Only what is actually wired up. "Vulners" was listed here and appears nowhere
 * in the codebase — naming a feed that contributes nothing is the same class of
 * claim as an inflated record count.
 */
const SOURCES = [
  "NVD", "EPSS · FIRST", "CISA KEV", "GitHub Advisories", "Google Project Zero",
  "Shodan", "Netlas", "Censys", "GreyNoise", "AbuseIPDB",
]
/**
 * Deliberate FLOORS, not point-in-time readings.
 *
 * These claimed 280k CVEs and 1,631 KEV entries against a database holding
 * 88,514 and 378 — numbers that were either aspirational or true of some other
 * deployment. A hardcoded exact figure on a marketing page is guaranteed to
 * drift into a lie, so each is rounded DOWN to a bound that stays true as the
 * corpus grows, and both quantities only ever grow.
 */
const STATS = [
  { target: 88, suffix: "k+", cap: "CVEs analyzed (NVD)" },
  { target: 370, suffix: "+", cap: "KEV flaws tracked" },
  { target: 10, suffix: "", cap: "intelligence sources" },
  { target: 5, suffix: "min", cap: "sync cadence" },
]
const FEATURES = [
  { icon: "⚖️", t: "Explained risk score", d: "Detailed CVSS / EPSS / KEV contributions, in plain language." },
  { icon: "🔬", t: "Evidence you can audit", d: "Every finding is tiered — confirmed, version-level, product-level — and only the strong tiers can raise an alert." },
  { icon: "🎯", t: "SOC alert workflow", d: "Acknowledge, assign, resolve or suppress with a reason. Batch-triage forty at once; every decision is in one timeline." },
  { icon: "🔑", t: "Your keys, your quota", d: "Bring your own exposure-provider accounts. Keys are encrypted at rest and never shown again after you save them." },
  { icon: "🕸️", t: "Threat graph", d: "CVE → CWE → CAPEC → ATT&CK → exploit → advisory, clickable." },
  { icon: "📤", t: "Export & alerts", d: "CSV export of the queue you filtered, and enriched Telegram notifications." },
]

function Counter({ target, suffix }: { target: number; suffix: string }) {
  const [n, setN] = useState(0)
  useEffect(() => {
    const dur = 1400, t0 = performance.now()
    let raf = 0
    const tick = (now: number) => {
      const k = Math.min((now - t0) / dur, 1)
      setN(Math.floor((1 - Math.pow(1 - k, 3)) * target))
      if (k < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target])
  return <>{n.toLocaleString("en-US")}{suffix}</>
}

export default function Home() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  useThreeBackground(canvasRef)

  return (
    <div className="relative overflow-hidden">
      <canvas ref={canvasRef} className="pointer-events-none fixed inset-0 -z-[1]" />

      {/* HERO */}
      <header className="mx-auto flex min-h-[86vh] max-w-4xl flex-col items-center justify-center px-4 text-center">
        <span className="mb-6 inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.28em] text-cyan-400">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400 shadow-[0_0_12px] shadow-cyan-400" />
          Threat Intelligence · RBVM · VOC
        </span>

        <Image src="/logo.png" alt="OCTUPUS" width={140} height={140} className="mb-4 animate-[octo-float_3.4s_ease-in-out_infinite] drop-shadow-[0_14px_46px_rgba(139,92,246,0.6)]" priority />

        <h1 className="bg-gradient-to-r from-white via-violet-300 to-cyan-400 bg-clip-text text-6xl font-bold tracking-tight text-transparent sm:text-8xl">
          OCTUPUS
        </h1>
        <p className="mt-2 text-xl italic text-foreground/80 sm:text-2xl">« Rise from the deep. Crush every threat. »</p>
        <p className="mx-auto mt-5 max-w-xl text-muted-foreground">
          A <strong>Vulnerability Operations Center</strong> that turns CVE chaos into decisions: prioritization by{" "}
          <strong>real-world risk</strong> (CVSS · EPSS · CISA KEV), internet-exposure intelligence on your own assets,
          a 0-day tracker and a SOC alert workflow.
        </p>

        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link href="/signup" className="rounded-full bg-gradient-to-r from-violet-600 to-pink-500 px-7 py-3 font-semibold text-white shadow-lg shadow-violet-600/40 transition hover:-translate-y-0.5">
            Create a free account
          </Link>
          <Link href="/login" className="rounded-full border border-border bg-white/5 px-7 py-3 font-semibold transition hover:-translate-y-0.5 hover:bg-white/10">
            Sign in
          </Link>
        </div>

        <div className="mt-8 flex flex-wrap items-center justify-center gap-2">
          <span className="text-xs uppercase tracking-widest text-muted-foreground">Sources</span>
          {SOURCES.map((s) => (
            <span key={s} className="rounded-full border border-border bg-white/5 px-3 py-1 text-xs">{s}</span>
          ))}
        </div>
      </header>

      {/* STATS */}
      <section className="mx-auto grid max-w-6xl grid-cols-2 gap-4 px-4 py-4 sm:grid-cols-4">
        {STATS.map((s) => (
          <div key={s.cap} className="glass rounded-2xl p-6 text-center">
            <div className="text-4xl font-bold neon-text sm:text-5xl"><Counter target={s.target} suffix={s.suffix} /></div>
            <div className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">{s.cap}</div>
          </div>
        ))}
      </section>

      {/* MODULES */}
      <section className="mx-auto max-w-6xl px-4 py-16">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">Modules</p>
        <h2 className="mb-8 text-3xl font-bold tracking-tight">{MODULES.length} doors in, one brain</h2>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {MODULES.map((m) => (
            <Link key={m.title} href={m.href}>
              <Card className="group h-full p-6 transition hover:-translate-y-2 hover:border-primary/50">
                <div className="mb-4 grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-violet-500 to-pink-500 text-2xl shadow-lg shadow-violet-600/30">{m.icon}</div>
                <h3 className="mb-2 text-xl font-semibold">{m.title}</h3>
                <p className="text-sm text-muted-foreground">{m.desc}</p>
                <span className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-cyan-400">Explore →</span>
              </Card>
            </Link>
          ))}
        </div>
      </section>

      {/* RBVM */}
      <section className="mx-auto max-w-6xl px-4 py-16">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">The engine</p>
        <h2 className="mb-8 text-3xl font-bold tracking-tight">Prioritization by real-world risk (RBVM)</h2>
        <div className="grid gap-4 sm:grid-cols-3">
          {STEPS.map((s) => (
            <Card key={s.n} className="p-6">
              <div className="text-4xl font-bold text-primary/40">{s.n}</div>
              <h4 className="mb-1 mt-2 font-semibold">{s.t}</h4>
              <p className="text-sm text-muted-foreground">{s.d}</p>
            </Card>
          ))}
        </div>
        <p className="mt-8 text-center text-lg">
          <code className="rounded-xl border border-border bg-primary/10 px-4 py-2 text-cyan-400">Risk = CVSS×0.4 + EPSS×0.4 + KEV×0.2</code>
        </p>
        <p className="mx-auto mt-6 max-w-xl text-center text-muted-foreground">
          A 9.8 CVE never exploited <strong>drops</strong>, a 7.5 actively exploited in the wild <strong>rises</strong>. You work on what actually matters.
        </p>
      </section>

      {/* CAPABILITIES */}
      <section className="mx-auto max-w-6xl px-4 py-16">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">Capabilities</p>
        <h2 className="mb-8 text-3xl font-bold tracking-tight">From junior analyst to full VOC</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <Card key={f.t} className="glass glow-hover accent-top p-5">
              <div className="mb-2 text-2xl">{f.icon}</div>
              <h3 className="mb-1 font-semibold">{f.t}</h3>
              <p className="text-sm text-muted-foreground">{f.d}</p>
            </Card>
          ))}
        </div>
      </section>

      <footer className="border-t border-border py-10 text-center text-sm text-muted-foreground">
        <div className="mb-1 font-semibold text-foreground">🐙 OCTUPUS</div>
        © 2026 Tbini Mustapha Amin · The 0-day and CVE feeds are free to read (see{" "}
        <Link href="/terms" className="underline decoration-dotted hover:text-foreground">Terms</Link>) · code is proprietary
      </footer>
    </div>
  )
}
