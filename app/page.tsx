"use client"

import Link from "next/link"
import Image from "next/image"
import { useEffect, useRef, useState } from "react"
import * as THREE from "three"
import { Card } from "@/components/ui/card"

/* ------------------------------------------------------------------ 3D bg */
function useThreeBackground(canvasRef: React.RefObject<HTMLCanvasElement | null>) {
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return

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

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener("mousemove", onMove)
      window.removeEventListener("resize", resize)
      renderer.dispose()
    }
  }, [canvasRef])
}

/* ------------------------------------------------------------------ data */
const MODULES = [
  { href: "/dashboard", icon: "🐛", title: "CVE Dashboard", desc: "Priorisation RBVM, triage, SLA, filtres avancés et alertes." },
  { href: "/dashboard", icon: "🕸️", title: "Threat Intelligence", desc: "Graphe de menace, CAPEC / MITRE ATT&CK, exploit intelligence." },
  { href: "/statistics", icon: "📊", title: "Statistiques", desc: "Tendances CVE, CVSS & EPSS, Top éditeurs / produits / CWE." },
]
const STEPS = [
  { n: "1", t: "Gravité (CVSS)", d: "La sévérité technique de la faille, sur 0–10." },
  { n: "2", t: "Probabilité (EPSS)", d: "La probabilité qu'elle soit exploitée sous 30 jours." },
  { n: "3", t: "Réalité (CISA KEV)", d: "Est-elle déjà exploitée dans la nature ?" },
]
const SOURCES = ["NVD", "Vulners", "EPSS · FIRST", "CISA KEV", "IA (OpenRouter)"]
const STATS = [
  { target: 280, suffix: "k+", cap: "CVE analysées (NVD)" },
  { target: 1631, suffix: "", cap: "failles KEV suivies" },
  { target: 3, suffix: "", cap: "signaux fusionnés (RBVM)" },
  { target: 5, suffix: "", cap: "sources temps réel" },
]
const FEATURES = [
  { icon: "⚖️", t: "Risk Score expliqué", d: "Contributions CVSS / EPSS / KEV détaillées + explication humaine." },
  { icon: "🤖", t: "Agent IA", d: "Analyse en clair : exploitation, impact, remédiation, scénario d'attaque." },
  { icon: "🕸️", t: "Graphe de menace", d: "CVE → CWE → CAPEC → ATT&CK → exploit → advisory, cliquable." },
  { icon: "🎯", t: "Triage & SLA", d: "Statut par CVE, échéances de remédiation, threat feed SOC." },
  { icon: "🔎", t: "Filtres avancés", d: "KEV, exploit, critiques, vecteur, CWE, Risk Score min." },
  { icon: "📤", t: "Export & alertes", d: "Export CSV/JSON et notifications Telegram enrichies." },
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
  return <>{n.toLocaleString("fr-FR")}{suffix}</>
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
          Un <strong>Vulnerability Operations Center</strong> qui transforme le chaos des CVE en décisions : priorisation par le <strong>risque réel</strong> (CVSS · EPSS · CISA KEV), threat intelligence et agent IA.
        </p>

        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link href="/dashboard" className="rounded-full bg-gradient-to-r from-violet-600 to-pink-500 px-7 py-3 font-semibold text-white shadow-lg shadow-violet-600/40 transition hover:-translate-y-0.5">
            Ouvrir le CVE Dashboard
          </Link>
          <Link href="/statistics" className="rounded-full border border-border bg-white/5 px-7 py-3 font-semibold transition hover:-translate-y-0.5 hover:bg-white/10">
            Voir les statistiques
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
        <h2 className="mb-8 text-3xl font-bold tracking-tight">Trois portes d&apos;entrée, un seul cerveau</h2>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {MODULES.map((m) => (
            <Link key={m.title} href={m.href}>
              <Card className="group h-full p-6 transition hover:-translate-y-2 hover:border-primary/50">
                <div className="mb-4 grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-violet-500 to-pink-500 text-2xl shadow-lg shadow-violet-600/30">{m.icon}</div>
                <h3 className="mb-2 text-xl font-semibold">{m.title}</h3>
                <p className="text-sm text-muted-foreground">{m.desc}</p>
                <span className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-cyan-400">Explorer →</span>
              </Card>
            </Link>
          ))}
        </div>
      </section>

      {/* RBVM */}
      <section className="mx-auto max-w-6xl px-4 py-16">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">Le moteur</p>
        <h2 className="mb-8 text-3xl font-bold tracking-tight">Priorisation par le risque réel (RBVM)</h2>
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
          Une CVE 9.8 jamais exploitée <strong>descend</strong>, une 7.5 activement exploitée <strong>remonte</strong>. Tu traites ce qui compte vraiment.
        </p>
      </section>

      {/* CAPACITÉS */}
      <section className="mx-auto max-w-6xl px-4 py-16">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-muted-foreground">Capacités</p>
        <h2 className="mb-8 text-3xl font-bold tracking-tight">De l&apos;analyste junior au VOC</h2>
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
        © 2025 Tbini Mustapha Amin · Licence MIT
      </footer>
    </div>
  )
}
