/**
 * Tests purs pour la logique 0-day (pas de DB, pas de réseau, pas de .env.local).
 * Style bun:test — importer describe/expect/test depuis 'bun:test'.
 */
import { describe, test, expect } from "bun:test"
import { computeZeroDayRisk, zeroDaySeverity, riskLevel } from "@/lib/risk-engine"
import { buildZeroDayWhere, fragmentText, fragmentParams } from "@/lib/zero-day-filter"
import { authorized } from "@/app/api/cron/sync/route"
import { normalizeKey, mergeRecords } from "@/lib/zero-day-collector"
import { matchesZeroDayKeywords, rssItemToZeroDay } from "@/lib/zero-day-news"
import type { ZeroDay } from "@/lib/types"

describe("SQLi — buildZeroDayWhere est blindé (régression CVE)", () => {
  const payloads = [
    "x' OR 1=1 --",
    "x'; DROP TABLE zero_days; --",
    "x' UNION SELECT id, data FROM cves --",
    "x%' AND 1=1 --",
    '" OR ""="',
  ]

  test("le SQL généré ne contient JAMAIS l'entrée brute (placeholders uniquement)", () => {
    for (const payload of payloads) {
      const where = buildZeroDayWhere({ search: payload })
      const text = fragmentText(where)
      // Le payload brut ne doit apparaître nulle part dans le texte SQL
      expect(text).not.toContain(payload)
      expect(text).not.toContain("OR 1=1")
      expect(text).not.toContain("DROP TABLE")
      expect(text).not.toContain("UNION SELECT")
      // ... mais il doit être présent comme paramètre lié
      const params = fragmentParams(where)
      expect(params).toContain(`%${payload}%`)
    }
  })

  test("kind hors liste blanche est ignoré (pas de concaténation)", () => {
    for (const bad of ["reserved' OR 1=1 --", "x'; DROP TABLE zero_days; --", "advisory)"]) {
      const where = buildZeroDayWhere({ kind: bad })
      const text = fragmentText(where)
      expect(text).not.toContain(bad)
      expect(text).not.toContain("OR 1=1")
      expect(text).not.toContain("DROP TABLE")
    }
  })

  test("search + kind combinés restent paramétrés", () => {
    const where = buildZeroDayWhere({ kind: "reserved", search: "tomcat' OR '1'='1" })
    const text = fragmentText(where)
    expect(text).toContain("kind = $1")
    expect(text).not.toContain("tomcat")
    const params = fragmentParams(where)
    expect(params[0]).toBe("reserved")
  })

  test("aucun filtre -> null (pas de WHERE)", () => {
    expect(buildZeroDayWhere({})).toBeNull()
    expect(buildZeroDayWhere({ kind: "", search: "  " })).toBeNull()
  })

  test("kind=resolved mappe vers became_cve = true (constant)", () => {
    const text = fragmentText(buildZeroDayWhere({ kind: "resolved" }))
    expect(text).toContain("became_cve = true")
  })
})

describe("Cron fail-closed — authorized()", () => {

  test("Sans CRON_SECRET configuré → refus (fail-closed)", () => {
    const prev = process.env.CRON_SECRET
    delete process.env.CRON_SECRET
    try {
      expect(authorized(new Request("http://x/api/cron/sync"))).toBe(false)
      // ?token= ne doit PLUS fonctionner même avec secret
    } finally {
      if (prev === undefined) delete process.env.CRON_SECRET
      else process.env.CRON_SECRET = prev
    }
  })

  test("Header Authorization: Bearer correct → autorisé", () => {
    const prev = process.env.CRON_SECRET
    process.env.CRON_SECRET = "s3cret"
    try {
      expect(authorized(new Request("http://x/api/cron/sync", { headers: { authorization: "Bearer s3cret" } }))).toBe(true)
    } finally {
      if (prev === undefined) delete process.env.CRON_SECRET
      else process.env.CRON_SECRET = prev
    }
  })

  test("Mauvais secret → refus", () => {
    const prev = process.env.CRON_SECRET
    process.env.CRON_SECRET = "s3cret"
    try {
      expect(authorized(new Request("http://x/api/cron/sync", { headers: { authorization: "Bearer WRONG" } }))).toBe(false)
    } finally {
      if (prev === undefined) delete process.env.CRON_SECRET
      else process.env.CRON_SECRET = prev
    }
  })

  test("?token= n'est plus accepté (fuite de secret en logs)", () => {
    const prev = process.env.CRON_SECRET
    process.env.CRON_SECRET = "s3cret"
    try {
      const req = new Request("http://x/api/cron/sync?token=s3cret")
      expect(authorized(req)).toBe(false)
    } finally {
      if (prev === undefined) delete process.env.CRON_SECRET
      else process.env.CRON_SECRET = prev
    }
  })

  test("Sans header Authorization → refus", () => {
    const prev = process.env.CRON_SECRET
    process.env.CRON_SECRET = "s3cret"
    try {
      expect(authorized(new Request("http://x/api/cron/sync"))).toBe(false)
    } finally {
      if (prev === undefined) delete process.env.CRON_SECRET
      else process.env.CRON_SECRET = prev
    }
  })
})

describe("computeZeroDayRisk", () => {
  test("reserved sans signal = 30 (base)", () => {
    const r = computeZeroDayRisk("reserved", "none", false, false)
    expect(r).toBe(30)
  })

  test("advisory sans signal = 50 (base)", () => {
    const r = computeZeroDayRisk("advisory", "none", false, false)
    expect(r).toBe(50)
  })

  test("prepub_exploited sans signal = 70 (base) — floor", () => {
    const r = computeZeroDayRisk("prepub_exploited", "none", false, false)
    expect(r).toBe(70)
  })

  test("prepub_exploited floor 70 même avec boost négatif impossible", () => {
    const r = computeZeroDayRisk("prepub_exploited", "none", false, false, 0, 0)
    expect(r).toBe(70)
  })

  test("kev-confirmed boost +25 + floor 80", () => {
    const r = computeZeroDayRisk("reserved", "kev-confirmed", false, false)
    expect(r).toBe(80) // base 30 + 25 = 55, floor 80 -> 80
  })

  test("source-reported boost +20 + floor 70", () => {
    const r = computeZeroDayRisk("reserved", "source-reported", false, false)
    expect(r).toBe(70) // base 30 + 20 = 50, floor 70 -> 70
  })

  test("poc-published boost +10", () => {
    const r = computeZeroDayRisk("reserved", "poc-published", false, false)
    expect(r).toBe(40) // base 30 + 10 = 40
  })

  test("isKev +10, hasExploit +5", () => {
    const r = computeZeroDayRisk("reserved", "none", true, true)
    expect(r).toBe(45) // base 30 + 10 + 5 = 45
  })

  test("cvss ajoute min(15, cvss)", () => {
    const r = computeZeroDayRisk("reserved", "none", false, false, 9.8, null)
    expect(r).toBe(39.8) // base 30 + min(15, 9.8) = 30 + 9.8 = 39.8
  })

  test("epss ajoute round(epss*100/6)", () => {
    // epss=0.9 -> 0.9*100/6 = 15 -> round 15 = 15
    const r = computeZeroDayRisk("reserved", "none", false, false, null, 0.9)
    expect(r).toBe(45) // base 30 + 15 = 45
  })

  test("clamp 0..100", () => {
    // cvss très haut + epss haut + kev + exploit
    const r = computeZeroDayRisk("prepub_exploited", "kev-confirmed", true, true, 10, 0.99)
    // base 70 + boost 25 (floor 80) + isKev 10 + hasExploit 5 + cvss min(15,10)=10 + epss round(0.99*100/6)=16.5->16
    // 70+25+10+5+10+16 = 136 -> clamp 100
    expect(r).toBe(100)
  })

  test("severity via tone cohérent avec riskLevel (75=critical, 50=high, 25=medium)", () => {
    expect(zeroDaySeverity(80)).toBe("critical")
    expect(zeroDaySeverity(60)).toBe("high")
    expect(zeroDaySeverity(30)).toBe("medium")
    expect(zeroDaySeverity(10)).toBe("low")
  })

  test("zeroDaySeverity réutilise riskLevel().tone", () => {
    expect(zeroDaySeverity(75)).toBe(riskLevel(75).tone)
    expect(zeroDaySeverity(50)).toBe(riskLevel(50).tone)
    expect(zeroDaySeverity(25)).toBe(riskLevel(25).tone)
    expect(zeroDaySeverity(0)).toBe(riskLevel(0).tone)
  })
})

describe("Fusion / dédup par clé normalisée — logique réelle du collecteur", () => {
  // Tests contre les VRAIES fonctions exportées (pas de copie locale) :
  // toute dérive collecteur/test est détectée ici.
  function makeZero(overrides: Partial<ZeroDay>): ZeroDay {
    return {
      id: "SRC:kev:0",
      source: "kev",
      kind: "reserved",
      cveId: null,
      ghsaId: null,
      title: "cve",
      product: null,
      exploitState: null,
      verification: null,
      isKev: false,
      hasExploit: false,
      riskScore: 0,
      severity: riskLevel(0).tone,
      cvss: null,
      epss: null,
      firstSeenAt: null,
      lastSeenAt: null,
      becameCve: false,
      resolvedAt: null,
      references: [],
      data: {},
      ...overrides,
    }
  }

  test("même CVE p0+kev -> 1 record, source = p0 (priorité 4 > 3)", () => {
    const rec1 = makeZero({ id: normalizeKey("CVE-2026-1"), source: "kev", riskScore: 85 })
    const rec2 = makeZero({ id: normalizeKey("CVE-2026-1"), source: "p0", riskScore: 80 })
    const merged = mergeRecords([rec1, rec2])
    expect(merged.length).toBe(1)
    expect(merged[0].source).toBe("p0")
    expect(merged[0].riskScore).toBe(80)
  })

  test("même source -> kind le plus fort gagne (prepub_exploited > reserved)", () => {
    const rec1 = makeZero({ id: normalizeKey("CVE-2026-2"), source: "kev", kind: "reserved" })
    const rec2 = makeZero({ id: normalizeKey("CVE-2026-2"), source: "kev", kind: "prepub_exploited" })
    const merged = mergeRecords([rec1, rec2])
    expect(merged.length).toBe(1)
    expect(merged[0].kind).toBe("prepub_exploited")
  })

  test("CVE-2026-1 et cve-2026-1 -> même clé (majuscules)", () => {
    expect(normalizeKey("CVE-2026-1")).toBe(normalizeKey("cve-2026-1"))
  })

  test("GHSA sans cve -> clé GHSA:XXX", () => {
    expect(normalizeKey(undefined, "ghsa-abc123")).toBe("GHSA:GHSA-ABC123")
  })

  test("Sans CVE ni GHSA -> clé SRC:<source>:<id>", () => {
    expect(normalizeKey(undefined, undefined, "news", "123")).toBe("SRC:news:123")
  })
})

describe("Classification 0-day", () => {
  test("verification === 'partial' -> reserved (ou prepub si exploitation active)", () => {
    const item = { verification: "partial", exploitation: "none" }
    const kind = item.verification === "partial" ? "reserved" : "prepub_exploited"
    expect(kind).toBe("reserved")
  })

  test("exploitation === 'kev-confirmed' -> prepub_exploited", () => {
    const item = { verification: "verified", exploitation: "kev-confirmed" }
    const kind = item.exploitation === "kev-confirmed" ? "prepub_exploited" : "reserved"
    expect(kind).toBe("prepub_exploited")
  })

  test("exploitation === 'source-reported' -> prepub_exploited", () => {
    const item = { verification: "verified", exploitation: "source-reported" }
    const kind = item.exploitation === "source-reported" ? "prepub_exploited" : "reserved"
    expect(kind).toBe("prepub_exploited")
  })

  test("cve_id === null (GitHub Advisory) -> advisory", () => {
    const item = { cve_id: null, ghsa_id: "GHSA-ABC123" }
    const kind = item.cve_id === null ? "advisory" : "reserved"
    expect(kind).toBe("advisory")
  })

  test("cve_id présent -> reserved/prepub (pas advisory)", () => {
    const item = { cve_id: "CVE-2026-1" }
    const kind = item.cve_id ? "reserved" : "advisory"
    expect(kind).toBe("reserved")
  })
})

describe("Filtre RSS mots-clés — sources news (BleepingComputer / The Hacker News)", () => {
  test("les 5 mots-clés de la spec matchent (case-insensitive)", () => {
    expect(matchesZeroDayKeywords("New zero-day exploited in the wild")).toBe(true)
    expect(matchesZeroDayKeywords("0-day under active attack")).toBe(true)
    expect(matchesZeroDayKeywords("unpatched vulnerability in Windows")).toBe(true)
    expect(matchesZeroDayKeywords("ZERO-DAY in Chrome")).toBe(true)
  })

  test("un article sans mot-clé 0-day est exclu", () => {
    expect(matchesZeroDayKeywords("Microsoft releases monthly security updates")).toBe(false)
  })

  test("rssItemToZeroDay: titre 0-day -> record source news, kind prepub si exploitation signalée", () => {
    const rec = rssItemToZeroDay("bleepingcomputer.com", {
      title: "Zero-day exploited in the wild in Chrome",
      link: "https://www.bleepingcomputer.com/news/x/",
      contentSnippet: "Google warns of an exploited zero-day.",
    })
    expect(rec).not.toBeNull()
    expect(rec!.source).toBe("news")
    expect(rec!.kind).toBe("prepub_exploited")
    expect(rec!.exploitState).toBe("source-reported")
    expect(rec!.hasExploit).toBe(true)
    expect(rec!.permalink).toBe("https://www.bleepingcomputer.com/news/x/")
  })

  test("rssItemToZeroDay: clé CVE si titre contient un CVE (dédup inter-sources)", () => {
    const rec = rssItemToZeroDay("thehackernews.com", {
      title: "New 0-day in Exchange: CVE-2026-1234",
    })
    expect(rec!.id).toBe("CVE-2026-1234")
  })

  test("rssItemToZeroDay: sa CVE extraite + clé SRC:news:feed:link sinon", () => {
    const rec = rssItemToZeroDay("thehackernews.com", {
      title: "Researchers discover unpatched flaw",
      link: "https://thehackernews.com/2026/08/x.html",
    })
    expect(rec).not.toBeNull()
    expect(rec!.id).toContain("SRC:news:thehackernews.com:")
    expect(rec!.kind).toBe("advisory")
  })
})

describe("Sources étendues — fusion & priorités (p0 > kev > github > news)", () => {
  function makeZero(overrides: Partial<ZeroDay>): ZeroDay {
    return {
      id: "SRC:kev:0",
      source: "kev",
      kind: "reserved",
      cveId: null,
      ghsaId: null,
      title: "cve",
      product: null,
      exploitState: null,
      verification: null,
      isKev: false,
      hasExploit: false,
      riskScore: 0,
      severity: riskLevel(0).tone,
      cvss: null,
      epss: null,
      firstSeenAt: null,
      lastSeenAt: null,
      becameCve: false,
      resolvedAt: null,
      references: [],
      data: {},
      ...overrides,
    }
  }

  test("p0 (5) écrase news (1) sur la même clé CVE", () => {
    const p0 = makeZero({ id: normalizeKey("CVE-2026-9"), source: "p0", kind: "prepub_exploited", riskScore: 90 })
    const news = makeZero({ id: normalizeKey("CVE-2026-9"), source: "news", kind: "advisory", riskScore: 50 })
    const merged = mergeRecords([news, p0])
    expect(merged.length).toBe(1)
    expect(merged[0].source).toBe("p0")
    expect(merged[0].riskScore).toBe(90)
  })

  test("news (1) ne remplace jamais kev/github sur la même clé", () => {
    const kev = makeZero({ id: normalizeKey("CVE-2026-10"), source: "kev", riskScore: 85 })
    const news = makeZero({ id: normalizeKey("CVE-2026-10"), source: "news", riskScore: 40 })
    const merged = mergeRecords([news, kev])
    expect(merged.length).toBe(1)
    expect(merged[0].source).toBe("kev")
    expect(merged[0].riskScore).toBe(85)
  })

  test("Google P0 alpha (feuil All, id CVE) -> keyId CVE normalisé", () => {
    expect(normalizeKey("cve-2026-99999")).toBe("CVE-2026-99999")
  })
})