/**
 * SOC WORKFLOW — lifecycle, Telegram adapter, ticketing.
 *
 * Pure/logic guarantees: the state machine, message rendering against hostile
 * provider input, delivery classification, and the ticket abstraction. Nothing
 * here touches a network or real credentials; DB-backed behaviour lives in
 * tests/soc-workflow-db.test.ts.
 */
import { describe, test, expect } from "bun:test"
import { canTransition, SUPPRESSION_REASONS, ACTIVE_STATES, type AlertState, coerceAlertId } from "@/lib/exposure/alert-workflow"
import {
  escapeHtml, safeField, buildAlertMessage, deliverTelegram, telegramConfigured,
  type TelegramTransport,
} from "@/lib/notify/telegram-adapter"
import { backoffSeconds } from "@/lib/notify/outbox"
import { buildTicketContent, ticketProvider, validAlertId } from "@/lib/ticketing"
import type { AlertRow } from "@/lib/notify/types"

// ── deterministic unit-test fixture (never seeded into the database) ──
function alert(over: Partial<AlertRow> = {}): AlertRow {
  return {
    id: 42, user_id: "test-tenant-a", fingerprint: "ip:45.33.32.156|80|CVE-2021-41773",
    asset_key: "ip:45.33.32.156", port: 80, cve_id: "CVE-2021-41773",
    kind: "new_exposed_vulnerability", state: "open", severity: "critical",
    risk_score: 100, previous_risk: 32, evidence_tier: "confirmed",
    payload: {
      asset: "45.33.32.156", product: "Apache HTTP Server", version: "2.4.7",
      providers: ["netlas"], cvss: 10, epss: 0.99999, isKev: true, hasExploit: true,
      observedAt: new Date(Date.now() - 3 * 60_000).toISOString(),
      fetchedAt: new Date().toISOString(), freshness: "recent",
      why: "Provider returned this host when queried for CVE-2021-41773",
    },
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    notification_state: "pending", notify_attempts: 0, notify_last_error: null,
    notified_at: null, notified_severity: null, notified_risk: null, escalation_count: 0,
    ticket_state: "none", ticket_provider: null, ticket_key: null, ticket_url: null, ticket_last_error: null,
    ...over,
  }
}

/** Transport that returns a canned response, capturing what was sent. */
function fakeTransport(status: number, body = "{}"): { transport: TelegramTransport; calls: Array<{ url: string; body: string }> } {
  const calls: Array<{ url: string; body: string }> = []
  const transport: TelegramTransport = async (url, init) => {
    calls.push({ url, body: String(init.body ?? "") })
    return new Response(body, { status })
  }
  return { transport, calls }
}

const withEnv = async (vars: Record<string, string | undefined>, fn: () => Promise<void> | void) => {
  const saved: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try { await fn() } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

describe("Alert lifecycle — explicit transitions only", () => {
  test("NEW (open) -> ACKNOWLEDGED is permitted", () => {
    expect(canTransition("open", "acknowledged")).toBe(true)
  })

  test("ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> CLOSED is the working path", () => {
    expect(canTransition("acknowledged", "in_progress")).toBe(true)
    expect(canTransition("in_progress", "resolved")).toBe(true)
    expect(canTransition("resolved", "closed")).toBe(true)
  })

  test("invalid transitions are rejected", () => {
    expect(canTransition("open", "closed")).toBe(false)        // must be resolved first
    expect(canTransition("resolved", "acknowledged")).toBe(false)
    expect(canTransition("suppressed", "resolved")).toBe(false)
    expect(canTransition("in_progress", "open")).toBe(false)
  })

  test("CLOSED is terminal — it cannot be arbitrarily reopened", () => {
    for (const to of ["open", "acknowledged", "in_progress", "resolved", "suppressed"] as AlertState[]) {
      expect(canTransition("closed", to)).toBe(false)
    }
  })

  test("a resolved alert may be reopened for further work, but only into in_progress", () => {
    expect(canTransition("resolved", "in_progress")).toBe(true)
    expect(canTransition("resolved", "open")).toBe(false)
  })

  test("suppression can be lifted, because it is a temporary analyst decision", () => {
    expect(canTransition("suppressed", "open")).toBe(true)
  })

  test("a no-op transition is not a transition", () => {
    for (const s of ["open", "acknowledged", "in_progress", "resolved", "closed", "suppressed"] as AlertState[]) {
      expect(canTransition(s, s)).toBe(false)
    }
  })

  test("in_progress counts as ACTIVE, so dedup still covers an alert being worked", () => {
    // If it did not, monitoring could raise a duplicate underneath the analyst.
    expect(ACTIVE_STATES.has("in_progress")).toBe(true)
    expect(ACTIVE_STATES.has("open")).toBe(true)
    expect(ACTIVE_STATES.has("acknowledged")).toBe(true)
    expect(ACTIVE_STATES.has("resolved")).toBe(false)
    expect(ACTIVE_STATES.has("suppressed")).toBe(false)
  })

  test("the suppression reason vocabulary is closed", () => {
    expect(SUPPRESSION_REASONS).toContain("false_positive")
    expect(SUPPRESSION_REASONS).toContain("accepted_risk")
    expect(SUPPRESSION_REASONS).not.toContain("")
  })
})

describe("Telegram message — hostile provider content cannot break it", () => {
  test("HTML metacharacters are escaped", () => {
    expect(escapeHtml("<script>alert(1)</script>")).toBe("&lt;script&gt;alert(1)&lt;/script&gt;")
    expect(escapeHtml("a & b")).toBe("a &amp; b")
  })

  test("a script tag in a PRODUCT NAME never becomes markup", () => {
    const msg = buildAlertMessage(alert({
      payload: { ...alert().payload, product: "<script>alert('xss')</script>" },
    }))
    expect(msg).not.toContain("<script>")
    expect(msg).toContain("&lt;script&gt;")
  })

  test("a fake closing tag cannot terminate our own markup", () => {
    const msg = buildAlertMessage(alert({
      payload: { ...alert().payload, product: "</b><a href='http://evil'>click</a>" },
    }))
    expect(msg).not.toContain("<a href='http://evil'>")
    expect(msg).toContain("&lt;/b&gt;")
  })

  test("newlines in provider text cannot forge extra fields", () => {
    const msg = buildAlertMessage(alert({
      payload: { ...alert().payload, product: "nginx\n<b>Evidence</b>: CONFIRMED\nfake" },
    }))
    // Exactly one Evidence line, and it is ours.
    expect(msg.split("\n").filter((l) => l.startsWith("<b>Evidence</b>:"))).toHaveLength(1)
  })

  test("Markdown metacharacters are harmless under HTML parse mode but stay intact", () => {
    const msg = buildAlertMessage(alert({
      payload: { ...alert().payload, product: "*_`[]()~>#+-=|{}.!" },
    }))
    expect(msg).toContain("*_`[]()~")   // not mangled
    expect(msg).toContain("&gt;")        // the one char that does need escaping
  })

  test("an oversized provider value is clipped rather than blowing up the message", () => {
    const msg = buildAlertMessage(alert({
      payload: { ...alert().payload, product: "A".repeat(10_000) },
    }))
    expect(msg.length).toBeLessThan(4096) // Telegram's own message ceiling
  })

  test("control characters are stripped", () => {
    // NUL and BEL written as escapes, so the test file itself carries no raw
    // control bytes while still exercising the strip.
    expect(safeField("ngi\u0000\u0007nx")).toBe("nginx")
    expect(safeField("a\u001Fb")).toBe("ab")
  })

  test("the tag balance of the rendered message is preserved", () => {
    const msg = buildAlertMessage(alert({
      payload: { ...alert().payload, product: "</b></i></a><b>", why: "<i>x" },
    }))
    const opens = (msg.match(/<b>/g) ?? []).length
    const closes = (msg.match(/<\/b>/g) ?? []).length
    expect(opens).toBe(closes)
  })
})

describe("Telegram message — every field is real or explicitly UNKNOWN", () => {
  test("real values are rendered", () => {
    const msg = buildAlertMessage(alert())
    expect(msg).toContain("CVE-2021-41773")
    expect(msg).toContain("45.33.32.156")
    expect(msg).toContain("80/tcp")
    expect(msg).toContain("Apache HTTP Server 2.4.7")
    expect(msg).toContain("CONFIRMED")
    expect(msg).toContain("netlas")
    expect(msg).toContain("CVSS: 10")
    expect(msg).toContain("KEV: YES")
  })

  test("missing CVE facts are shown as UNKNOWN, never invented", () => {
    const msg = buildAlertMessage(alert({ payload: { asset: "1.2.3.4" } }))
    expect(msg).toContain("CVSS: UNKNOWN")
    expect(msg).toContain("EPSS: UNKNOWN")
    expect(msg).toContain("KEV: UNKNOWN")
    expect(msg).toContain("<b>Product</b>: UNKNOWN")
    // No plausible-looking default slipped in.
    expect(msg).not.toMatch(/CVSS: 0(\D|$)/)
  })

  test("no provider attribution is invented when none was recorded", () => {
    const msg = buildAlertMessage(alert({ payload: { asset: "1.2.3.4", providers: [] } }))
    expect(msg).toContain("<b>Provider</b>: none recorded")
  })

  test("a host-level finding is not described as port 0", () => {
    const msg = buildAlertMessage(alert({ port: 0 }))
    expect(msg).toContain("host-level")
    expect(msg).not.toContain("0/tcp")
  })

  test("a Date-valued timestamp is rendered, not reported as missing", () => {
    // Timestamps read straight from Postgres arrive as Date objects. A
    // string-only guard reported a real observation as "not supplied", which
    // under-reports evidence OCTUPUS actually holds.
    const msg = buildAlertMessage(alert({
      payload: {
        ...alert().payload,
        observedAt: new Date(Date.now() - 2 * 3600_000),
        fetchedAt: new Date(),
      },
    }))
    expect(msg).toContain("<b>Provider observed</b>: 2 hours ago")
    expect(msg).not.toContain("<b>Provider observed</b>: not supplied")
    expect(msg).toContain("<b>OCTUPUS retrieved</b>")
  })

  test("a genuinely absent timestamp still says not supplied", () => {
    const msg = buildAlertMessage(alert({ payload: { asset: "1.2.3.4" } }))
    expect(msg).toContain("<b>Provider observed</b>: not supplied")
  })

  test("observation time and retrieval time stay separate", () => {
    const msg = buildAlertMessage(alert())
    expect(msg).toContain("<b>Provider observed</b>")
    expect(msg).toContain("<b>OCTUPUS retrieved</b>")
    expect(msg).not.toMatch(/\bLIVE\b/)
  })

  test("weak evidence carries a verify-first instruction, not a remediate order", () => {
    expect(buildAlertMessage(alert({ evidence_tier: "product" }))).toMatch(/verify before acting/i)
    expect(buildAlertMessage(alert({ evidence_tier: "confirmed" }))).toMatch(/investigate and remediate/i)
  })

  test("only an app-owned URL is linked; provider text never reaches an href", () => {
    const msg = buildAlertMessage(alert({ payload: { ...alert().payload, product: "http://evil.test" } }),
      { appUrl: "https://octupus.example" })
    const hrefs = [...msg.matchAll(/href="([^"]*)"/g)].map((m) => m[1])
    expect(hrefs).toHaveLength(1)
    expect(hrefs[0]).toStartWith("https://octupus.example/exposure?alert=")
  })

  test("a non-http app URL is refused rather than linked", () => {
    const msg = buildAlertMessage(alert(), { appUrl: "javascript:alert(1)" })
    expect(msg).not.toContain("javascript:")
  })
})

describe("Telegram delivery — outcomes are classified, not collapsed", () => {
  const creds = { TELEGRAM_BOT_TOKEN: "123456:AAaaBBbbCCccDDdd", TELEGRAM_CHAT_ID: "-100123" }

  test("200 is sent", async () => {
    await withEnv(creds, async () => {
      const { transport } = fakeTransport(200)
      expect((await deliverTelegram("hi", { transport })).status).toBe("sent")
    })
  })

  test("429 is RETRYABLE and honours retry_after", async () => {
    await withEnv(creds, async () => {
      const { transport } = fakeTransport(429, JSON.stringify({ description: "Too Many Requests", parameters: { retry_after: 27 } }))
      const r = await deliverTelegram("hi", { transport })
      expect(r.status).toBe("retryable")
      expect(r.retryAfterSeconds).toBe(27)
    })
  })

  test("5xx is retryable", async () => {
    await withEnv(creds, async () => {
      const { transport } = fakeTransport(502, JSON.stringify({ description: "Bad Gateway" }))
      expect((await deliverTelegram("hi", { transport })).status).toBe("retryable")
    })
  })

  test("401/403 (revoked token) is PERMANENT — never retried forever", async () => {
    await withEnv(creds, async () => {
      for (const code of [401, 403]) {
        const { transport } = fakeTransport(code, JSON.stringify({ description: "Unauthorized" }))
        expect((await deliverTelegram("hi", { transport })).status).toBe("permanent")
      }
    })
  })

  test("400 (bad chat id) is permanent", async () => {
    await withEnv(creds, async () => {
      const { transport } = fakeTransport(400, JSON.stringify({ description: "chat not found" }))
      const r = await deliverTelegram("hi", { transport })
      expect(r.status).toBe("permanent")
      expect(r.message).toContain("chat not found")
    })
  })

  test("a network error is retryable", async () => {
    await withEnv(creds, async () => {
      const transport: TelegramTransport = async () => { throw new Error("ECONNRESET") }
      expect((await deliverTelegram("hi", { transport })).status).toBe("retryable")
    })
  })

  test("with no credentials nothing is sent and it is NOT reported as failure", async () => {
    await withEnv({ TELEGRAM_BOT_TOKEN: undefined, TELEGRAM_CHAT_ID: undefined }, async () => {
      expect(telegramConfigured()).toBe(false)
      const { transport, calls } = fakeTransport(200)
      const r = await deliverTelegram("hi", { transport })
      expect(r.status).toBe("not_configured")
      expect(calls).toHaveLength(0) // no request attempted
    })
  })

  test("the bot token never appears in a returned message", async () => {
    await withEnv(creds, async () => {
      // A provider/proxy echoing the request URL back at us.
      const { transport } = fakeTransport(400, JSON.stringify({
        description: "failed to call https://api.telegram.org/bot123456:AAaaBBbbCCccDDdd/sendMessage",
      }))
      const r = await deliverTelegram("hi", { transport })
      expect(r.message).not.toContain("123456:AAaaBBbbCCccDDdd")
      // Redacted by the exact-value pass, which runs first.
      expect(r.message).toContain("[TELEGRAM_BOT_TOKEN]")
    })
  })

  test("a token we do NOT hold is still scrubbed by URL shape", async () => {
    // Covers a rotated or foreign token appearing in an upstream error, where
    // the exact-value pass has nothing to match on.
    await withEnv(creds, async () => {
      const { transport } = fakeTransport(400, JSON.stringify({
        description: "upstream said https://api.telegram.org/bot999888:ZZZZrotatedSECRET/sendMessage failed",
      }))
      const r = await deliverTelegram("hi", { transport })
      expect(r.message).not.toContain("ZZZZrotatedSECRET")
      expect(r.message).toContain("/bot[redacted]")
    })
  })

  test("the request targets Telegram and carries HTML parse mode", async () => {
    await withEnv(creds, async () => {
      const { transport, calls } = fakeTransport(200)
      await deliverTelegram("<b>x</b>", { transport })
      expect(calls[0].url).toStartWith("https://api.telegram.org/bot")
      const body = JSON.parse(calls[0].body) as Record<string, unknown>
      expect(body.parse_mode).toBe("HTML")
      expect(body.disable_web_page_preview).toBe(true)
    })
  })
})

describe("Retry backoff is bounded", () => {
  test("it grows with attempts", () => {
    expect(backoffSeconds(2)).toBeGreaterThan(backoffSeconds(1))
    expect(backoffSeconds(3)).toBeGreaterThan(backoffSeconds(2))
  })

  test("it is capped — a long outage cannot produce an unbounded delay", () => {
    expect(backoffSeconds(999)).toBeLessThanOrEqual(3600)
  })

  test("Telegram's own retry_after wins over our schedule", () => {
    expect(backoffSeconds(1, 42)).toBe(42)
    expect(backoffSeconds(999, 30)).toBe(30)
  })

  test("an absurd retry_after is still capped", () => {
    expect(backoffSeconds(1, 999_999)).toBeLessThanOrEqual(3600)
  })
})

describe("Ticketing is provider-neutral and honest when unconfigured", () => {
  test("the default provider is NOT configured", async () => {
    await withEnv({ TICKETING_PROVIDER: undefined }, () => {
      const p = ticketProvider()
      expect(p.name).toBe("none")
      expect(p.configured).toBe(false)
    })
  })

  test("an unconfigured provider reports failure instead of pretending", async () => {
    await withEnv({ TICKETING_PROVIDER: undefined }, async () => {
      const r = await ticketProvider().create(alert(), { title: "t", description: "d" })
      expect(r.ok).toBe(false)
      if (!r.ok) {
        expect(r.configured).toBe(false)
        expect(r.error).toMatch(/not configured/i)
      }
    })
  })

  test("an unknown provider name falls back to none rather than guessing", async () => {
    await withEnv({ TICKETING_PROVIDER: "jira" }, () => {
      expect(ticketProvider().name).toBe("none")
    })
  })

  test("a BIGINT alert id arriving as a string is accepted, not rejected", () => {
    // `exposure_alerts.id` is BIGSERIAL and the Postgres driver returns BIGINT
    // as a string. A strict typeof check would reject every real alert.
    // Asserted on the guard directly so this pure test never writes to a database.
    expect(validAlertId("123")).toBe(true)
    expect(validAlertId(123)).toBe(true)
    expect(validAlertId(-1)).toBe(false)
    expect(validAlertId(0)).toBe(false)
    expect(validAlertId("abc")).toBe(false)
    expect(validAlertId(null)).toBe(false)
    expect(validAlertId(1.5)).toBe(false)
  })

  test("the internal provider is opt-in", async () => {
    await withEnv({ TICKETING_PROVIDER: "internal" }, () => {
      expect(ticketProvider().name).toBe("internal")
      expect(ticketProvider().configured).toBe(true)
    })
  })
})

describe("Ticket content is built from the alert, with nothing invented", () => {
  test("the title identifies severity, CVE and asset", () => {
    expect(buildTicketContent(alert()).title).toBe("[CRITICAL] CVE-2021-41773 on 45.33.32.156")
  })

  test("the body carries the existing intelligence verbatim", () => {
    const d = buildTicketContent(alert()).description
    expect(d).toContain("ALT-42")
    expect(d).toContain("Evidence: CONFIRMED")
    expect(d).toContain("Provider evidence: netlas")
    expect(d).toContain("RBVM risk: 100 / critical")
    expect(d).toContain("CVSS: 10")
  })

  test("absent fields read UNKNOWN rather than being filled in", () => {
    const d = buildTicketContent(alert({ payload: { asset: "1.2.3.4" } })).description
    expect(d).toContain("Product: UNKNOWN")
    expect(d).toContain("CVSS: UNKNOWN")
    expect(d).toContain("Provider evidence: none recorded")
  })

  test("no remediation guidance is invented", () => {
    const d = buildTicketContent(alert()).description
    expect(d).toMatch(/does not hold vendor remediation guidance/i)
  })

  test("weak evidence produces a verify-first action, not a remediate order", () => {
    expect(buildTicketContent(alert({ evidence_tier: "product" })).description).toMatch(/verify the finding before acting/i)
  })

  test("ticket text is plain — not HTML-escaped like the Telegram message", () => {
    const c = buildTicketContent(alert({ payload: { ...alert().payload, product: "A & B" } }))
    expect(c.description).toContain("A & B")
    expect(c.description).not.toContain("&amp;")
  })

  test("hostile provider content is flattened and bounded", () => {
    const c = buildTicketContent(alert({
      payload: { ...alert().payload, product: `X${"y".repeat(20000)}\n\nInjected: true` },
    }))
    expect(c.description.length).toBeLessThanOrEqual(6001)
    expect(c.description).not.toContain("\nInjected: true")
  })
})

describe("Architecture — the workflow layer holds no intelligence", () => {
  const files = [
    "lib/exposure/alert-workflow.ts",
    "lib/notify/telegram-adapter.ts",
    "lib/notify/outbox.ts",
    "lib/ticketing/index.ts",
  ]

  test("no notification or ticket code computes risk", async () => {
    for (const f of files) {
      const src = await Bun.file(f).text()
      expect(src).not.toMatch(/^import .*risk-engine/m)
      expect(src).not.toMatch(/computeRiskScore\(|computeExposureRisk\(/)
    }
  })

  test("no notification or ticket code decides alert eligibility or correlates CVEs", async () => {
    for (const f of files) {
      const src = await Bun.file(f).text()
      expect(src).not.toMatch(/isAlertEligible\(/)
      expect(src).not.toMatch(/correlateServices\(|makeVulnerability\(/)
      expect(src).not.toMatch(/^import .*cve-correlation/m)
    }
  })

  test("no credential name is referenced outside the adapter that needs it", async () => {
    for (const f of ["lib/exposure/alert-workflow.ts", "lib/ticketing/index.ts"]) {
      const src = await Bun.file(f).text()
      expect(src).not.toContain("TELEGRAM_BOT_TOKEN")
      expect(src).not.toContain("TELEGRAM_CHAT_ID")
    }
  })

  test("the outbox worker is fail-closed behind the existing cron secret", async () => {
    const src = await Bun.file("app/api/exposure/notifications/run/route.ts").text()
    expect(src).toContain("authorized(req)")
    expect(src).toContain("401")
  })

  test("monitoring never calls Telegram or the outbox directly", async () => {
    const src = await Bun.file("lib/exposure/monitoring.ts").text()
    expect(src).not.toMatch(/telegram/i)
    expect(src).not.toContain("runNotificationCycle")
    expect(src).not.toContain("deliverTelegram")
  })

  test("the delivery claim is bounded by a materialized CTE, not a bare subquery", async () => {
    const src = await Bun.file("lib/notify/outbox.ts").text()
    // Same planner hazard as the monitoring scheduler: FOR UPDATE makes the
    // subquery non-hashable, so an IN (SELECT ... LIMIT n) can over-claim.
    expect(src).toContain("WITH due AS")
    expect(src).toContain("FOR UPDATE SKIP LOCKED")
    expect(src).not.toMatch(/IN \(\s*SELECT id FROM exposure_alerts/)
  })

  test("suppressed and closed alerts are excluded from delivery", async () => {
    const src = await Bun.file("lib/notify/outbox.ts").text()
    expect(src).toMatch(/state IN \('open', ?'acknowledged', ?'in_progress'\)/)
  })
})

describe("coerceAlertId — the JSON boundary between BIGSERIAL and the client", () => {
  test("accepts the STRING form the driver actually produces", () => {
    // The regression this exists for: exposure_alerts.id is BIGSERIAL, the Neon
    // driver returns BIGINT as a string, and an id round-tripped through the
    // API arrives as "5198". Validating with `typeof === "number"` rejected
    // every real alert, so Acknowledge/Start/Resolve/Close/Suppress all
    // answered 400 while the client's type declared `id: number`.
    expect(coerceAlertId("5198")).toBe(5198)
    expect(coerceAlertId(5198)).toBe(5198)
  })

  test("still rejects everything that is not a positive integer id", () => {
    expect(coerceAlertId(0)).toBeNull()
    expect(coerceAlertId(-1)).toBeNull()
    expect(coerceAlertId("-1")).toBeNull()
    expect(coerceAlertId("")).toBeNull()
    expect(coerceAlertId("   ")).toBeNull()
    expect(coerceAlertId("abc")).toBeNull()
    expect(coerceAlertId(null)).toBeNull()
    expect(coerceAlertId(undefined)).toBeNull()
    expect(coerceAlertId({})).toBeNull()
    expect(coerceAlertId([])).toBeNull()
    expect(coerceAlertId(Number.NaN)).toBeNull()
    expect(coerceAlertId(Infinity)).toBeNull()
  })

  test("truncates rather than rounding, so a crafted id cannot reach a neighbour row", () => {
    expect(coerceAlertId("5198.9")).toBe(5198)
  })
})
