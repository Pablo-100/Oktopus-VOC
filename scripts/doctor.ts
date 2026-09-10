/**
 * Setup doctor — `bun run doctor`
 *
 * Validates a fresh install before the first `bun dev`, so a new operator gets
 * one actionable report instead of discovering problems as cryptic runtime
 * failures spread across the app.
 *
 * Exit code 1 when anything REQUIRED is missing/broken, else 0 (CI-friendly).
 * Read-only: connects to Postgres to verify reachability, writes nothing.
 */
import { neon } from "@neondatabase/serverless"

type Status = "ok" | "warn" | "fail"
type Check = { status: Status; label: string; detail: string; fix?: string }

const results: Check[] = []
const add = (status: Status, label: string, detail: string, fix?: string) => results.push({ status, label, detail, fix })

const has = (k: string) => Boolean(process.env[k]?.trim())

// ─────────────────────────────── REQUIRED ────────────────────────────────

async function checkDatabase() {
  if (!has("DATABASE_URL")) {
    add("fail", "Database", "DATABASE_URL is not set.", "Create a free Postgres database at neon.tech, then put its connection string in .env.local as DATABASE_URL.")
    return
  }
  const url = process.env.DATABASE_URL!.trim()
  if (!/^postgres(ql)?:\/\//.test(url)) {
    add("fail", "Database", "DATABASE_URL is not a postgres:// connection string.", "Expected a value starting with postgresql:// — copy it from your Neon dashboard.")
    return
  }
  try {
    const sql = neon(url)
    const rows = (await sql`SELECT 1 AS ok`) as Array<{ ok: number }>
    if (rows[0]?.ok !== 1) throw new Error("unexpected response")
    add("ok", "Database", "Connected successfully.")
  } catch (e) {
    add("fail", "Database", `Could not connect: ${e instanceof Error ? e.message : String(e)}`, "Check the connection string is current and that your IP isn't blocked. Neon connection strings expire when the project is deleted or the password is rotated.")
  }
}

function checkAuthSecret() {
  if (!has("BETTER_AUTH_SECRET")) {
    add("fail", "Auth secret", "BETTER_AUTH_SECRET is not set — sessions cannot be signed.", "Generate one with:  openssl rand -base64 32   (or: bun run doctor:secret)")
    return
  }
  const v = process.env.BETTER_AUTH_SECRET!.trim().replace(/^"|"$/g, "")
  if (v.length < 32) {
    add("fail", "Auth secret", `BETTER_AUTH_SECRET is only ${v.length} characters — too short to be safe.`, "Use at least 32 characters:  openssl rand -base64 32")
    return
  }
  add("ok", "Auth secret", "Set and long enough.")
}

function checkAppUrl() {
  if (has("BETTER_AUTH_URL")) {
    const v = process.env.BETTER_AUTH_URL!.trim()
    if (!/^https?:\/\//.test(v)) {
      add("fail", "App URL", `BETTER_AUTH_URL ("${v}") must start with http:// or https://.`, "Use http://localhost:3000 for local dev, or your full https:// domain in production.")
      return
    }
    add("ok", "App URL", `${v}`)
    return
  }
  if (has("VERCEL_PROJECT_PRODUCTION_URL") || has("VERCEL_URL")) {
    add("ok", "App URL", "Auto-detected from Vercel environment.")
    return
  }
  add("warn", "App URL", "BETTER_AUTH_URL is not set — falling back to http://localhost:3000.", "Fine for local dev. In production set it to your real domain, or OAuth redirects and email links will point at localhost.")
}

/**
 * The trap this check exists for: signup uses requireEmailVerification with an
 * emailed OTP, and the mailer no-ops when no provider is configured. Without
 * this warning an operator sees "account created", never receives a code, and
 * can never sign in — with nothing in the UI explaining why.
 */
function checkEmail() {
  const provider = process.env.EMAIL_PROVIDER?.trim()
  const gmail = has("GMAIL_USER") && has("GMAIL_APP_PASSWORD")
  const resend = has("RESEND_API_KEY")

  if (provider === "gmail" && !gmail) {
    add("fail", "Email (sign-up codes)", "EMAIL_PROVIDER=gmail but GMAIL_USER / GMAIL_APP_PASSWORD are incomplete.", "Set both, using a Google App Password (not your account password): myaccount.google.com/apppasswords")
    return
  }
  if (provider === "resend" && !resend) {
    add("fail", "Email (sign-up codes)", "EMAIL_PROVIDER=resend but RESEND_API_KEY is missing.", "Add your Resend API key, or switch to EMAIL_PROVIDER=gmail.")
    return
  }
  if (!gmail && !resend) {
    add("fail", "Email (sign-up codes)", "No email provider configured — NOBODY CAN REGISTER. Sign-up sends a 6-digit code and no session is issued until it is entered, so every account gets stuck at the verification step.", "Easiest: EMAIL_PROVIDER=gmail plus GMAIL_USER and a Google App Password (free, ~500/day, no domain needed).")
    return
  }
  add("ok", "Email (sign-up codes)", `Configured via ${provider || (gmail ? "gmail" : "resend")} (auto-detected).`)
}

// ─────────────────────────────── OPTIONAL ────────────────────────────────

function optional(label: string, ok: boolean, onDetail: string, offDetail: string, fix?: string) {
  if (ok) add("ok", label, onDetail)
  else add("warn", label, offDetail, fix)
}

function checkOptional() {
  optional("Scheduled sync", has("CRON_SECRET"),
    "CRON_SECRET set — /api/cron/sync is protected and callable.",
    "CRON_SECRET not set — scheduled CVE sync is disabled (the endpoint refuses all callers, by design).",
    "Generate any random string, put it in .env.local AND in your repo's Actions secrets so the workflow matches.")

  optional("NVD API key", has("NVD_API_KEY"),
    "Set — 50 requests/30s.",
    "Not set — NVD throttles you to 5 requests/30s, so syncs are much slower.",
    "Free key: nvd.nist.gov/developers/request-an-api-key")

  optional("GitHub token", has("GITHUB_TOKEN"),
    "Set — 5,000 requests/hour for the 0-day advisory source.",
    "Not set — GitHub advisories are limited to 60 requests/hour.",
    "Any classic token with no scopes works: github.com/settings/tokens")

  optional("AI analysis", has("OPENROUTER_API_KEY"),
    "Set — per-CVE AI analysis is available.",
    "Not set — the AI analysis panel stays hidden.",
    "openrouter.ai — a free model is preconfigured in .env.example")

  optional("Telegram alerts", has("TELEGRAM_BOT_TOKEN") && has("TELEGRAM_CHAT_ID"),
    "Set — high-risk CVEs are pushed to Telegram.",
    "Not set — alerting is off (everything else works).",
    "Create a bot with @BotFather, then set both the token and your chat id.")

  // Labelled by role, because the roles are not interchangeable: without a
  // DISCOVERY provider the Exposure Intelligence search has nothing to seed
  // the pipeline with, no matter how many enrichment keys are configured.
  const easm: Array<[string, boolean]> = [
    ["GreyNoise (threat)", has("GREYNOISE_API_KEY")],
    ["LeakIX (discovery)", has("LEAKIX_API_KEY")],
    ["Netlas (enrichment)", has("NETLAS_API_KEY")],
    ["Censys (enrichment)", has("CENSYS_API_TOKEN")],
    ["FOFA (discovery)", has("FOFA_EMAIL") && has("FOFA_API_KEY")],
    ["ZoomEye (discovery)", has("ZOOMEYE_API_KEY")],
  ]
  const hasDiscovery = has("LEAKIX_API_KEY") || (has("FOFA_EMAIL") && has("FOFA_API_KEY")) || has("ZOOMEYE_API_KEY")
  if (!hasDiscovery && (has("CENSYS_API_TOKEN") || has("NETLAS_API_KEY"))) {
    add("warn", "Exposure discovery", "Enrichment providers are configured but NO discovery provider is — searches will find no hosts to enrich.",
      "Add LEAKIX_API_KEY (free tier, best discovery coverage) to make Exposure Intelligence searches useful.")
  }
  const on = easm.filter(([, v]) => v).map(([n]) => n)
  const off = easm.filter(([, v]) => !v).map(([n]) => n)
  if (on.length) {
    add("ok", "Exposure providers", `${on.length}/6 configured: ${on.join(", ")}${off.length ? ` (off: ${off.join(", ")})` : ""}.`)
  } else {
    add("warn", "Exposure providers", "None configured — the Exposure page loads but returns no data.",
      "All optional. See docs/exposure-providers-setup.md; GreyNoise and LeakIX have the most useful free tiers.")
  }

  // FOFA needs BOTH values — a key alone silently never activates.
  if (has("FOFA_API_KEY") && !has("FOFA_EMAIL")) {
    add("warn", "FOFA", "FOFA_API_KEY is set but FOFA_EMAIL is empty — FOFA stays disabled.", "FOFA's API requires the account email alongside the key. Add FOFA_EMAIL.")
  }
}

// ──────────────────────────────── REPORT ─────────────────────────────────

function report() {
  const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - s.length))
  const width = Math.max(...results.map((r) => r.label.length)) + 2

  console.log("\n  OCTUPUS-VOC — setup check\n")
  for (const r of results) {
    const sym = r.status === "ok" ? "[ ok ]" : r.status === "warn" ? "[warn]" : "[FAIL]"
    console.log(`  ${sym}  ${pad(r.label, width)}${r.detail}`)
    if (r.fix) console.log(`          ${pad("", width)}-> ${r.fix}`)
  }

  const fails = results.filter((r) => r.status === "fail")
  const warns = results.filter((r) => r.status === "warn")
  console.log("")
  if (fails.length) {
    console.log(`  ${fails.length} blocking issue${fails.length > 1 ? "s" : ""} — the app will not work correctly until fixed.`)
    console.log(`  ${warns.length} optional feature${warns.length === 1 ? "" : "s"} not configured.\n`)
    process.exit(1)
  }
  console.log(`  All required checks passed. ${warns.length} optional feature${warns.length === 1 ? "" : "s"} not configured.`)
  console.log("  Start the app with:  bun dev\n")
}

async function main() {
  if (process.argv.includes("--secret")) {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    console.log(Buffer.from(bytes).toString("base64"))
    return
  }
  await checkDatabase()
  checkAuthSecret()
  checkAppUrl()
  checkEmail()
  checkOptional()
  report()
}

main().catch((e) => {
  console.error("doctor failed:", e)
  process.exit(1)
})
