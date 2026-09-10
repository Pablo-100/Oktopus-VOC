/**
 * Database guard for the suites that write real rows.
 *
 * MUST be the first import in any test file that touches the database:
 * `lib/db.ts` binds `DATABASE_URL` at module-evaluation time, so redirecting it
 * afterwards has no effect. ES modules are evaluated in import order, so
 * importing this first is what makes the redirection take.
 *
 * The rule it enforces: these suites INSERT, UPDATE and DELETE. Pointed at a
 * production database they will mutate real users' alerts, monitoring rows and
 * credentials. Previously they inherited whatever `DATABASE_URL` happened to be
 * in `.env.local` — which on a developer's machine is the production database —
 * so `bun test` quietly wrote to live data.
 *
 * So a dedicated database is now REQUIRED rather than preferred. Without
 * `TEST_DATABASE_URL` the DB suites skip loudly instead of falling back to
 * whatever connection string is lying around: a skipped test is a visible gap,
 * a test that silently rewrites production data is not.
 */
import { existsSync, readFileSync } from "fs"

if (existsSync(".env.local")) {
  for (const line of readFileSync(".env.local", "utf8").split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "")
  }
}

const testUrl = process.env.TEST_DATABASE_URL?.trim()

if (testUrl) {
  // Redirect BEFORE lib/db.ts is evaluated.
  process.env.DATABASE_URL = testUrl
} else {
  // No test database: make the connection string unusable so that a suite which
  // ignores HAS_TEST_DB cannot reach production by accident. Failing to connect
  // is a far better outcome than succeeding against live data.
  process.env.DATABASE_URL = "postgresql://placeholder:placeholder@localhost/placeholder"
}

/**
 * Whether a real, dedicated test database is available.
 *
 * DB suites gate on this: `describe.skipIf(!HAS_TEST_DB)`.
 */
export const HAS_TEST_DB = Boolean(testUrl)

if (!HAS_TEST_DB && !process.env.OCTUPUS_TEST_DB_NOTICE_SHOWN) {
  process.env.OCTUPUS_TEST_DB_NOTICE_SHOWN = "1"
  console.warn(
    [
      "",
      "  ⚠ Database-backed test suites are SKIPPED: TEST_DATABASE_URL is not set.",
      "",
      "    These suites write real rows, so they refuse to run against whatever",
      "    DATABASE_URL is configured — that is the production database on a dev",
      "    machine. Create a disposable branch and point the tests at it:",
      "",
      "      neon branches create --name test        # or the Neon console",
      "      TEST_DATABASE_URL=postgresql://…  (add to .env.local)",
      "",
    ].join("\n"),
  )
}
