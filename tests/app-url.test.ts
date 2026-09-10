import { describe, test, expect, afterEach } from "bun:test"
import { getAppUrl } from "@/lib/app-url"

/**
 * The canonical public URL of a deployment.
 *
 * This decides the origin session cookies are issued for, so getting it wrong
 * does not throw — it just means nobody can stay signed in, with no error
 * anywhere. That silence is why it is pinned here.
 */

const KEYS = ["BETTER_AUTH_URL", "VERCEL_PROJECT_PRODUCTION_URL", "VERCEL_URL"] as const
const saved: Record<string, string | undefined> = {}
for (const k of KEYS) saved[k] = process.env[k]
afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k]
    else process.env[k] = saved[k]
  }
})
const clear = () => { for (const k of KEYS) delete process.env[k] }

describe("getAppUrl", () => {
  test("an explicit public URL wins", () => {
    clear()
    process.env.BETTER_AUTH_URL = "https://octupus-voc.vercel.app"
    process.env.VERCEL_PROJECT_PRODUCTION_URL = "something-else.vercel.app"
    expect(getAppUrl()).toBe("https://octupus-voc.vercel.app")
  })

  test("a localhost override is IGNORED on a deployed instance", () => {
    // The failure this exists for: .env.local gets pasted into a hosting
    // dashboard, BETTER_AUTH_URL stays on localhost, and every session cookie
    // is issued for an origin the browser will not keep. Sign-in appears to
    // work and no session survives the redirect.
    clear()
    process.env.BETTER_AUTH_URL = "http://localhost:3000"
    process.env.VERCEL_PROJECT_PRODUCTION_URL = "octupus-voc.vercel.app"
    expect(getAppUrl()).toBe("https://octupus-voc.vercel.app")
  })

  test("every local form is recognised, not just 'localhost'", () => {
    for (const local of ["http://localhost:3000", "http://127.0.0.1:3000", "http://0.0.0.0:3000", "http://[::1]:3000"]) {
      clear()
      process.env.BETTER_AUTH_URL = local
      process.env.VERCEL_URL = "deploy-abc.vercel.app"
      expect(getAppUrl()).toBe("https://deploy-abc.vercel.app")
    }
  })

  test("localhost is respected when NOT deployed", () => {
    // Local development must keep working exactly as before.
    clear()
    process.env.BETTER_AUTH_URL = "http://localhost:3000"
    expect(getAppUrl()).toBe("http://localhost:3000")
  })

  test("a domain merely containing 'localhost' is not treated as local", () => {
    clear()
    process.env.BETTER_AUTH_URL = "https://localhost.example.com"
    process.env.VERCEL_PROJECT_PRODUCTION_URL = "octupus-voc.vercel.app"
    expect(getAppUrl()).toBe("https://localhost.example.com")
  })

  test("falls back through the Vercel variables, then to localhost", () => {
    clear()
    process.env.VERCEL_PROJECT_PRODUCTION_URL = "prod.vercel.app"
    process.env.VERCEL_URL = "preview.vercel.app"
    expect(getAppUrl()).toBe("https://prod.vercel.app")

    clear()
    process.env.VERCEL_URL = "preview.vercel.app"
    expect(getAppUrl()).toBe("https://preview.vercel.app")

    clear()
    expect(getAppUrl()).toBe("http://localhost:3000")
  })

  test("a trailing slash never survives — it would double up in every link", () => {
    clear()
    process.env.BETTER_AUTH_URL = "https://octupus-voc.vercel.app/"
    expect(getAppUrl()).toBe("https://octupus-voc.vercel.app")
  })
})
