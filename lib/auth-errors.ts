/**
 * Centralized translation of auth errors (Better Auth codes + OAuth errors
 * returned in the query string) into friendly English messages. Single source.
 */
const MESSAGES: Record<string, string> = {
  // Email / password
  invalid_email_or_password: "Incorrect email or password.",
  "invalid email or password": "Incorrect email or password.",
  user_already_exists: "An account already exists with this email.",
  "user already exists": "An account already exists with this email.",
  weak_password: "Password too weak (8 characters minimum).",
  password_too_short: "Password too short (8 characters minimum).",
  email_not_verified: "Your email isn't verified yet — check your inbox.",

  // Account linking
  account_not_linked:
    "This email is already used with another sign-in method. Sign in with that one, then link this provider from your account.",
  account_already_linked: "This provider is already linked to your account.",
  unable_to_unlink_last_account: "You can't remove your last sign-in method.",

  // OAuth
  state_mismatch:
    "OAuth session expired or cookies blocked. Try again (VPN mode / private browsing often blocks cookies).",
  access_denied: "Sign-in cancelled.",
  oauth_cancelled: "Sign-in cancelled.",
  invalid_callback: "Invalid OAuth callback. Try signing in again.",
  invalid_token: "Invalid or expired link.",

  // Session / rate limit
  session_expired: "Your session has expired. Sign in again.",
  too_many_requests: "Too many attempts. Wait a moment and try again.",
  rate_limited: "Too many attempts. Wait a moment and try again.",
}

/** Shape of the `error` object returned by the Better Auth client. */
type AuthClientError = { code?: string; message?: string; status?: number; statusText?: string }

/**
 * Accepts either a code/message string (e.g. `?error=` from an OAuth redirect)
 * or the client's `error` object.
 *
 * When the auth server itself fails (database unreachable, quota exceeded,
 * function crash) it answers 5xx with no JSON body, so the client error carries
 * neither `code` nor `message`. That used to collapse into the generic
 * "Something went wrong", which looked like a user mistake and hid an outage.
 * The status code is enough to say what actually happened.
 */
export function friendlyAuthError(input?: string | AuthClientError | null): string {
  if (input && typeof input === "object") {
    const text = input.code || input.message
    if (!text) {
      if (input.status === 429) return MESSAGES.too_many_requests
      if (input.status && input.status >= 500)
        return "The sign-in service is temporarily unavailable (server error). Please try again later."
      return "Something went wrong. Try again."
    }
    input = text
  }
  if (!input) return "Something went wrong. Try again."
  const key = input.toLowerCase().trim()
  if (MESSAGES[key]) return MESSAGES[key]
  for (const k of Object.keys(MESSAGES)) if (key.includes(k)) return MESSAGES[k]
  return input
}
