import { createAuthClient } from "better-auth/react"
import { emailOTPClient } from "better-auth/client/plugins"

/**
 * Client Better Auth (navigateur). Same-origin : la baseURL est déduite.
 * - `emailOTPClient()` : vérification d'email par code OTP.
 */
export const authClient = createAuthClient({
  plugins: [emailOTPClient()],
})

export const { signIn, signUp, signOut, useSession } = authClient
