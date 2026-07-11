import { createAuthClient } from "better-auth/react"
import { emailOTPClient } from "better-auth/client/plugins"
import { dashClient } from "@better-auth/infra/client"

/**
 * Client Better Auth (navigateur). Same-origin : la baseURL est déduite.
 * - `emailOTPClient()` : vérification d'email par code OTP.
 * - `dashClient()` : pendant du plugin serveur `dash()`.
 */
export const authClient = createAuthClient({
  plugins: [emailOTPClient(), dashClient()],
})

export const { signIn, signUp, signOut, useSession } = authClient
