/**
 * Traduction centralisée des erreurs d'auth (codes Better Auth + erreurs OAuth
 * renvoyées en query string) vers des messages FR conviviaux. Source unique.
 */
const MESSAGES: Record<string, string> = {
  // Email / mot de passe
  invalid_email_or_password: "Email ou mot de passe incorrect.",
  "invalid email or password": "Email ou mot de passe incorrect.",
  user_already_exists: "Un compte existe déjà avec cet email.",
  "user already exists": "Un compte existe déjà avec cet email.",
  weak_password: "Mot de passe trop faible (8 caractères minimum).",
  password_too_short: "Mot de passe trop court (8 caractères minimum).",
  email_not_verified: "Ton email n'est pas encore vérifié — regarde ta boîte mail.",

  // Account linking
  account_not_linked:
    "Cet email est déjà utilisé avec une autre méthode de connexion. Connecte-toi avec celle-ci, puis lie ce fournisseur depuis ton compte.",
  account_already_linked: "Ce fournisseur est déjà lié à ton compte.",
  unable_to_unlink_last_account: "Impossible de retirer ta dernière méthode de connexion.",

  // OAuth
  state_mismatch:
    "Session OAuth expirée ou cookies bloqués. Réessaie (le mode VPN / navigation privée bloque souvent les cookies).",
  access_denied: "Connexion annulée.",
  oauth_cancelled: "Connexion annulée.",
  invalid_callback: "Retour OAuth invalide. Réessaie la connexion.",
  invalid_token: "Lien invalide ou expiré.",

  // Session / rate limit
  session_expired: "Ta session a expiré. Reconnecte-toi.",
  too_many_requests: "Trop de tentatives. Patiente un instant puis réessaie.",
  rate_limited: "Trop de tentatives. Patiente un instant puis réessaie.",
}

export function friendlyAuthError(input?: string | null): string {
  if (!input) return "Une erreur est survenue. Réessaie."
  const key = input.toLowerCase().trim()
  if (MESSAGES[key]) return MESSAGES[key]
  for (const k of Object.keys(MESSAGES)) if (key.includes(k)) return MESSAGES[k]
  return input
}
