import type { NextConfig } from "next"

const securityHeaders = [
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  {
    key: "X-DNS-Prefetch-Control",
    value: "off",
  },
  // CSP : dur en prod (pas de scripts inline/eval), relâché en dev pour le HMR.
  ...(process.env.NODE_ENV === "production"
    ? ([
        {
          key: "Content-Security-Policy",
          value: [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https://*.nvd.nist.gov https://avatars.githubusercontent.com https://*.googleusercontent.com https://*.gstatic.com",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
          ].join("; "),
        },
      ] satisfies Record<string, string>[])
    : []),
]

const nextConfig: NextConfig = {
  // rss-parser utilise des APIs Node.js (http/https) → interdit de bundler (doc Next 16 : serverExternalPackages)
  serverExternalPackages: ["rss-parser"],
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ]
  },
}

export default nextConfig