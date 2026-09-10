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
  // The Content-Security-Policy is NOT set here.
  //
  // It used to be, as a static `script-src 'self'` applied only in production —
  // which blocked the eleven inline <script> tags Next.js uses to ship the RSC
  // payload, so hydration never ran in any production build. A static header
  // cannot carry a per-request nonce, so the policy now lives in proxy.ts where
  // one can be generated. Keeping a second copy here would emit a duplicate
  // header and the stricter of the two would win, silently undoing the fix.
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
