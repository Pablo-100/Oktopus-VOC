import { NextResponse } from "next/server"
import { sql } from "@/lib/db"
import { requireUser } from "@/lib/api-auth"
import { apiError } from "@/lib/errors"
import { providerConfiguration } from "@/lib/exposure/orchestrator"
import { quotaUsage } from "@/lib/exposure/quota"
import { capabilityFor } from "@/lib/exposure/capabilities"
import type { ProviderName } from "@/lib/exposure/types"
import { cacheScope, withUserCredentials } from "@/lib/exposure/credentials"
import { rateLimited, keyFrom } from "@/lib/rate-limit"

/**
 * Which exposure providers are configured, their role, and the shared hourly
 * quota consumed so far. No external calls — pure env + DB read.
 *
 * B1 migration: sourced from the single `lib/exposure/` abstraction, which also
 * means the role information (discovery / enrichment / threat) is now available
 * here; the old module had no concept of provider roles.
 */
export async function GET(req: Request) {
  const gate = await requireUser(req)
  if (gate.deny) return gate.deny
  // polled by the provider strip on every page load.
  const denied = rateLimited(keyFrom(req, gate.user.id), 60, 60_000)
  if (denied) return denied
  // Runs inside the caller's credential context so `providerConfiguration()`,
  // `quotaUsage()` and the health lookup all describe THIS user's providers.
  // Outside a context they would silently report the platform's own keys, which
  // is the wrong answer for anyone who brought their own.
  return withUserCredentials(gate.user.id, async () => {
  try {
    const configured = providerConfiguration()
    const usage = await quotaUsage()
    const byProvider = new Map(usage.map((u) => [u.provider, u]))
    // Last OBSERVED outcome. `configured` only means a key exists; it cannot
    // tell the user that Censys is out of credits and contributing nothing.
    // Scoped per provider: a user on their own key must see THEIR account's
    // last outcome, not the platform's, and vice versa.
    const healthRows = (await sql`
      SELECT provider, scope, status, message, observations, checked_at, last_ok_at FROM exposure_provider_health
    `.catch(() => [])) as Array<{ provider: string; scope: string; status: string; message: string | null; observations: number; checked_at: string; last_ok_at: string | null }>
    const healthBy = new Map(
      healthRows.filter((h) => h.scope === cacheScope(h.provider)).map((h) => [h.provider, h]),
    )
    const providers = configured.map((p) => {
      const cap = capabilityFor(p.provider as ProviderName)
      return {
        // `name` retained for backward compatibility with existing consumers.
        name: p.provider,
        provider: p.provider,
        role: p.role,
        configured: p.configured,
        quotaUsed: byProvider.get(p.provider)?.used ?? 0,
        quotaBudget: byProvider.get(p.provider)?.budget ?? null,
        // What the provider actually did last time, or null if never called.
        health: healthBy.get(p.provider)
          ? {
              status: healthBy.get(p.provider)!.status,
              message: healthBy.get(p.provider)!.message,
              observations: healthBy.get(p.provider)!.observations,
              checkedAt: healthBy.get(p.provider)!.checked_at,
              lastOkAt: healthBy.get(p.provider)!.last_ok_at,
            }
          : null,
        // Capability matrix — sourced from lib/exposure/capabilities.ts so the
        // API and the docs cannot drift apart.
        capabilities: cap
          ? {
              liveLookup: cap.liveLookup,
              search: cap.search,
              cveSearch: cap.cveSearch,
              observationTimestamp: cap.observationTimestamp,
              observationTimestampField: cap.observationTimestampField,
              serviceDiscovery: cap.serviceDiscovery,
              vulnerabilityData: cap.vulnerabilityData,
              typicalObservationAge: cap.typicalObservationAge,
              queryLimitations: cap.queryLimitations,
            }
          : null,
      }
    })
    return NextResponse.json(
      {
        providers,
        // Stated explicitly so no consumer can infer live scanning.
        scansOnDemand: false,
        note: "No configured provider performs an on-demand scan. All observations come from each provider's own periodic internet-wide scanning; freshness reflects their observation time, not retrieval time.",
      },
      { headers: { "Cache-Control": "private, max-age=30" } },
    )
  } catch (e) {
    return apiError(e, "exposure-status")
  }
  })
}
