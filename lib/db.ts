/**
 * Couche persistance Neon PostgreSQL (serveur uniquement).
 * Les tables sont créées automatiquement à la première requête.
 */
import { neon } from "@neondatabase/serverless"

// Placeholder si DATABASE_URL absent (imports de tests, script isolés) — les requêtes
// réelles ne partent qu'en production/dev où la variable est toujours définie.
export const sql = neon(process.env.DATABASE_URL || "postgresql://placeholder:placeholder@localhost/placeholder")

let ready: Promise<void> | null = null

/**
 * Crée les tables si besoin (une seule fois par instance).
 *
 * BUG CORRIGÉ : si la migration échouait une seule fois (ex. coupure
 * transitoire Neon au cold-start), `ready` restait une Promise REJETÉE pour
 * toujours -> chaque route qui appelle `await initDb()` (cves, zero-days,
 * triage, assets, metrics, exposure, greynoise...) renvoyait un 500
 * PERMANENT jusqu'au redémarrage du process serveur, même après le retour
 * de la connexion. `.catch` ci-dessous réinitialise `ready` à `null` en cas
 * d'échec -> le prochain appel retente toute la migration depuis zéro (sûr,
 * `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` sont idempotents).
 */
export function initDb(): Promise<void> {
  if (!ready) {
    ready = (async () => {
      await sql`CREATE TABLE IF NOT EXISTS triage (
        cve_id     TEXT PRIMARY KEY,
        status     TEXT NOT NULL DEFAULT 'new',
        note       TEXT,
        assignee   TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      await sql`CREATE TABLE IF NOT EXISTS assets (
        id          SERIAL PRIMARY KEY,
        user_id     TEXT,
        name        TEXT NOT NULL,
        vendor      TEXT,
        product     TEXT,
        criticality TEXT NOT NULL DEFAULT 'medium',
        owner       TEXT,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // Migration : ajoute user_id si la table existait déjà sans cette colonne
      await sql`ALTER TABLE assets ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`CREATE INDEX IF NOT EXISTS assets_user_id_idx ON assets (user_id)`
      await sql`CREATE TABLE IF NOT EXISTS alerts_sent (
        cve_id  TEXT PRIMARY KEY,
        sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // CVE traitées & enrichies par le collecteur serveur (source unique du dashboard)
      await sql`CREATE TABLE IF NOT EXISTS cves (
        cve_id        TEXT PRIMARY KEY,
        risk_score    REAL NOT NULL DEFAULT 0,
        severity      TEXT,
        is_kev        BOOLEAN NOT NULL DEFAULT false,
        has_exploit   BOOLEAN NOT NULL DEFAULT false,
        epss          REAL,
        cvss          REAL,
        published     TIMESTAMPTZ,
        last_modified TIMESTAMPTZ,
        data          JSONB NOT NULL,
        synced_at     TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      await sql`CREATE INDEX IF NOT EXISTS cves_risk_idx      ON cves (risk_score DESC)`
      await sql`CREATE INDEX IF NOT EXISTS cves_severity_idx  ON cves (severity)`
      await sql`CREATE INDEX IF NOT EXISTS cves_kev_idx       ON cves (is_kev)`
      await sql`CREATE INDEX IF NOT EXISTS cves_published_idx ON cves (published DESC)`
      // Traçage des imports manuels (qui a importé cette CVE) — gardé même si un
      // run du collecteur re-synchronise la ligne (COALESCE côté upsert).
      await sql`ALTER TABLE cves ADD COLUMN IF NOT EXISTS imported_by TEXT`
      // État de synchronisation (1 seule ligne, id=1)
      await sql`CREATE TABLE IF NOT EXISTS sync_state (
        id          INT PRIMARY KEY,
        last_sync   TIMESTAMPTZ,
        last_run_at TIMESTAMPTZ,
        total_cves  INT DEFAULT 0,
        last_status TEXT
      )`
      // 0-day / pré-CVE (id=2 pour sync_state, total_cves réutilisé comme compteur)
      await sql`CREATE TABLE IF NOT EXISTS zero_days (
        id            TEXT PRIMARY KEY,
        source        TEXT NOT NULL,
        kind          TEXT NOT NULL,
        cve_id        TEXT,
        ghsa_id       TEXT,
        title         TEXT NOT NULL,
        product       TEXT,
        exploit_state TEXT,
        verification  TEXT,
        is_kev        BOOLEAN NOT NULL DEFAULT false,
        has_exploit   BOOLEAN NOT NULL DEFAULT false,
        risk_score    REAL NOT NULL DEFAULT 0,
        severity      TEXT,
        cvss          REAL,
        epss          REAL,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        became_cve    BOOLEAN NOT NULL DEFAULT false,
        resolved_at   TIMESTAMPTZ,
        data          JSONB NOT NULL,
        synced_at     TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // Migration : description/permalink/references étaient calculés par le collecteur
      // puis jetés (jamais persistés) -> l'API /api/zero-days ne pouvait renvoyer que la
      // colonne `data` brute (payload source, ex. l'entrée KEV telle quelle), jamais les
      // champs 0-day normalisés attendus par le frontend. Root cause du bug "on ne voit
      // que des CVE" : ces colonnes manquaient totalement.
      await sql`ALTER TABLE zero_days ADD COLUMN IF NOT EXISTS description TEXT`
      await sql`ALTER TABLE zero_days ADD COLUMN IF NOT EXISTS permalink TEXT`
      await sql`ALTER TABLE zero_days ADD COLUMN IF NOT EXISTS references_json JSONB NOT NULL DEFAULT '[]'`
      await sql`CREATE INDEX IF NOT EXISTS zd_kind_idx   ON zero_days (kind)`
      await sql`CREATE INDEX IF NOT EXISTS zd_risk_idx   ON zero_days (risk_score DESC)`
      await sql`CREATE INDEX IF NOT EXISTS zd_cve_idx    ON zero_days (cve_id)`
      await sql`CREATE INDEX IF NOT EXISTS zd_became_idx ON zero_days (became_cve)`
      await sql`CREATE TABLE IF NOT EXISTS zero_day_alerts_sent (
        id      TEXT PRIMARY KEY,
        sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // Per-source scraper health for the 0-day collector — two of its six sources
      // are screen-scrapes (Google Sheet gviz, RSS) that can break silently; this
      // table lets syncZeroDays notice and alert instead of just logging to a void.
      await sql`CREATE TABLE IF NOT EXISTS zero_day_source_health (
        source               TEXT PRIMARY KEY,
        consecutive_failures INT NOT NULL DEFAULT 0,
        consecutive_empty    INT NOT NULL DEFAULT 0,
        last_ok_at           TIMESTAMPTZ,
        last_error           TEXT,
        last_alerted_at      TIMESTAMPTZ,
        updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // Internet-exposure signal (lib/exposure-providers.ts) — 24h cache per
      // product name, shared across all users/instances (Vercel is stateless
      // between invocations, so an in-memory cache like kev-cache.ts wouldn't hold).
      await sql`CREATE TABLE IF NOT EXISTS exposure_cache (
        query      TEXT PRIMARY KEY,
        results    JSONB NOT NULL,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // GreyNoise CVE exploitation-activity (lib/greynoise.ts) — 6h cache, shorter
      // than exposure_cache because "is this being exploited right now" is
      // time-sensitive in a way "how many instances exist" isn't.
      await sql`CREATE TABLE IF NOT EXISTS greynoise_cache (
        query      TEXT PRIMARY KEY,
        result     JSONB NOT NULL,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // ── Exposure Intelligence (EASM) ────────────────────────────────────
      // Correlated search results. One row per normalized query; the payload is
      // the fully correlated ExposureSearchResult so a repeat search costs no
      // provider quota (free tiers are small and easily exhausted).
      await sql`CREATE TABLE IF NOT EXISTS exposure_search_cache (
        query      TEXT PRIMARY KEY,
        result     JSONB NOT NULL,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      await sql`CREATE INDEX IF NOT EXISTS exposure_search_cache_fetched_idx ON exposure_search_cache (fetched_at DESC)`
      // Append-only asset history — powers genuine first-seen/last-seen and
      // "new asset / new service" events rather than a fabricated timeline.
      await sql`CREATE TABLE IF NOT EXISTS exposure_history (
        asset_key     TEXT PRIMARY KEY,
        query         TEXT,
        ip            TEXT,
        domain        TEXT,
        service_count INT  NOT NULL DEFAULT 0,
        vuln_count    INT  NOT NULL DEFAULT 0,
        risk_score    REAL NOT NULL DEFAULT 0,
        sources       JSONB NOT NULL DEFAULT '[]',
        first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen     TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // Global per-provider call budget (lib/exposure/quota.ts). Fixed hourly
      // window, shared across users AND serverless instances — the in-memory
      // route limiter cannot cap a shared third-party quota on its own.
      await sql`CREATE TABLE IF NOT EXISTS exposure_provider_quota (
        provider   TEXT NOT NULL,
        window_key TEXT NOT NULL,
        used       INT  NOT NULL DEFAULT 0,
        PRIMARY KEY (provider, window_key)
      )`
      await sql`CREATE INDEX IF NOT EXISTS exposure_provider_quota_window_idx ON exposure_provider_quota (window_key)`

      // ── BYOK: user-supplied provider credentials ────────────────────────
      // The EASM providers are paid, so users bring their own keys and spend
      // their own credits; the CVE/0-day feeds stay free and shared. These are
      // OTHER PEOPLE'S secrets, so only the sealed form is stored: AES-256-GCM
      // ciphertext whose key lives in the environment, never here. A database
      // dump on its own therefore yields nothing usable. `last4` exists so the
      // UI can show which key is stored without ever decrypting it.
      await sql`CREATE TABLE IF NOT EXISTS user_provider_credentials (
        user_id      TEXT NOT NULL,
        provider     TEXT NOT NULL,
        field        TEXT NOT NULL,
        ciphertext   TEXT NOT NULL,
        last4        TEXT,
        status       TEXT NOT NULL DEFAULT 'unverified',
        status_note  TEXT,
        verified_at  TIMESTAMPTZ,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (user_id, provider, field)
      )`
      await sql`CREATE INDEX IF NOT EXISTS user_provider_credentials_user_idx ON user_provider_credentials (user_id)`

      // ── Proof of entitlement to MONITOR a target ────────────────────────
      // One-off lookups stay open: every provider here is passive, so a single
      // query is no different from using Shodan's own site. Continuous
      // monitoring is different in kind — repeated queries, stored history,
      // paging a human — and requires a DNS TXT record only the domain's
      // controller can publish. IPs are authorised transitively, by a verified
      // domain that currently resolves to them.
      await sql`CREATE TABLE IF NOT EXISTS target_ownership (
        user_id         TEXT NOT NULL,
        target          TEXT NOT NULL,
        token           TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'pending',
        method          TEXT NOT NULL DEFAULT 'dns_txt',
        verified_at     TIMESTAMPTZ,
        last_checked_at TIMESTAMPTZ,
        last_error      TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (user_id, target)
      )`
      await sql`CREATE INDEX IF NOT EXISTS target_ownership_verified_idx ON target_ownership (user_id, status)`

      // ── Analyst workflow: ownership of an alert ─────────────────────────
      // "Who is working this" is the first question on a shared queue. Without
      // it two analysts investigate the same finding and neither knows.
      // Nullable on purpose: unassigned is a real, common state, not a default
      // that needs filling in.
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS assigned_to TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ`
      await sql`CREATE INDEX IF NOT EXISTS exposure_alerts_assignee_idx ON exposure_alerts (user_id, assigned_to)`

      // ── BYOK migration: scope cached results and quota by whose key paid ──
      // Under shared platform keys a global cache was correct: one query, one
      // answer, everybody benefits. Once users bring their own keys it stops
      // being correct — a result fetched with someone's paid Shodan key would
      // be served to a user who never paid for it, and plans differ in what
      // they return, so the cached answer may not even be reachable with the
      // reader's own credentials. Results fetched on PLATFORM keys stay shared
      // under the 'platform' scope, which is what keeps the free tier cheap.
      // Written out per table rather than looped: the Neon driver interpolates
      // VALUES, not identifiers, so a table name cannot be a parameter, and
      // building DDL by string concatenation is how injection gets in.
      await sql`ALTER TABLE exposure_cache ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'platform'`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_cache_pk_scope') THEN
          ALTER TABLE exposure_cache DROP CONSTRAINT IF EXISTS exposure_cache_pkey;
          ALTER TABLE exposure_cache ADD CONSTRAINT exposure_cache_pk_scope PRIMARY KEY (scope, query);
        END IF;
      END $$`
      await sql`ALTER TABLE greynoise_cache ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'platform'`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'greynoise_cache_pk_scope') THEN
          ALTER TABLE greynoise_cache DROP CONSTRAINT IF EXISTS greynoise_cache_pkey;
          ALTER TABLE greynoise_cache ADD CONSTRAINT greynoise_cache_pk_scope PRIMARY KEY (scope, query);
        END IF;
      END $$`
      await sql`ALTER TABLE exposure_search_cache ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'platform'`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_search_cache_pk_scope') THEN
          ALTER TABLE exposure_search_cache DROP CONSTRAINT IF EXISTS exposure_search_cache_pkey;
          ALTER TABLE exposure_search_cache ADD CONSTRAINT exposure_search_cache_pk_scope PRIMARY KEY (scope, query);
        END IF;
      END $$`

      // Quota follows the same rule. A user spending their own credits must not
      // be throttled by the platform's hourly budget, and must not be able to
      // exhaust it for everyone else — which is exactly what a single global
      // (provider, window) counter allowed.
      await sql`ALTER TABLE exposure_provider_quota ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'platform'`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_provider_quota_pk_scope') THEN
          ALTER TABLE exposure_provider_quota DROP CONSTRAINT IF EXISTS exposure_provider_quota_pkey;
          ALTER TABLE exposure_provider_quota ADD CONSTRAINT exposure_provider_quota_pk_scope PRIMARY KEY (provider, scope, window_key);
        END IF;
      END $$`

      // Last OBSERVED health of each provider, platform-wide.
      // `configured` only means "a key is present" — it says nothing about the
      // account behind it. Censys, FOFA and ZoomEye all have valid keys and
      // return nothing because their credits are spent, so a UI built on
      // `configured` alone tells the user a provider is fine while it silently
      // contributes no data. This records what actually happened on the last
      // call so the product can say "out of credits" instead of "operational".
      await sql`CREATE TABLE IF NOT EXISTS exposure_provider_health (
        provider     TEXT NOT NULL,
        status       TEXT NOT NULL,
        message      TEXT,
        observations INT  NOT NULL DEFAULT 0,
        checked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_ok_at   TIMESTAMPTZ,
        scope        TEXT NOT NULL DEFAULT 'platform',
        PRIMARY KEY (provider, scope)
      )`
      // Existing single-column-PK installs are migrated in place. Health is
      // per-scope for the same reason quota is: "out of credits" is a fact
      // about ONE account, and reporting another user's exhausted key as this
      // user's status would be exactly the false information this table exists
      // to prevent.
      await sql`ALTER TABLE exposure_provider_health ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'platform'`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_provider_health_pk_scope') THEN
          ALTER TABLE exposure_provider_health DROP CONSTRAINT IF EXISTS exposure_provider_health_pkey;
          ALTER TABLE exposure_provider_health ADD CONSTRAINT exposure_provider_health_pk_scope PRIMARY KEY (provider, scope);
        END IF;
      END $$`
      // Normalized change events + last-known snapshot per asset. Stores the
      // SNAPSHOT (ports/products/CVEs/sources) and the diff — never raw
      // provider payloads, which are large and already stripped from the cache.
      await sql`CREATE TABLE IF NOT EXISTS exposure_asset_state (
        asset_key  TEXT PRIMARY KEY,
        snapshot   JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      await sql`CREATE TABLE IF NOT EXISTS exposure_events (
        id         BIGSERIAL PRIMARY KEY,
        asset_key  TEXT NOT NULL,
        kind       TEXT NOT NULL,
        detail     TEXT NOT NULL,
        before_val TEXT,
        after_val  TEXT,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // ── Periodic exposure monitoring (scheduler state) ──────────────────
      // One row per asset the operator has explicitly opted into monitoring.
      // `enabled` defaults to FALSE so deploying this never suddenly fans out
      // provider calls across every historical search result.
      //
      // `locked_at`/`locked_by` implement a LEASE, not a DB transaction lock:
      // a run spans multiple slow HTTP calls, far longer than a transaction
      // should be held open on a serverless connection. A stale lease is
      // reclaimable so a crashed invocation cannot block an asset forever.
      await sql`CREATE TABLE IF NOT EXISTS exposure_monitoring (
        asset_key           TEXT PRIMARY KEY,
        target              TEXT NOT NULL,
        enabled             BOOLEAN NOT NULL DEFAULT false,
        interval_seconds    INT NOT NULL DEFAULT 21600,
        last_attempt_at     TIMESTAMPTZ,
        last_success_at     TIMESTAMPTZ,
        next_run_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_status         TEXT,
        last_error          TEXT,
        consecutive_failures INT NOT NULL DEFAULT 0,
        locked_at           TIMESTAMPTZ,
        locked_by           TEXT,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      // The scheduler's hot query is (enabled, next_run_at) — index it directly.
      await sql`CREATE INDEX IF NOT EXISTS exposure_monitoring_due_idx ON exposure_monitoring (enabled, next_run_at) WHERE enabled`
      await sql`CREATE INDEX IF NOT EXISTS exposure_monitoring_locked_idx ON exposure_monitoring (locked_at)`
      // Per-run execution log (observability). Normalized metadata only —
      // never provider payloads, never credentials.
      await sql`CREATE TABLE IF NOT EXISTS exposure_monitoring_runs (
        id                  BIGSERIAL PRIMARY KEY,
        run_id              TEXT NOT NULL,
        asset_key           TEXT NOT NULL,
        started_at          TIMESTAMPTZ NOT NULL,
        completed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
        status              TEXT NOT NULL,
        providers_attempted INT NOT NULL DEFAULT 0,
        providers_succeeded INT NOT NULL DEFAULT 0,
        providers_failed    INT NOT NULL DEFAULT 0,
        quota_deferrals     INT NOT NULL DEFAULT 0,
        events_created      INT NOT NULL DEFAULT 0,
        duration_ms         INT NOT NULL DEFAULT 0,
        error               TEXT
      )`
      // ── Exposure -> CVE relationship (STEP 3) ───────────────────────────
      // The traceable answer to "WHY does OCTUPUS believe this asset is
      // affected by this CVE?". One row per (asset, port, CVE): the port is
      // part of the identity because the same CVE can be reached through two
      // different services, and each has its own evidence.
      //
      // `status` is active/resolved rather than a delete: history is evidence.
      // A vulnerability that goes away and returns must be visible as exactly
      // that, not as a row that quietly reappeared.
      await sql`CREATE TABLE IF NOT EXISTS exposure_vulnerability (
        asset_key      TEXT NOT NULL,
        port           INT  NOT NULL,          -- 0 = asset-level (no specific service)
        cve_id         TEXT NOT NULL,
        evidence_tier  TEXT NOT NULL,          -- confirmed | strong | product | pivot | weak
        confirmed      BOOLEAN NOT NULL DEFAULT false,
        match_type     TEXT,                   -- cve-search | version | product | pivot | banner
        source_providers TEXT[] NOT NULL DEFAULT '{}',  -- providers that supplied the evidence (may be empty for local correlation)
        product        TEXT,
        version        TEXT,
        matched_via    TEXT,                   -- human-readable provenance, e.g. "local CPE product match"
        observed_at    TIMESTAMPTZ,            -- PROVIDER observation time (never our fetch time)
        fetched_at     TIMESTAMPTZ,            -- when OCTUPUS retrieved it
        risk_score     REAL,                   -- from the EXISTING RBVM path, not a second engine
        severity       TEXT,
        status         TEXT NOT NULL DEFAULT 'active',   -- active | resolved
        first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        resolved_at    TIMESTAMPTZ,
        PRIMARY KEY (asset_key, port, cve_id)
      )`
      // Idempotent migration: the table may predate the array column.
      await sql`ALTER TABLE exposure_vulnerability ADD COLUMN IF NOT EXISTS source_providers TEXT[] NOT NULL DEFAULT '{}'`
      await sql`ALTER TABLE exposure_vulnerability DROP COLUMN IF EXISTS source_provider`
      await sql`CREATE INDEX IF NOT EXISTS exposure_vuln_asset_idx  ON exposure_vulnerability (asset_key, status)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_vuln_cve_idx    ON exposure_vulnerability (cve_id)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_vuln_active_idx ON exposure_vulnerability (status, risk_score DESC)`

      // ── SOC alerts generated by Exposure Intelligence (STEP 3) ──────────
      // No general alert object existed: `alerts_sent` is a Telegram dedup
      // ledger keyed by cve_id, and `triage` is CVE-level workflow state.
      // Neither can express "this ASSET, on this PORT, for this CVE".
      //
      // `fingerprint` is the dedup identity (asset+port+cve). A UNIQUE partial
      // index on the OPEN/ACKNOWLEDGED states is what makes "one active alert
      // per condition" a database guarantee rather than application etiquette:
      // the 15-minute scheduler cannot create a second one even if it races.
      await sql`CREATE TABLE IF NOT EXISTS exposure_alerts (
        id            BIGSERIAL PRIMARY KEY,
        fingerprint   TEXT NOT NULL,
        asset_key     TEXT NOT NULL,
        port          INT  NOT NULL,
        cve_id        TEXT NOT NULL,
        kind          TEXT NOT NULL,            -- new_exposed_vulnerability | risk_increased
        state         TEXT NOT NULL DEFAULT 'open',  -- open | acknowledged | resolved | suppressed
        severity      TEXT NOT NULL,            -- from the EXISTING RBVM severity
        risk_score    REAL,
        previous_risk REAL,
        evidence_tier TEXT NOT NULL,
        payload       JSONB NOT NULL,           -- analyst detail; NEVER provider credentials
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        resolved_at   TIMESTAMPTZ
      )`
      // ── STEP 5: workflow, notification and ticket state ────────────────
      // Added to the EXISTING alert row rather than a parallel table: an alert
      // and its delivery status are one fact, and splitting them would allow
      // them to disagree. Columns only — no data is rewritten.
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notification_state TEXT NOT NULL DEFAULT 'pending'`  // pending|sent|failed|retrying|disabled
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notify_attempts INT NOT NULL DEFAULT 0`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notify_last_attempt_at TIMESTAMPTZ`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notify_next_attempt_at TIMESTAMPTZ`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notify_last_error TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ`
      // What was last ANNOUNCED, so an escalation is distinguishable from a
      // repeat of the same condition without re-reading the notification log.
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notified_severity TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notified_risk REAL`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS escalation_count INT NOT NULL DEFAULT 0`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS ticket_state TEXT NOT NULL DEFAULT 'none'`      // none|pending|open|updated|closed|failed
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS ticket_provider TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS ticket_key TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS ticket_url TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS ticket_last_error TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS suppressed_reason TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS suppressed_by TEXT`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS suppressed_until TIMESTAMPTZ`

      // Deduplication identity. `in_progress` MUST be part of the active set:
      // an alert an analyst is working is still the live one for that finding,
      // and omitting it would let monitoring raise a duplicate underneath them.
      await sql`DROP INDEX IF EXISTS exposure_alerts_active_uniq`
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS exposure_alerts_active_uniq
        ON exposure_alerts (fingerprint) WHERE state IN ('open','acknowledged','in_progress')`
      await sql`CREATE INDEX IF NOT EXISTS exposure_alerts_state_idx ON exposure_alerts (state, created_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_alerts_asset_idx ON exposure_alerts (asset_key, created_at DESC)`
      // ── STEP 5.1: atomic delivery claim ────────────────────────────────
      // `notify_claimed_at` / `notify_claimed_by` turn the state transition
      // into the claim. Previously the claim only bumped `notify_attempts` and
      // left the state at 'pending' for the duration of the HTTP call, so an
      // overlapping run re-selected the same row — reproduced as 2 Telegram
      // sends for 1 alert. A row moves to 'sending' in the SAME statement that
      // selects it, which no concurrent claimer can then see.
      //
      // `notify_claimed_at` also drives STALE-CLAIM RECOVERY: a serverless
      // crash mid-send leaves a row stuck in 'sending', and only an expired
      // claim may be reclaimed.
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notify_claimed_at TIMESTAMPTZ`
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notify_claimed_by TEXT`
      // Delivery latency is REPORTED, never invented: it is the difference
      // between two timestamps we actually recorded.
      await sql`ALTER TABLE exposure_alerts ADD COLUMN IF NOT EXISTS notify_first_queued_at TIMESTAMPTZ`

      // Outbox lookup: which alerts still need delivering. `sending` is included
      // so the stale-claim sweep is index-backed too.
      await sql`DROP INDEX IF EXISTS exposure_alerts_notify_idx`
      await sql`CREATE INDEX IF NOT EXISTS exposure_alerts_notify_idx
        ON exposure_alerts (notification_state, notify_next_attempt_at)
        WHERE notification_state IN ('pending','retrying','sending')`
      // Backfill so alerts created before this migration have a queue time and
      // therefore a measurable latency rather than a null.
      await sql`UPDATE exposure_alerts SET notify_first_queued_at = created_at WHERE notify_first_queued_at IS NULL`

      // ── Alert lifecycle audit trail ────────────────────────────────────
      // `exposure_events` records ASSET changes; nothing recorded what happened
      // to an ALERT. This is that trail: append-only, normalized, and never a
      // second source of alert state — the alert row remains authoritative.
      await sql`CREATE TABLE IF NOT EXISTS exposure_alert_events (
        id         BIGSERIAL PRIMARY KEY,
        alert_id   BIGINT NOT NULL,
        type       TEXT NOT NULL,   -- alert_created | alert_acknowledged | ... | telegram_sent | ticket_created
        actor      TEXT NOT NULL,   -- 'system' | 'scheduler' | a user id
        detail     TEXT,
        metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,  -- never credentials
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
      await sql`CREATE INDEX IF NOT EXISTS exposure_alert_events_alert_idx
        ON exposure_alert_events (alert_id, occurred_at, id)`

      // ── Work items (STEP 5) ────────────────────────────────────────────
      // Backing store for the `internal` ticket provider, so a SOC can run the
      // workflow without buying a ticketing product. External providers (Jira,
      // ServiceNow, ...) store only their reference on the alert row itself.
      // UNIQUE on alert_id is what makes repeated monitoring UPDATE one work
      // item instead of opening a new one every cycle.
      await sql`CREATE TABLE IF NOT EXISTS exposure_tickets (
        id           BIGSERIAL PRIMARY KEY,
        alert_id     BIGINT NOT NULL UNIQUE,
        provider     TEXT NOT NULL,
        title        TEXT NOT NULL,
        description  TEXT NOT NULL,
        state        TEXT NOT NULL DEFAULT 'open',   -- open | closed
        close_reason TEXT,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        closed_at    TIMESTAMPTZ
      )`
      await sql`CREATE INDEX IF NOT EXISTS exposure_tickets_state_idx ON exposure_tickets (state, updated_at DESC)`

      // Indexed product lookup for CVE correlation (item 32).
      // Without this, `data->'products' ? 'apache'` is a sequential scan over
      // ~86k CVEs on every refresh. GIN on the extracted array makes the
      // containment operator index-backed.
      await sql`CREATE INDEX IF NOT EXISTS cves_products_gin ON cves USING GIN ((data->'products'))`
      await sql`CREATE INDEX IF NOT EXISTS cves_vendors_gin  ON cves USING GIN ((data->'vendors'))`

      await sql`CREATE INDEX IF NOT EXISTS exposure_monitoring_runs_time_idx  ON exposure_monitoring_runs (completed_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_monitoring_runs_asset_idx ON exposure_monitoring_runs (asset_key, completed_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_events_asset_idx ON exposure_events (asset_key, occurred_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_events_time_idx  ON exposure_events (occurred_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_history_ip_idx        ON exposure_history (ip)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_history_domain_idx    ON exposure_history (domain)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_history_last_seen_idx ON exposure_history (last_seen DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_history_risk_idx      ON exposure_history (risk_score DESC)`

      // ══════════════════════════════════════════════════════════════════
      // PER-USER TENANCY
      // ══════════════════════════════════════════════════════════════════
      // Every user owns their own attack surface. Two analysts may monitor the
      // SAME IP without seeing, overwriting or resolving each other's records,
      // so identity becomes (user_id, asset_key) rather than asset_key alone.
      //
      // WHAT STAYS SHARED, and why:
      //   cves / zero_days        public threat intelligence — identical for
      //                           everyone, and duplicating 169 MB per user
      //                           would be absurd.
      //   exposure_provider_quota the API keys belong to the PLATFORM, so the
      //                           hourly budget is a genuinely shared physical
      //                           resource. Fairness is enforced in the
      //                           scheduler, not by splitting the budget.
      //   *_cache tables          cached PROVIDER responses keyed by query.
      //                           The data is public and identical per query,
      //                           so sharing saves large amounts of quota and
      //                           reveals nothing about who searched.
      //
      // The PK swaps run inside DO blocks guarded on the NEW constraint name,
      // so `initDb()` can run on every cold start without re-doing surgery.
      const legacyOwner = process.env.EXPOSURE_LEGACY_OWNER_ID || null

      // Rows created before tenancy existed are attributed to the OLDEST
      // account (the installation owner). A sentinel is used only when no user
      // exists at all — a fresh install, where these tables are empty anyway.
      // Nothing is ever deleted: unattributable history would be data loss.
      await sql`ALTER TABLE exposure_asset_state      ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_history          ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_monitoring       ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_monitoring_runs  ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_events           ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_vulnerability    ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_alerts           ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_alert_events     ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE exposure_tickets          ADD COLUMN IF NOT EXISTS user_id TEXT`
      await sql`ALTER TABLE triage                    ADD COLUMN IF NOT EXISTS user_id TEXT`

      // Resolved in JS, not composed into the template: the Neon HTTP driver
      // interpolates VALUES, not SQL fragments — a nested tagged template would
      // be serialized as a parameter and silently corrupt the backfill.
      const ownerRows = (await sql`SELECT id FROM "user" ORDER BY "createdAt" ASC LIMIT 1`) as Array<{ id: string }>
      const owner = legacyOwner ?? ownerRows[0]?.id ?? "__legacy__"
      await sql`UPDATE exposure_asset_state     SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_history         SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_monitoring      SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_monitoring_runs SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_events          SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_vulnerability   SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_alerts          SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_alert_events    SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE exposure_tickets         SET user_id = ${owner} WHERE user_id IS NULL`
      await sql`UPDATE triage                   SET user_id = ${owner} WHERE user_id IS NULL`

      // ── Identity swaps: asset_key alone -> (user_id, asset_key) ──
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_asset_state_pk_tenant') THEN
          ALTER TABLE exposure_asset_state DROP CONSTRAINT IF EXISTS exposure_asset_state_pkey;
          ALTER TABLE exposure_asset_state ALTER COLUMN user_id SET NOT NULL;
          ALTER TABLE exposure_asset_state ADD CONSTRAINT exposure_asset_state_pk_tenant PRIMARY KEY (user_id, asset_key);
        END IF;
      END $$`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_history_pk_tenant') THEN
          ALTER TABLE exposure_history DROP CONSTRAINT IF EXISTS exposure_history_pkey;
          ALTER TABLE exposure_history ALTER COLUMN user_id SET NOT NULL;
          ALTER TABLE exposure_history ADD CONSTRAINT exposure_history_pk_tenant PRIMARY KEY (user_id, asset_key);
        END IF;
      END $$`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_monitoring_pk_tenant') THEN
          ALTER TABLE exposure_monitoring DROP CONSTRAINT IF EXISTS exposure_monitoring_pkey;
          ALTER TABLE exposure_monitoring ALTER COLUMN user_id SET NOT NULL;
          ALTER TABLE exposure_monitoring ADD CONSTRAINT exposure_monitoring_pk_tenant PRIMARY KEY (user_id, asset_key);
        END IF;
      END $$`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'exposure_vulnerability_pk_tenant') THEN
          ALTER TABLE exposure_vulnerability DROP CONSTRAINT IF EXISTS exposure_vulnerability_pkey;
          ALTER TABLE exposure_vulnerability ALTER COLUMN user_id SET NOT NULL;
          ALTER TABLE exposure_vulnerability ADD CONSTRAINT exposure_vulnerability_pk_tenant PRIMARY KEY (user_id, asset_key, port, cve_id);
        END IF;
      END $$`
      await sql`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'triage_pk_tenant') THEN
          ALTER TABLE triage DROP CONSTRAINT IF EXISTS triage_pkey;
          ALTER TABLE triage ALTER COLUMN user_id SET NOT NULL;
          ALTER TABLE triage ADD CONSTRAINT triage_pk_tenant PRIMARY KEY (user_id, cve_id);
        END IF;
      END $$`

      // ── Alert deduplication is now PER USER ──
      // Without user_id in this index, the first analyst to be alerted about a
      // CVE would silently suppress the alert for everyone else monitoring the
      // same host — a security failure, not just a UX one.
      await sql`DROP INDEX IF EXISTS exposure_alerts_active_uniq`
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS exposure_alerts_active_uniq
        ON exposure_alerts (user_id, fingerprint) WHERE state IN ('open','acknowledged','in_progress')`

      // ── Tenant-scoped lookup paths ──
      await sql`CREATE INDEX IF NOT EXISTS exposure_alerts_user_idx        ON exposure_alerts (user_id, state, created_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_alert_events_user_idx  ON exposure_alert_events (user_id, occurred_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_tickets_user_idx       ON exposure_tickets (user_id)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_events_user_idx        ON exposure_events (user_id, occurred_at DESC)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_vuln_user_idx          ON exposure_vulnerability (user_id, status)`
      await sql`CREATE INDEX IF NOT EXISTS exposure_monitoring_runs_user_idx ON exposure_monitoring_runs (user_id, completed_at DESC)`
      // The scheduler's hot path: due assets, per user, for round-robin fairness.
      await sql`DROP INDEX IF EXISTS exposure_monitoring_due_idx`
      await sql`CREATE INDEX IF NOT EXISTS exposure_monitoring_due_idx
        ON exposure_monitoring (enabled, next_run_at, user_id) WHERE enabled`

    })().catch((e) => {
      ready = null
      throw e
    })
  }
  return ready
}
