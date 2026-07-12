/**
 * Couche persistance Neon PostgreSQL (serveur uniquement).
 * Les tables sont créées automatiquement à la première requête.
 */
import { neon } from "@neondatabase/serverless"

export const sql = neon(process.env.DATABASE_URL || "")

let ready: Promise<void> | null = null

/** Crée les tables si besoin (une seule fois par instance). */
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
      // État de synchronisation (1 seule ligne, id=1)
      await sql`CREATE TABLE IF NOT EXISTS sync_state (
        id          INT PRIMARY KEY,
        last_sync   TIMESTAMPTZ,
        last_run_at TIMESTAMPTZ,
        total_cves  INT DEFAULT 0,
        last_status TEXT
      )`
    })()
  }
  return ready
}
