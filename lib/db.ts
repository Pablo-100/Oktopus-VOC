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
    })()
  }
  return ready
}
