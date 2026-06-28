-- Migration: Add session family columns (family_id, family_created_at, replaced_by)
-- Phase: Expand (1 of Expand–Migrate–Contract)
-- Breaking: No
--
-- Adds token-family tracking columns to public.sessions to support
-- single-winner refresh-token rotation, family-scoped theft revocation, and
-- absolute-session-lifetime enforcement (refresh-token-auth-hardening spec):
--
--   * family_id          -- root session id of the token family; denormalized so
--                           family revoke is a single indexed UPDATE instead of a
--                           recursive rotated_from walk.
--   * family_created_at  -- initial-login timestamp for the family, propagated to
--                           every rotated member; basis for the absolute-lifetime gate.
--   * replaced_by        -- forward pointer to the successor session set atomically
--                           during the rotation claim; supports audit/forensics and
--                           overlap reasoning.
--
-- All three columns are nullable in this expand phase (non-destructive). A later,
-- approval-gated Contract migration adds NOT NULL after backfill is verified.
--
-- DDL only — no DML (Supabase migration convention; backfill lives in a separate task).
-- Idempotent: safe to re-run (IF NOT EXISTS columns/index + guarded constraint add).
--
-- Requirements: 1.4, 2.3, 3.2, 5.1, 7.3, 20.4

-- New columns (all nullable — non-destructive expand).
ALTER TABLE "public"."sessions" ADD COLUMN IF NOT EXISTS "family_id" "uuid";
ALTER TABLE "public"."sessions" ADD COLUMN IF NOT EXISTS "family_created_at" timestamp with time zone;
ALTER TABLE "public"."sessions" ADD COLUMN IF NOT EXISTS "replaced_by" "uuid";

-- Partial index on active (non-revoked) sessions for fast family-scoped lookups/revocation.
CREATE INDEX IF NOT EXISTS "idx_sessions_family" ON "public"."sessions" USING "btree" ("family_id") WHERE ("revoked" = false);

-- Self-referential forward-pointer FK, mirroring sessions_rotated_from_fkey.
-- Guarded so re-running the migration does not error if the constraint already exists.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM "pg_constraint"
    WHERE "conname" = 'sessions_replaced_by_fkey'
      AND "conrelid" = '"public"."sessions"'::"regclass"
  ) THEN
    ALTER TABLE ONLY "public"."sessions"
      ADD CONSTRAINT "sessions_replaced_by_fkey" FOREIGN KEY ("replaced_by") REFERENCES "public"."sessions"("id");
  END IF;
END
$$;
