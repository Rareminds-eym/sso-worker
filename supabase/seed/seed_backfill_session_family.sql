-- Seed (Migrate phase): Backfill session family columns on public.sessions
-- Phase: Migrate (2 of Expand–Migrate–Contract)
-- Breaking: No
-- Type: DML (data manipulation) — lives in seed/, NOT in migrations/
--        (Supabase convention: migration files are DDL-only; backfill/DML is seed-side.
--         See steering 04-database-api-standards §11.8.1.)
--
-- Backfills the family-tracking columns added by the Expand migration
-- 20260609110716_session_family_columns.sql so that pre-existing sessions keep
-- working under single-winner rotation, family-scoped theft revocation, and the
-- absolute-session-lifetime gate (refresh-token-auth-hardening spec):
--
--   * family_id          -- root session id of the token family
--   * family_created_at  -- initial-login timestamp for the family (true origin)
--
-- Idempotent: every UPDATE is guarded by `family_id IS NULL`, so already-backfilled
-- rows are skipped and the script is safe to re-run. New sessions created by the
-- rotate_session RPC set these columns directly and are likewise untouched here.
--
-- Run (requires explicit user approval per Supabase command policy):
--   supabase db seed --file supabase/seed/seed_backfill_session_family.sql
--
-- Requirements: 5.1, 20.4

BEGIN;

-- 1) Root sessions (no parent): the family is the session itself, and the family
--    origin timestamp is the session's own created_at.
UPDATE "public"."sessions"
   SET "family_id" = "id",
       "family_created_at" = "created_at"
 WHERE "rotated_from" IS NULL
   AND "family_id" IS NULL;

-- 2) Rotated sessions: walk the rotated_from chain back to the root via a recursive
--    CTE, inheriting the root's id as family_id and the root's created_at as
--    family_created_at. Guarded by family_id IS NULL for idempotent re-runs.
WITH RECURSIVE "chain" AS (
    SELECT "id",
           "rotated_from",
           "id"         AS "root_id",
           "created_at" AS "root_created"
      FROM "public"."sessions"
     WHERE "rotated_from" IS NULL
    UNION ALL
    SELECT "s"."id",
           "s"."rotated_from",
           "c"."root_id",
           "c"."root_created"
      FROM "public"."sessions" "s"
      JOIN "chain" "c" ON "s"."rotated_from" = "c"."id"
)
UPDATE "public"."sessions" "s"
   SET "family_id" = "c"."root_id",
       "family_created_at" = "c"."root_created"
  FROM "chain" "c"
 WHERE "s"."id" = "c"."id"
   AND "s"."family_id" IS NULL;

COMMIT;
