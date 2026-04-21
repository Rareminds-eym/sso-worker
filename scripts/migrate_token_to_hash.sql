-- ─── Migration: Rename token → token_hash ────────────────────────
-- Run this against an EXISTING database to apply the schema changes.
-- For NEW databases, schema.sql already has the correct column names.
--
-- ⚠️  DOWNTIME NOTICE:
--   These ALTER TABLE statements acquire an ACCESS EXCLUSIVE lock.
--   Run during a maintenance window. On small tables (<10k rows)
--   this completes in milliseconds.
-- ──────────────────────────────────────────────────────────────────

-- 1. Password resets
ALTER TABLE password_resets RENAME COLUMN token TO token_hash;
DROP INDEX IF EXISTS idx_password_resets_token;
CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets (token_hash);

-- 2. Email verifications
ALTER TABLE email_verifications RENAME COLUMN token TO token_hash;
DROP INDEX IF EXISTS idx_email_verifications_token;
CREATE INDEX IF NOT EXISTS idx_email_verifications_token_hash ON email_verifications (token_hash);

-- 3. Invites
ALTER TABLE invites RENAME COLUMN token TO token_hash;
DROP INDEX IF EXISTS idx_invites_token;
CREATE INDEX IF NOT EXISTS idx_invites_token_hash ON invites (token_hash);
CREATE INDEX IF NOT EXISTS idx_invites_email_org_active ON invites (email, org_id, accepted) WHERE accepted = false;

-- 4. Add cleanup function (idempotent — CREATE OR REPLACE)
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS integer AS $fn$
DECLARE
  v_deleted integer := 0;
  v_count integer;
BEGIN
  DELETE FROM email_verifications WHERE expires_at < now() - interval '48 hours';
  GET DIAGNOSTICS v_count = row_count;
  v_deleted := v_deleted + v_count;

  DELETE FROM password_resets WHERE expires_at < now() - interval '2 hours';
  GET DIAGNOSTICS v_count = row_count;
  v_deleted := v_deleted + v_count;

  DELETE FROM invites WHERE expires_at < now() - interval '14 days';
  GET DIAGNOSTICS v_count = row_count;
  v_deleted := v_deleted + v_count;

  RETURN v_deleted;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER;

-- ─── Post-migration verification ────────────────────────────────
-- Run these queries to confirm the migration succeeded:
--
--   SELECT column_name FROM information_schema.columns
--     WHERE table_name = 'password_resets' AND column_name = 'token_hash';
--   SELECT column_name FROM information_schema.columns
--     WHERE table_name = 'email_verifications' AND column_name = 'token_hash';
--   SELECT column_name FROM information_schema.columns
--     WHERE table_name = 'invites' AND column_name = 'token_hash';
--
-- Expected: 1 row each for token_hash.
