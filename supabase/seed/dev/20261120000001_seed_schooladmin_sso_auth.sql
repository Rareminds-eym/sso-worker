-- =============================================================================
-- SSO Auth DB seed — School Admin demo login
-- Ensures schooladmin@testdev.com can log in with password: Test_123456
-- Creates ALL required SSO records if missing; idempotent.
--
-- Usage (SSO DB — port 54332):
--   psql postgresql://postgres:postgres@127.0.0.1:54332/postgres \
--        -f sso-worker/supabase/seed/dev/20261120000001_seed_schooladmin_sso_auth.sql
-- =============================================================================

BEGIN;

-- 1. Organisation (Greenwood High School) ─────────────────────────────────────
INSERT INTO public.organizations (id, name, slug, metadata)
VALUES (
  'a1b2c3d4-0002-4000-8000-000000000002',
  'Greenwood High School',
  'greenwood-high-school',
  '{"is_demo": true, "demo_batch": "school_admin_demo_v1"}'
)
ON CONFLICT (id) DO UPDATE
  SET name = EXCLUDED.name,
      metadata = EXCLUDED.metadata;

-- 2. User (schooladmin@testdev.com) ───────────────────────────────────────────
-- bcrypt hash (cost 12) for password: Test_123456
INSERT INTO public.users (id, email, password_hash, is_email_verified, is_blocked, user_metadata)
VALUES (
  'a1b2c3d4-0001-4000-8000-000000000001',
  'schooladmin@testdev.com',
  '$2a$12$dlkN954O62Mx8emL14UE9uYLvMKQm1qXW1q3x8Utb.M8cWB4SRaXi',
  true,
  false,
  '{"first_name": "School", "last_name": "Admin"}'
)
ON CONFLICT (id) DO UPDATE
  SET password_hash     = EXCLUDED.password_hash,
      is_email_verified = EXCLUDED.is_email_verified,
      is_blocked        = EXCLUDED.is_blocked,
      updated_at        = NOW();

-- 3. Membership (user ↔ org) ───────────────────────────────────────────────────
INSERT INTO public.memberships (id, user_id, org_id, status)
VALUES (
  'a1b2c3d4-0003-4000-8000-000000000003',
  'a1b2c3d4-0001-4000-8000-000000000001',
  'a1b2c3d4-0002-4000-8000-000000000002',
  'active'
)
ON CONFLICT (id) DO UPDATE
  SET status = 'active';

-- 4. Membership role (school_admin) ───────────────────────────────────────────
-- role_id for 'school_admin' is stable in the initial dev seed:
--   a750dd44-691f-4636-9d73-9aaa47476c87
INSERT INTO public.membership_roles (id, membership_id, role_id)
VALUES (
  'a1b2c3d4-0004-4000-8000-000000000004',
  'a1b2c3d4-0003-4000-8000-000000000003',
  'a750dd44-691f-4636-9d73-9aaa47476c87'
)
ON CONFLICT (id) DO NOTHING;

COMMIT;

-- Verify ──────────────────────────────────────────────────────────────────────
SELECT
  (SELECT COUNT(*) FROM public.users        WHERE id = 'a1b2c3d4-0001-4000-8000-000000000001') AS user_exists,
  (SELECT COUNT(*) FROM public.organizations WHERE id = 'a1b2c3d4-0002-4000-8000-000000000002') AS org_exists,
  (SELECT COUNT(*) FROM public.memberships   WHERE id = 'a1b2c3d4-0003-4000-8000-000000000003') AS membership_exists,
  (SELECT COUNT(*) FROM public.membership_roles WHERE id = 'a1b2c3d4-0004-4000-8000-000000000004') AS role_assigned;
