-- Migration for SSO / Auth DB (sso-worker)
-- Seeds 1 Soundarya learner account: abhisheknd267@gmail.com
-- Safe, standalone, and idempotent (can be re-run safely after sso reset).

BEGIN;

-- 1. Ensure prerequisite roles exist in "public"."roles"
INSERT INTO "public"."roles" ("id", "name", "description", "created_at") VALUES
  ('8d018d55-46f4-4e67-b6a5-8c216737a374', 'learner', 'Self-directed learner', NOW())
ON CONFLICT ("id") DO NOTHING;

-- 2. Ensure Soundarya Organization exists in "public"."organizations"
INSERT INTO "public"."organizations" ("id", "name", "slug", "created_at") VALUES
  ('284c9ed9-cd13-584d-b5bc-e198866b917b', 'Soundarya Institute of Management and Science', 'soundarya-institute-management-science', NOW())
ON CONFLICT ("id") DO NOTHING;

-- 3. Seed the Soundarya learner user
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata") VALUES 
('69b35ea7-3c06-488f-b360-32bc2c60e729', 'abhisheknd267@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', 'true', '2026-08-29 07:55:59.826969+00', '2026-08-29 08:09:37.137481+00', null, 'false', '{"role": "learner", "lastName": "nd", "firstName": "Abhishek", "contact_number": "7892915864"}')
ON CONFLICT ("id") DO UPDATE SET
  email = EXCLUDED.email,
  password_hash = EXCLUDED.password_hash,
  user_metadata = EXCLUDED.user_metadata,
  updated_at = NOW(),
  is_blocked = false;

-- 4. Seed the Soundarya learner membership
-- Handle both id conflict and unique constraint on (user_id, org_id)
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
('a9e8f6d2-3c06-488f-b360-32bc2c60e729', '69b35ea7-3c06-488f-b360-32bc2c60e729', '284c9ed9-cd13-584d-b5bc-e198866b917b', NOW(), 'active')
ON CONFLICT ("user_id", "org_id") DO UPDATE SET
  status = 'active';

-- 5. Assign learner role to the membership
INSERT INTO "public"."membership_roles" ("membership_id", "role_id") VALUES
('a9e8f6d2-3c06-488f-b360-32bc2c60e729', '8d018d55-46f4-4e67-b6a5-8c216737a374')
ON CONFLICT ("membership_id", "role_id") DO NOTHING;


COMMIT;

-- ============================================================
-- VERIFICATION QUERIES
-- ============================================================
-- Run these after the migration to verify success:

-- 1. Check user exists in public.users
SELECT 
  id, 
  email, 
  is_email_verified,
  user_metadata->>'firstName' as first_name,
  user_metadata->>'lastName' as last_name,
  user_metadata->>'contact_number' as phone,
  created_at,
  updated_at,
  is_blocked
FROM public.users 
WHERE id = '69b35ea7-3c06-488f-b360-32bc2c60e729';

-- 2. Check membership record
SELECT 
  m.id as membership_id,
  m.user_id,
  m.org_id,
  o.name as organization_name,
  m.status,
  m.created_at
FROM public.memberships m
LEFT JOIN public.organizations o ON o.id = m.org_id
WHERE m.user_id = '69b35ea7-3c06-488f-b360-32bc2c60e729';

-- 3. Check role assignment
SELECT 
  m.user_id,
  u.email,
  r.name as role_name,
  o.name as organization_name
FROM public.membership_roles mr
JOIN public.memberships m ON m.id = mr.membership_id
JOIN public.users u ON u.id = m.user_id
JOIN public.roles r ON r.id = mr.role_id
JOIN public.organizations o ON o.id = m.org_id
WHERE m.user_id = '69b35ea7-3c06-488f-b360-32bc2c60e729';

-- Expected: 1 row with all data matching abhisheknd267@gmail.com

-- ============================================================
-- LOGIN CREDENTIALS
-- ============================================================
-- Email: abhisheknd267@gmail.com
-- Password: Welcome@123
-- 
-- IMPORTANT: User should change password after first login
-- Note: Password hash used is: $2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.
-- ============================================================
