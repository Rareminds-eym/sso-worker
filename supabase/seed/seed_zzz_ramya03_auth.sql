-- ============================================================
-- RAMYA TEST ACCOUNT - AUTH DATABASE
-- Email: ramya03@acharya.ac.in
-- Password: intentionally not stored in plaintext in this file.
-- User ID shared with SkillPassport DB: 3c14e807-1f15-5dec-b361-88fdb7a28820
-- Role: learner
-- Organization: SkillPassport Platform
-- ============================================================

BEGIN;

-- 1. User login
INSERT INTO "public"."users"
  ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked")
VALUES
  ('3c14e807-1f15-5dec-b361-88fdb7a28820', 'ramya03@acharya.ac.in', '$2a$12$9UBXM8IolJEJXeIHLMzbd.5BJUIDDhEV863YjyeNiJuhPfXFDlI2S', true, '2026-07-11 00:00:00+00', '2026-07-11 00:00:00+00', null, false)
ON CONFLICT DO NOTHING;

-- 2. Platform membership
INSERT INTO "public"."memberships"
  ("id", "user_id", "org_id", "created_at", "status")
VALUES
  ('99af3a29-3fec-5506-bff5-9dc999ddab2c', '3c14e807-1f15-5dec-b361-88fdb7a28820', '00000000-0000-0000-0000-000000000001', '2026-07-11 00:00:00+00', 'active')
ON CONFLICT DO NOTHING;

-- 3. Learner role
INSERT INTO "public"."membership_roles"
  ("id", "membership_id", "role_id", "created_at")
VALUES
  ('c479faf4-c703-5a3d-b29c-92d16d4eaf2f', '99af3a29-3fec-5506-bff5-9dc999ddab2c', '8d018d55-46f4-4e67-b6a5-8c216737a374', '2026-07-11 00:00:00+00')
ON CONFLICT DO NOTHING;

COMMIT;
