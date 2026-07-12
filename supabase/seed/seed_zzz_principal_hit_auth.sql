-- ============================================================
-- PRINCIPAL HIT TEST ACCOUNT - AUTH DATABASE
-- Email: principal.hit@harshainstitute.edu.in
-- Password: intentionally not stored in plaintext in this file.
-- User ID shared with SkillPassport DB: eb7313eb-bd50-582b-8da5-412ddf8d1ecd
-- Role: learner
-- Organization: SkillPassport Platform
-- ============================================================

BEGIN;

-- 1. User login
INSERT INTO "public"."users"
  ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked")
VALUES
  ('eb7313eb-bd50-582b-8da5-412ddf8d1ecd', 'principal.hit@harshainstitute.edu.in', '$2a$12$9UBXM8IolJEJXeIHLMzbd.5BJUIDDhEV863YjyeNiJuhPfXFDlI2S', true, '2026-07-11 00:00:00+00', '2026-07-11 00:00:00+00', null, false)
ON CONFLICT DO NOTHING;

-- 2. Platform membership
INSERT INTO "public"."memberships"
  ("id", "user_id", "org_id", "created_at", "status")
VALUES
  ('04449298-7301-5f2a-94bb-aba7b1f153ed', 'eb7313eb-bd50-582b-8da5-412ddf8d1ecd', '00000000-0000-0000-0000-000000000001', '2026-07-11 00:00:00+00', 'active')
ON CONFLICT DO NOTHING;

-- 3. Learner role
INSERT INTO "public"."membership_roles"
  ("id", "membership_id", "role_id", "created_at")
VALUES
  ('caa051c3-2b00-5a0b-99eb-3e336f1a1be5', '04449298-7301-5f2a-94bb-aba7b1f153ed', '8d018d55-46f4-4e67-b6a5-8c216737a374', '2026-07-11 00:00:00+00')
ON CONFLICT DO NOTHING;

COMMIT;
