-- ============================================================
-- NARESH TEST ACCOUNT - AUTH DATABASE
-- Email: naresh.kumar@seaim.ac.in
-- User ID shared with SkillPassport DB: 8b2e4c9a-f1d3-4a6e-b5c2-7d9e3a1f5b8c
-- Role: learner
-- Organization: SkillPassport Platform
-- ============================================================

BEGIN;

-- 1. User login
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked") VALUES
  ('8b2e4c9a-f1d3-4a6e-b5c2-7d9e3a1f5b8c', 'naresh.kumar@seaim.ac.in', '$2b$12$wa3wMzjo7belyU3c36KAf.NOO00rgZr5zlW1NzZnse5ZPUTOYV19.', true, '2026-06-09 12:05:00.000+00', '2026-06-09 12:05:00.000+00', null, false)
ON CONFLICT DO NOTHING;

-- 2. Platform membership
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
  ('9d3f5c7a-e2b1-4e8c-a6f3-8b1c9d7e2f4a', '8b2e4c9a-f1d3-4a6e-b5c2-7d9e3a1f5b8c', '00000000-0000-0000-0000-000000000001', '2026-06-09 12:05:00.000+00', 'active')
ON CONFLICT DO NOTHING;

-- 3. Learner role
INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
  ('1e5a8c3d-9f7b-4d2e-6a1c-5b8e3f9c2d7a', '9d3f5c7a-e2b1-4e8c-a6f3-8b1c9d7e2f4a', '8d018d55-46f4-4e67-b6a5-8c216737a374', '2026-06-09 12:05:00.000+00')
ON CONFLICT DO NOTHING;

COMMIT;
