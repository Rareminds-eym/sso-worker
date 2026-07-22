-- ============================================================
-- ARJUN TEST ACCOUNT - AUTH DATABASE
-- Email: arjun.sharma@seaim.ac.in
-- User ID shared with SkillPassport DB: 6f3a9d2e-c5b8-4e1f-a7d9-3c6f8b2e5a9d
-- Role: learner
-- Organization: SkillPassport Platform
-- ============================================================

BEGIN;

-- 1. User login
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked") VALUES
  ('6f3a9d2e-c5b8-4e1f-a7d9-3c6f8b2e5a9d', 'arjun.sharma@seaim.ac.in', '$2b$12$wa3wMzjo7belyU3c36KAf.NOO00rgZr5zlW1NzZnse5ZPUTOYV19.', true, '2026-06-09 13:00:00.000+00', '2026-06-09 13:00:00.000+00', null, false)
ON CONFLICT DO NOTHING;

-- 2. Platform membership
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
  ('7e4b0f3c-d6c9-5f2a-b8e0-4d7a9c3f6b0e', '6f3a9d2e-c5b8-4e1f-a7d9-3c6f8b2e5a9d', '00000000-0000-0000-0000-000000000001', '2026-06-09 13:00:00.000+00', 'active')
ON CONFLICT DO NOTHING;

-- 3. Learner role
INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
  ('8f5c1a4d-e7d0-6a3b-c9f1-5e8b0d4a7c1f', '7e4b0f3c-d6c9-5f2a-b8e0-4d7a9c3f6b0e', '8d018d55-46f4-4e67-b6a5-8c216737a374', '2026-06-09 13:00:00.000+00')
ON CONFLICT DO NOTHING;

COMMIT;
