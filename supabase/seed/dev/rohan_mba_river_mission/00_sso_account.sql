-- LOCAL DEVELOPMENT ONLY. Target: SSO database. Optional login provisioning.
-- In the same session, SET seed.demo_password_hash to a newly generated bcrypt hash before running.
-- Requires the reference product/plan IDs to exist. No existing user credentials are copied.
-- Migration for SSO / Auth DB (sso-worker)
-- Seeds learner account: rohan.iyer.mba@example.com
-- Safe, standalone, and idempotent.

BEGIN;

-- 1. Ensure prerequisite roles exist in "public"."roles"
INSERT INTO "public"."roles" ("id", "name", "description", "created_at") VALUES
  ('8d018d55-46f4-4e67-b6a5-8c216737a374', 'learner', 'Self-directed learner', NOW())
ON CONFLICT ("id") DO NOTHING;

-- 2. Ensure Platform and Bengaluru Institute of Management Organizations exist in "public"."organizations"
INSERT INTO "public"."organizations" ("id", "name", "slug", "created_by", "created_at", "metadata") VALUES
  ('00000000-0000-0000-0000-000000000001', 'SkillPassport Platform', 'platform', null, NOW(), '{"is_platform_org": true}'::jsonb),
  ('2fcd9dc2-9a24-5c52-8d91-8b414996f23d', 'Bengaluru Institute of Management', 'bengaluru-management-demo', null, NOW(), '{}'::jsonb)
ON CONFLICT ("id") DO NOTHING;

-- 3. Seed User
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata") VALUES 
  ('02f0a43d-3c0a-5026-b44f-5d0696e75f19', 'rohan.iyer.mba@example.com', current_setting('seed.demo_password_hash'), true, '2026-06-09 11:27:01.022313+00', NOW(), '2026-06-09 16:11:25.459+00', false, '{"role": "learner", "firstName": "Rohan", "lastName": "Iyer", "contact_number": ""}'::jsonb)
ON CONFLICT ("id") DO UPDATE SET
  email = EXCLUDED.email,
  user_metadata = EXCLUDED.user_metadata,
  updated_at = NOW(),
  is_blocked = false;

-- 4. Seed Membership
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
  ('f3b93f81-b670-543a-898e-65605aa16765', '02f0a43d-3c0a-5026-b44f-5d0696e75f19', '00000000-0000-0000-0000-000000000001', '2026-06-09 11:27:01.022313+00', 'active')
ON CONFLICT ("user_id", "org_id") DO UPDATE SET
  status = 'active';

-- 5. Assign learner role to membership
INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
  ('e810192c-b31e-5469-aadf-69feda648082', 'f3b93f81-b670-543a-898e-65605aa16765', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW())
ON CONFLICT ("membership_id", "role_id") DO NOTHING;

-- 6. Link Organization and Membership to Products (SkillPassport & LTE)
INSERT INTO "public"."organization_products" ("org_id", "product_id", "active") VALUES
  ('00000000-0000-0000-0000-000000000001', '7352d0f4-88a6-4e14-9421-6c5706791973', true),
  ('00000000-0000-0000-0000-000000000001', '912d5049-e195-46e9-a319-49e3502bf7e7', true)
ON CONFLICT ("org_id", "product_id") DO UPDATE SET active = true;

INSERT INTO "public"."membership_products" ("membership_id", "product_id") VALUES
  ('f3b93f81-b670-543a-898e-65605aa16765', '7352d0f4-88a6-4e14-9421-6c5706791973'),
  ('f3b93f81-b670-543a-898e-65605aa16765', '912d5049-e195-46e9-a319-49e3502bf7e7')
ON CONFLICT ("membership_id", "product_id") DO NOTHING;

-- 7. Seed Subscription in SSO DB
INSERT INTO "public"."subscriptions" (
  "id", "user_id", "plan_id", "full_name", "email", "plan_code", 
  "plan_type", "plan_amount", "billing_cycle", "features", "status", 
  "subscription_start_date", "subscription_end_date", "is_organization_subscription", 
  "purchased_by", "seat_count", "created_at", "updated_at", "product_id"
) VALUES (
  'af3e7e1f-92a5-535a-aecd-3f5b628beb84',
  '02f0a43d-3c0a-5026-b44f-5d0696e75f19',
  '8460ee67-18ff-4c2e-ac57-7e1f87dc8316',
  'Rohan Iyer',
  'rohan.iyer.mba@example.com',
  'premium',
  'Career Accelerator',
  999,
  'yearly',
  '["Advanced career assessment", "Skill gap report", "6-month learning plan", "Portfolio creation", "Course/LTE access", "Opportunity matching", "Interview readiness tools", "Resume/profile review", "Priority opportunity matching", "Advanced portfolio proof", "Career progress analytics"]'::jsonb,
  'active',
  '2026-11-13 10:00:00+00',
  '2027-11-13 10:00:00+00',
  false,
  '02f0a43d-3c0a-5026-b44f-5d0696e75f19',
  1,
  NOW(),
  NOW(),
  '912d5049-e195-46e9-a319-49e3502bf7e7'
)
ON CONFLICT ("id") DO UPDATE SET
  status = 'active',
  subscription_end_date = EXCLUDED.subscription_end_date,
  updated_at = NOW();

COMMIT;
