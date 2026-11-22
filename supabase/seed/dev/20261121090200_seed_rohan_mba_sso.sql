-- LOCAL DEVELOPMENT ONLY. Never apply to production.
-- Account, platform learner membership, SkillPassport/LTE access and Premium subscription.
-- Demo password: 12345678@Aa. Bcryptjs cost 12; reruns update only this guarded fixture.
-- Requires product and plan reference records from initial dev seeds.
-- No school or college organization is created.
BEGIN;
DO $identity$ BEGIN IF EXISTS(SELECT 1 FROM public.users WHERE email='rohan.iyer.mba@example.com' AND id<>'02f0a43d-3c0a-5026-b44f-5d0696e75f19') OR EXISTS(SELECT 1 FROM public.users WHERE id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND email<>'rohan.iyer.mba@example.com') THEN RAISE EXCEPTION 'Conflicting local demo identity: rohan.iyer.mba@example.com'; END IF; END $identity$;


-- 1. Ensure prerequisite roles exist in "public"."roles"
INSERT INTO "public"."roles" ("id", "name", "description", "created_at") VALUES
  ('8d018d55-46f4-4e67-b6a5-8c216737a374', 'learner', 'Self-directed learner', NOW())
ON CONFLICT ("id") DO NOTHING;

-- 2. Required shared platform organization only
INSERT INTO "public"."organizations" ("id", "name", "slug", "created_by", "created_at", "metadata") VALUES
 ('00000000-0000-0000-0000-000000000001', 'SkillPassport Platform', 'platform', null, NOW(), '{"is_platform_org": true}'::jsonb)
ON CONFLICT ("id") DO NOTHING;

-- 3. Seed User
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata") VALUES 
  ('02f0a43d-3c0a-5026-b44f-5d0696e75f19', 'rohan.iyer.mba@example.com', '$2a$12$c4H9rAX0U.Pf6k3Fqgwvh.1/mn1CfSk72vn2g.92PMYvCC5sRJO7u', true, '2026-06-09 11:27:01.022313+00', NOW(), '2026-06-09 16:11:25.459+00', false, '{"role": "learner", "firstName": "Rohan", "lastName": "Iyer", "contact_number": ""}'::jsonb)
ON CONFLICT ("id") DO UPDATE SET
  email = EXCLUDED.email,
  password_hash = EXCLUDED.password_hash,
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
  ('e810192c-b31e-5469-aadf-69feda648082', (SELECT id FROM public.memberships WHERE user_id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND org_id='00000000-0000-0000-0000-000000000001'), '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW())
ON CONFLICT ("membership_id", "role_id") DO NOTHING;

-- 6. Link Organization and Membership to Products (SkillPassport & LTE)
INSERT INTO "public"."organization_products" ("org_id", "product_id", "active") VALUES
  ('00000000-0000-0000-0000-000000000001', '7352d0f4-88a6-4e14-9421-6c5706791973', true),
  ('00000000-0000-0000-0000-000000000001', '912d5049-e195-46e9-a319-49e3502bf7e7', true)
ON CONFLICT ("org_id", "product_id") DO UPDATE SET active = true;

INSERT INTO "public"."membership_products" ("membership_id", "product_id") VALUES
  ((SELECT id FROM public.memberships WHERE user_id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND org_id='00000000-0000-0000-0000-000000000001'), '7352d0f4-88a6-4e14-9421-6c5706791973'),
  ((SELECT id FROM public.memberships WHERE user_id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND org_id='00000000-0000-0000-0000-000000000001'), '912d5049-e195-46e9-a319-49e3502bf7e7')
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

-- JOB-MATCHING FEATURE GRANT
-- LOCAL ROHAN DEMO ONLY. Preserve plans, pricing, expiry and other users.

DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM public.subscriptions WHERE id='af3e7e1f-92a5-535a-aecd-3f5b628beb84' AND user_id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND email='rohan.iyer.mba@example.com' AND plan_code='premium' AND status='active' AND subscription_end_date>now()) THEN
  RAISE EXCEPTION 'Rohan active local Premium subscription is required';
 END IF;
END $$;
UPDATE public.subscriptions SET features=coalesce(features,'[]'::jsonb)||jsonb_build_array('ai_job_matching'),updated_at=now()
WHERE id='af3e7e1f-92a5-535a-aecd-3f5b628beb84' AND user_id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND email='rohan.iyer.mba@example.com' AND plan_code='premium' AND status='active' AND subscription_end_date>now()
AND NOT coalesce(features,'[]'::jsonb) ? 'ai_job_matching';
COMMIT;
