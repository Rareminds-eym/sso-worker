-- LOCAL DEVELOPMENT ONLY. Never apply to production.
-- Account, platform learner membership, SkillPassport/LTE access and Premium subscription.
-- Demo password: 12345678@Aa. Bcryptjs cost 12; reruns update only this guarded fixture.
-- Requires product and plan reference records from initial dev seeds.
-- No school or college organization is created.
BEGIN;
DO $identity$ BEGIN IF EXISTS(SELECT 1 FROM public.users WHERE email='arjun.srinivasan27@example.com' AND id<>'77feba55-cc92-5f00-9ff6-49df5ec581b3') OR EXISTS(SELECT 1 FROM public.users WHERE id='77feba55-cc92-5f00-9ff6-49df5ec581b3' AND email<>'arjun.srinivasan27@example.com') THEN RAISE EXCEPTION 'Conflicting local demo identity: arjun.srinivasan27@example.com'; END IF; END $identity$;


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
  ('77feba55-cc92-5f00-9ff6-49df5ec581b3', 'arjun.srinivasan27@example.com', '$2a$12$1GhLLwpTIV3hGo2gQEVNfu8goXwzMWiU7fBRegHpqSemSN4OBiSmq', true, '2026-06-09 11:27:01.022313+00', NOW(), '2026-06-09 16:11:25.459+00', false, '{"role": "learner", "firstName": "Arjun", "lastName": "Srinivasan", "contact_number": ""}'::jsonb)
ON CONFLICT ("id") DO UPDATE SET
  email = EXCLUDED.email,
  password_hash = EXCLUDED.password_hash,
  user_metadata = EXCLUDED.user_metadata,
  updated_at = NOW(),
  is_blocked = false;

-- 4. Seed Membership
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
  ('1f0a40c1-d425-5523-abd1-622218ea92a3', '77feba55-cc92-5f00-9ff6-49df5ec581b3', '00000000-0000-0000-0000-000000000001', '2026-06-09 11:27:01.022313+00', 'active')
ON CONFLICT ("user_id", "org_id") DO UPDATE SET
  status = 'active';

-- 5. Assign learner role to membership
INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
  ('6d3dadee-d01e-55e9-8780-cd70e60158b8', (SELECT id FROM public.memberships WHERE user_id='77feba55-cc92-5f00-9ff6-49df5ec581b3' AND org_id='00000000-0000-0000-0000-000000000001'), '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW())
ON CONFLICT ("membership_id", "role_id") DO NOTHING;

-- 6. Link Organization and Membership to Products (SkillPassport & LTE)
INSERT INTO "public"."organization_products" ("org_id", "product_id", "active") VALUES
  ('00000000-0000-0000-0000-000000000001', '7352d0f4-88a6-4e14-9421-6c5706791973', true),
  ('00000000-0000-0000-0000-000000000001', '912d5049-e195-46e9-a319-49e3502bf7e7', true)
ON CONFLICT ("org_id", "product_id") DO UPDATE SET active = true;

INSERT INTO "public"."membership_products" ("membership_id", "product_id") VALUES
  ((SELECT id FROM public.memberships WHERE user_id='77feba55-cc92-5f00-9ff6-49df5ec581b3' AND org_id='00000000-0000-0000-0000-000000000001'), '7352d0f4-88a6-4e14-9421-6c5706791973'),
  ((SELECT id FROM public.memberships WHERE user_id='77feba55-cc92-5f00-9ff6-49df5ec581b3' AND org_id='00000000-0000-0000-0000-000000000001'), '912d5049-e195-46e9-a319-49e3502bf7e7')
ON CONFLICT ("membership_id", "product_id") DO NOTHING;

-- 7. Seed Subscription in SSO DB
INSERT INTO "public"."subscriptions" (
  "id", "user_id", "plan_id", "full_name", "email", "plan_code", 
  "plan_type", "plan_amount", "billing_cycle", "features", "status", 
  "subscription_start_date", "subscription_end_date", "is_organization_subscription", 
  "purchased_by", "seat_count", "created_at", "updated_at", "product_id"
) VALUES (
  'ba5259ad-b2f7-587b-a19c-06c4091e6de4',
  '77feba55-cc92-5f00-9ff6-49df5ec581b3',
  '8460ee67-18ff-4c2e-ac57-7e1f87dc8316',
  'Arjun Srinivasan',
  'arjun.srinivasan27@example.com',
  'premium',
  'Career Accelerator',
  999,
  'yearly',
  '["Advanced career assessment", "Skill gap report", "6-month learning plan", "Portfolio creation", "Course/LTE access", "Opportunity matching", "Interview readiness tools", "Resume/profile review", "Priority opportunity matching", "Advanced portfolio proof", "Career progress analytics"]'::jsonb,
  'active',
  '2026-11-13 10:00:00+00',
  '2027-11-13 10:00:00+00',
  false,
  '77feba55-cc92-5f00-9ff6-49df5ec581b3',
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
-- LOCAL DEMO ONLY. Preserve plan, pricing, expiry and other users.

DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM public.subscriptions WHERE id='ba5259ad-b2f7-587b-a19c-06c4091e6de4' AND user_id='77feba55-cc92-5f00-9ff6-49df5ec581b3' AND email='arjun.srinivasan27@example.com' AND plan_code='premium' AND status='active' AND subscription_end_date>now()) THEN
  RAISE EXCEPTION 'Arjun active local Premium subscription is required';
 END IF;
END $$;
UPDATE public.subscriptions SET features=coalesce(features,'[]'::jsonb)||jsonb_build_array('ai_job_matching'),updated_at=now()
WHERE id='ba5259ad-b2f7-587b-a19c-06c4091e6de4' AND user_id='77feba55-cc92-5f00-9ff6-49df5ec581b3' AND email='arjun.srinivasan27@example.com' AND plan_code='premium' AND status='active' AND subscription_end_date>now()
AND NOT coalesce(features,'[]'::jsonb) ? 'ai_job_matching';
COMMIT;
