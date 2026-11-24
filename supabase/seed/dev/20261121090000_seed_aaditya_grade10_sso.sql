-- LOCAL DEVELOPMENT ONLY. Never apply to production.
-- Account, platform learner membership, SkillPassport/LTE access and Premium subscription.
-- Demo password: 12345678@Aa. Bcryptjs cost 12; reruns update only this guarded fixture.
-- Requires product and plan reference records from initial dev seeds.
-- No school or college organization is created.
BEGIN;
DO $identity$ BEGIN IF EXISTS(SELECT 1 FROM public.users WHERE email='aaditya.raman10@example.com' AND id<>'6d1c48f6-b3a9-57fb-998c-6a7255713e0c') OR EXISTS(SELECT 1 FROM public.users WHERE id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c' AND email<>'aaditya.raman10@example.com') THEN RAISE EXCEPTION 'Conflicting local demo identity: aaditya.raman10@example.com'; END IF; END $identity$;


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
  ('6d1c48f6-b3a9-57fb-998c-6a7255713e0c', 'aaditya.raman10@example.com', '$2a$12$fxLsdG./SRJ6naAnO2jzoevMmnyi1ViQ/.Vwsb.n.0..j9cXCGF9C', true, '2026-06-09 11:27:01.022313+00', NOW(), '2026-06-09 16:11:25.459+00', false, '{"role": "learner", "firstName": "Aaditya", "lastName": "Raman", "contact_number": ""}'::jsonb)
ON CONFLICT ("id") DO UPDATE SET
  email = EXCLUDED.email,
  password_hash = EXCLUDED.password_hash,
  user_metadata = EXCLUDED.user_metadata,
  updated_at = NOW(),
  is_blocked = false;

-- 4. Seed Membership
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
  ('6ec016b3-c97f-5b52-8598-5049db47e55c', '6d1c48f6-b3a9-57fb-998c-6a7255713e0c', '00000000-0000-0000-0000-000000000001', '2026-06-09 11:27:01.022313+00', 'active')
ON CONFLICT ("user_id", "org_id") DO UPDATE SET
  status = 'active';

-- 5. Assign learner role to membership
INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
  ('a3b97a61-ee0b-52ef-b7a4-657da85406db', (SELECT id FROM public.memberships WHERE user_id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c' AND org_id='00000000-0000-0000-0000-000000000001'), '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW())
ON CONFLICT ("membership_id", "role_id") DO NOTHING;

-- 6. Link Organization and Membership to Products (SkillPassport & LTE)
INSERT INTO "public"."organization_products" ("org_id", "product_id", "active") VALUES
  ('00000000-0000-0000-0000-000000000001', '7352d0f4-88a6-4e14-9421-6c5706791973', true),
  ('00000000-0000-0000-0000-000000000001', '912d5049-e195-46e9-a319-49e3502bf7e7', true)
ON CONFLICT ("org_id", "product_id") DO UPDATE SET active = true;

INSERT INTO "public"."membership_products" ("membership_id", "product_id") VALUES
  ((SELECT id FROM public.memberships WHERE user_id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c' AND org_id='00000000-0000-0000-0000-000000000001'), '7352d0f4-88a6-4e14-9421-6c5706791973'),
  ((SELECT id FROM public.memberships WHERE user_id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c' AND org_id='00000000-0000-0000-0000-000000000001'), '912d5049-e195-46e9-a319-49e3502bf7e7')
ON CONFLICT ("membership_id", "product_id") DO NOTHING;

-- 7. Seed Subscription in SSO DB
INSERT INTO "public"."subscriptions" (
  "id", "user_id", "plan_id", "full_name", "email", "plan_code", 
  "plan_type", "plan_amount", "billing_cycle", "features", "status", 
  "subscription_start_date", "subscription_end_date", "is_organization_subscription", 
  "purchased_by", "seat_count", "created_at", "updated_at", "product_id"
) VALUES (
  '9df777e6-f9fd-54c4-bd74-a9d970913e2a',
  '6d1c48f6-b3a9-57fb-998c-6a7255713e0c',
  '8460ee67-18ff-4c2e-ac57-7e1f87dc8316',
  'Aaditya Raman',
  'aaditya.raman10@example.com',
  'premium',
  'Career Accelerator',
  999,
  'yearly',
  '["Advanced career assessment", "Skill gap report", "6-month learning plan", "Portfolio creation", "Course/LTE access", "Opportunity matching", "Interview readiness tools", "Resume/profile review", "Priority opportunity matching", "Advanced portfolio proof", "Career progress analytics"]'::jsonb,
  'active',
  '2026-11-13 10:00:00+00',
  '2027-11-13 10:00:00+00',
  false,
  '6d1c48f6-b3a9-57fb-998c-6a7255713e0c',
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
-- LOCAL DEMO ONLY. Keep the machine-readable job-matching grant in SSO.
-- Does not change plans, prices, expiry, or other users' subscriptions.

DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM public.subscriptions
   WHERE id='9df777e6-f9fd-54c4-bd74-a9d970913e2a'
     AND user_id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c'
     AND email='aaditya.raman10@example.com' AND plan_code='premium'
     AND status='active' AND subscription_end_date>now()) THEN
   RAISE EXCEPTION 'Apply Aaditya local SSO subscription seed first';
 END IF;
END $$;
UPDATE public.subscriptions
SET features=coalesce(features,'[]'::jsonb)||'["ai_job_matching"]'::jsonb, updated_at=now()
WHERE id='9df777e6-f9fd-54c4-bd74-a9d970913e2a'
  AND user_id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c'
  AND email='aaditya.raman10@example.com' AND plan_code='premium'
  AND status='active' AND subscription_end_date>now()
  AND NOT coalesce(features,'[]'::jsonb) @> '["ai_job_matching"]'::jsonb;

UPDATE public.users SET user_metadata=coalesce(user_metadata,'{}'::jsonb)||'{"schoolName":"Cambridge School"}'::jsonb WHERE id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c' AND email='aaditya.raman10@example.com';
COMMIT;
