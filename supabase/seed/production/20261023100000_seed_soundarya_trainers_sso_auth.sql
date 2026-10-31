-- Seed for SSO / Auth DB (production)
-- Creates the login accounts of ALL 14 Soundarya trainers of the SkillPassport production educator seed
-- (skillpassport 20261023100100_seed_soundarya_trainers_skillpassport.sql), with the same user ids:
--   MBA with assignments: MOHAMMED SADIQ (Business Analytics), Ajay Kumar (Finance), Vishwanath Gurlhosur (Marketing), Poornima D U (HR)
--   MCA with assignments: Karthik Keyan, Suraj S P, Raghu B.N
--   Profile and login only (no assignment, session or task seed exists for them yet): Maheswari kumar, Visakh Madhu, Sandhya Mohan, Koutham K A,
--   Subashini Ramaswamy, Krishnalatha Atmakuri, Lalitha Srinivasan
-- Reused from the validated dev seed (dev/20261023100000_seed_soundarya_educators_sso_auth.sql) with the same user ids, password hashes, memberships and
-- role ids, made production-safe: an existing role, organization or account is never replaced, and an account is matched by lower(email).
-- Run this FIRST. Then run the SkillPassport production seed 20261023100100_seed_soundarya_trainers_skillpassport.sql, which creates the
-- application users with these same ids. The two databases are linked only by identical user ids, so the ids below must not change.
--
-- ORGANIZATION: the memberships link each trainer to "SkillPassport Platform" (00000000-0000-0000-0000-000000000001), the organization the
-- SP Admin "Add Educator" screen uses. It is not a college; the college comes later from organization_staff_assignments.
-- PASSWORDS: every account gets the temporary password rare@123456 as a bcrypt hash (cost 12, the SSO worker's hashPassword, a different salt per account), plus
-- must_change_password = true, so each trainer must replace it at the first sign-in: the first-login screen asks for the temporary password and a new one of 10 to 72
-- characters. No invitation email is sent by a seed: tell the trainers the temporary password yourself. Anyone who knows an email and this password can sign in until
-- that trainer changes it. This file never changes an account that already exists (matched by email); its password stays as it is.
-- Safe and idempotent: a second run inserts nothing. An existing account keeps its own id and password, and its membership/role are only added if missing.
--
-- NEEDS CLARIFICATION BEFORE PRODUCTION: Karthik Keyan's login email below (karthikeyan201219996@gmail.com) differs from the Educator Details
-- sheet of the Soundarya workbook (karhitkeyan@rareminds.in). Confirm which one is the real login before running this file.
--
-- PRE-CHECK (read-only), run first. A row whose id differs from the seed id means the account already exists under another id: stop and review,
-- because the SkillPassport application user must use that existing id (the SkillPassport seed matches by email and keeps an existing row):
--   SELECT id, email FROM "public"."users" WHERE lower(email) IN ('msadiq.india@gmail.com', 'maheswarikumar27@gmail.com', 'cacsajay22@gmail.com', 'surajsp263@gmail.com', 'vishwanathgurlhosur@gmail.com', 'poornima.du@gmail.com', 'raghu.astepahead@gmail.com', 'visakh2013@rediffmail.com', 'sandhyamohan.sharath@gmail.com', 'koutham8505@gmail.com', 'subashini.r@rareminds.in', 'krishnalatha@rareminds.in', 'lalitha@rareminds.in', 'karthikeyan201219996@gmail.com');
--   SELECT id, name FROM "public"."roles" WHERE name = 'educator';
--   SELECT id, name FROM "public"."organizations" WHERE id = '00000000-0000-0000-0000-000000000001';

BEGIN;

-- 1. Prerequisites (left unchanged when they already exist, whatever their id)
INSERT INTO "public"."roles" ("id", "name", "description", "created_at") VALUES
  ('0c9c3c7e-0b0e-4889-986c-a7cc5bae5878', 'educator', 'General educator/teacher', NOW())
ON CONFLICT DO NOTHING;

INSERT INTO "public"."organizations" ("id", "name", "slug", "created_at", "metadata") VALUES
  ('00000000-0000-0000-0000-000000000001', 'SkillPassport Platform', 'platform', NOW(), '{"is_platform_org": true}')
ON CONFLICT DO NOTHING;

-- 2. Trainer login accounts (skipped when an account with the same email already exists)
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "is_blocked", "user_metadata")
SELECT v.id, v.email, v.password_hash, v.is_email_verified, v.created_at, v.updated_at, v.is_blocked, v.user_metadata
FROM (VALUES
  ('87365516-0544-53af-ad0f-5ab9bbf0af79'::uuid, 'msadiq.india@gmail.com'::text, '$2a$12$bm0CvrSs9zM8rq2otTzJqeyxqJZoIXReoq4QzRKDyHNhzf3gEwfVq'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('15e10302-640c-530a-b9bd-b504545533f8'::uuid, 'maheswarikumar27@gmail.com'::text, '$2a$12$2cYGAT2RCIwVeA4Ga79bxObQ1YBt8JqE60vmcnZU/p3bKGytYvSpi'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('9c51fd6a-ee87-5242-81b6-344e731dec99'::uuid, 'cacsajay22@gmail.com'::text, '$2a$12$HgscLkcmdwgObGEGFqtQqOPEiUfn17rarfWcecPT2y1oRPW3jP5FW'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('46da4792-8114-5f05-8643-a8d5abb01649'::uuid, 'surajsp263@gmail.com'::text, '$2a$12$KBaFt.Qk6PiTLR7IqrcSJuPJC971zjTx/TjQeeloZ.qqqabNDPlP2'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('c6382d2e-106a-5f5c-9560-0b368cb1733f'::uuid, 'vishwanathgurlhosur@gmail.com'::text, '$2a$12$sPCa2vA/bLFHrF3y2F9r8eTbvWqteq9n2rz0EseDtL/AjKAQZ2LP.'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('e89184ee-3463-5e09-916b-a1be24d39921'::uuid, 'poornima.du@gmail.com'::text, '$2a$12$x5H0HW9JMmjhtP6yXF0hUeFtEv4zJa5PY2c5JB0XjBc.Bkr9cPxO.'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('867ff9d5-b17d-5090-8324-c33ee7da2e7e'::uuid, 'raghu.astepahead@gmail.com'::text, '$2a$12$PR9gJM1oGka45jTmzkzbjOQvRD.FN7LasValKQ0NS/8KR.F5rEuHi'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('f6b51694-440b-5943-bebf-8d99eb2c859a'::uuid, 'visakh2013@rediffmail.com'::text, '$2a$12$/90lFVg8dQUjrIy1HUgdQ.C3hbZpAzGC7b5/GsyZSDtpuUE7BBD46'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('4e10ea49-f661-5e4d-a75d-d564beb775d3'::uuid, 'sandhyamohan.sharath@gmail.com'::text, '$2a$12$GtZ4WLtWZC4NbCCzhWiInOzhjUsooMnRzmNELblJCR2Q6cx1mpO/6'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('e6e95b97-0328-595a-a6ea-090cfa0975f4'::uuid, 'koutham8505@gmail.com'::text, '$2a$12$Nf8v9FPp.q0oSkk7lRYCceCJi98GaVfzs8yvksbInPcJBUJhIloPS'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('80670692-dfe0-533a-bcc3-c594eff43667'::uuid, 'subashini.r@rareminds.in'::text, '$2a$12$eO8Xq/2koMofrsdh0UPc4.vC1HdbxSaKxxR8TYfVXq7kmt83sTwNu'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('0be98a69-a2ca-5462-897f-d64d9e95a3f4'::uuid, 'krishnalatha@rareminds.in'::text, '$2a$12$Yceq/SfUy.KRrREzIiJxX..NgVyhokaBz8WAxFWMf4mTHx5YY./2y'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('d5199eeb-253c-5f29-94b0-44c0d8c998e3'::uuid, 'lalitha@rareminds.in'::text, '$2a$12$iomx9Sq/4h8fsQxVe6Jx2eVSKbJ9EM6E86GAovpdj4vT72vlqEAx2'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb),
  ('55a442d2-99a1-5c31-9668-4ee506353bcb'::uuid, 'karthikeyan201219996@gmail.com'::text, '$2a$12$Q98kjumM./Z6yRpowejLheF3N7ZcZVXwHmtJ.Ts4ZexGB/GBZaBTW'::text, true::boolean, NOW(), NOW(), false, '{"source": "seed_educator_details", "portal_mode": "assigned_trainer", "role": "educator", "must_change_password": true}'::jsonb)
) AS v(id, email, password_hash, is_email_verified, created_at, updated_at, is_blocked, user_metadata)
WHERE NOT EXISTS (SELECT 1 FROM "public"."users" x WHERE lower(x."email") = v.email)
ON CONFLICT DO NOTHING;

-- 3. Memberships in the platform organization (joined by email, so an existing account keeps its own id)
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status")
SELECT v.membership_id, u."id", '00000000-0000-0000-0000-000000000001'::uuid, NOW(), 'active'
FROM (VALUES
  ('a1f45f60-5358-538c-8787-1e0bfecb2fed'::uuid, 'msadiq.india@gmail.com'),
  ('384bdfc2-75a9-50b2-84d4-5b5b6fb7f549'::uuid, 'maheswarikumar27@gmail.com'),
  ('c71763aa-c548-5005-b41d-3f824490ac0f'::uuid, 'cacsajay22@gmail.com'),
  ('e84c9377-bb12-581d-8396-5cae9d9f986e'::uuid, 'surajsp263@gmail.com'),
  ('57006491-e184-5251-b80b-a4e8f085a451'::uuid, 'vishwanathgurlhosur@gmail.com'),
  ('bea0af54-9fd1-5c8f-a65f-b84d1945e55f'::uuid, 'poornima.du@gmail.com'),
  ('03a25627-a5bd-536a-8687-740a89be4a79'::uuid, 'raghu.astepahead@gmail.com'),
  ('62163423-232b-5669-8624-46e5ecc09ddd'::uuid, 'visakh2013@rediffmail.com'),
  ('e23270bc-ccf9-5fc9-b6a8-c70d29fa6dc9'::uuid, 'sandhyamohan.sharath@gmail.com'),
  ('8d0d0846-396d-5180-921f-ea4a59b4fdab'::uuid, 'koutham8505@gmail.com'),
  ('364d0421-03b6-5fe8-be54-6c02cafde04a'::uuid, 'subashini.r@rareminds.in'),
  ('3a9b8ef9-2e7d-5a21-a39a-37dc8032a90a'::uuid, 'krishnalatha@rareminds.in'),
  ('784a0075-a245-5bf8-bf40-1485197d3863'::uuid, 'lalitha@rareminds.in'),
  ('497f7934-f60c-560b-8952-136ad044bad6'::uuid, 'karthikeyan201219996@gmail.com')
) AS v(membership_id, email)
JOIN "public"."users" u ON lower(u."email") = v.email
ON CONFLICT ("user_id", "org_id") DO NOTHING;

-- 4. Role: educator (the role is found by name, so it also works when production's educator role has another id)
INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at")
SELECT v.membership_role_id, m."id", r."id", NOW()
FROM (VALUES
  ('7717ba5c-05bc-5aa5-b59b-f30bfcf1653c'::uuid, 'msadiq.india@gmail.com'),
  ('4ae57405-b90d-5ad7-9a62-04e2fcd614e3'::uuid, 'maheswarikumar27@gmail.com'),
  ('c0dc8e0d-f880-53e9-9f9e-c367b9ef2973'::uuid, 'cacsajay22@gmail.com'),
  ('035167b9-6a64-5358-bfb7-36c8d5b7a35a'::uuid, 'surajsp263@gmail.com'),
  ('92c85dd2-ecb1-5061-afb3-30966b8d9289'::uuid, 'vishwanathgurlhosur@gmail.com'),
  ('c1e5a151-5892-5c5e-aaaf-9a424bb6a6c6'::uuid, 'poornima.du@gmail.com'),
  ('05b60d50-bf4a-5117-b3b5-0fed753e158f'::uuid, 'raghu.astepahead@gmail.com'),
  ('457984d2-796a-5018-90aa-c5bfc03c36c0'::uuid, 'visakh2013@rediffmail.com'),
  ('ba8b3747-2cb0-5f91-a133-9083479dc1d8'::uuid, 'sandhyamohan.sharath@gmail.com'),
  ('2179536b-c7fa-5bb9-b177-43897c70893e'::uuid, 'koutham8505@gmail.com'),
  ('71e445dc-36eb-528b-b696-d29f87aae8a9'::uuid, 'subashini.r@rareminds.in'),
  ('dfbeb84b-adc0-5ba9-8d8f-f1dec68cacc9'::uuid, 'krishnalatha@rareminds.in'),
  ('8b6b879b-aa44-5f73-8d24-444d33ce952a'::uuid, 'lalitha@rareminds.in'),
  ('8491c47e-1f14-5716-a8b9-546d4f1187f2'::uuid, 'karthikeyan201219996@gmail.com')
) AS v(membership_role_id, email)
JOIN "public"."users" u ON lower(u."email") = v.email
JOIN "public"."memberships" m ON m."user_id" = u."id" AND m."org_id" = '00000000-0000-0000-0000-000000000001'
JOIN "public"."roles" r ON r."name" = 'educator'
ON CONFLICT ("membership_id", "role_id") DO NOTHING;

COMMIT;
