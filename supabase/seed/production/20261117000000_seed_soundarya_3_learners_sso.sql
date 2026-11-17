-- Soundarya College / SSO Worker - three learner auth accounts
-- Run FIRST in the SSO Worker database; then run the SkillPassport seed.
-- Mirrors the Shivaganesh SSO seed (same organization, role, bcrypt hash).
-- IMPORTANT: Shared initial credential Soundarya@123; require password reset on first login.
-- Idempotent on fixed IDs; rejects email/ID mismatches to avoid duplicate identities.
-- Source inputs: Chethan, Gagana K S, Charan H S.

BEGIN;

DO $soundarya_sso_preflight$
DECLARE
  v_conflict record;
BEGIN
  -- An email already attached to a different SSO ID must not be silently duplicated.
  SELECT x.email, u.id AS existing_id INTO v_conflict
  FROM (VALUES
  ('ef7bdd44-ebc5-5128-9ad3-a2ebb488358c'::uuid, 'chethuchethan781@gmail.com'),
  ('e14cac5a-fb99-56cf-ad9e-d8971206db87'::uuid, 'gaganaks029@gmail.com'),
  ('79141bdd-bc46-58ce-bbd4-aee57340cbd6'::uuid, 'charuc250@gmail.com')
  ) AS x(id,email)
  JOIN public.users u ON lower(u.email) = lower(x.email) AND u.id <> x.id
  LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION 'SSO conflict: email % is already owned by user ID %', v_conflict.email, v_conflict.existing_id;
  END IF;

  -- Never reuse a fixed UUID already attached to another email.
  SELECT x.email, u.email AS existing_email INTO v_conflict
  FROM (VALUES
  ('ef7bdd44-ebc5-5128-9ad3-a2ebb488358c'::uuid, 'chethuchethan781@gmail.com'),
  ('e14cac5a-fb99-56cf-ad9e-d8971206db87'::uuid, 'gaganaks029@gmail.com'),
  ('79141bdd-bc46-58ce-bbd4-aee57340cbd6'::uuid, 'charuc250@gmail.com')
  ) AS x(id,email)
  JOIN public.users u ON u.id = x.id AND lower(u.email) <> lower(x.email)
  LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION 'SSO conflict: intended user % has another email %', v_conflict.email, v_conflict.existing_email;
  END IF;

  -- Do not attach a new role record to a wrong or missing membership.
  SELECT x.email, m.id AS existing_id INTO v_conflict
  FROM (VALUES
  ('b43ec53b-e2c8-5829-89fb-f82c0740c7f9'::uuid, 'ef7bdd44-ebc5-5128-9ad3-a2ebb488358c'::uuid, 'chethuchethan781@gmail.com'),
  ('120b9769-8d93-52b3-ad02-28bd97eadd9a'::uuid, 'e14cac5a-fb99-56cf-ad9e-d8971206db87'::uuid, 'gaganaks029@gmail.com'),
  ('268f3eda-b222-518f-b743-9814aa377f6a'::uuid, '79141bdd-bc46-58ce-bbd4-aee57340cbd6'::uuid, 'charuc250@gmail.com')
  ) AS x(membership_id,user_id,email)
  JOIN public.memberships m ON m.user_id = x.user_id AND m.org_id = '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid
  WHERE m.id <> x.membership_id
  LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION 'SSO conflict: learner % already has Soundarya membership ID %', v_conflict.email, v_conflict.existing_id;
  END IF;
END;
$soundarya_sso_preflight$;

-- 0. Ensure Soundarya organization exists.
INSERT INTO public.organizations (id,name,slug,created_at)
VALUES ('284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, 'Soundarya Institute of Management and Science', 'soundarya-institute-management-science', NOW())
ON CONFLICT (id) DO NOTHING;

-- 1. Create the SSO users (same hash as supplied reference; is_email_verified mirrors reference).
INSERT INTO public.users
 (id,email,password_hash,is_email_verified,created_at,updated_at,last_login_at,is_blocked,user_metadata)
VALUES
  ('ef7bdd44-ebc5-5128-9ad3-a2ebb488358c'::uuid, 'chethuchethan781@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"","firstName":"Chethan","contact_number":"8095123213"}'::jsonb),
  ('e14cac5a-fb99-56cf-ad9e-d8971206db87'::uuid, 'gaganaks029@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"K S","firstName":"Gagana","contact_number":"9108412946"}'::jsonb),
  ('79141bdd-bc46-58ce-bbd4-aee57340cbd6'::uuid, 'charuc250@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"H S","firstName":"Charan","contact_number":"9380121190"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- 2. Link the users to Soundarya.
INSERT INTO public.memberships (id,user_id,org_id,created_at,status)
VALUES
  ('b43ec53b-e2c8-5829-89fb-f82c0740c7f9'::uuid, 'ef7bdd44-ebc5-5128-9ad3-a2ebb488358c'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active'),
  ('120b9769-8d93-52b3-ad02-28bd97eadd9a'::uuid, 'e14cac5a-fb99-56cf-ad9e-d8971206db87'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active'),
  ('268f3eda-b222-518f-b743-9814aa377f6a'::uuid, '79141bdd-bc46-58ce-bbd4-aee57340cbd6'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active')
ON CONFLICT (id) DO NOTHING;

-- 3. Grant the learner role for each membership.
INSERT INTO public.membership_roles (id,membership_id,role_id,created_at)
VALUES
  ('12245510-250d-521d-a64b-b4e3616593c5'::uuid, 'b43ec53b-e2c8-5829-89fb-f82c0740c7f9'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW()),
  ('759bc9ea-8bea-5437-be26-591d2b842fec'::uuid, '120b9769-8d93-52b3-ad02-28bd97eadd9a'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW()),
  ('cb5f5322-5c4c-57de-8d9d-c4a097fce451'::uuid, '268f3eda-b222-518f-b743-9814aa377f6a'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW())
ON CONFLICT (id) DO NOTHING;

COMMIT;

-- Optional post-run verification (run in SSO DB):
-- SELECT u.id,u.email,m.org_id,m.status,mr.role_id
-- FROM public.users u
-- JOIN public.memberships m ON m.user_id=u.id
-- JOIN public.membership_roles mr ON mr.membership_id=m.id
-- WHERE u.email IN ('chethuchethan781@gmail.com','gaganaks029@gmail.com','charuc250@gmail.com');
