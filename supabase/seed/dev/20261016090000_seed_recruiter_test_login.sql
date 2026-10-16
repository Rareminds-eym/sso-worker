-- DEV ONLY: known-password fixture. Never copy into production seeds.
-- Login: recruiter.dev@example.com; password is the requested test password.
-- Bcrypt cost 12, compatible with src/lib/hash.ts. No plaintext password stored.
-- Pair with SkillPassport's same-named dev seed (SSO first, app second).
-- Reruns reset only this explicitly marked fixture; collisions fail atomically.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $seed$
DECLARE
  fixture_user CONSTANT uuid := 'c90dd3d7-48da-4736-968d-3c796ecbb63d';
  fixture_org CONSTANT uuid := '83b535de-4f65-43c3-926b-2bf209c068b1';
  fixture_email CONSTANT text := 'recruiter.dev@example.com';
  fixture_tag CONSTANT text := 'recruiter-test-login-v1';
  recruiter_role uuid;
  skillpassport_product uuid;
  fixture_membership uuid;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(fixture_tag, 0));
  SELECT id INTO recruiter_role FROM public.roles WHERE name = 'recruiter';
  SELECT id INTO skillpassport_product FROM public.products WHERE code = 'skillpassport';
  IF recruiter_role IS NULL OR skillpassport_product IS NULL THEN
    RAISE EXCEPTION 'Run the initial SSO dev seed first: recruiter role and SkillPassport product are required';
  END IF;
  IF EXISTS (SELECT 1 FROM public.users
    WHERE (id = fixture_user AND (email <> fixture_email OR user_metadata->>'dev_seed' IS DISTINCT FROM fixture_tag))
       OR (lower(email) = fixture_email AND id <> fixture_user)) THEN
    RAISE EXCEPTION 'Recruiter fixture user ID/email collides with another account; nothing changed';
  END IF;
  IF EXISTS (SELECT 1 FROM public.organizations
    WHERE (id = fixture_org AND metadata->>'dev_seed' IS DISTINCT FROM fixture_tag)
       OR (slug = 'dev-recruiter-test-company' AND id <> fixture_org)) THEN
    RAISE EXCEPTION 'Recruiter fixture organization ID/slug collides with another organization; nothing changed';
  END IF;
  IF EXISTS (SELECT 1 FROM public.memberships WHERE user_id = fixture_user AND org_id <> fixture_org)
    OR EXISTS (SELECT 1 FROM public.memberships m
      JOIN public.membership_roles mr ON mr.membership_id = m.id
      JOIN public.roles r ON r.id = mr.role_id
      WHERE m.user_id = fixture_user AND r.name <> 'recruiter') THEN
    RAISE EXCEPTION 'Recruiter fixture has unexpected memberships/roles; refusing to change them';
  END IF;
  IF EXISTS (SELECT 1 FROM public.memberships m
    JOIN public.membership_products mp ON mp.membership_id = m.id
    WHERE m.user_id = fixture_user AND mp.product_id <> skillpassport_product) THEN
    RAISE EXCEPTION 'Recruiter fixture has unexpected product access; refusing to change it';
  END IF;

  INSERT INTO public.users (id, email, password_hash, is_email_verified, is_blocked, user_metadata)
  VALUES (fixture_user, fixture_email,
    '$2a$12$zN8rUIcjfA6w48X182KMKuand0D/UCx24qGP9n5/qBSXrcLJPXmki', true, false,
    jsonb_build_object('dev_seed', fixture_tag, 'role', 'recruiter',
      'firstName', 'Dev', 'lastName', 'Recruiter', 'org_id', fixture_org))
  ON CONFLICT (id) DO UPDATE SET
    password_hash = EXCLUDED.password_hash, is_email_verified = true,
    is_blocked = false, user_metadata = EXCLUDED.user_metadata, updated_at = now();
  INSERT INTO public.organizations (id, name, slug, created_by, metadata)
  VALUES (fixture_org, 'Dev Recruiter Test Company', 'dev-recruiter-test-company', fixture_user,
    jsonb_build_object('dev_seed', fixture_tag, 'organization_type', 'company',
      'email', fixture_email, 'website', 'https://example.com'))
  ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, metadata = EXCLUDED.metadata;
  INSERT INTO public.memberships (id, user_id, org_id, status)
  VALUES ('a242a91b-0697-4870-8ae7-9c03477a8dcf', fixture_user, fixture_org, 'active')
  ON CONFLICT (user_id, org_id) DO UPDATE SET status = 'active'
  RETURNING id INTO fixture_membership;
  -- Authoritative recruiter claim; intentionally no owner/admin grants.
  INSERT INTO public.membership_roles (membership_id, role_id)
  VALUES (fixture_membership, recruiter_role)
  ON CONFLICT (membership_id, role_id) DO NOTHING;
  INSERT INTO public.organization_products (org_id, product_id, active)
  VALUES (fixture_org, skillpassport_product, true)
  ON CONFLICT (org_id, product_id) DO UPDATE SET active = true;
  INSERT INTO public.membership_products (membership_id, product_id)
  VALUES (fixture_membership, skillpassport_product)
  ON CONFLICT (membership_id, product_id) DO NOTHING;
  RAISE NOTICE 'SSO recruiter test fixture ready: %. Apply the matching app dev seed next.', fixture_email;
END;
$seed$;
COMMIT;
