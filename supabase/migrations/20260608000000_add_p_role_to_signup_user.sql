-- Migration: Add p_role parameter to signup_user RPC
-- Phase: 1 of 1 (Expand)
-- Breaking: No
--
-- Previously, signup_user always assigned only the 'owner' role to the
-- membership. Institution admins (school_admin, college_admin, university_admin)
-- who signed up via POST /auth/signup were missing their specific admin role in
-- the JWT. This caused VerifyEmail.tsx routing to misidentify them as
-- recruitment company admins (because the JWT only had the 'owner' role).
--
-- The new p_role parameter optionally assigns an additional role (e.g.,
-- 'college_admin') alongside 'owner' on the membership, so the JWT contains
-- the full set of roles.
--
-- Related: SSO signup.ts handler now passes body.role to this RPC.

-- Drop old 4-param version so the 5-param replacement is the only overload.
-- Since this is a new migration, no existing caller depends on the old OID.
DROP FUNCTION IF EXISTS public.signup_user(p_email text, p_password_hash text, p_org_name text, p_org_slug text);

-- Recreate with optional p_role parameter
CREATE OR REPLACE FUNCTION public.signup_user(
  p_email text,
  p_password_hash text,
  p_org_name text,
  p_org_slug text,
  p_role text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path TO 'public'
AS $$
declare
  v_user_id       uuid;
  v_org_id        uuid;
  v_membership_id uuid;
  v_owner_role_id uuid;
  v_role_id       uuid;
  v_slug          text := p_org_slug;
begin
  -- Create user
  insert into users (email, password_hash, is_email_verified)
  values (p_email, p_password_hash, false)
  returning id into v_user_id;

  -- Create org (handle slug collision)
  begin
    insert into organizations (name, slug, created_by)
    values (p_org_name, v_slug, v_user_id)
    returning id into v_org_id;
  exception when unique_violation then
    v_slug := v_slug || '-' || substr(gen_random_uuid()::text, 1, 6);
    insert into organizations (name, slug, created_by)
    values (p_org_name, v_slug, v_user_id)
    returning id into v_org_id;
  end;

  -- Create membership
  insert into memberships (user_id, org_id, status)
  values (v_user_id, v_org_id, 'active')
  returning id into v_membership_id;

  -- Assign 'owner' role via join table
  select id into v_owner_role_id from roles where name = 'owner';
  insert into membership_roles (membership_id, role_id)
  values (v_membership_id, v_owner_role_id);

  -- If the specified role is not 'owner', assign it too.
  -- This ensures institution admins (college_admin, school_admin, university_admin)
  -- have their specific role in the JWT alongside the owner role.
  if p_role != 'owner' then
    select id into v_role_id from roles where name = p_role;
    if v_role_id is not null then
      insert into membership_roles (membership_id, role_id)
      values (v_membership_id, v_role_id);
    end if;
  end if;

  return jsonb_build_object(
    'user_id', v_user_id,
    'org_id', v_org_id,
    'slug', v_slug
  );
end;
$$;

-- Update ownership to match new signature
ALTER FUNCTION public.signup_user(p_email text, p_password_hash text, p_org_name text, p_org_slug text, p_role text) OWNER TO postgres;

-- Grant execute permissions (matching original schema's pattern for 4-param version)
GRANT ALL ON FUNCTION public.signup_user(p_email text, p_password_hash text, p_org_name text, p_org_slug text, p_role text) TO "anon";
GRANT ALL ON FUNCTION public.signup_user(p_email text, p_password_hash text, p_org_name text, p_org_slug text, p_role text) TO "authenticated";
GRANT ALL ON FUNCTION public.signup_user(p_email text, p_password_hash text, p_org_name text, p_org_slug text, p_role text) TO "service_role";
