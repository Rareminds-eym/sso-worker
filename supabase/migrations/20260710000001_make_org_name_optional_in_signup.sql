-- Migration: Make org_name optional in signup_user RPC
-- For recruiter onboarding flow where org setup happens after email verification
-- Date: 2026-07-10

-- First, make organizations.name nullable (if not already)
ALTER TABLE public.organizations ALTER COLUMN name DROP NOT NULL;

-- Update the 6-parameter signup_user to handle NULL org_name
CREATE OR REPLACE FUNCTION public.signup_user(
  p_email text,
  p_password_hash text,
  p_org_name text,
  p_org_slug text,
  p_role text,
  p_user_metadata jsonb
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
  v_actual_org_name text;
begin
  -- Create user with user_metadata
  insert into users (email, password_hash, is_email_verified, user_metadata)
  values (p_email, p_password_hash, false, p_user_metadata)
  returning id into v_user_id;

  -- If org_name is NULL, use a temporary name based on email
  -- This will be updated later during onboarding
  v_actual_org_name := COALESCE(p_org_name, 'Organization for ' || p_email);

  -- Create org (handle slug collision)
  begin
    insert into organizations (name, slug, created_by)
    values (v_actual_org_name, v_slug, v_user_id)
    returning id into v_org_id;
  exception when unique_violation then
    v_slug := v_slug || '-' || substr(gen_random_uuid()::text, 1, 6);
    insert into organizations (name, slug, created_by)
    values (v_actual_org_name, v_slug, v_user_id)
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

-- Grant permissions
ALTER FUNCTION public.signup_user(text, text, text, text, text, jsonb) OWNER TO postgres;
GRANT ALL ON FUNCTION public.signup_user(text, text, text, text, text, jsonb) TO "anon";
GRANT ALL ON FUNCTION public.signup_user(text, text, text, text, text, jsonb) TO "authenticated";
GRANT ALL ON FUNCTION public.signup_user(text, text, text, text, text, jsonb) TO "service_role";

COMMENT ON FUNCTION public.signup_user(text, text, text, text, text, jsonb) IS
  'Creates user + org + membership. p_org_name can be NULL for deferred org setup (e.g., post-verification onboarding).';
