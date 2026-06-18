-- Phase: 1 of 3 (Expand)
-- Breaking: No
--
-- This migration creates a new 6-parameter version of signup_user with p_user_metadata,
-- and updates the existing 5-parameter version to act as a backward-compatible wrapper.

-- 1. Create the new 6-parameter version
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
begin
  -- Create user with user_metadata
  insert into users (email, password_hash, is_email_verified, user_metadata)
  values (p_email, p_password_hash, false, p_user_metadata)
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

-- 2. Update the existing 5-parameter version to be a backward-compatible wrapper
CREATE OR REPLACE FUNCTION public.signup_user(
  p_email text,
  p_password_hash text,
  p_org_name text,
  p_org_slug text,
  p_role text
) RETURNS jsonb
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN public.signup_user(p_email, p_password_hash, p_org_name, p_org_slug, p_role, '{}'::jsonb);
END;
$$;

-- Update ownership and permissions
ALTER FUNCTION public.signup_user(text, text, text, text, text, jsonb) OWNER TO postgres;
GRANT ALL ON FUNCTION public.signup_user(text, text, text, text, text, jsonb) TO "anon";
GRANT ALL ON FUNCTION public.signup_user(text, text, text, text, text, jsonb) TO "authenticated";
GRANT ALL ON FUNCTION public.signup_user(text, text, text, text, text, jsonb) TO "service_role";
