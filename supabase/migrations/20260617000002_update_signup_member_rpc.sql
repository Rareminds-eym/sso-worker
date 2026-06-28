-- Phase: 1 of 3 (Expand)
-- Breaking: No
--
-- This migration creates a new 5-parameter version of signup_member with p_user_metadata,
-- and updates the existing 4-parameter version to act as a backward-compatible wrapper.

-- 1. Create the new 5-parameter version
CREATE OR REPLACE FUNCTION public.signup_member(
  p_email text,
  p_password_hash text,
  p_role text,
  p_org_id uuid,
  p_user_metadata jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path TO 'public'
AS $$
DECLARE
  v_user_id       uuid;
  v_membership_id uuid;
  v_role_id       uuid;
  v_org_id        uuid;
  v_platform_org  uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
  -- Validate role exists
  SELECT id INTO v_role_id FROM roles WHERE name = p_role;
  IF v_role_id IS NULL THEN
    RAISE EXCEPTION 'Invalid role: %', p_role;
  END IF;

  -- Determine target org: use provided org_id, or fall back to platform org
  IF p_org_id IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = p_org_id) THEN
      RAISE EXCEPTION 'Organization not found';
    END IF;
    v_org_id := p_org_id;
  ELSE
    v_org_id := v_platform_org;
  END IF;

  -- Create user with user_metadata
  INSERT INTO users (email, password_hash, is_email_verified, user_metadata)
  VALUES (p_email, p_password_hash, false, p_user_metadata)
  RETURNING id INTO v_user_id;

  -- Always create membership and assign role
  INSERT INTO memberships (user_id, org_id, status)
  VALUES (v_user_id, v_org_id, 'active')
  RETURNING id INTO v_membership_id;

  INSERT INTO membership_roles (membership_id, role_id)
  VALUES (v_membership_id, v_role_id);

  RETURN jsonb_build_object(
    'user_id', v_user_id,
    'org_id', v_org_id,
    'membership_id', v_membership_id
  );
END;
$$;

-- 2. Update the existing 4-parameter version to be a backward-compatible wrapper
CREATE OR REPLACE FUNCTION public.signup_member(
  p_email text,
  p_password_hash text,
  p_role text,
  p_org_id uuid DEFAULT NULL::uuid
) RETURNS jsonb
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN public.signup_member(p_email, p_password_hash, p_role, p_org_id, '{}'::jsonb);
END;
$$;

-- Update ownership and permissions
ALTER FUNCTION public.signup_member(text, text, text, uuid, jsonb) OWNER TO postgres;
GRANT ALL ON FUNCTION public.signup_member(text, text, text, uuid, jsonb) TO "anon";
GRANT ALL ON FUNCTION public.signup_member(text, text, text, uuid, jsonb) TO "authenticated";
GRANT ALL ON FUNCTION public.signup_member(text, text, text, uuid, jsonb) TO "service_role";
