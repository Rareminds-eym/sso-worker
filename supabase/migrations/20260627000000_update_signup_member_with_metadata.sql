-- Update signup_member function to accept and store user_metadata
-- This allows learners and other users to have additional metadata stored during signup

CREATE OR REPLACE FUNCTION "public"."signup_member"(
  "p_email" "text", 
  "p_password_hash" "text", 
  "p_role" "text", 
  "p_org_id" "uuid" DEFAULT NULL::"uuid",
  "p_user_metadata" "jsonb" DEFAULT '{}'::jsonb
) RETURNS "jsonb"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
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

  -- Create user with metadata
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

ALTER FUNCTION "public"."signup_member"(
  "p_email" "text", 
  "p_password_hash" "text", 
  "p_role" "text", 
  "p_org_id" "uuid",
  "p_user_metadata" "jsonb"
) OWNER TO "postgres";
