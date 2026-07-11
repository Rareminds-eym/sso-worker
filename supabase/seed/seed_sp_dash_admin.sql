-- Seed file for sp-dash super_admin user
-- Email: admin@rareminds.in
-- Password: admin@123 (should be changed after first login)
-- Role: super_admin

-- Insert the admin user
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "is_blocked")
VALUES (
  gen_random_uuid(),
  'admin@rareminds.in',
  '$2a$12$t9aYkPLyoK2p4hH8Af1kAePFLAH/UeGqyQ7SNAhsJY3lIdi8TQs2a', -- bcrypt hash for "admin@123"
  true,
  NOW(),
  NOW(),
  false
)
ON CONFLICT (email) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  is_email_verified = true,
  is_blocked = false,
  updated_at = NOW();

-- Get the user ID and create membership in platform org
DO $$
DECLARE
  v_user_id uuid;
  v_platform_org uuid := '00000000-0000-0000-0000-000000000001';
  v_super_admin_role uuid := 'a41f7ac5-7c65-406c-beac-94211b0f7207';
  v_membership_id uuid;
BEGIN
  -- Get the user ID
  SELECT id INTO v_user_id FROM users WHERE email = 'admin@rareminds.in';
  
  -- Create membership in platform org if it doesn't exist
  INSERT INTO memberships (user_id, org_id, status)
  VALUES (v_user_id, v_platform_org, 'active')
  ON CONFLICT (user_id, org_id) DO NOTHING
  RETURNING id INTO v_membership_id;
  
  -- If membership already exists, get its ID
  IF v_membership_id IS NULL THEN
    SELECT id INTO v_membership_id FROM memberships WHERE user_id = v_user_id AND org_id = v_platform_org;
  END IF;
  
  -- Assign super_admin role
  INSERT INTO membership_roles (membership_id, role_id)
  VALUES (v_membership_id, v_super_admin_role)
  ON CONFLICT (membership_id, role_id) DO NOTHING;
  
  RAISE NOTICE 'Admin user admin@rareminds.in created/updated with super_admin role';
END $$;
