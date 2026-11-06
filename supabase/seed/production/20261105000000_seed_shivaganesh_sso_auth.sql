-- Soundarya College: add shivaganesh2046@gmail.com learner to SSO Auth DB
-- Learner: Shivaganesh (MBA - Marketing)
-- Password: Soundarya@123 (same bcrypt hash used by existing Soundarya learner seeds)
-- Safe and idempotent: can be re-run safely, uses fixed IDs with ON CONFLICT DO NOTHING
-- Organization ID: 284c9ed9-cd13-584d-b5bc-e198866b917b (Soundarya Institute of Management and Science)
-- Learner Role ID: 8d018d55-46f4-4e67-b6a5-8c216737a374 (learner role)

BEGIN;

-- 0. Ensure Soundarya Organization exists in SSO database
INSERT INTO "public"."organizations" ("id", "name", "slug", "created_at")
VALUES (
  '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid,
  'Soundarya Institute of Management and Science',
  'soundarya-institute-management-science',
  NOW()
)
ON CONFLICT ("id") DO NOTHING;

-- 1. Insert SSO user account
INSERT INTO "public"."users"
  ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata")
VALUES
  ('f8182d23-28f3-5d54-b610-dc82f2470d4d'::uuid, 
   'shivaganesh2046@gmail.com', 
   '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', 
   true, 
   NOW(), 
   NOW(), 
   NULL, 
   false, 
   '{"role":"learner","lastName":"","firstName":"Shivaganesh","contact_number":""}'::jsonb)
ON CONFLICT ("id") DO NOTHING;

-- 2. Insert membership in Soundarya organization
INSERT INTO "public"."memberships"
  ("id", "user_id", "org_id", "created_at", "status")
VALUES
  ('d85a3c12-7b9e-5f42-8730-1e4a8b2c9d3f'::uuid, 
   'f8182d23-28f3-5d54-b610-dc82f2470d4d'::uuid, 
   '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, 
   NOW(), 
   'active')
ON CONFLICT ("id") DO NOTHING;

-- 3. Assign learner role to membership
INSERT INTO "public"."membership_roles"
  ("id", "membership_id", "role_id", "created_at")
VALUES
  ('e92b4d78-3a1c-5e87-9d42-2f6b8c3a1e5d'::uuid, 
   'd85a3c12-7b9e-5f42-8730-1e4a8b2c9d3f'::uuid, 
   '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, 
   NOW())
ON CONFLICT ("id") DO NOTHING;

COMMIT;
