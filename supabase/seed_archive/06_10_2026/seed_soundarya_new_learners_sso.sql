-- Soundarya College: add 3 new learners to SSO Auth DB
-- Learners: 1 MCA + 2 MBA
-- Password for all learners: Soundarya@123 (same bcrypt hash used by the supplied Soundarya reference seed).
-- Same execution flow as the supplied Soundarya seed package.
-- Insert-only: this file does not update existing Soundarya users, memberships, roles, organization data, or passwords.
BEGIN;

INSERT INTO "public"."users"
  ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata")
VALUES
  ('e180eacc-144a-5129-8a43-37833d561941'::uuid, 'sanjay299sanju@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"k","firstName":"Sanchay","contact_number":"8848270420"}'::jsonb),
  ('c6baed07-e92b-5e5f-8e68-fadd85eae5c9'::uuid, 'harshaabhi56@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"","firstName":"Harsha","contact_number":"9606793933"}'::jsonb),
  ('e10a439c-1725-5301-944f-79bcec5cf169'::uuid, 'likhib612@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"B","firstName":"Likhitha","contact_number":"7348910496"}'::jsonb)
ON CONFLICT ("id") DO NOTHING;

INSERT INTO "public"."memberships"
  ("id", "user_id", "org_id", "created_at", "status")
VALUES
  ('e33d4f15-b523-5862-8b2e-be246300eb2c'::uuid, 'e180eacc-144a-5129-8a43-37833d561941'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active'),
  ('4b2e00fb-2d34-5fa7-a315-2d01e8a3a557'::uuid, 'c6baed07-e92b-5e5f-8e68-fadd85eae5c9'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active'),
  ('6d6fe2a6-5cec-5826-8eda-938d39be76fa'::uuid, 'e10a439c-1725-5301-944f-79bcec5cf169'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active')
ON CONFLICT ("id") DO NOTHING;

INSERT INTO "public"."membership_roles"
  ("id", "membership_id", "role_id", "created_at")
VALUES
  ('cccd8b36-26e3-55db-abc9-30d1dbdfb086'::uuid, 'e33d4f15-b523-5862-8b2e-be246300eb2c'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW()),
  ('6fb2bbc8-27d0-5a75-a00d-9e51ebbfce9b'::uuid, '4b2e00fb-2d34-5fa7-a315-2d01e8a3a557'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW()),
  ('dde2b02d-87e1-5777-995a-db85aeea53a7'::uuid, '6d6fe2a6-5cec-5826-8eda-938d39be76fa'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW())
ON CONFLICT ("id") DO NOTHING;

COMMIT;
