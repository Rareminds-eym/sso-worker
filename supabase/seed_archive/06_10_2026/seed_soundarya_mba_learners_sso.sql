-- Soundarya College: add 4 MBA learners to SSO Auth DB
-- Password for all learners: Soundarya@123 (same bcrypt hash pattern as existing Soundarya learner seed).
-- Safe to re-run: upserts by fixed IDs; memberships/roles use fixed IDs.
BEGIN;

INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata") VALUES
('a42bacdf-bcb3-441e-9a5c-2413f20616f1'::uuid, 'simrithasuresh31@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"S","firstName":"Simritha","contact_number":"7904603568"}'::jsonb),
('523512cd-9c31-4ae9-8eeb-a1e839a99946'::uuid, 'ddeekshith920@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"","firstName":"Deekshith","contact_number":"9035626885"}'::jsonb),
('597faf14-c863-4e95-bb8e-d90a9e0c33ff'::uuid, 'sumithasenthil0225@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"S","firstName":"Sumitha","contact_number":"9092039023"}'::jsonb),
('376652c3-0405-557d-9610-54c96740a56a'::uuid, 'priyankapriyanka54295@gmail.com', '$2a$12$5KnQCfP6VqMlQ6aF9RaKS.0SfJqEPyfHAcKISSRYCX7bLgWC/qDC.', true, NOW(), NOW(), NULL, false, '{"role":"learner","lastName":"Y A","firstName":"Priyanka","contact_number":"7892349083"}'::jsonb)
ON CONFLICT ("id") DO UPDATE SET
  "email"=EXCLUDED."email", "password_hash"=EXCLUDED."password_hash", "is_email_verified"=true, "updated_at"=NOW(), "is_blocked"=false, "user_metadata"=EXCLUDED."user_metadata";

INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
('21a84bce-983d-44ec-a51c-68285ed45b18'::uuid, 'a42bacdf-bcb3-441e-9a5c-2413f20616f1'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active'),
('ae3f5302-4ee3-49a1-9132-cf863c1e8fcb'::uuid, '523512cd-9c31-4ae9-8eeb-a1e839a99946'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active'),
('0b420ea9-3bbe-4a2c-92c3-f3c1f675cce4'::uuid, '597faf14-c863-4e95-bb8e-d90a9e0c33ff'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active'),
('cc5c57f5-7e53-51bb-a3fe-ec2ad3e04b07'::uuid, '376652c3-0405-557d-9610-54c96740a56a'::uuid, '284c9ed9-cd13-584d-b5bc-e198866b917b'::uuid, NOW(), 'active')
ON CONFLICT ("id") DO UPDATE SET "status"='active';

INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
('e8015bf6-25f0-4599-8abd-306e44bc9b9c'::uuid, '21a84bce-983d-44ec-a51c-68285ed45b18'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW()),
('33589a87-fbfd-48ae-b030-9dc86989a45c'::uuid, 'ae3f5302-4ee3-49a1-9132-cf863c1e8fcb'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW()),
('9e745b4d-1d1b-4804-b62f-99605792c3e6'::uuid, '0b420ea9-3bbe-4a2c-92c3-f3c1f675cce4'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW()),
('6944a2e7-8495-53f5-84b9-39bc9b8646b6'::uuid, 'cc5c57f5-7e53-51bb-a3fe-ec2ad3e04b07'::uuid, '8d018d55-46f4-4e67-b6a5-8c216737a374'::uuid, NOW())
ON CONFLICT ("id") DO NOTHING;

COMMIT;
