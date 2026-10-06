-- Dev educator fixtures copied from production.
-- College: test.college.educator@rareminds.in
-- School: test.school.educator@rareminds.in
-- Missing optional actor references are NULL; original account and organization IDs are retained.
BEGIN;

INSERT INTO "public"."organizations" ("id", "name", "slug", "created_by", "created_at", "metadata", "deleted_at") VALUES
  ('d325841a-7350-45ca-853d-6107e0c57224', 'testing2collegeadmin', 'testing2collegeadmin-dbc8f7b7', NULL, '2026-10-01 07:00:49.162141+00', '{"organization_type": "college"}', NULL),
  ('01d58214-1542-426c-862c-827e219b9899', 'Testing School Admin', 'testing-school-admin-49b28fc1', NULL, '2026-10-01 09:19:51.511669+00', '{"organization_type": "school"}', NULL)
ON CONFLICT DO NOTHING;

INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata") VALUES
  ('fcd52c03-3a09-48cd-8594-d062971533a6', 'test.college.educator@rareminds.in', '$2a$12$soidLX1Z0m90GslqdJ3tj.5XnIuo.IDS7UVGVgFzZ8jCSkftts0hu', true, '2026-10-01 09:23:10.485273+00', '2026-10-01 09:23:10.752756+00', NULL, false, '{}'),
  ('201960e7-b0d1-4dd0-9d1b-a4ff9b02b968', 'test.school.educator@rareminds.in', '$2a$12$soidLX1Z0m90GslqdJ3tj.5XnIuo.IDS7UVGVgFzZ8jCSkftts0hu', true, '2026-10-01 09:30:27.916167+00', '2026-10-01 09:32:06.300344+00', '2026-10-01 09:32:05.783+00', false, '{}')
ON CONFLICT DO NOTHING;

INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
  ('3937d765-2f54-44da-8649-15bd89357ecc', 'fcd52c03-3a09-48cd-8594-d062971533a6', 'd325841a-7350-45ca-853d-6107e0c57224', '2026-10-01 09:23:10.485273+00', 'active'),
  ('c3d85c6b-c453-4579-9729-9d08af6dd2ff', '201960e7-b0d1-4dd0-9d1b-a4ff9b02b968', '01d58214-1542-426c-862c-827e219b9899', '2026-10-01 09:30:27.916167+00', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
  ('23d012b4-ffd0-4abc-8fbc-54d684671011', '3937d765-2f54-44da-8649-15bd89357ecc', 'de492521-2042-4cb2-b866-3372a4e711bc', '2026-10-01 09:23:10.485273+00'),
  ('61daee4a-2ce1-4998-9221-6adf72e41733', 'c3d85c6b-c453-4579-9729-9d08af6dd2ff', 'e0427f8f-442d-4d5a-b755-3bf52c6e7fe3', '2026-10-01 09:30:27.916167+00')
ON CONFLICT DO NOTHING;

COMMIT;
