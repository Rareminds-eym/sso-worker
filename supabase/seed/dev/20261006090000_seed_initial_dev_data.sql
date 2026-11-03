SET session_replication_role = replica;

--
-- PostgreSQL database dump
--

-- \restrict NvxGDkqCP8gNYxvPAnUEfCzdC9G2IgBtKjy7oH0k9sbiYSp9Rv3UCWNPOehoemu

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: audit_log_entries; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: custom_oauth_providers; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: flow_state; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: identities; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: instances; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: oauth_clients; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: sessions; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: mfa_amr_claims; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: mfa_factors; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: mfa_challenges; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: mfa_recovery_code_sets; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: mfa_recovery_codes; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: oauth_authorizations; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: oauth_client_states; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: oauth_consents; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: one_time_tokens; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: refresh_tokens; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: sso_providers; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: saml_providers; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: saml_relay_states; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: scim_tokens; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: scim_users; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: sso_domains; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: webauthn_challenges; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: webauthn_credentials; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--



--
-- Data for Name: products; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."products" ("id", "code", "name", "description", "created_at") VALUES
	('912d5049-e195-46e9-a319-49e3502bf7e7', 'skillpassport', 'SkillPassport', 'Skill development and career advancement platform', '2026-05-22 04:01:09.763845+00'),
	('7352d0f4-88a6-4e14-9421-6c5706791973', 'lte', 'LTE', 'Enterprise learning transformation and training management system', '2026-05-22 04:01:09.763845+00');


--
-- Data for Name: addon_catalog; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."addon_catalog" ("id", "product_id", "category", "feature_key", "feature_name", "feature_value", "description", "price_monthly", "price_annual", "target_roles", "icon", "display_order", "is_active", "created_at", "updated_at") VALUES
	('2a9d446c-2d77-4e67-80d7-7df0ce0dc01c', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learning', 'career_ai', 'Career AI', 'AI-powered career guidance', 'AI-powered career guidance and personalized recommendations', 1999.00, 19990.00, '{learner}', '≡ƒñû', 1, true, '2026-05-26 10:06:30.993173+00', '2026-05-26 10:06:30.993173+00'),
	('b6c7f870-1dae-4962-bd55-339067f17831', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learning', 'ai_job_matching', 'AI Job Matching', 'Smart job matching', 'Intelligent job matching that connects you with relevant opportunities', 1999.00, 19990.00, '{learner}', '≡ƒÄ»', 2, true, '2026-05-26 10:06:30.993173+00', '2026-05-26 10:06:30.993173+00'),
	('60f254cc-adc7-4dd4-8847-5049e9dc764c', '912d5049-e195-46e9-a319-49e3502bf7e7', 'content', 'video_portfolio', 'Video Portfolio', 'Showcase with video', 'Showcase your skills and projects with a professional video portfolio', 499.00, 4990.00, '{learner}', '≡ƒÄ¼', 3, true, '2026-05-26 10:06:30.993173+00', '2026-05-26 10:06:30.993173+00');


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata") VALUES
	('17b4400f-6737-40bc-899f-071cbd7ce552', 'gokul@rareminds.in', '$2a$12$soidLX1Z0m90GslqdJ3tj.5XnIuo.IDS7UVGVgFzZ8jCSkftts0hu', true, '2026-05-26 10:09:39.236338+00', '2026-09-05 06:46:06.374497+00', '2026-09-05 06:46:05.867+00', false, '{"last_name": "Raj", "first_name": "Gokul"}'),
	('a822aedd-2ade-4d42-86ff-74775215a5ff', 'admin@rareminds.in', '$2a$12$t9aYkPLyoK2p4hH8Af1kAePFLAH/UeGqyQ7SNAhsJY3lIdi8TQs2a', true, '2026-06-20 06:31:53.550462+00', '2026-10-05 10:48:18.951639+00', '2026-10-05 10:48:18.339+00', false, '{}'),
	('8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b1', 'admin@cambridgeschool.edu.in', '$2a$12$mPJ9i/r78DWsSlXVQeKi1..f5NWkl4Tk8KXerQ8kya946hcZx.pwq', true, '2026-07-21 04:18:14.870874+00', '2026-07-21 05:46:50.61375+00', '2026-07-21 05:46:49.963+00', false, '{}'),
	('783d8431-a034-5369-ae47-3aca2c4ec618', 'sims.info@soundaryainstitutions.in', '$2b$12$TXc2NhMMjYxKuPoQYdI8UeRRzw5v/XEtEjpcYbYIwomWAZGBeWpny', true, '2026-08-31 14:36:38.698278+00', '2026-10-03 05:56:37.501772+00', '2026-10-03 05:56:37.658+00', false, '{}');


--
-- Data for Name: addon_purchases; Type: TABLE DATA; Schema: public; Owner: postgres
--




--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."organizations" ("id", "name", "slug", "created_by", "created_at", "metadata", "deleted_at") VALUES
	('00000000-0000-0000-0000-000000000001', 'SkillPassport Platform', 'platform', NULL, '2026-05-06 09:25:39.909089+00', '{"is_platform_org": true}', NULL),
	('8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', 'Cambridge School', 'cambridge-school', NULL, '2026-07-21 04:18:14.870874+00', '{"city": "Bengaluru", "board": "CBSE", "state": "Karnataka", "country": "India", "contact_email": "admin@cambridgeschool.edu.in", "organization_type": "school"}', NULL),
	('284c9ed9-cd13-584d-b5bc-e198866b917b', 'Soundarya Institute of Management and Science', 'soundarya-institute-management-science', '783d8431-a034-5369-ae47-3aca2c4ec618', '2026-08-31 14:36:38.698278+00', '{"city": "Bengaluru", "state": "Karnataka", "country": "India", "website": "https://soundarya.edu.in/", "admin_id": "783d8431-a034-5369-ae47-3aca2c4ec618", "short_name": "SIMS", "postal_code": "560073", "founded_year": 2007, "academic_year": "2026/2027", "address_line_1": "Soundarya Nagar, Sidedahalli, Nagasandra Post, 296, 9th Cross Road, Prakruthi Layout, Siddeshwar Layout, Soundarya Layout", "placement_phone": "+919606245769", "admissions_email": "admissions@soundaryainstitutions.in", "institution_name": "Soundarya Institute of Management and Science", "information_email": "sims.info@soundaryainstitutions.in", "onboarding_source": "soundarya_admin_migration", "organization_type": "college", "admissions_phone_1": "+916269000092", "admissions_phone_2": "+916269000093", "principal_director": "Dr. Prakash HS", "onboarding_completed": true, "affiliated_university": "Bangalore University"}', NULL);


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--




--
-- Data for Name: bundles; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."bundles" ("id", "product_id", "name", "slug", "description", "target_roles", "monthly_price", "annual_price", "discount_percentage", "is_active", "display_order", "created_at", "updated_at") VALUES
	('e848e655-b02d-4c3b-bf61-dfeb4a6bc7b7', '912d5049-e195-46e9-a319-49e3502bf7e7', 'Career Starter', 'career-starter', 'Career AI + AI Job Matching bundle for students', '{student}', 3558.40, 35584.00, 20, true, 1, '2026-05-22 05:28:49.088424+00', '2026-05-22 05:28:49.088424+00'),
	('8ca0531d-a112-4e48-9f8d-3dc5acfa6f1e', '912d5049-e195-46e9-a319-49e3502bf7e7', 'Educator Pro', 'educator-pro', 'Complete toolkit for educators to enhance teaching effectiveness', '{educator}', 518.00, 5180.00, 20, true, 2, '2026-05-22 05:28:49.088424+00', '2026-05-22 05:28:49.088424+00'),
	('02a9df7d-fbfa-4f9b-aa34-614d6c04bab5', '912d5049-e195-46e9-a319-49e3502bf7e7', 'Institution Complete', 'institution-complete', 'Full suite of administrative tools for institutions', '{school_admin,college_admin,university_admin}', 958.00, 9580.00, 25, true, 3, '2026-05-22 05:28:49.088424+00', '2026-05-22 05:28:49.088424+00'),
	('f70d80db-a528-4fae-8e6a-e07c0d9b2361', '912d5049-e195-46e9-a319-49e3502bf7e7', 'Recruiter Suite', 'recruiter-suite', 'Comprehensive recruitment and talent management tools', '{recruiter}', 1037.00, 10370.00, 20, true, 4, '2026-05-22 05:28:49.088424+00', '2026-05-22 05:28:49.088424+00');


--
-- Data for Name: bundle_features; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."bundle_features" ("id", "bundle_id", "feature_key", "created_at") VALUES
	('242bef44-f2ed-4c53-8e49-5488fe5c7944', 'e848e655-b02d-4c3b-bf61-dfeb4a6bc7b7', 'career_ai', '2026-05-22 05:28:49.088424+00'),
	('041606bf-7fd2-47be-a857-1fae5cd3da13', 'e848e655-b02d-4c3b-bf61-dfeb4a6bc7b7', 'ai_job_matching', '2026-05-22 05:28:49.088424+00'),
	('1aed8866-6f36-41d9-adec-b607d0901eaf', '8ca0531d-a112-4e48-9f8d-3dc5acfa6f1e', 'advanced_analytics', '2026-05-22 05:28:49.088424+00'),
	('e1ce1789-fce1-4879-ac4e-1f88fe78764d', '8ca0531d-a112-4e48-9f8d-3dc5acfa6f1e', 'course_analytics', '2026-05-22 05:28:49.088424+00'),
	('51abb4db-9e50-46b7-a36c-0d68004e282f', '8ca0531d-a112-4e48-9f8d-3dc5acfa6f1e', 'educator_ai', '2026-05-22 05:28:49.088424+00'),
	('408030f8-9b44-4cd9-b326-49b2697f30b5', '02a9df7d-fbfa-4f9b-aa34-614d6c04bab5', 'curriculum_builder', '2026-05-22 05:28:49.088424+00'),
	('85d40b97-fb1a-4a78-b98d-ccb47c5f9dc1', '02a9df7d-fbfa-4f9b-aa34-614d6c04bab5', 'fee_management', '2026-05-22 05:28:49.088424+00'),
	('1268a061-2c99-4153-82ca-2b58150d9d5e', '02a9df7d-fbfa-4f9b-aa34-614d6c04bab5', 'kpi_dashboard', '2026-05-22 05:28:49.088424+00'),
	('88635ba7-7959-4ccf-be75-4eca3de8dc03', '02a9df7d-fbfa-4f9b-aa34-614d6c04bab5', 'sso', '2026-05-22 05:28:49.088424+00'),
	('f5ecdb2d-869a-4e74-99c1-895f5291f716', 'f70d80db-a528-4fae-8e6a-e07c0d9b2361', 'pipeline_management', '2026-05-22 05:28:49.088424+00'),
	('3cb5f87c-e46e-4046-a034-83a6646ac2be', 'f70d80db-a528-4fae-8e6a-e07c0d9b2361', 'project_hiring', '2026-05-22 05:28:49.088424+00'),
	('38e705e9-82dd-4a75-a3bb-261cb3b5dedd', 'f70d80db-a528-4fae-8e6a-e07c0d9b2361', 'recruiter_ai', '2026-05-22 05:28:49.088424+00'),
	('a15dd5a6-fe99-4891-8067-3c7be7a3c01b', 'f70d80db-a528-4fae-8e6a-e07c0d9b2361', 'talent_pool_access', '2026-05-22 05:28:49.088424+00');


--
-- Data for Name: bundle_purchases; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: email_verifications; Type: TABLE DATA; Schema: public; Owner: postgres
--




--
-- Data for Name: events; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: feature_keys; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."feature_keys" ("id", "product_id", "key", "role", "nav_group", "nav_label", "nav_path", "display_order", "is_active", "created_at", "updated_at") VALUES
	('8599fb83-315e-4931-88c9-fcf423e54c51', '912d5049-e195-46e9-a319-49e3502bf7e7', 'admissions_data', 'college_admin', 'Learners', 'Admissions & Data', '/college-admin/learners/data-management', 10, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('7beea5bb-8c2d-4a95-8aa8-cd0d37f878e9', '912d5049-e195-46e9-a319-49e3502bf7e7', 'enrolled_learners', 'college_admin', 'Learners', 'Enrolled Learners', '/college-admin/learners/enrolled', 20, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('b84b3126-b19e-4492-b15d-72c2118e3ac2', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learner_attendance', 'college_admin', 'Learners', 'Attendance', '/college-admin/learners/attendance', 30, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('0d8f5bfe-0577-4016-9c3e-c0c9b03c26b8', '912d5049-e195-46e9-a319-49e3502bf7e7', 'assessment_results', 'college_admin', 'Learners', 'Assessment Results', '/college-admin/learners/assessment-results', 40, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d0032c77-f036-40c8-9f8a-b3c65f021f9b', '912d5049-e195-46e9-a319-49e3502bf7e7', 'digital_portfolio', 'college_admin', 'Learners', 'Digital Portfolio', '/college-admin/learners/digital-portfolio', 50, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('30bbd14f-b505-4b9e-9a71-9fba8f8c17fa', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learner_verifications', 'college_admin', 'Learners', 'Verifications', '/college-admin/learners/verifications', 60, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('9a6ecc36-5660-43fd-8bf6-78b5691d2df4', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learner_communication', 'college_admin', 'Learners', 'Communication', '/college-admin/learners/communication', 70, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('4307c0c3-86e9-4227-9959-e93b9e01a5fd', '912d5049-e195-46e9-a319-49e3502bf7e7', 'departments', 'college_admin', 'Departments & Faculty', 'Departments', '/college-admin/departments/management', 80, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('2b5a27fd-0503-48e5-92d5-a834795a3174', '912d5049-e195-46e9-a319-49e3502bf7e7', 'faculty', 'college_admin', 'Departments & Faculty', 'Faculty', '/college-admin/departments/educators', 90, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('9bc9cdb6-cf7b-445c-923d-52af51f54059', '912d5049-e195-46e9-a319-49e3502bf7e7', 'courses', 'college_admin', 'Academics', 'Courses', '/college-admin/academics/browse-courses', 100, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('f2ec82fb-f6b2-4d3a-9c68-21d141c9f3d5', '912d5049-e195-46e9-a319-49e3502bf7e7', 'programs', 'college_admin', 'Academics', 'Programs', '/college-admin/academics/programs', 110, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('f536bbd6-5e83-4a34-ab99-d37dafc4bc05', '912d5049-e195-46e9-a319-49e3502bf7e7', 'program_sections', 'college_admin', 'Academics', 'Program & Sections', '/college-admin/academics/program-sections', 120, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('6bc666dd-4f76-45e0-aa81-3bb84aa7d929', '912d5049-e195-46e9-a319-49e3502bf7e7', 'course_mapping', 'college_admin', 'Academics', 'Course Mapping', '/college-admin/departments/mapping', 130, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('cf698808-de5e-4d34-9bc5-712f414138ea', '912d5049-e195-46e9-a319-49e3502bf7e7', 'curriculum_builder', 'college_admin', 'Academics', 'Curriculum Builder', '/college-admin/academics/curriculum', 140, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d3cf5614-3c20-4881-b61b-1967d9a7c6d4', '912d5049-e195-46e9-a319-49e3502bf7e7', 'lesson_plans', 'college_admin', 'Academics', 'Lesson Plans', '/college-admin/academics/lesson-plans', 150, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('4566a511-838e-409d-9b10-1826011e30e0', '912d5049-e195-46e9-a319-49e3502bf7e7', 'exam_management', 'college_admin', 'Examinations', 'Exam Management', '/college-admin/examinations', 160, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('852e48db-8b83-4512-afac-4cddfaf411bb', '912d5049-e195-46e9-a319-49e3502bf7e7', 'placement_status', 'college_admin', 'Placements & Skills', 'Placements', '/college-admin/placements', 170, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('603accbb-95b1-4bd4-af33-89990258f2f3', '912d5049-e195-46e9-a319-49e3502bf7e7', 'mentors', 'college_admin', 'Placements & Skills', 'Mentors', '/college-admin/mentors', 180, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('df2ab8f3-ca34-46ba-be9c-1d296cf36466', '912d5049-e195-46e9-a319-49e3502bf7e7', 'finance', 'college_admin', 'Operations', 'Finance', '/college-admin/finance', 190, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('46d1a75c-2c21-4126-bdbb-4dce77092b57', '912d5049-e195-46e9-a319-49e3502bf7e7', 'library', 'college_admin', 'Operations', 'Library', '/college-admin/library', 200, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('b3e27a34-6b4f-496e-a612-53f71219477e', '912d5049-e195-46e9-a319-49e3502bf7e7', 'events', 'college_admin', 'Operations', 'Events', '/college-admin/events', 210, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('98fe85bf-d988-4dac-b394-401157e30b58', '912d5049-e195-46e9-a319-49e3502bf7e7', 'circulars', 'college_admin', 'Operations', 'Circulars', '/college-admin/circulars', 220, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('bb30c2bd-833c-41c6-89b5-f4347247c01e', '912d5049-e195-46e9-a319-49e3502bf7e7', 'user_management', 'college_admin', 'Administration', 'User Management', '/college-admin/users', 230, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('92b902e6-1e6e-4419-a1a7-c0c5d1994f9b', '912d5049-e195-46e9-a319-49e3502bf7e7', 'reports_analytics', 'college_admin', 'Administration', 'Reports & Analytics', '/college-admin/reports', 240, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('39a0790b-8144-4da9-93d6-a62e0bff039c', '912d5049-e195-46e9-a319-49e3502bf7e7', 'basic_analytics', 'college_admin', 'Administration', 'Course Analytics', '/college-admin/course-analytics', 250, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d1939fac-9030-4d4a-91bd-f95a53a02f01', '912d5049-e195-46e9-a319-49e3502bf7e7', 'admissions', 'school_admin', 'Learner Management', 'Admissions', '/school-admin/learners/admissions', 10, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('50494373-3027-4445-bed3-6e1aae09679f', '912d5049-e195-46e9-a319-49e3502bf7e7', 'digital_portfolio', 'school_admin', 'Learner Management', 'Digital Portfolio', '/school-admin/learners/digital-portfolio', 20, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('b79848dd-2bc6-4e7e-b8a7-a46ae28c4ffc', '912d5049-e195-46e9-a319-49e3502bf7e7', 'class_management', 'school_admin', 'Learner Management', 'Class Management', '/school-admin/classes/management', 30, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('ec337772-0aae-4760-9960-70f655c38abe', '912d5049-e195-46e9-a319-49e3502bf7e7', 'attendance_reports', 'school_admin', 'Learner Management', 'Attendance & Reports', '/school-admin/learners/attendance-reports', 40, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('43f3adf2-8b68-4ef6-a3fd-8d2cc27d8660', '912d5049-e195-46e9-a319-49e3502bf7e7', 'assessment_results', 'school_admin', 'Learner Management', 'Assessment Results', '/school-admin/learners/assessment-results', 50, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('11c05478-3dd4-41cb-8cd2-28f64f4ae3d7', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learner_verifications', 'school_admin', 'Learner Management', 'Verifications', '/school-admin/learners/verifications', 60, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('12270b08-7df4-438a-a4b4-080e863d9b2b', '912d5049-e195-46e9-a319-49e3502bf7e7', 'teachers', 'school_admin', 'Teacher Management', 'Teachers', '/school-admin/teachers/list', 70, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('6c5db5d2-b72d-42ff-83ff-bc3f2ca60a57', '912d5049-e195-46e9-a319-49e3502bf7e7', 'teacher_onboarding', 'school_admin', 'Teacher Management', 'Onboarding', '/school-admin/teachers/onboarding', 80, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d48b03c8-aca3-42df-8457-aa69868ea20f', '912d5049-e195-46e9-a319-49e3502bf7e7', 'teacher_timetable', 'school_admin', 'Teacher Management', 'Timetable', '/school-admin/teachers/timetable', 90, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('4a98bbdf-c6db-439a-9bc7-fdb949b5e85a', '912d5049-e195-46e9-a319-49e3502bf7e7', 'courses', 'school_admin', 'Academic Management', 'Courses', '/school-admin/academics/browse-courses', 100, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('2ef80181-731e-4f6b-85a6-05d2ac532d46', '912d5049-e195-46e9-a319-49e3502bf7e7', 'curriculum_builder', 'school_admin', 'Academic Management', 'Curriculum Builder', '/school-admin/academics/curriculum', 110, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('16890eea-838d-4e6e-a9c9-21c9275a48c2', '912d5049-e195-46e9-a319-49e3502bf7e7', 'lesson_plans', 'school_admin', 'Academic Management', 'Lesson Plans', '/school-admin/academics/lesson-plans', 120, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('a2dae388-2a45-41a6-a1b9-af178701f86c', '912d5049-e195-46e9-a319-49e3502bf7e7', 'exams_assessments', 'school_admin', 'Academic Management', 'Exams & Assessments', '/school-admin/academics/exams', 130, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('1dedc7a2-7cf1-4716-96a5-acef8de64902', '912d5049-e195-46e9-a319-49e3502bf7e7', 'parent_portal', 'school_admin', 'Parent & Communication', 'Parent Portal', '/school-admin/communication/parents', 140, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('87bfd514-2694-47ec-88bf-c71d09523cf0', '912d5049-e195-46e9-a319-49e3502bf7e7', 'message_center', 'school_admin', 'Parent & Communication', 'Message Center', '/school-admin/communication/messages', 150, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('3efc1140-28fa-4a55-8268-c0da006c2830', '912d5049-e195-46e9-a319-49e3502bf7e7', 'parent_communication', 'school_admin', 'Parent & Communication', 'Parent Communication', '/school-admin/communication/circulars', 160, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('4e0266f9-8292-498c-8439-747c3ff7575b', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learner_communication', 'school_admin', 'Parent & Communication', 'Learner Communication', '/school-admin/communication/messages-learner', 170, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('98903721-4fe6-409b-8955-5a34fc82a420', '912d5049-e195-46e9-a319-49e3502bf7e7', 'fee_setup_payments', 'school_admin', 'Finance & Infrastructure', 'Fee Setup & Payments', '/school-admin/finance/fees', 180, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('458b10f3-51e6-4786-a3bf-b98f886220ab', '912d5049-e195-46e9-a319-49e3502bf7e7', 'library_assets', 'school_admin', 'Finance & Infrastructure', 'Library & Assets', '/school-admin/infrastructure/library', 190, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('13ab4648-fec7-425a-9091-a484649d7472', '912d5049-e195-46e9-a319-49e3502bf7e7', 'maintenance', 'school_admin', 'Finance & Infrastructure', 'Maintenance', '/school-admin/infrastructure/maintenance', 200, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('ad17f6b0-5501-4206-be28-b620ab912f16', '912d5049-e195-46e9-a319-49e3502bf7e7', 'clubs_competitions', 'school_admin', 'Skill & Co-Curricular', 'Clubs & Competitions', '/school-admin/skills/clubs', 210, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('93707ada-5086-48c7-85a1-6303d97db19a', '912d5049-e195-46e9-a319-49e3502bf7e7', 'competition_certificates', 'school_admin', 'Skill & Co-Curricular', 'Competition Certificates', '/school-admin/skills/badges', 220, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d5126fb1-4870-4285-abaa-47e43efe91a8', '912d5049-e195-46e9-a319-49e3502bf7e7', 'skills_reports', 'school_admin', 'Skill & Co-Curricular', 'Reports', '/school-admin/skills/reports', 230, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('30efc79c-5893-4eb0-b596-460cb13d7029', '912d5049-e195-46e9-a319-49e3502bf7e7', 'basic_analytics', 'school_admin', 'Skill & Co-Curricular', 'Course Analytics', '/school-admin/course-analytics', 240, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('33d04b6e-cd97-484b-8866-0909ebdb5779', '912d5049-e195-46e9-a319-49e3502bf7e7', 'college_registration', 'university_admin', 'Affiliated College Management', 'College Registration', '/university-admin/colleges/registration', 10, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('20751277-a3a7-49ea-bb53-4d8f7d3f2869', '912d5049-e195-46e9-a319-49e3502bf7e7', 'program_allocation', 'university_admin', 'Affiliated College Management', 'Program Allocation', '/university-admin/colleges/programs', 20, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('bf7004e7-a76b-4187-a6c9-7e1823032770', '912d5049-e195-46e9-a319-49e3502bf7e7', 'performance_monitoring', 'university_admin', 'Affiliated College Management', 'Performance Monitoring', '/university-admin/colleges/performance', 30, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('2f1e9c23-47e7-410d-8d94-52366b6eedbb', '912d5049-e195-46e9-a319-49e3502bf7e7', 'courses', 'university_admin', 'Course & Curriculum Management', 'Courses', '/university-admin/browse-courses', 40, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('a0165aa9-4306-4875-a91e-b0aa98d7f7ff', '912d5049-e195-46e9-a319-49e3502bf7e7', 'syllabus_approval', 'university_admin', 'Course & Curriculum Management', 'Syllabus Approval', '/university-admin/courses/syllabus', 50, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('3a0f8568-a7cf-4d37-9aa9-29fdfa6a3b02', '912d5049-e195-46e9-a319-49e3502bf7e7', 'course_updates', 'university_admin', 'Course & Curriculum Management', 'Course Updates', '/university-admin/courses/updates', 60, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('eef471f7-87bd-489c-b196-6b3961b0518e', '912d5049-e195-46e9-a319-49e3502bf7e7', 'content_repository', 'university_admin', 'Course & Curriculum Management', 'Content Repository', '/university-admin/courses/content', 70, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('fda108d2-9878-4343-83e0-9b479a5e64bf', '912d5049-e195-46e9-a319-49e3502bf7e7', 'faculty_empanelment', 'university_admin', 'Faculty & Trainer Management', 'Empanelment & Assignment', '/university-admin/faculty/empanelment', 80, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('0eb4dfc0-9529-4a54-b853-eb33025336da', '912d5049-e195-46e9-a319-49e3502bf7e7', 'faculty_feedback_certification', 'university_admin', 'Faculty & Trainer Management', 'Feedback & Certification', '/university-admin/faculty/feedback', 90, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('4d81834d-6899-4dbf-a566-7b196dc48c46', '912d5049-e195-46e9-a319-49e3502bf7e7', 'enrollment_profiles', 'university_admin', 'Learner Records', 'Enrollment & Profiles', '/university-admin/learners/enrollments', 100, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('3b4837bc-aa53-47d3-938a-a6efee30f902', '912d5049-e195-46e9-a319-49e3502bf7e7', 'digital_portfolios', 'university_admin', 'Learner Records', 'Digital Portfolios', '/university-admin/learners/digital-portfolios', 110, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('e13ecc05-e76a-485e-971e-75596dbcab4b', '912d5049-e195-46e9-a319-49e3502bf7e7', 'assessment_results', 'university_admin', 'Learner Records', 'Assessment Results', '/university-admin/learners/assessment-results', 120, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('502c86dc-3987-431c-9c57-6bea4376979c', '912d5049-e195-46e9-a319-49e3502bf7e7', 'continuous_assessment', 'university_admin', 'Learner Records', 'Continuous Assessment', '/university-admin/learners/continuous-assessment', 130, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('4bbff25e-9f69-4bbe-8f69-0fd7346347e6', '912d5049-e195-46e9-a319-49e3502bf7e7', 'centralized_results', 'university_admin', 'Learner Records', 'Centralized Results', '/university-admin/learners/results', 140, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d2b74054-b976-4b99-8b78-50d784ad2251', '912d5049-e195-46e9-a319-49e3502bf7e7', 'certificate_generation', 'university_admin', 'Learner Records', 'Certificate Generation', '/university-admin/learners/certificates', 150, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('e1de4390-e351-4b8d-af58-6ab5f769db1f', '912d5049-e195-46e9-a319-49e3502bf7e7', 'examination_scheduling', 'university_admin', 'Examination Management', 'Examination Scheduling', '/university-admin/examinations', 160, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('c0523c20-7457-47ab-aba5-9335daf935c4', '912d5049-e195-46e9-a319-49e3502bf7e7', 'grade_calculation', 'university_admin', 'Examination Management', 'Grade Calculation', '/university-admin/examinations/grades', 170, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('106e5712-26b2-4491-b179-ad59eaa4b301', '912d5049-e195-46e9-a319-49e3502bf7e7', 'results_publishing', 'university_admin', 'Examination Management', 'Results Publishing', '/university-admin/examinations/results', 180, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('137d0423-bdf1-45e0-b56f-3898c9affe75', '912d5049-e195-46e9-a319-49e3502bf7e7', 'placement_readiness', 'university_admin', 'Placement & Industry Linkages', 'Placement Readiness', '/university-admin/placements/readiness', 190, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('b4229a46-e017-4ba1-9270-c3b6e86650b4', '912d5049-e195-46e9-a319-49e3502bf7e7', 'company_database', 'university_admin', 'Placement & Industry Linkages', 'Company Database', '/university-admin/placements/companies', 200, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('1bcf1804-bf88-414c-94c8-0aef23474ac3', '912d5049-e195-46e9-a319-49e3502bf7e7', 'internship_reports', 'university_admin', 'Placement & Industry Linkages', 'Internship Reports', '/university-admin/placements/internships', 210, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('b2d3d334-c568-4bed-9911-0baad29495f9', '912d5049-e195-46e9-a319-49e3502bf7e7', 'mous_partnerships', 'university_admin', 'Placement & Industry Linkages', 'MoUs & Partnerships', '/university-admin/placements/mous', 220, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('51c8823c-7699-40a8-9d2f-5f9fd5fca125', '912d5049-e195-46e9-a319-49e3502bf7e7', 'fee_structures', 'university_admin', 'Finance & Fees', 'Fee Structures', '/university-admin/finance', 230, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d8df4230-0cf3-4a19-a3f9-f54062f19e97', '912d5049-e195-46e9-a319-49e3502bf7e7', 'payment_tracking', 'university_admin', 'Finance & Fees', 'Payment Tracking', '/university-admin/finance/payments', 240, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('756f6625-12ad-40e6-a339-d93f43cb0f1d', '912d5049-e195-46e9-a319-49e3502bf7e7', 'financial_reports', 'university_admin', 'Finance & Fees', 'Financial Reports', '/university-admin/finance/reports', 250, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('3e526179-4939-4e32-a757-2058c756d472', '912d5049-e195-46e9-a319-49e3502bf7e7', 'district_college_reports', 'university_admin', 'Analytics & Compliance', 'District & College Reports', '/university-admin/analytics/reports', 260, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('776a1560-8943-438c-814a-3ce95b2864cc', '912d5049-e195-46e9-a319-49e3502bf7e7', 'basic_analytics', 'university_admin', 'Analytics & Compliance', 'Course Analytics', '/university-admin/analytics/course-analytics', 270, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('29fabbba-4221-4c6e-bf71-dbafb6539ef0', '912d5049-e195-46e9-a319-49e3502bf7e7', 'scheme_compliance', 'university_admin', 'Analytics & Compliance', 'Scheme Compliance (TNSDC)', '/university-admin/analytics/compliance', 280, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('4b128a78-8cf2-4d45-b33a-b553248c24a8', '912d5049-e195-46e9-a319-49e3502bf7e7', 'obe_tracking', 'university_admin', 'Analytics & Compliance', 'OBE Tracking', '/university-admin/analytics/obe-tracking', 290, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('e0d69d1e-8d47-4b9c-8860-2604176aa5ab', '912d5049-e195-46e9-a319-49e3502bf7e7', 'library_management', 'university_admin', 'Library & Learner Services', 'Library Management', '/university-admin/library/management', 300, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('ef20acf8-1e14-4ab9-bc11-7f2e15cfda1a', '912d5049-e195-46e9-a319-49e3502bf7e7', 'library_clearance', 'university_admin', 'Library & Learner Services', 'Library Clearance', '/university-admin/library/clearance', 310, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('7f7dc361-e83f-4c0c-82e1-af82554fa592', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learner_service_requests', 'university_admin', 'Library & Learner Services', 'Learner Service Requests', '/university-admin/library/service-requests', 320, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('99d0242b-18e5-4337-b47d-2aa78426b3bb', '912d5049-e195-46e9-a319-49e3502bf7e7', 'graduation_integration', 'university_admin', 'Library & Learner Services', 'Graduation Integration', '/university-admin/library/graduation-integration', 330, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('0f52caec-5ee8-49f9-a59a-99497bea2197', '912d5049-e195-46e9-a319-49e3502bf7e7', 'faculty_lifecycle', 'university_admin', 'HR & Payroll', 'Faculty Lifecycle', '/university-admin/hr/faculty-lifecycle', 340, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('f8b68604-bf31-40d4-8bca-d920001f0115', '912d5049-e195-46e9-a319-49e3502bf7e7', 'staff_management', 'university_admin', 'HR & Payroll', 'Staff Management', '/university-admin/hr/staff-management', 350, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('14043bb2-b9f3-47e0-926b-16ea973656ab', '912d5049-e195-46e9-a319-49e3502bf7e7', 'payroll_processing', 'university_admin', 'HR & Payroll', 'Payroll Processing', '/university-admin/hr/payroll', 360, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('e960e443-a893-4681-8832-914dce711241', '912d5049-e195-46e9-a319-49e3502bf7e7', 'statutory_deductions', 'university_admin', 'HR & Payroll', 'Statutory Deductions', '/university-admin/hr/statutory-deductions', 370, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('44692a46-c6c8-4393-88d0-f7e0f06b224b', '912d5049-e195-46e9-a319-49e3502bf7e7', 'employee_records', 'university_admin', 'HR & Payroll', 'Employee Records', '/university-admin/hr/employee-records', 380, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('d8d0378f-b1b6-4067-af0b-d10eebe918a5', '912d5049-e195-46e9-a319-49e3502bf7e7', 'leave_management', 'university_admin', 'HR & Payroll', 'Leave Management', '/university-admin/hr/leave-management', 390, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('a0bc4d9a-b769-4146-ac07-e67338a7344b', '912d5049-e195-46e9-a319-49e3502bf7e7', 'circulars_notices', 'university_admin', 'Communication & Announcements', 'Circulars & Notices', '/university-admin/communication/circulars', 400, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00'),
	('71b45101-11ae-46f6-8a15-35806c5a0d3f', '912d5049-e195-46e9-a319-49e3502bf7e7', 'training_updates', 'university_admin', 'Communication & Announcements', 'Training Updates', '/university-admin/communication/training', 410, true, '2026-09-29 06:05:10.441259+00', '2026-10-01 06:49:12.877939+00');


--
-- Data for Name: invites; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: memberships; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
	('d33b65a0-f2ff-44ad-967c-27a9633af911', '17b4400f-6737-40bc-899f-071cbd7ce552', '00000000-0000-0000-0000-000000000001', '2026-05-26 10:09:39.236338+00', 'active'),
	('d19f7c8b-e853-4911-9942-2234ca35f1fd', 'a822aedd-2ade-4d42-86ff-74775215a5ff', '00000000-0000-0000-0000-000000000001', '2026-06-20 06:31:53.550462+00', 'active'),
	('8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b2', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b1', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', '2026-07-21 04:18:14.870874+00', 'active'),
	('ac5a8887-5058-552b-8d5b-421b61c4bf79', '783d8431-a034-5369-ae47-3aca2c4ec618', '284c9ed9-cd13-584d-b5bc-e198866b917b', '2026-08-31 14:36:38.698278+00', 'active');


--
-- Data for Name: membership_products; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."membership_products" ("id", "membership_id", "product_id", "created_at") VALUES
	('f6adb940-d15e-4445-8092-b505090f39af', 'd33b65a0-f2ff-44ad-967c-27a9633af911', '7352d0f4-88a6-4e14-9421-6c5706791973', '2026-09-05 04:15:06.155182+00');


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."roles" ("id", "name", "description", "created_at") VALUES
	('77cbb094-e23f-4e2a-831d-acc88fd54a75', 'owner', 'Organization owner with full access', '2026-04-11 07:58:47.639862+00'),
	('607887e8-8eab-4274-ae8a-53daec73933d', 'admin', 'Administrator with management access', '2026-04-11 07:58:47.639862+00'),
	('c24e153b-c852-4dac-b33b-ab9872af2996', 'member', 'Regular organization member', '2026-04-11 07:58:47.639862+00'),
	('a41f7ac5-7c65-406c-beac-94211b0f7207', 'super_admin', NULL, '2026-04-27 10:24:25.55545+00'),
	('8d946f32-3ccb-4430-a6c2-4ad0ddf5adb8', 'rm_admin', NULL, '2026-04-27 10:24:25.55545+00'),
	('b94b0035-1c81-4ea1-b978-5e7f5f0d778a', 'rm_manager', NULL, '2026-04-27 10:24:25.55545+00'),
	('0c1c14dc-448f-4957-93a4-c9baf4c870c9', 'company_admin', NULL, '2026-04-27 10:24:25.55545+00'),
	('0c9c3c7e-0b0e-4889-986c-a7cc5bae5878', 'educator', 'General educator/teacher', '2026-05-05 06:39:13.566845+00'),
	('e0427f8f-442d-4d5a-b755-3bf52c6e7fe3', 'school_educator', 'School-level educator', '2026-04-27 10:24:25.55545+00'),
	('de492521-2042-4cb2-b866-3372a4e711bc', 'college_educator', 'College-level educator', '2026-04-27 10:24:25.55545+00'),
	('a750dd44-691f-4636-9d73-9aaa47476c87', 'school_admin', 'School administrator', '2026-04-27 10:24:25.55545+00'),
	('cd6c98bc-67bc-4e3c-83a6-cdcb2dc6961e', 'college_admin', 'College administrator', '2026-04-27 10:24:25.55545+00'),
	('ebad8db9-bd7c-4ccb-8018-c0b021726bf7', 'university_admin', 'University administrator', '2026-04-27 10:24:25.55545+00'),
	('c53c6293-b1fc-43c5-a488-09a5b875f7f9', 'recruiter', 'Recruiter', '2026-04-27 10:24:25.55545+00'),
	('9d60ef12-be85-4d08-9588-d2699a3235a4', 'hr', 'Human resources', '2026-05-05 06:39:13.566845+00'),
	('8d018d55-46f4-4e67-b6a5-8c216737a374', 'learner', 'Self-directed learner', '2026-04-27 10:52:33.399156+00');


--
-- Data for Name: membership_roles; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."membership_roles" ("id", "membership_id", "role_id", "created_at") VALUES
	('2786a56c-1f3c-4b29-b2bc-8ad851ca8329', 'd33b65a0-f2ff-44ad-967c-27a9633af911', '8d018d55-46f4-4e67-b6a5-8c216737a374', '2026-05-26 10:09:39.236338+00'),
	('2470b3d2-c81a-4aeb-84a5-1bdd8ada0b99', 'd19f7c8b-e853-4911-9942-2234ca35f1fd', 'a41f7ac5-7c65-406c-beac-94211b0f7207', '2026-06-20 06:31:53.550462+00'),
	('8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b3', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b2', 'a750dd44-691f-4636-9d73-9aaa47476c87', '2026-07-21 04:18:14.870874+00'),
	('eb62c537-5e17-5dc8-84b8-238c38d99798', 'ac5a8887-5058-552b-8d5b-421b61c4bf79', 'cd6c98bc-67bc-4e3c-83a6-cdcb2dc6961e', '2026-08-31 14:36:38.698278+00');


--
-- Data for Name: oauth_accounts; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."oauth_accounts" ("id", "user_id", "provider", "provider_user_id", "created_at") VALUES
	('71d17085-9766-4ba1-a7b1-8ca6f958dd50', '17b4400f-6737-40bc-899f-071cbd7ce552', 'google', '102721960045304711804', '2026-09-01 07:05:46.986802+00');


--
-- Data for Name: organization_products; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."organization_products" ("id", "org_id", "product_id", "active", "created_at") VALUES
	('40a43822-5e1a-4c0c-abd6-361ecf3c613f', '00000000-0000-0000-0000-000000000001', '7352d0f4-88a6-4e14-9421-6c5706791973', true, '2026-09-05 04:12:31.532753+00'),
	('b172739f-ea78-4520-b864-a057decf4f94', '284c9ed9-cd13-584d-b5bc-e198866b917b', '7352d0f4-88a6-4e14-9421-6c5706791973', true, '2026-09-05 06:07:28.014519+00');


--
-- Data for Name: password_resets; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: plans; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."plans" ("id", "plan_code", "name", "business_type", "applicable_entities", "pricing_matrix", "base_features", "entity_config", "display_order", "is_active", "created_at", "updated_at", "product_id") VALUES
	('ef4a94ac-17b7-4a35-b47a-3a031f049b31', 'freemium', 'Discover', 'b2c', '{all}', '{"all": {"yearly": 0, "monthly": 0, "currency": "INR"}}', '["learner_profile_creation", "marketplace_explore", "sample_career_paths", "limited_dashboard_access", "1_basic_assessment", "basic_opportunity_view"]', '{"all": {"tagline": "Start free and explore career possibilities", "duration": "lifetime", "ideal_for": "Learners exploring the platform", "max_users": 1, "description": "Free learner plan with profile creation, limited dashboard access, and one basic assessment.", "positioning": "Free discovery plan for learners", "display_name": "Discover", "storage_limit": "0GB", "is_recommended": false}}', 0, true, '2026-05-21 11:27:23.226425+00', '2026-07-21 04:18:14.870874+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('b3d700e3-da45-4e3d-9387-5f5dbff06c0b', 'professional', 'Career Builder', 'b2c', '{all}', '{"all": {"yearly": 749, "currency": "INR"}}', '["advanced_career_assessment", "skill_gap_report", "6_month_learning_plan", "portfolio_creation", "course_lte_access", "opportunity_matching"]', '{"all": {"tagline": "Build a career-ready profile", "duration": "yearly", "ideal_for": "Learners preparing for career pathways and opportunities", "max_users": 1, "description": "Career-focused learner plan with advanced assessment, skill gap report, learning plan, portfolio, and matching.", "positioning": "Career readiness plan for learners", "display_name": "Career Builder", "storage_limit": "10GB", "is_recommended": true}}', 2, true, '2026-05-21 11:27:23.226425+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('8460ee67-18ff-4c2e-ac57-7e1f87dc8316', 'premium', 'Career Accelerator', 'b2c', '{all}', '{"all": {"yearly": 999, "monthly": 99, "currency": "INR"}}', '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "advanced_analytics", "career_path_recommendations", "resume_builder", "linkedin_optimization", "mock_interviews", "skill_assessments"]', '{"all": {"tagline": "Accelerate your career growth", "duration": "yearly", "ideal_for": "Students serious about career development", "max_users": 1, "description": "Premium features for career-focused learners", "positioning": "Unlock your full potential with premium career tools", "display_name": "Career Accelerator", "storage_limit": "5GB", "is_recommended": true}}', 1, true, '2026-05-21 11:27:23.226425+00', '2026-07-21 04:18:14.870874+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('d8d9828a-8f24-490b-81f9-6c03bcf77255', 'basic', 'Skill Starter', 'b2c', '{all}', '{"all": {"yearly": 499, "currency": "INR"}}', '["full_learner_dashboard", "basic_skill_assessment", "course_recommendations", "profile_completion_score", "marketplace_access", "opportunity_access"]', '{"all": {"tagline": "Build your skills with guided recommendations", "duration": "yearly", "ideal_for": "Learners starting structured skill development", "max_users": 1, "description": "Entry paid learner plan with full learner dashboard, basic assessment, recommendations, and opportunity access.", "positioning": "Starter plan for structured skill development", "display_name": "Skill Starter", "storage_limit": "5GB", "is_recommended": false}}', 1, true, '2026-05-21 11:27:23.226425+00', '2026-08-08 03:23:54.194421+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000011', 'school_starter', 'School Starter', 'b2b', '{school}', '{"school": {"yearly": 3999, "currency": "INR"}}', '["up_to_250_learners", "basic_learner_dashboard", "assessment_allocation", "basic_reports", "course_listing_access", "parent_counsellor_view_optional"]', '{"school": {"tagline": "Essential school learner management", "duration": "yearly", "ideal_for": "Schools starting learner assessment and reporting", "max_users": 250, "description": "School starter plan for up to 250 learners with basic dashboard, assessments, reports, and course access.", "positioning": "Starter plan for schools", "display_name": "School Starter", "storage_limit": "5GB", "is_recommended": false}}', 11, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000012', 'school_professional', 'School Professional', 'b2b', '{school}', '{"school": {"yearly": 9999, "currency": "INR"}}', '["up_to_1000_learners", "career_assessment_reports", "class_wise_analytics", "student_capability_wheel", "counsellor_dashboard", "parent_report_exports"]', '{"school": {"tagline": "Advanced school analytics and counselling", "duration": "yearly", "ideal_for": "Schools scaling learner analytics and counsellor workflows", "max_users": 1000, "description": "Professional school plan with career assessment reports, class-wise analytics, capability wheel, counsellor dashboard, and parent exports.", "positioning": "Professional plan for growing schools", "display_name": "School Professional", "storage_limit": "10GB", "is_recommended": true}}', 12, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000021', 'college_starter', 'College Starter', 'b2b', '{college}', '{"college": {"yearly": 4999, "currency": "INR"}}', '["up_to_500_learners", "department_dashboard", "course_listing_access", "assessment_allocation", "basic_placement_readiness_view", "marketplace_access"]', '{"college": {"tagline": "Starter placement-readiness tools for colleges", "duration": "yearly", "ideal_for": "Colleges beginning learner and placement readiness tracking", "max_users": 500, "description": "College starter plan for up to 500 learners with department dashboard, assessments, placement readiness view, and marketplace access.", "positioning": "Starter plan for colleges", "display_name": "College Starter", "storage_limit": "5GB", "is_recommended": false}}', 21, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000022', 'college_professional', 'College Professional', 'b2b', '{college}', '{"college": {"yearly": 14999, "currency": "INR"}}', '["up_to_2000_learners", "skill_gap_analytics", "lte_course_assignment", "placement_readiness_reports", "opportunity_tracking", "faculty_mentor_dashboard"]', '{"college": {"tagline": "Professional college readiness analytics", "duration": "yearly", "ideal_for": "Colleges scaling skill gap analytics and placement tracking", "max_users": 2000, "description": "Professional college plan with skill gap analytics, LTE/course assignment, placement reports, opportunity tracking, and faculty dashboard.", "positioning": "Professional plan for colleges", "display_name": "College Professional", "storage_limit": "10GB", "is_recommended": true}}', 22, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000031', 'university_starter', 'University Starter', 'b2b', '{university}', '{"university": {"yearly": 9999, "currency": "INR"}}', '["single_department_pilot", "basic_learner_management", "course_and_assessment_access", "department_level_dashboard", "basic_reports", "marketplace_access"]', '{"university": {"tagline": "Pilot learner management for one department", "duration": "yearly", "ideal_for": "Universities piloting with a single department", "max_users": null, "description": "University starter plan for a single department pilot with learner management, course and assessment access, dashboard, reports, and marketplace access.", "positioning": "Starter pilot plan for universities", "display_name": "University Starter", "storage_limit": "5GB", "is_recommended": false}}', 31, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000032', 'university_professional', 'University Professional', 'b2b', '{university}', '{"university": {"yearly": 24999, "currency": "INR"}}', '["multi_department_access", "advanced_learner_analytics", "placement_readiness_dashboard", "lte_assignment_and_tracking", "faculty_mentor_access", "opportunity_management"]', '{"university": {"tagline": "Multi-department university analytics", "duration": "yearly", "ideal_for": "Universities managing readiness across multiple departments", "max_users": null, "description": "Professional university plan with multi-department access, advanced analytics, placement readiness dashboard, LTE tracking, faculty access, and opportunity management.", "positioning": "Professional plan for universities", "display_name": "University Professional", "storage_limit": "10GB", "is_recommended": true}}', 32, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000013', 'school_enterprise', 'School Enterprise', 'b2b', '{school}', '{"school": {"yearly": 29999, "currency": "INR"}}', '["up_to_1000_learners", "career_assessment_reports", "class_wise_analytics", "student_capability_wheel", "counsellor_dashboard", "parent_report_exports"]', '{"school": {"tagline": "Enterprise-grade school deployment", "duration": "yearly", "ideal_for": "Large schools and school groups needing custom rollout", "max_users": null, "description": "Enterprise school plan with custom learner volume, multi-branch support, advanced analytics, reports, onboarding, and priority support.", "positioning": "Enterprise plan for school groups", "display_name": "School Enterprise", "storage_limit": "50GB", "is_recommended": false}}', 13, true, '2026-07-11 04:23:49.530804+00', '2026-07-21 04:18:14.870874+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000023', 'college_enterprise', 'College Enterprise', 'b2b', '{college}', '{"college": {"yearly": 49999, "currency": "INR"}}', '["up_to_5000_learners_or_custom", "multi_department_analytics", "recruiter_access", "advanced_placement_dashboard", "bulk_onboarding", "dedicated_success_manager"]', '{"college": {"duration": "yearly", "max_users": 5000, "display_name": "College Enterprise", "storage_limit": "50GB"}}', 23, true, '2026-07-11 04:23:49.530804+00', '2026-09-18 07:22:50.692915+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000033', 'university_enterprise', 'University Enterprise', 'b2b', '{university}', '{"university": {"yearly": 99999, "currency": "INR"}}', '["university_wide_deployment", "multi_campus_management", "api_lms_integration", "custom_dashboards", "recruiter_ecosystem_access", "dedicated_account_manager"]', '{"university": {"tagline": "University-wide enterprise deployment", "duration": "yearly", "ideal_for": "Universities needing multi-campus deployment and LMS integration", "max_users": null, "description": "Enterprise university plan with university-wide deployment, multi-campus management, API/LMS integration, custom dashboards, recruiter ecosystem access, and account manager.", "positioning": "Enterprise plan for universities", "display_name": "University Enterprise", "storage_limit": "50GB", "is_recommended": false}}', 33, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000010', 'school_freemium', 'Institution Trial', 'b2b', '{school}', '{"school": {"yearly": 0, "currency": "INR"}}', '["admin_dashboard_preview", "sample_learner_reports", "1_trial_assessment", "institution_profile_setup", "limited_marketplace_view", "demo_access"]', '{"school": {"tagline": "Preview institutional capabilities", "duration": "trial", "ideal_for": "Schools evaluating Rareminds before rollout", "max_users": 25, "description": "Free school trial plan with dashboard preview, sample reports, one trial assessment, and demo access.", "positioning": "Trial plan for school evaluation", "display_name": "Institution Trial", "storage_limit": "1GB", "is_recommended": false}}', 10, true, '2026-07-11 04:23:49.530804+00', '2026-07-11 05:05:29.760273+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('a0000000-0000-4000-8000-000000000040', 'hybrid', 'Hybrid', 'b2b', '{school,college,university}', '{}', '[]', '{"all": {"tagline": "Your institution. Your plan.", "duration": "custom", "terms_note": "Features and services are subject to the agreed proposal.", "description": "Work with our sales team to choose your features, user limits, integrations, support, and billing terms.", "positioning": "Built around you", "price_label": "Custom pricing", "sales_email": "marketing@rareminds.in", "sales_phone": "+91 9902326951", "display_name": "Hybrid", "purchase_mode": "contact_sales", "is_recommended": false, "sales_highlights": ["Tailored combination of features", "Flexible student and educator licenses", "Agreed usage allowances", "Optional integrations and onboarding", "Personalized support options", "Negotiated pricing and contract terms"]}}', 40, true, '2026-10-01 08:41:25.131839+00', '2026-10-01 08:41:25.131839+00', '912d5049-e195-46e9-a319-49e3502bf7e7');


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: postgres
--




--
-- Data for Name: subscriptions; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."subscriptions" ("id", "user_id", "plan_id", "organization_id", "full_name", "email", "plan_code", "plan_type", "plan_amount", "billing_cycle", "features", "status", "razorpay_subscription_id", "razorpay_customer_id", "razorpay_payment_id", "razorpay_order_id", "auto_renew", "receipt_url", "subscription_start_date", "subscription_end_date", "cancelled_at", "paused_at", "paused_until", "last_webhook_at", "cancellation_reason", "cancellation_feedback", "cancelled_by", "is_organization_subscription", "organization_type", "purchased_by", "seat_count", "is_bulk_purchase", "metadata", "created_at", "updated_at", "product_id") VALUES
	('fe1f1ce0-9603-48ce-afdc-764c4764ede7', '17b4400f-6737-40bc-899f-071cbd7ce552', '8460ee67-18ff-4c2e-ac57-7e1f87dc8316', NULL, 'Freemium User', 'gokul@rareminds.in', 'premium', 'Premium', 999.00, 'yearly', '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access"]', 'active', NULL, NULL, 'pay_SwEfFP5hO3WVVy', 'order_SwEf6N1cPXWX9e', true, NULL, '2026-06-01 04:30:10.472+00', '2027-06-01 04:30:10.472+00', NULL, NULL, NULL, NULL, NULL, NULL, NULL, false, NULL, NULL, 1, false, '{}', '2026-05-26 10:10:11.936405+00', '2026-06-01 04:30:10.391655+00', NULL),
	('8c8f6c10-8e7a-4f66-9a20-a75cd6fd80c1', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b1', 'a0000000-0000-4000-8000-000000000013', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', 'Cambridge School Admin', 'admin@cambridgeschool.edu.in', 'school_enterprise', 'School Enterprise', 29999.00, 'yearly', '["up_to_1000_learners", "career_assessment_reports", "class_wise_analytics", "student_capability_wheel", "counsellor_dashboard", "parent_report_exports"]', 'active', NULL, NULL, NULL, NULL, false, NULL, '2026-07-21 02:15:15.752+00', '2027-07-21 02:15:15.752+00', NULL, NULL, NULL, NULL, NULL, NULL, NULL, true, 'school', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b1', 46, true, '{"city": "Bengaluru", "board": "CBSE", "grade": "8", "state": "Karnataka", "country": "India", "sections": ["A", "B", "C"], "school_name": "Cambridge School", "student_count": 46}', '2026-07-21 02:14:19.393005+00', '2026-07-21 02:14:19.393005+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('d3876903-b74e-55d7-910f-90907ea3e11f', '783d8431-a034-5369-ae47-3aca2c4ec618', 'a0000000-0000-4000-8000-000000000023', '284c9ed9-cd13-584d-b5bc-e198866b917b', 'Soundarya College Admin', 'sims.info@soundaryainstitutions.in', 'college_enterprise', 'College Enterprise', 49999.00, 'yearly', '["up_to_5000_learners_or_custom", "multi_department_analytics", "recruiter_access", "advanced_placement_dashboard", "bulk_onboarding", "dedicated_success_manager"]', 'active', NULL, NULL, NULL, NULL, true, NULL, '2026-08-31 14:36:38.698278+00', '2027-08-31 14:36:38.698278+00', NULL, NULL, NULL, NULL, NULL, NULL, NULL, true, 'college', '783d8431-a034-5369-ae47-3aca2c4ec618', 5000, true, '{"package": "highest", "short_name": "SIMS", "institution_name": "Soundarya Institute of Management and Science", "seeded_subscription": true}', '2026-08-31 14:36:38.698278+00', '2026-09-07 07:06:32.195593+00', '912d5049-e195-46e9-a319-49e3502bf7e7');


--
-- Data for Name: transactions; Type: TABLE DATA; Schema: public; Owner: postgres
--




--
-- Data for Name: buckets; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--



--
-- Data for Name: buckets_analytics; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--



--
-- Data for Name: buckets_vectors; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--



--
-- Data for Name: objects; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--



--
-- Data for Name: s3_multipart_uploads; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--



--
-- Data for Name: s3_multipart_uploads_parts; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--



--
-- Data for Name: vector_indexes; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--



--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE SET; Schema: auth; Owner: supabase_auth_admin
--

SELECT pg_catalog.setval('"auth"."refresh_tokens_id_seq"', 1, false);


--
-- PostgreSQL database dump complete
--

-- \unrestrict NvxGDkqCP8gNYxvPAnUEfCzdC9G2IgBtKjy7oH0k9sbiYSp9Rv3UCWNPOehoemu

RESET ALL;
