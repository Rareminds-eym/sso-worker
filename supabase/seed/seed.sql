SET session_replication_role = replica;

--
-- PostgreSQL database dump
--

-- \restrict QX2HlLFEaRzoHddrwfUXPjdu6JzFlye9rk8JzZS5Rog9HLtNDcvoZcgy0NnjuC9

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
	('7352d0f4-88a6-4e14-9421-6c5706791973', 'lte', 'Learning Transformation Engine', 'Enterprise learning transformation and training management system', '2026-05-22 04:01:09.763845+00');


--
-- Data for Name: addon_catalog; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."addon_catalog" ("id", "product_id", "category", "feature_key", "feature_name", "feature_value", "description", "price_monthly", "price_annual", "target_roles", "icon", "display_order", "is_active", "created_at", "updated_at") VALUES
	('2a9d446c-2d77-4e67-80d7-7df0ce0dc01c', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learning', 'career_ai', 'Career AI', 'AI-powered career guidance', 'AI-powered career guidance and personalized recommendations', 1999.00, 19990.00, '{learner}', '🤖', 1, true, '2026-05-26 10:06:30.993173+00', '2026-05-26 10:06:30.993173+00'),
	('b6c7f870-1dae-4962-bd55-339067f17831', '912d5049-e195-46e9-a319-49e3502bf7e7', 'learning', 'ai_job_matching', 'AI Job Matching', 'Smart job matching', 'Intelligent job matching that connects you with relevant opportunities', 1999.00, 19990.00, '{learner}', '🎯', 2, true, '2026-05-26 10:06:30.993173+00', '2026-05-26 10:06:30.993173+00'),
	('60f254cc-adc7-4dd4-8847-5049e9dc764c', '912d5049-e195-46e9-a319-49e3502bf7e7', 'content', 'video_portfolio', 'Video Portfolio', 'Showcase with video', 'Showcase your skills and projects with a professional video portfolio', 499.00, 4990.00, '{learner}', '🎬', 3, true, '2026-05-26 10:06:30.993173+00', '2026-05-26 10:06:30.993173+00');


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked") VALUES
	('17b4400f-6737-40bc-899f-071cbd7ce552', 'gokul@rareminds.in', '$2a$12$6TEKcMzuiqJGLRC6GmpAWeIa7MGadAV1dxkQDAR9rp1cvB8.LlH/S', true, '2026-05-26 10:09:39.236338+00', '2026-05-26 10:09:59.447642+00', NULL, false);


--
-- Data for Name: addon_purchases; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."organizations" ("id", "name", "slug", "created_by", "created_at", "metadata") VALUES
	('00000000-0000-0000-0000-000000000001', 'SkillPassport Platform', 'platform', NULL, '2026-05-06 09:25:39.909089+00', '{"is_platform_org": true}');


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."audit_logs" ("id", "user_id", "action", "metadata", "ip_address", "user_agent", "created_at", "org_id") VALUES
	('a31b6509-4bd5-4763-93ec-88c892e26792', NULL, 'login_failed', '{"email": "gokul@rareminds.in"}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:09:10.964079+00', NULL),
	('41ed5359-46e7-4d0b-a548-b68b931c7922', '17b4400f-6737-40bc-899f-071cbd7ce552', 'signup_member', '{"role": "learner", "email_sent": true}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:09:39.260341+00', '00000000-0000-0000-0000-000000000001'),
	('a20ea659-f021-4da3-bf5a-75ca8dfa91af', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:09:59.357375+00', '00000000-0000-0000-0000-000000000001'),
	('4f99caa0-a398-4931-8c2c-6e13477d4c1c', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:09:59.394363+00', '00000000-0000-0000-0000-000000000001'),
	('eade23f0-3325-4fd9-bb63-34b51aba1c1c', '17b4400f-6737-40bc-899f-071cbd7ce552', 'email_verified', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:09:59.450747+00', NULL),
	('35a94128-2104-41fc-9c13-bb1b0b490c63', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:09:59.474215+00', '00000000-0000-0000-0000-000000000001'),
	('57b8cdc9-68e5-4b39-9951-0b3b56745016', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:09:59.498544+00', '00000000-0000-0000-0000-000000000001'),
	('3f9539df-e868-4dfe-96a4-d7690ee0746d', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:10:34.438128+00', '00000000-0000-0000-0000-000000000001'),
	('c05b75a0-a448-4cfb-86e4-1dbc931f0805', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:10:34.455848+00', '00000000-0000-0000-0000-000000000001'),
	('6c37de6b-6748-4949-a996-f4258bdcb100', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:24:54.513566+00', '00000000-0000-0000-0000-000000000001'),
	('21582450-328f-4b7a-a9d3-98bc9af884cf', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:27:47.2718+00', '00000000-0000-0000-0000-000000000001'),
	('5dc34ad8-3a5a-4060-8649-e2a2e35bbf3d', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:32:18.317316+00', '00000000-0000-0000-0000-000000000001'),
	('ff370d6d-95a9-46d5-abdb-8b01fa4a66f3', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:32:20.406394+00', '00000000-0000-0000-0000-000000000001'),
	('87499f28-0e6a-47d0-92b1-b72218dc0940', '17b4400f-6737-40bc-899f-071cbd7ce552', 'refresh', '{}', '127.0.0.1', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '2026-05-26 10:32:21.758983+00', '00000000-0000-0000-0000-000000000001');


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

INSERT INTO "public"."email_verifications" ("id", "user_id", "token_hash", "used", "expires_at", "created_at") VALUES
	('02126681-ce76-4736-af2b-a7a8d437ab87', '17b4400f-6737-40bc-899f-071cbd7ce552', '8d2e3ead9bcdfa8a3aa463ee6240da2bfb6dab918d0807136e8c75d5b0b9586a', true, '2026-05-27 10:09:39.255+00', '2026-05-26 10:09:39.256545+00');


--
-- Data for Name: events; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: invites; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: memberships; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
	('d33b65a0-f2ff-44ad-967c-27a9633af911', '17b4400f-6737-40bc-899f-071cbd7ce552', '00000000-0000-0000-0000-000000000001', '2026-05-26 10:09:39.236338+00', 'active');


--
-- Data for Name: membership_products; Type: TABLE DATA; Schema: public; Owner: postgres
--



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
	('2786a56c-1f3c-4b29-b2bc-8ad851ca8329', 'd33b65a0-f2ff-44ad-967c-27a9633af911', '8d018d55-46f4-4e67-b6a5-8c216737a374', '2026-05-26 10:09:39.236338+00');


--
-- Data for Name: oauth_accounts; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: organization_products; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: password_resets; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: plans; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."plans" ("id", "plan_code", "name", "business_type", "applicable_entities", "pricing_matrix", "base_features", "entity_config", "display_order", "is_active", "created_at", "updated_at", "product_id") VALUES
	('ef4a94ac-17b7-4a35-b47a-3a031f049b31', 'freemium', 'Freemium', 'b2c', '{all}', '{"all": {"yearly": 0, "monthly": 0, "currency": "INR"}}', '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access"]', '{"all": {"tagline": "Start free, upgrade anytime", "duration": "lifetime", "ideal_for": "Users who want to explore the platform", "max_users": 1, "description": "Free forever plan with basic features", "positioning": "Start free. Upgrade anytime to unlock all features.", "storage_limit": "0GB", "is_recommended": false}}', 0, true, '2026-05-21 11:27:23.226425+00', '2026-05-22 04:01:09.763845+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('d8d9828a-8f24-490b-81f9-6c03bcf77255', 'basic', 'Basic', 'b2c', '{all}', '{"all": {"yearly": 499, "currency": "INR"}}', '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "skill_analytics", "portfolio_builder", "5_assessments_month", "3_projects", "5gb_storage", "basic_support"]', '{"all": {"tagline": "Get started with essential features", "duration": "yearly", "ideal_for": "Individual learners starting their journey", "max_users": 1, "description": "Perfect for individuals who want to build their skills", "positioning": "Essential tools for individual learning", "storage_limit": "5GB", "is_recommended": false}}', 1, true, '2026-05-21 11:27:23.226425+00', '2026-05-22 04:01:09.763845+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('b3d700e3-da45-4e3d-9387-5f5dbff06c0b', 'professional', 'Professional', 'b2c', '{all}', '{"all": {"yearly": 749, "currency": "INR"}}', '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "advanced_analytics", "advanced_portfolio", "career_paths", "interview_prep", "resume_builder", "certificates", "10_assessments_month", "10_projects", "10gb_storage", "priority_support"]', '{"all": {"tagline": "Accelerate your career growth", "duration": "yearly", "ideal_for": "Professionals advancing their careers", "max_users": 1, "description": "Most popular plan with advanced career tools", "positioning": "Advanced features for serious learners", "storage_limit": "10GB", "is_recommended": true}}', 2, true, '2026-05-21 11:27:23.226425+00', '2026-05-22 04:01:09.763845+00', '912d5049-e195-46e9-a319-49e3502bf7e7'),
	('8460ee67-18ff-4c2e-ac57-7e1f87dc8316', 'premium', 'Premium', 'b2c', '{all}', '{"all": {"yearly": 999, "currency": "INR"}}', '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "advanced_analytics", "advanced_portfolio", "all_career_paths", "mock_interviews", "linkedin_opt", "resume_builder", "verified_certs", "unlimited_assessments", "unlimited_projects", "50gb_storage", "priority_support", "mentorship", "placement_assist"]', '{"all": {"tagline": "Everything you need to succeed", "duration": "yearly", "ideal_for": "Ambitious professionals seeking comprehensive support", "max_users": 1, "description": "All features unlocked with premium support", "positioning": "Complete toolkit for maximum career success", "storage_limit": "50GB", "is_recommended": false}}', 3, true, '2026-05-21 11:27:23.226425+00', '2026-05-22 04:01:09.763845+00', '912d5049-e195-46e9-a319-49e3502bf7e7');


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."sessions" ("id", "user_id", "refresh_token_hash", "user_agent", "ip_address", "expires_at", "revoked", "created_at", "rotated_from", "last_used_at", "device_info", "org_id") VALUES
	('3d1ac5c2-91b7-4ac9-86bf-1ce0670f24f4', '17b4400f-6737-40bc-899f-071cbd7ce552', 'd4f4e1c08689a693592cd66b277411d8f8a2eec2bbe30ca23a3c2839652d88d3', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:09:39.252+00', true, '2026-05-26 10:09:39.253042+00', NULL, NULL, NULL, '00000000-0000-0000-0000-000000000001'),
	('6af3658e-a995-478a-9f08-47db921226c2', '17b4400f-6737-40bc-899f-071cbd7ce552', '26e6d9038589ba88cbc38d280441cc7e79165a5354c6f78440061f47839cdc82', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:09:59.341+00', true, '2026-05-26 10:09:59.342909+00', '3d1ac5c2-91b7-4ac9-86bf-1ce0670f24f4', '2026-05-26 10:09:59.341+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('781f2781-d1af-4f93-83d0-3ebb08f7efd6', '17b4400f-6737-40bc-899f-071cbd7ce552', '2ad144c9a1a777801c25cb071cd2cc32aba7b3e3a8cdbe171f7bc5cea9069bd0', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:09:59.383+00', true, '2026-05-26 10:09:59.384995+00', '6af3658e-a995-478a-9f08-47db921226c2', '2026-05-26 10:09:59.384+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('b1e547cf-2f98-4a6b-8dd3-d875d4cd04a4', '17b4400f-6737-40bc-899f-071cbd7ce552', '844b030b43746dd396d669d692b5438c314d406ffa2f318fe88d51bb34ba7296', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:09:59.466+00', true, '2026-05-26 10:09:59.467556+00', '781f2781-d1af-4f93-83d0-3ebb08f7efd6', '2026-05-26 10:09:59.466+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('ff833be5-362e-4187-94c5-7ecb0bf79df1', '17b4400f-6737-40bc-899f-071cbd7ce552', '75a6979494e06117a65c1086f6e7481a1d92f5029e4d627c8e3a75160ee5fb20', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:09:59.489+00', true, '2026-05-26 10:09:59.490056+00', 'b1e547cf-2f98-4a6b-8dd3-d875d4cd04a4', '2026-05-26 10:09:59.489+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('a01cab2b-7939-411e-b6ad-7a6c06796b60', '17b4400f-6737-40bc-899f-071cbd7ce552', 'd1170118e0e1d66447b40807712b51d9b5cc5f363ae8400ea3819643010d0aa0', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:10:34.431+00', true, '2026-05-26 10:10:34.432811+00', 'ff833be5-362e-4187-94c5-7ecb0bf79df1', '2026-05-26 10:10:34.431+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('94c74233-fa49-4cdd-bdf8-0d9dab1c2bb0', '17b4400f-6737-40bc-899f-071cbd7ce552', '582396e81d47a5aa5d64c3de1e7273be4ba5cf8beee899dea77ca6aa866e5580', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:10:34.447+00', true, '2026-05-26 10:10:34.448687+00', 'a01cab2b-7939-411e-b6ad-7a6c06796b60', '2026-05-26 10:10:34.447+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('903f317b-956b-4dd2-8d46-08516ad2ca08', '17b4400f-6737-40bc-899f-071cbd7ce552', '3dc3ed0067106d7a2b90befa47d118be61fc91c9382d130622c29a2ab6ad180b', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:24:54.499+00', true, '2026-05-26 10:24:54.50077+00', '94c74233-fa49-4cdd-bdf8-0d9dab1c2bb0', '2026-05-26 10:24:54.499+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('4cab68f6-6376-4988-bd6c-f6dd0e844ddb', '17b4400f-6737-40bc-899f-071cbd7ce552', '973f96f1ac52be10e01ccc69bd311548d814caec1e8e1240b3fbab2e69d08221', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:27:47.26+00', true, '2026-05-26 10:27:47.261627+00', '903f317b-956b-4dd2-8d46-08516ad2ca08', '2026-05-26 10:27:47.26+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('daa4fef7-d4d5-481e-871b-1f7116f07786', '17b4400f-6737-40bc-899f-071cbd7ce552', '77da85a8ff71ec28375eb1e81cf9c43b55f0682efbcaa751e10265735e555c08', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:32:18.309+00', true, '2026-05-26 10:32:18.310446+00', '4cab68f6-6376-4988-bd6c-f6dd0e844ddb', '2026-05-26 10:32:18.309+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('e5771028-e400-4d57-8571-92f3b986d425', '17b4400f-6737-40bc-899f-071cbd7ce552', '77380ae11cc5181ffcb37754dd929105ae006b51a7e7b887226743a6cdd7cc7a', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:32:20.398+00', true, '2026-05-26 10:32:20.400338+00', 'daa4fef7-d4d5-481e-871b-1f7116f07786', '2026-05-26 10:32:20.398+00', NULL, '00000000-0000-0000-0000-000000000001'),
	('2f6d71b1-f84b-4457-8686-d49457a42d69', '17b4400f-6737-40bc-899f-071cbd7ce552', '56b30ca875d25528a722ab7975ef5ae6d3e314d1573641b3f47efcd27b54d3ee', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36', '127.0.0.1', '2026-06-25 10:32:21.753+00', false, '2026-05-26 10:32:21.754135+00', 'e5771028-e400-4d57-8571-92f3b986d425', '2026-05-26 10:32:21.753+00', NULL, '00000000-0000-0000-0000-000000000001');


--
-- Data for Name: subscriptions; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO "public"."subscriptions" ("id", "user_id", "plan_id", "organization_id", "full_name", "email", "phone", "plan_code", "plan_type", "plan_amount", "billing_cycle", "features", "status", "razorpay_subscription_id", "razorpay_customer_id", "razorpay_payment_id", "razorpay_order_id", "auto_renew", "receipt_url", "subscription_start_date", "subscription_end_date", "cancelled_at", "paused_at", "paused_until", "last_webhook_at", "cancellation_reason", "cancellation_feedback", "cancelled_by", "is_organization_subscription", "organization_type", "purchased_by", "seat_count", "is_bulk_purchase", "metadata", "created_at", "updated_at", "product_id") VALUES
	('fe1f1ce0-9603-48ce-afdc-764c4764ede7', '17b4400f-6737-40bc-899f-071cbd7ce552', 'ef4a94ac-17b7-4a35-b47a-3a031f049b31', NULL, 'Freemium User', 'gokul@rareminds.in', NULL, 'freemium', 'Freemium', 0.00, 'lifetime', '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access"]', 'active', NULL, NULL, NULL, NULL, false, NULL, '2026-05-26 10:10:11.935+00', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false, NULL, NULL, 1, false, '{}', '2026-05-26 10:10:11.936405+00', '2026-05-26 10:10:11.936405+00', NULL);


--
-- Data for Name: transactions; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: hooks; Type: TABLE DATA; Schema: supabase_functions; Owner: supabase_functions_admin
--



--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE SET; Schema: auth; Owner: supabase_auth_admin
--

SELECT pg_catalog.setval('"auth"."refresh_tokens_id_seq"', 1, false);


--
-- Name: hooks_id_seq; Type: SEQUENCE SET; Schema: supabase_functions; Owner: supabase_functions_admin
--

SELECT pg_catalog.setval('"supabase_functions"."hooks_id_seq"', 1, false);


--
-- PostgreSQL database dump complete
--

-- \unrestrict QX2HlLFEaRzoHddrwfUXPjdu6JzFlye9rk8JzZS5Rog9HLtNDcvoZcgy0NnjuC9

RESET ALL;
