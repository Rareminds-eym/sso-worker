-- ============================================================
-- SEED FILE: SEA College Learners Data
-- Updates Demo College organization name to "SEA College"
-- Inserts 48 SEA College students into SSO database
-- ============================================================

BEGIN;

-- ============================================================
-- STEP 0: Create the demo college admin user first
-- ============================================================
INSERT INTO public.users (id, email, password_hash, is_email_verified, created_at, updated_at, last_login_at, is_blocked)
VALUES (
  '22222222-2222-2222-2222-222222222222',
  'demo.college@skillpassport.com',
  '$2a$12$KDHnErzFxic0xTsyCZpvLOVYy75JYGG7JowJPxFjrDBXi2EcVR6/K',
  true,
  NOW(),
  NOW(),
  NULL,
  false
)
ON CONFLICT (id) DO UPDATE SET
  email = EXCLUDED.email,
  password_hash = EXCLUDED.password_hash,
  is_email_verified = EXCLUDED.is_email_verified,
  updated_at = NOW(),
  is_blocked = EXCLUDED.is_blocked;

-- ============================================================
-- STEP 1: Create or Update Demo College organization to SEA College
-- ============================================================
INSERT INTO public.organizations (id, name, slug, created_by, created_at, metadata)
VALUES (
  '11111111-1111-1111-1111-111111111111',
  'S.E.A College of Engineering and Technology',
  'sea-college',
  '22222222-2222-2222-2222-222222222222',
  NOW(),
  jsonb_build_object(
    'organization_type', 'college',
    'admin_id', '22222222-2222-2222-2222-222222222222',
    'institution_name', 'S.E.A College of Engineering and Technology',
    'short_name', 'SEA College',
    'academic_year', '2026/2027',
    'founded_year', 2020,
    'affiliated_university', 'Visvesvaraya Technological University (VTU)',
    'website', 'https://seaedu.ac.in',
    'address_line_1', 'SEA Campus',
    'city', 'Bangalore',
    'state', 'Karnataka',
    'postal_code', '560049',
    'country', 'India',
    'information_email', 'seainfo@seaedu.ac.in',
    'admissions_email', 'admissions@seaedu.ac.in',
    'admissions_phone_1', '+919876543210',
    'principal_director', 'Dr. SEA Principal',
    'onboarding_completed', true,
    'onboarding_source', 'demo_admin_seed'
  )
)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name,
  slug = EXCLUDED.slug,
  metadata = EXCLUDED.metadata;

-- ============================================================
-- STEP 2: Insert SEA College Student Users
-- All students are assigned to the Demo College org ID
-- ============================================================
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked") VALUES
('59dc759d-45ff-4d14-b7f3-34c435cbf4ae', 'amruthareddy.9353@gmail.com', '$2a$12$9UBXM8IolJEJXeIHLMzbd.5BJUIDDhEV863YjyeNiJuhPfXFDlI2S', true, '2026-06-09 11:27:01.022313+00', '2026-06-09 16:11:25.472373+00', '2026-06-09 16:11:25.459+00', false),
('0052ca76-baeb-4ac2-b246-be56385cdae0', 'ddeepthi029@gmail.com', '$2a$12$IROJozd9tOZ76Cn1cJLeL.WmPjlxi2VS7908WwSW9b3tN2rSf6gQ.', true, '2026-06-09 11:24:23.301554+00', '2026-06-09 12:01:02.341979+00', null, false),
('09efdfa1-e0e7-4c39-8b25-30208af81fd3', 'ankitapriyadarshiniankita@gmail.com', '$2a$12$zEQ5eaQ65kMSEEzu0MiLYee8LRQqWvp2bV7ZwOtnm3ToY8wpevYM.', true, '2026-06-09 11:24:18.718574+00', '2026-06-09 12:01:02.341979+00', null, false),
('1c3fc236-05dc-48d3-9412-df0b20069cca', 'bhavaniv252004@gmail.com', '$2a$12$WsAIwaalCJO0JTq8JcelfOVccz6DjtZY6QVOVUE267TJdz4VdsiO2', true, '2026-06-09 11:18:42.771339+00', '2026-06-09 12:01:02.341979+00', null, false),
('1e812594-df4b-4acd-a70b-6927f0863ed6', 'shivrajum911@gmail.com', '$2a$12$OuQnIW9ZLZLtkOIznEctyOzfeNJ1CAS/jijmPTj1N31F5yf0gMc1W', true, '2026-06-09 11:16:09.570121+00', '2026-06-09 12:01:02.341979+00', null, false),
('1ece2083-87f8-463d-8d16-6a529d6936c0', 'tejaswinid2004@gmail.com', '$2a$12$79xHVwlME3sL5EaZnbc/KulR3u9MUpS8BSRLCzjgbPTuG39o0JfMW', true, '2026-06-09 11:22:51.862592+00', '2026-06-09 12:01:02.341979+00', null, false),
('2432b7ef-e290-42bc-8cab-353568738245', 'hudhashahista.klr@gmail.com', '$2a$12$USj9FffS4qq0djWHYboLB.3WublrQPEM/lUcqLXby5DkcIc6hNNvq', true, '2026-06-09 11:27:13.681707+00', '2026-06-09 12:01:02.341979+00', '2026-06-09 11:54:37.2+00', false),
('29699c06-5d01-4c21-ae77-cee9b86dff7d', 'vellenaningthoujam20@gmail.com', '$2a$12$kExRvXOb.ZQObXjwqWYVQukNpow6W7bgOhxPB.Y2QHMFkLNNr4BFC', true, '2026-06-09 11:18:46.526528+00', '2026-06-09 12:01:02.341979+00', null, false),
('31025eb5-3b4e-4019-95c7-ea6be9bd0db8', 'adaesocial@gmail.com', '$2a$12$UhY7aNi4j2lt/gABu0Kw4uHuv/OuZVKDkH.YkSlr2kgMmiYTdH5tG', true, '2026-06-09 11:22:55.663217+00', '2026-06-09 12:01:02.341979+00', null, false),
('3348a078-7c3c-49da-8f3f-a542bf2cc9ae', 'aishwarym4549@gmail.com', '$2a$12$sS5Ka/AESCsy2SBzqLI7VO3ywidGRnc63bXAMRqhGuQqfdRn2OzDm', true, '2026-06-09 11:16:05.866673+00', '2026-06-09 12:01:02.341979+00', null, false),
('3bfaf704-a2d1-4807-9aab-de96bdc54745', 'asmitapandey580@gmail.com', '$2a$12$ap5Re8Qt/.EUkl9GwDAmsOyhDdQjuqi6.oTG9MRAfxOtFMg5dWDYu', true, '2026-06-09 11:17:32.20235+00', '2026-06-09 12:01:02.341979+00', null, false),
('3edbebfc-3eaf-4e2b-8dbb-9bc8020699de', 'payalmagar38@gmail.com', '$2a$12$ZfIyEDuZy7mKWvhwnRvOTOzJle0YgXjzNXoxb63H0Shu1KIsBBvMa', true, '2026-06-09 11:27:18.42009+00', '2026-06-09 12:01:02.341979+00', null, false),
('46232284-b790-4871-ab6c-78a47a9652a3', 'i.am.adnanshaikhhh@gmail.com', '$2a$12$1Codd8palVmUEAKo.onhTuxj4LhOJFDCFrpLVC6sQYPHXvL8RzWgC', true, '2026-06-09 11:24:09.983638+00', '2026-06-09 12:01:02.341979+00', null, false),
('4b5b55a5-1bd7-42ef-8c3c-2a1fc5b7de12', 'amjedcp4@gmail.com', '$2a$12$WwfxL138Z5Hla5dWXW.z/uDnCwrgKQ7bGZIt7JdyoUApISFaZNvAW', true, '2026-06-09 11:20:04.724705+00', '2026-06-09 12:01:02.341979+00', null, false),
('4fd4c664-7302-4734-b670-57aea55b553a', 'johnmarvel390@gmail.com', '$2a$12$JdbG5SJTJgwWJc9Ig0SHuO1HHjnE0/JqHwUbSQuEjWxCQ6H5Q3yaS', true, '2026-06-09 11:22:59.384239+00', '2026-06-09 12:01:02.341979+00', null, false),
('52c5236c-7705-4385-8661-4bba511c0b72', 'sanjaygowda048@gmail.com', '$2a$12$7uYXV22ET0KeY/pyDT9gG.zg9RRDLuztgOelibRJUYWkmN6w3DhyW', true, '2026-06-09 11:21:41.163543+00', '2026-06-09 12:01:02.341979+00', null, false),
('5d9b55b6-c697-4563-a9ab-a2ed14138fef', 'akashakash216782@gmail.com', '$2a$12$HaUocGzq65s6eQvKUB7bl.fx4m4pU5CKekAGowZLB/aaj6HOzMBU.', true, '2026-06-09 11:20:08.436622+00', '2026-06-09 12:01:02.341979+00', null, false),
('5ed6db64-0fbc-4435-9ad7-4ac3cb0f688d', 'tajj379@gmail.com', '$2a$12$Tr.XTKPbIYjU7f1qrJQOt.RJ5mlC6UV/NlPYbTk0Fs88kLfBD5CSK', true, '2026-06-09 11:18:50.438417+00', '2026-06-09 12:01:02.341979+00', null, false),
('605e178d-c0c1-4290-8ea1-3c6e0eb7cece', 'kartikinkwit@gmail.com', '$2a$12$kwvE2/GybPWy1f6/SsJsJuu.3FmH6eWGwgjcGkUpHieDeN4J/f246', true, '2026-06-09 11:25:35.720061+00', '2026-06-09 12:01:02.341979+00', null, false),
('64741287-dd37-4f72-95ed-97e9ee9fbe11', 'chandanadn2005@gmail.com', '$2a$12$M6N8TxuKsi137U.Iqd7RS.OVj7HL7ZyJ8a1c.WyQPiFpffS8mH4Wy', true, '2026-06-09 11:21:37.436094+00', '2026-06-09 12:01:02.341979+00', null, false),
('6e1fccc2-5f60-40ba-9790-c04fa1b5f3f1', 'spandusrinivas10@gmail.com', '$2a$12$.kpBqxMg9niLjaiPnVfiqeF2YM12EhA7rc1NsH1/9YsiTg.q9h1.S', true, '2026-06-09 11:18:57.697122+00', '2026-06-09 12:01:02.341979+00', null, false),
('7601c0bb-b06b-4493-bd19-96440d28043a', 'ruhi80353@gmail.com', '$2a$12$u5ZOz5LSpMaCrj7rtXQORO9ZRTSfeYzsrTtbb9ureuxri9wGzqwV2', true, '2026-06-09 11:20:12.087608+00', '2026-06-09 12:01:02.341979+00', null, false),
('77849552-57a8-47e5-a6fd-4f19cd20d378', 'sharathaj105@gmail.com', '$2a$12$vdm9DbpaDnxyMJ2EyyQ8y.X1sVUZZ2P1DXGWpB0BXQin2BE6lYDwK', true, '2026-06-09 11:22:48.146538+00', '2026-06-09 12:01:02.341979+00', null, false),
('7c81d97c-97f8-41da-a717-53cc1d6228aa', 'babuenbabuen5@gmail.com', '$2a$12$DyhNymPFpJfb3hn3GHKR7usYP7ijoiqB0CumvgCUSwDicloyJJ7Z.', true, '2026-06-09 11:25:53.763682+00', '2026-06-09 12:01:02.341979+00', null, false),
('7d281e75-ce41-40cc-84af-238817ecb387', 'grswathi84@gmail.com', '$2a$12$vztUnF4k0v4vI9JwwGW.AeT2hXen3SIRqTLi9CaNjpjhor4ehr0rm', true, '2026-06-09 11:24:28.129477+00', '2026-06-09 12:01:02.341979+00', null, false),
('83b663e1-8fe2-4ea0-bda4-9c5f5ad0de5b', 'naikchaitra2005@gmail.com', '$2a$12$3jw6388H4WGJO3nElispauDPUGd.HR2dNdri3T4UX9N7jffJVsQrm', true, '2026-06-09 11:25:40.058932+00', '2026-06-09 12:01:02.341979+00', null, false),
('87123589-4217-4c4e-8baa-a4ea9515498c', 'manasvibv2004@gmail.com', '$2a$12$yEZXcmCnSxkRRNsWJJRDM.DObeZspXyC55WCgAlraGBiHSH08U9z.', true, '2026-06-09 11:16:02.119926+00', '2026-06-09 12:01:02.341979+00', null, false),
('8dd85fac-5449-4bca-8660-007d4218af99', 'cyabhinavakarthik@gmail.com', '$2a$12$x.yC9cl3bKvzqidNCUIPROhiDuITvRq7bdkuFEASLw7shOvf4nvBa', true, '2026-06-09 11:20:15.685913+00', '2026-06-09 12:01:02.341979+00', null, false),
('9d0876cd-3e87-4ce5-96bf-8fce44c96236', 'pkjithin383@gmail.com', '$2a$12$/bE5/wYpczyxt08S/2VSIuIJJkVoD6l1HWpFi9fBdzYk.RzMqmRqm', true, '2026-06-09 11:21:29.891978+00', '2026-06-09 12:01:02.341979+00', null, false),
('b2c04f39-53ac-4c77-8f3e-9e35f5d83356', 'ashutoshrai2204@gmail.com', '$2a$12$8qcZuoTKR06EcOgwaDu9nOW3bPu4Zma5JP2mVJW/YMHTnQEZy2lSa', true, '2026-06-09 11:17:35.929388+00', '2026-06-09 12:01:02.341979+00', null, false),
('b2f0e12f-67db-4213-9fe7-e8dd18935fcb', '2020tasmiya@gmail.com', '$2a$12$JJ9.Ye8pnFYxr3RVOZymMu0obLAXZmP4W4f8E0R7reKbflEgBd6wS', true, '2026-06-09 11:23:02.937478+00', '2026-06-09 12:01:02.341979+00', null, false),
('bd002cc3-13d2-495a-a8ad-5154110561c2', 'harikrishnapradeep12@gmail.com', '$2a$12$uqfxLo9YlYXMgIEeXGYDbOAxn1PuJsKm0AxTBz81DmzsrGwbJq/S6', true, '2026-06-09 11:15:58.273818+00', '2026-06-09 12:01:02.341979+00', null, false),
('be787755-123f-42ac-b2f0-33894e35ff16', 'asiyataj205@gmail.com', '$2a$12$IHmWe1cKCzGOAOEoLiau0OeMoiVgm12Yn5LJ.23DW/oF8Ok8PJsdm', true, '2026-06-09 11:21:26.247388+00', '2026-06-09 12:01:02.341979+00', null, false),
('c101edc9-cba8-4fda-b7d4-626795a468e0', 'niranjanmathapati65@gmail.com', '$2a$12$YAQLTcEHiQt8MpiiMXUUIO2oQfPpVuAJaQyh98bIkZQNvTEKiu0na', true, '2026-06-09 11:17:24.224198+00', '2026-06-09 12:01:02.341979+00', null, false),
('c3551929-a5b5-438b-82ae-bee6c8424432', 'rithikroshancareer@gmail.com', '$2a$12$Y4WvwIXd0rdPnmR87S0R3etTpXHCgfF0mxz43XWl9XAJ9fKfIX8xq', true, '2026-06-09 11:20:19.356631+00', '2026-06-09 12:01:02.341979+00', null, false),
('c74474e5-31eb-459b-9862-416c84e9533b', 'varshithmanjunath@gmail.com', '$2a$12$tdQhg4asv9ENsWn0lfhElufSSMCh3PHgY3Unw0bowHIrnsHB6d1cC', true, '2026-06-09 11:25:44.43722+00', '2026-06-09 12:01:02.341979+00', null, false),
('ca250822-d681-4488-8f2a-379f4178e8f5', 's66332108@gmail.com', '$2a$12$.HzFgJRaQCPMFn62fTkt4eRiiTSyCmZKfdRvrqDYRoKEzHmumxYNO', true, '2026-06-09 11:18:54.070281+00', '2026-06-09 12:01:02.341979+00', null, false),
('d30ef7dc-9a76-454c-b148-ade4f256606f', 'rachithaammujk2004@gmail.com', '$2a$12$Ti6zSTluiAURblwEEfKOeumkG4VRxgqqMgGcSlKBqcJp.b9sL7K4y', true, '2026-06-09 11:25:49.072453+00', '2026-06-09 12:01:02.341979+00', null, false),
('d7a7a6e3-83af-4c54-82a7-b7b50403d352', 'akshithasrinivas1620@gmail.com', '$2a$12$JbahSt8hXP0Mk4.5W/0nM.EeyZJx5iKozFDbNZ1I9.CMwJWZsG6FO', true, '2026-06-09 11:17:28.241463+00', '2026-06-09 12:01:02.341979+00', null, false),
('e06b1aed-122a-4750-a446-0c46669847e7', 'amitkumar123456va@gmail.com', '$2a$12$l4MYYzZOuPoNuPBe4lK2R.Dxci2zYIbcAgKvNNhOBE2i09Gpws50G', true, '2026-06-09 11:16:13.314847+00', '2026-06-09 12:01:02.341979+00', null, false),
('e559f511-231a-4243-8dd7-42f3b25b8eec', 'anu07gowda@gmail.com', '$2a$12$7HEKyVqW3KVNLnklohq5T.fBzSAeqjZ0sIeKr8RYw.3GnB6CqxYW2', true, '2026-06-09 11:21:33.661137+00', '2026-06-09 12:01:02.341979+00', null, false),
('e59cc66a-28bc-4a97-a395-84151936de36', 'ananduvm202@gmail.com', '$2a$12$bod3K7qP37Zhh5VNJfLZAOnJfGSbi/kr5OjjTWbssvxBh4MB64sUO', true, '2026-06-09 11:27:04.737362+00', '2026-06-09 12:01:02.341979+00', null, false),
('ed01ff14-0a41-4873-abf9-b4f4b31f72ba', 'anjukvanjukv012@gmail.com', '$2a$12$oEArISgQQAnj9F.VQqNjvuNThFL.xhbSvMo4Xx/2YOQU3VTGTomeW', true, '2026-06-09 11:24:14.169201+00', '2026-06-09 12:01:02.341979+00', null, false),
('f4b51f3b-b73a-491e-b54c-5fdf675ee1ae', 'arif18052@gmail.com', '$2a$12$XUBVNAUXEsdzvD17WbfuJuGUa8QOZ5yQ1nyb7Cq6.NQlD/Lw02FiO', true, '2026-06-09 11:17:20.224788+00', '2026-06-09 12:01:02.341979+00', null, false),
('fc79926a-ada9-461c-8b7e-20288ac4753f', 'muskan.a.6361@gmail.com', '$2a$12$xA.5L5qPt2oqLYZDu04AgOwtuRXC/6.uP0A4cyzPfqY3.z.5/r4i2', true, '2026-06-09 11:27:09.059434+00', '2026-06-09 12:01:02.341979+00', null, false)
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- STEP 2.5: Create admin membership and role assignment
-- ============================================================
-- Ensure college_admin role exists
INSERT INTO public.roles (id, name, description, created_at)
VALUES ('cd6c98bc-67bc-4e3c-83a6-cdcb2dc6961e', 'college_admin', 'College administrator', NOW())
ON CONFLICT (id) DO NOTHING;

-- Create membership for admin
INSERT INTO public.memberships (id, user_id, org_id, created_at, status)
VALUES (
  '33333333-3333-3333-3333-333333333333',
  '22222222-2222-2222-2222-222222222222',
  '11111111-1111-1111-1111-111111111111',
  NOW(),
  'active'
)
ON CONFLICT (id) DO UPDATE SET
  user_id = EXCLUDED.user_id,
  org_id = EXCLUDED.org_id,
  status = EXCLUDED.status;

-- Assign college_admin role to the membership
INSERT INTO public.membership_roles (id, membership_id, role_id, created_at)
VALUES (
  '44444444-4444-4444-4444-444444444444',
  '33333333-3333-3333-3333-333333333333',
  'cd6c98bc-67bc-4e3c-83a6-cdcb2dc6961e',
  NOW()
)
ON CONFLICT (id) DO UPDATE SET
  membership_id = EXCLUDED.membership_id,
  role_id = EXCLUDED.role_id;

-- Ensure product exists
INSERT INTO public.products (id, code, name, description, created_at)
VALUES (
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'skillpassport',
  'SkillPassport',
  'Skill development and career advancement platform',
  NOW()
)
ON CONFLICT (id) DO UPDATE SET
  code = EXCLUDED.code,
  name = EXCLUDED.name,
  description = EXCLUDED.description;

-- Ensure college_enterprise plan exists
INSERT INTO public.plans (
  id, plan_code, name, business_type, applicable_entities, pricing_matrix,
  base_features, entity_config, display_order, is_active, created_at, updated_at, product_id
)
VALUES (
  'a0000000-0000-4000-8000-000000000023',
  'college_enterprise',
  'College Enterprise',
  'b2b',
  ARRAY['college'],
  '{"college":{"yearly":49999,"currency":"INR"}}'::jsonb,
  '["up_to_5000_learners_or_custom","multi_department_analytics","recruiter_access","advanced_placement_dashboard","bulk_onboarding","dedicated_success_manager"]'::jsonb,
  '{"college":{"display_name":"College Enterprise","max_users":5000,"storage_limit":"50GB","duration":"yearly"}}'::jsonb,
  23,
  true,
  NOW(),
  NOW(),
  '912d5049-e195-46e9-a319-49e3502bf7e7'
)
ON CONFLICT (id) DO UPDATE SET
  plan_code = EXCLUDED.plan_code,
  name = EXCLUDED.name,
  pricing_matrix = EXCLUDED.pricing_matrix,
  base_features = EXCLUDED.base_features,
  entity_config = EXCLUDED.entity_config,
  is_active = true,
  updated_at = NOW();

-- Create subscription for the college
INSERT INTO public.subscriptions (
  id, user_id, plan_id, organization_id, full_name, email, plan_code, plan_type,
  plan_amount, billing_cycle, features, status, subscription_start_date,
  subscription_end_date, is_organization_subscription, organization_type,
  purchased_by, seat_count, is_bulk_purchase, metadata, created_at, updated_at, product_id
)
VALUES (
  '55555555-5555-5555-5555-555555555555',
  '22222222-2222-2222-2222-222222222222',
  'a0000000-0000-4000-8000-000000000023',
  '11111111-1111-1111-1111-111111111111',
  'Demo College Admin',
  'demo.college@skillpassport.com',
  'college_enterprise',
  'College Enterprise',
  49999,
  'yearly',
  '["up_to_5000_learners_or_custom","multi_department_analytics","recruiter_access","advanced_placement_dashboard","bulk_onboarding","dedicated_success_manager"]'::jsonb,
  'active',
  NOW(),
  NOW() + INTERVAL '1 year',
  true,
  'college',
  '22222222-2222-2222-2222-222222222222',
  5000,
  true,
  '{"institution_name":"S.E.A College of Engineering and Technology","short_name":"SEA College","package":"enterprise","seeded_subscription":true,"demo_account":true}'::jsonb,
  NOW(),
  NOW(),
  '912d5049-e195-46e9-a319-49e3502bf7e7'
)
ON CONFLICT (id) DO UPDATE SET
  user_id = EXCLUDED.user_id,
  organization_id = EXCLUDED.organization_id,
  plan_id = EXCLUDED.plan_id,
  features = EXCLUDED.features,
  status = EXCLUDED.status,
  metadata = EXCLUDED.metadata,
  updated_at = NOW();

-- ============================================================
-- STEP 3: Create Memberships for all students
-- All memberships point to Demo College org (11111111-1111-1111-1111-111111111111)
-- ============================================================
INSERT INTO "public"."memberships" ("id", "user_id", "org_id", "created_at", "status") VALUES
(gen_random_uuid(), '59dc759d-45ff-4d14-b7f3-34c435cbf4ae', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '0052ca76-baeb-4ac2-b246-be56385cdae0', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '09efdfa1-e0e7-4c39-8b25-30208af81fd3', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '1c3fc236-05dc-48d3-9412-df0b20069cca', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '1e812594-df4b-4acd-a70b-6927f0863ed6', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '1ece2083-87f8-463d-8d16-6a529d6936c0', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '2432b7ef-e290-42bc-8cab-353568738245', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '29699c06-5d01-4c21-ae77-cee9b86dff7d', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '31025eb5-3b4e-4019-95c7-ea6be9bd0db8', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '3348a078-7c3c-49da-8f3f-a542bf2cc9ae', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '3bfaf704-a2d1-4807-9aab-de96bdc54745', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '3edbebfc-3eaf-4e2b-8dbb-9bc8020699de', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '46232284-b790-4871-ab6c-78a47a9652a3', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '4b5b55a5-1bd7-42ef-8c3c-2a1fc5b7de12', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '4fd4c664-7302-4734-b670-57aea55b553a', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '52c5236c-7705-4385-8661-4bba511c0b72', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '5d9b55b6-c697-4563-a9ab-a2ed14138fef', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '5ed6db64-0fbc-4435-9ad7-4ac3cb0f688d', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '605e178d-c0c1-4290-8ea1-3c6e0eb7cece', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '64741287-dd37-4f72-95ed-97e9ee9fbe11', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '6e1fccc2-5f60-40ba-9790-c04fa1b5f3f1', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '7601c0bb-b06b-4493-bd19-96440d28043a', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '77849552-57a8-47e5-a6fd-4f19cd20d378', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '7c81d97c-97f8-41da-a717-53cc1d6228aa', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '7d281e75-ce41-40cc-84af-238817ecb387', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '83b663e1-8fe2-4ea0-bda4-9c5f5ad0de5b', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '87123589-4217-4c4e-8baa-a4ea9515498c', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '8dd85fac-5449-4bca-8660-007d4218af99', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), '9d0876cd-3e87-4ce5-96bf-8fce44c96236', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'b2c04f39-53ac-4c77-8f3e-9e35f5d83356', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'b2f0e12f-67db-4213-9fe7-e8dd18935fcb', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'bd002cc3-13d2-495a-a8ad-5154110561c2', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'be787755-123f-42ac-b2f0-33894e35ff16', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'c101edc9-cba8-4fda-b7d4-626795a468e0', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'c3551929-a5b5-438b-82ae-bee6c8424432', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'c74474e5-31eb-459b-9862-416c84e9533b', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'ca250822-d681-4488-8f2a-379f4178e8f5', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'd30ef7dc-9a76-454c-b148-ade4f256606f', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'd7a7a6e3-83af-4c54-82a7-b7b50403d352', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'e06b1aed-122a-4750-a446-0c46669847e7', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'e559f511-231a-4243-8dd7-42f3b25b8eec', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'e59cc66a-28bc-4a97-a395-84151936de36', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'ed01ff14-0a41-4873-abf9-b4f4b31f72ba', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'f4b51f3b-b73a-491e-b54c-5fdf675ee1ae', '11111111-1111-1111-1111-111111111111', NOW(), 'active'),
(gen_random_uuid(), 'fc79926a-ada9-461c-8b7e-20288ac4753f', '11111111-1111-1111-1111-111111111111', NOW(), 'active')
ON CONFLICT DO NOTHING;

-- ============================================================
-- STEP 4: Assign learner role to all students
-- Get the learner role ID and assign to all memberships
-- ============================================================

-- First, ensure learner role exists (use specific ID from seed.sql)
INSERT INTO public.roles (id, name, description, created_at)
VALUES (
  '8d018d55-46f4-4e67-b6a5-8c216737a374',
  'learner',
  'Self-directed learner',
  NOW()
)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description;

-- Also handle case where learner role exists with different ID
INSERT INTO public.roles (id, name, description, created_at)
SELECT 
  '8d018d55-46f4-4e67-b6a5-8c216737a374',
  'learner',
  'Self-directed learner',
  NOW()
WHERE NOT EXISTS (
  SELECT 1 FROM public.roles WHERE lower(name) = 'learner'
);

DO $$
DECLARE
  v_learner_role_id uuid;
  r_membership RECORD;
BEGIN
  -- Get learner role ID (works regardless of which ID it has)
  SELECT id INTO v_learner_role_id 
  FROM public.roles 
  WHERE lower(name) = 'learner' 
  LIMIT 1;

  IF v_learner_role_id IS NULL THEN
    RAISE EXCEPTION 'Learner role not found in roles table';
  END IF;

  -- Assign learner role to all new memberships
  FOR r_membership IN 
    SELECT m.id as membership_id
    FROM public.memberships m
    WHERE m.org_id = '11111111-1111-1111-1111-111111111111'
    AND NOT EXISTS (
      SELECT 1 FROM public.membership_roles mr 
      WHERE mr.membership_id = m.id
    )
  LOOP
    INSERT INTO public.membership_roles (id, membership_id, role_id, created_at)
    VALUES (gen_random_uuid(), r_membership.membership_id, v_learner_role_id, NOW())
    ON CONFLICT DO NOTHING;
  END LOOP;
END $$;

COMMIT;

-- Summary: Updated Demo College to SEA College and inserted 48 student users with memberships
