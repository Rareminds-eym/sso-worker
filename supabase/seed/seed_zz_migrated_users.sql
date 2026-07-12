-- Seed for SSO auth database (public.users) - selected users from demo DB

SET session_replication_role = replica;
SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Data for public.users (23 rows)
--
INSERT INTO "public"."users" ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked", "user_metadata") VALUES
	('f94dc792-07cd-41e0-9c9a-c3fbad4c801c', 'stu506@school.edu', '$2a$10$mYexI9tDkbhF8Yzfxu3ad.PrIb9MFICXXzRKjBiP1ITv91RWl38Lm', true, '2025-12-04 11:15:15.113498+00', '2026-02-04 03:43:49.956464+00', '2026-02-04 03:43:49.948333+00', false, '{"name": "Harini S", "role": "school_student", "email_verified": true}'),
	('8e85088c-590e-49f7-8159-e030ffa1303e', 'stu505@school.edu', '$2a$10$N7ZJWfcVUg73p0H/1YsFRupBD7k55mhB8P6XNBWPhfIHt5OrTm6bO', true, '2025-12-04 11:15:14.838181+00', '2026-02-04 03:45:06.788183+00', '2026-02-03 10:10:04.674628+00', false, '{"name": "Ananya Rao", "role": "school_student", "email_verified": true}'),
	('62fdc63a-d6e0-461e-bf82-ffb6875481e4', 'stu502@school.edu', '$2a$10$FQUZa9kA4Lsy.TIGwHxWP.t0NAdCY37S16R3uSwMQDz6.m4INgHea', true, '2025-12-04 11:15:14.015506+00', '2026-06-12 05:46:10.472458+00', '2026-06-12 05:46:10.460719+00', false, '{"name": "Rahul Nair", "role": "school_student", "email_verified": true}'),
	('453e1035-823d-4c9e-a32e-a8d8952f3fc0', 'priya.joshi@aditya.college.edu', '$2a$10$CFX4N1jdXhwmrBOfZDGWWeIHZDXVqpexlk23uGjd7OxPHbKUcpr8e', true, '2025-12-05 06:33:30.211612+00', '2026-02-02 06:32:31.389977+00', '2026-02-02 06:32:31.38796+00', false, '{"role": "college_student", "lastName": "Joshi", "firstName": "Priya", "email_verified": true}'),
	('4452a7a8-689e-4806-bae3-fe3ecc32735a', 'nilesh.jain@aditya.college.edu', '$2a$10$BNjfPwy6XUitji.pkz81NOWAXrdjl85bsu0jGJT3vNYnbJZS07kcG', true, '2025-12-05 06:33:32.32409+00', '2026-02-03 09:44:30.47267+00', '2026-02-02 10:49:56.412138+00', false, '{"role": "college_student", "lastName": "Jain", "firstName": "Nilesh", "email_verified": true}'),
	('813ba663-3c44-4f51-bd52-68a80780cc09', 'ananya.iye@gmail.com', '$2a$10$rhgqL7hjfPa7dV4tlJUbqedFiKS8gop/Umrd34TD/iHoB9g5oUcqe', true, '2026-03-05 12:56:17.531252+00', '2026-06-29 06:50:54.004508+00', '2026-06-29 06:50:53.999468+00', false, '{"name": "Ananya Iyer", "role": "school_student", "phone": "9876512399", "last_name": "Iyer", "first_name": "Ananya", "email_verified": true}'),
	('de0c914d-7d4c-4f8d-ae82-fecff6dcd695', 'priya.nair@gmail.com', '$2a$10$3vgMpl20v1ZgrU.1i4PUY.jJcC05M8e9kezRTfyvtwUVZilI0RmnK', true, '2026-03-05 12:39:30.177509+00', '2026-06-22 10:49:39.733446+00', '2026-06-22 09:51:16.060642+00', false, '{"name": "Priya N", "role": "college_student", "phone": "9876543211", "last_name": "N", "first_name": "Priya", "email_verified": true}'),
	('e9da0cfb-64ce-4493-a54e-8da09109086b', 'sneha.g@gmail.com', '$2a$10$dmm.i5zN3TQ6rGs3jNYiuOYTZmy/xOLuWz23acsA1FymampSSRBTe', true, '2026-03-05 12:45:16.088756+00', '2026-06-03 03:50:57.275158+00', '2026-06-03 03:50:57.27179+00', false, '{"name": "Sneha G", "role": "college_student", "phone": "9876543213", "last_name": "G", "first_name": "Sneha", "email_verified": true}'),
	('5c2cf3f7-8848-4116-9bb0-322e6fee5963', 'karthik.r@gmail.com', '$2a$10$VGUq1lS.HHSRuIHvmLHtBuqqjjjGRpkFgPi7uca9y.GLTunQMSjSi', true, '2026-03-05 12:42:39.783225+00', '2026-06-22 09:50:14.810896+00', '2026-06-22 04:52:06.033383+00', false, '{"name": "Karthik R", "role": "college_student", "phone": "9876543212", "last_name": "R", "first_name": "Karthik", "email_verified": true}'),
	('136a860c-73d9-4711-8b6c-b46934d471c6', 'arjun.shah@gmail.com', '$2a$10$45aDsrD5aCtPfgE2OEDXFuD4Jx4a2Hhrm22lZmOjIGGi0SMd4S4Im', true, '2026-03-05 12:48:56.293689+00', '2026-06-22 04:50:31.823354+00', '2026-06-19 07:29:29.090613+00', false, '{"name": "Arjun Shah", "role": "college_student", "phone": "9876543214", "last_name": "Shah", "first_name": "Arjun", "email_verified": true}'),
	('8b1ba262-747a-4b9c-a933-ec85e87be2a6', 'rohan.mehta07@gmail.com', '$2a$10$JnbZ6yykcIDcPkvK8KPEq.t5m2iBG3iR5Qak060LPsD12UEO58r5.', true, '2026-03-05 13:00:33.204556+00', '2026-06-24 12:21:08.031964+00', '2026-06-16 03:51:03.551527+00', false, '{"name": "Rohan Mehta", "role": "school_student", "phone": "9876512302", "last_name": "Mehta", "first_name": "Rohan", "email_verified": true}'),
	('53a223b9-649b-4c18-98af-db4d235f26cd', 'diya.kapoor@gmail.com', '$2a$10$jJpMdHL0dvNoYFZGScU89uqzOn1n2zl5SHVZGre9GAWokn8LV1XcO', true, '2026-03-05 12:51:34.551035+00', '2026-05-05 08:09:23.344795+00', '2026-05-05 08:09:23.33538+00', false, '{"name": "Diya Kapoor", "role": "college_student", "phone": "9876543215", "last_name": "Kapoor", "first_name": "Diya", "email_verified": true}'),
	('065616ce-7d75-4185-890a-c6e0e3b62242', 'kabir.singh09@gmail.com', '$2a$10$k1lRRD3JpZ./rtOQ9.FqMOt68VcUDUWwofbmR2mJ5zBjR1zXAre/O', true, '2026-03-05 13:02:13.328507+00', '2026-06-30 16:55:58.659675+00', '2026-06-25 07:20:56.954438+00', false, '{"name": "Kabir Singh", "role": "school_student", "phone": "9876512303", "last_name": "Singh", "first_name": "Kabir", "email_verified": true}'),
	('29aa05c6-fef0-4f84-ba91-0bcdcd766878', 'pooja.agarwal@learner.com', '$2a$10$yL1CsKAE5aidaxlDi9nnFe88z.Ja949VAhG6KQdOTwVich1Gtvkca', true, '2026-03-07 09:12:25.228498+00', '2026-06-16 03:39:33.304962+00', '2026-06-16 03:39:33.298225+00', false, '{"name": "Pooja Agarwal", "role": "learner", "last_name": "Agarwal", "first_name": "Pooja", "email_verified": true}'),
	('2f8ce917-4764-4593-a2ba-a49f2c91ae16', 'arjun.patel12@gmail.com', '$2a$10$XIBt3xxpl5h7Q.ojY3cTIe.8Vmoc1C.GfLJNGYg.LSY5p8Vk4V2Qu', true, '2026-03-05 13:08:09.383713+00', '2026-05-31 13:52:42.064376+00', '2026-05-31 13:52:42.056878+00', false, '{"name": "Arjun Patel", "role": "school_student", "phone": "9876512305", "last_name": "Patel", "first_name": "Arjun", "email_verified": true}'),
	('0c26352e-252e-4427-ba35-a9dab315763d', 'rakesh.menon@learner.com', '$2a$10$QGikev.aaZxCwk7fDVwh7OUkArkQzDnvfbhQP8Vn./kz0CKHohh/6', true, '2026-03-07 09:20:03.7358+00', '2026-06-08 06:35:20.219434+00', '2026-06-03 04:02:37.377525+00', false, '{"name": "Rakesh Menon", "role": "learner", "last_name": "Menon", "first_name": "Rakesh", "email_verified": true}'),
	('2c20f726-0fdd-4820-87c5-1a3b921eb1a5', 'vikram.naidu@learner.com', '$2a$10$Fy69WJiHnLJ0reRTbhqi7OwWj4bX9vsAssFLEk01ku0hjbaImcIjS', true, '2026-03-07 09:09:02.17125+00', '2026-06-03 04:01:10.830977+00', '2026-06-03 04:01:10.825144+00', false, '{"name": "Vikram Naidu", "role": "learner", "last_name": "Naidu", "first_name": "Vikram", "email_verified": true}'),
	('9c6c6598-f2b0-449d-97da-df6270ffa1c7', 'neha.sharma@learner.com', '$2a$10$E6p0N62MJbdOJcjM0WrTq.FKrGvRUxy1kZ7MWtm4l/5eAkZuuPvWm', true, '2026-03-07 09:05:01.328161+00', '2026-06-16 03:49:48.583569+00', '2026-06-16 03:49:48.579277+00', false, '{"name": "Neha Sharma", "role": "learner", "last_name": "Sharma", "first_name": "Neha", "email_verified": true}'),
	('be897d11-9e3a-445c-98d1-959a9175d922', 'ishita.verma12@gmail.com', '$2a$10$Rg.BPwjPBvQedwX7TTiW6.qlQYcmXwK3gIVHbvUiNF0xUiHu3mzqy', true, '2026-03-05 13:03:47.477496+00', '2026-06-19 07:04:11.592721+00', '2026-06-18 10:33:44.099246+00', false, '{"name": "Ishita Verma", "role": "school_student", "phone": "9876542107", "last_name": "Verma", "first_name": "Ishita", "email_verified": true}'),
	('67908a3b-d5b8-46d9-a2ed-a5b4261ff223', 'sham.mehta07@gmail.com', '$2a$10$mze8y4fiXq93vZkCXP4AdORiifiLcV2QPYW4dVFHfHFpVZ15OVKN6', true, '2026-03-05 13:08:09.187144+00', '2026-07-10 07:05:30.571389+00', '2026-07-10 07:05:30.527815+00', false, '{"name": "Sham Meta", "role": "school_student", "phone": "9876542102", "last_name": "Meta", "first_name": "Sham", "email_verified": true}'),
	('5da54367-2e1f-41be-ac42-bef026ad666d', 'aman.kumar@learner.com', '$2a$10$JoLR3YoTAbM0XRALPXIBoumDy0RyEkd.YchjhdKosYJ5YhsvgCXe.', true, '2026-03-07 09:01:43.098348+00', '2026-06-03 03:59:04.572009+00', '2026-06-03 03:59:04.569047+00', false, '{"name": "Aman Kumar", "role": "learner", "last_name": "Kumar", "first_name": "Aman", "email_verified": true}'),
	('7725b2ca-355f-4a1e-9913-b51b1a40c61b', 'tanya.singh@learner.com', '$2a$10$80LzqnXCZuFJO6BkM6dBB.tEdae4C7S5ZqRXOXEJqRXP0jAoLYPvK', true, '2026-03-07 09:22:34.08248+00', '2026-03-20 12:19:36.739804+00', '2026-03-20 12:17:03.864928+00', false, '{"name": "Tanya Singh", "role": "learner", "last_name": "Singh", "first_name": "Tanya", "email_verified": true}'),
	('9233df2c-d1d6-431c-8acd-8c95af16853e', 'rahul.v@gmail.com', '$2a$10$9IXzgrrgJB7kOvEXC1zhPOzFqqLMiam/aV95K.iVJO7JXi2UbVOCa', true, '2026-03-07 05:29:11.365732+00', '2026-06-24 03:49:45.199316+00', '2026-06-23 10:50:25.448214+00', false, '{"name": "Rahul V", "role": "college_student", "phone": "98745621528", "last_name": "V", "first_name": "Rahul", "email_verified": true}');


--
-- Memberships for migrated users: platform org + learner role
--
INSERT INTO "public"."memberships" ("user_id", "org_id", "status")
SELECT u.id, '00000000-0000-0000-0000-000000000001', 'active'
FROM "public"."users" u
WHERE u.email IN (
    'rahul.v@gmail.com',
    'priya.nair@gmail.com',
    'karthik.r@gmail.com',
    'sneha.g@gmail.com',
    'arjun.shah@gmail.com',
    'diya.kapoor@gmail.com',
    'ananya.iye@gmail.com',
    'rohan.mehta07@gmail.com',
    'kabir.singh09@gmail.com',
    'ishita.verma12@gmail.com',
    'sham.mehta07@gmail.com',
    'arjun.patel12@gmail.com',
    'aman.kumar@learner.com',
    'neha.sharma@learner.com',
    'vikram.naidu@learner.com',
    'pooja.agarwal@learner.com',
    'rakesh.menon@learner.com',
    'tanya.singh@learner.com',
    'stu502@school.edu',
    'stu506@school.edu',
    'stu505@school.edu',
    'nilesh.jain@aditya.college.edu',
    'priya.joshi@aditya.college.edu'
)
ON CONFLICT ("user_id", "org_id") DO NOTHING;

INSERT INTO "public"."membership_roles" ("membership_id", "role_id")
SELECT m.id, r.id
FROM "public"."memberships" m
JOIN "public"."users" u ON u.id = m.user_id
CROSS JOIN "public"."roles" r
WHERE r.name = 'learner'
  AND u.email IN (
    'rahul.v@gmail.com',
    'priya.nair@gmail.com',
    'karthik.r@gmail.com',
    'sneha.g@gmail.com',
    'arjun.shah@gmail.com',
    'diya.kapoor@gmail.com',
    'ananya.iye@gmail.com',
    'rohan.mehta07@gmail.com',
    'kabir.singh09@gmail.com',
    'ishita.verma12@gmail.com',
    'sham.mehta07@gmail.com',
    'arjun.patel12@gmail.com',
    'aman.kumar@learner.com',
    'neha.sharma@learner.com',
    'vikram.naidu@learner.com',
    'pooja.agarwal@learner.com',
    'rakesh.menon@learner.com',
    'tanya.singh@learner.com',
    'stu502@school.edu',
    'stu506@school.edu',
    'stu505@school.edu',
    'nilesh.jain@aditya.college.edu',
    'priya.joshi@aditya.college.edu'
)
ON CONFLICT ("membership_id", "role_id") DO NOTHING;

--
-- Premium subscriptions (Career Accelerator) for migrated users
--
INSERT INTO "public"."subscriptions"
  ("user_id", "plan_id", "full_name", "email", "plan_code", "plan_type", "plan_amount",
   "billing_cycle", "features", "status", "auto_renew",
   "subscription_start_date", "subscription_end_date")
SELECT u.id, p.id,
       COALESCE(u.user_metadata->>'name', u.email),
       u.email, p.plan_code, 'Premium', 999,
       'yearly', p.base_features, 'active', false,
       now(), now() + interval '1 year'
FROM "public"."users" u
CROSS JOIN "public"."plans" p
WHERE p.plan_code = 'premium' AND p.business_type = 'b2c'
  AND u.email IN (
    'rahul.v@gmail.com',
    'priya.nair@gmail.com',
    'karthik.r@gmail.com',
    'sneha.g@gmail.com',
    'arjun.shah@gmail.com',
    'diya.kapoor@gmail.com',
    'ananya.iye@gmail.com',
    'rohan.mehta07@gmail.com',
    'kabir.singh09@gmail.com',
    'ishita.verma12@gmail.com',
    'sham.mehta07@gmail.com',
    'arjun.patel12@gmail.com',
    'aman.kumar@learner.com',
    'neha.sharma@learner.com',
    'vikram.naidu@learner.com',
    'pooja.agarwal@learner.com',
    'rakesh.menon@learner.com',
    'tanya.singh@learner.com',
    'stu502@school.edu',
    'stu506@school.edu',
    'stu505@school.edu',
    'nilesh.jain@aditya.college.edu',
    'priya.joshi@aditya.college.edu'
)
  AND NOT EXISTS (
    SELECT 1 FROM "public"."subscriptions" s
    WHERE s.user_id = u.id AND s.status = 'active'
);

SET session_replication_role = DEFAULT;
