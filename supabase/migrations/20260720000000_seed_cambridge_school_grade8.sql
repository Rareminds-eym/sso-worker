-- ============================================================
-- SEED FILE | CAMBRIDGE SCHOOL - GRADE 8
-- Order: organizations → users → memberships → membership_roles
-- Students: 46 | Sections: A, B and C
-- Shared initial password: Cambridge@123
-- ============================================================

-- ------------------------------------------------------------
-- 1. ORGANIZATIONS
-- ------------------------------------------------------------
INSERT INTO "public"."organizations"
  ("id", "name", "slug", "created_by", "created_at", "metadata")
VALUES
  ('8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', 'Cambridge School', 'cambridge-school', NULL, NOW(), '{"organization_type":"school","contact_email":"admin@cambridgeschool.edu.in","board":"CBSE","city":"Bengaluru","state":"Karnataka","country":"India"}'::jsonb)
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------
-- 2. USERS
-- ------------------------------------------------------------
INSERT INTO "public"."users"
  ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked")
VALUES
  ('8c8f6c10-8e7a-4f66-9a20-a75cd6fd8002', 'amrutha.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('589b2816-6201-5b25-a706-4ac572616db2', 'deepthi.t.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('2b55acbc-0dd5-587d-839e-13c1ada123eb', 'ankita.priyadarshini.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('19f4edfc-835d-5a53-825e-9f624d894d15', 'gokul.raj.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('a47f5063-936e-5514-9bba-ac5b276bc11e', 'bhavani.v.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('3ed96a9f-c575-525a-ba43-e797ec7c277a', 'shivaraj.m.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('74a45f8e-b84a-51f6-8652-53bf680fdeb8', 'tejaswini.d.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('5aa1f76f-8365-5713-9536-f0f733d35533', 'hudha.durwesh.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('6bc55f35-5c04-55b3-adf8-0fb123a6a2b4', 'vellena.ningthoujam.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('24cccf8d-068d-5036-8e08-6495b0d93b28', 'adarsh.patil.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('60ccbfe6-b379-57d6-ad78-05c764be94dc', 'aishwarya.m.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('73e758ec-d84e-5b0b-b5aa-cf4d0275f57f', 'asmita.pandey.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('388111a8-2259-559c-9d42-a0e255ffdc33', 'payal.magar.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('3accb191-27fa-5445-a71a-55227dc7c010', 'mohammed.shaikh.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('9a45d5f7-deca-57de-976e-3cd61fc8f223', 'amjed.p.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('a9ae44f3-0ce1-563e-b73f-5148d79019a6', 'jhonathan.p.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('81a081d2-3c6b-57aa-9b06-f9549011cc9d', 'sanjay.b.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('358b3c0a-f872-57ce-aa6f-59d9cabc9bb6', 'akash.s.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('c8f3d5c0-1f2d-5a72-870d-f87d0cf25545', 'saniya.khan.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('262ff05f-7571-5556-900b-1e30b3ead6e4', 'kartik.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('2d9ec53a-96bc-5d1e-a912-521b67c6b96c', 'd.chandana.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('72b0565e-ef4f-5b58-b0db-ba884b639853', 'spandana.s.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('878d4255-8c83-50d4-9f93-e5c810605859', 'ruhiya.taj.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('1af650d9-3f08-5815-862e-7510405f36cc', 'sharath.j.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('19eaf83e-85e4-5fcc-b344-8ee6f41acb9c', 'babu.n.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('1c61aad9-24f9-5aac-bd74-fa6df89b98a4', 'swathi.gr.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('79aede48-83ba-5219-bb64-949205e67e39', 'chaitra.naik.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('e8e1ef65-1251-53ba-971f-7637c34b4694', 'manasvi.bv.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('fc4e2675-9981-58f0-ad69-4dc06cbce68f', 'abhinava.cy.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('5e3bbaad-8313-540b-9d0e-0cb754e2f83f', 'jithin.k.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('d243d1d0-9729-5af3-886b-97cba079b25a', 'ashutosh.rai.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('b78ea08e-9080-5c31-a2ed-8c6d9a5c8e1b', 'tasmiya.a.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('04fb80a6-2ddc-5104-9c68-ac8684a7d899', 'harikrishna.pradeeep.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('96e7b236-4f10-58a9-978d-b9212ee7db2b', 'asiya.taj.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('9b6a6f8a-838e-5dda-856e-a9ee4ba8e2a2', 'niranjan.m.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('814c5898-9d96-5be6-a1de-039fd0706eec', 'rithik.m.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('55df8d07-f030-50ab-b4b3-162027db786c', 'varshith.m.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('8fbe1deb-fb45-5d50-9970-f28f87917b06', 'shreya.p.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('6f249fca-65da-5202-81cd-8c7f80b19f76', 'rachitha.k.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('43f9c919-27fe-5c31-b4e2-6dd622262bba', 'akshitha.s.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('6c5b3c81-71a2-5548-b3fc-e7f2dc93bcd3', 'amit.kumar.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('f2c82b3d-fcb9-5acf-b0f8-e058722096b1', 'ananya.y.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('ad5d549a-d57c-5c31-ae64-b32257b23960', 'anandu.m.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('171351f3-ad9f-5390-9b9d-9fa982ab1181', 'anju.kv.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('9b3cdd2f-2b22-5c06-ad38-882ac6eb28ed', 'arif.ashraf.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE),
  ('b44d5f67-ce7b-5fcb-9d06-2470cc19a766', 'muskan.a.grade8@cambridgeschool.edu.in', '$2a$12$6.qn3f8EBBSwbMximggeAOdwb6nH5ZpAkOJvxePfgOvJoBBmVPl2u', TRUE, NOW(), NOW(), NULL, FALSE)
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------
-- 3. MEMBERSHIPS
-- ------------------------------------------------------------
INSERT INTO "public"."memberships"
  ("id", "user_id", "org_id", "created_at", "status")
VALUES
  ('8c8f6c10-8e7a-4f66-9a20-a75cd6fd8003', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8002', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('3c5a7d98-90db-5ee6-81a2-078ad062db65', '589b2816-6201-5b25-a706-4ac572616db2', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('84db6e6d-c58f-5743-8594-6fc5b31d9dde', '2b55acbc-0dd5-587d-839e-13c1ada123eb', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('75945f12-af76-501c-b3fd-f65d09b06ad0', '19f4edfc-835d-5a53-825e-9f624d894d15', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('00a775e5-ee22-56fd-a13e-85a7cd4645a0', 'a47f5063-936e-5514-9bba-ac5b276bc11e', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('f5db14ab-673c-57b4-8ba7-69b99cf87b57', '3ed96a9f-c575-525a-ba43-e797ec7c277a', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('b5c67475-231e-5dc7-8ea7-115f939b6136', '74a45f8e-b84a-51f6-8652-53bf680fdeb8', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('d4293eb0-99ad-52b4-b689-38de3bcd1fa4', '5aa1f76f-8365-5713-9536-f0f733d35533', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('29ec5f30-91c7-5123-8457-b08e6fcbe2d7', '6bc55f35-5c04-55b3-adf8-0fb123a6a2b4', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('401975b9-a305-5d3f-a5e1-055daa795f9c', '24cccf8d-068d-5036-8e08-6495b0d93b28', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('5279f984-b6e8-5804-8c8c-e0994eb875be', '60ccbfe6-b379-57d6-ad78-05c764be94dc', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('819ce26a-d610-5b62-9ced-e727606466f2', '73e758ec-d84e-5b0b-b5aa-cf4d0275f57f', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('34ffaf59-ae02-5595-bd82-9c2b65106e23', '388111a8-2259-559c-9d42-a0e255ffdc33', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('5ac3290b-d6dd-58f0-bbae-4379f123b8a6', '3accb191-27fa-5445-a71a-55227dc7c010', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('7b5bae39-f921-5cb4-ac89-f0b1971e6cb0', '9a45d5f7-deca-57de-976e-3cd61fc8f223', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('f42d503d-0646-5fb6-a345-142a696da68e', 'a9ae44f3-0ce1-563e-b73f-5148d79019a6', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('0c7f59c1-2e48-569a-8e22-df46ab8b6d8b', '81a081d2-3c6b-57aa-9b06-f9549011cc9d', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('4fb73e69-60b7-57b1-9110-1cd2460831b4', '358b3c0a-f872-57ce-aa6f-59d9cabc9bb6', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('6ed64634-83b6-52ad-abca-c06844ae0642', 'c8f3d5c0-1f2d-5a72-870d-f87d0cf25545', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('58934ad0-9f79-54e5-b3a5-f3300140b55c', '262ff05f-7571-5556-900b-1e30b3ead6e4', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('2d4c2d65-74ad-5f0e-ab41-fbe0b15542a4', '2d9ec53a-96bc-5d1e-a912-521b67c6b96c', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('ae6deb49-3145-5400-b99d-6672d5fd5dd6', '72b0565e-ef4f-5b58-b0db-ba884b639853', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('59c61374-83d9-559b-b25b-970c1b195a2e', '878d4255-8c83-50d4-9f93-e5c810605859', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('7fd06ba8-b680-54a9-b4d5-6582bd619911', '1af650d9-3f08-5815-862e-7510405f36cc', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('cac944dc-dd53-5475-84d4-412fe9e4e1cb', '19eaf83e-85e4-5fcc-b344-8ee6f41acb9c', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('b7d84aa8-e477-5214-8a5c-0333ca67d1fe', '1c61aad9-24f9-5aac-bd74-fa6df89b98a4', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('971843e7-ad75-5ed7-a0f4-f8de1070ebad', '79aede48-83ba-5219-bb64-949205e67e39', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('29a882d0-f37c-540c-9900-5a8c93269197', 'e8e1ef65-1251-53ba-971f-7637c34b4694', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('65cc5183-216e-564e-ab7f-154bfc0ef868', 'fc4e2675-9981-58f0-ad69-4dc06cbce68f', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('50536e34-0dc3-53fe-b969-bcf93bea4c34', '5e3bbaad-8313-540b-9d0e-0cb754e2f83f', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('9584167a-8366-5734-b96a-c48a257ecaee', 'd243d1d0-9729-5af3-886b-97cba079b25a', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('04909b81-b9cd-57e7-ba91-eea0130003c7', 'b78ea08e-9080-5c31-a2ed-8c6d9a5c8e1b', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('677768a3-ef7a-52f0-8bd6-736dea69a5b9', '04fb80a6-2ddc-5104-9c68-ac8684a7d899', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('fcc9e9ac-04db-57cf-b01b-1168325d8f81', '96e7b236-4f10-58a9-978d-b9212ee7db2b', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('dedfe741-56fd-5032-95c0-eaac28dad7d9', '9b6a6f8a-838e-5dda-856e-a9ee4ba8e2a2', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('621f47a0-a6b6-5acb-8546-9075c1660afc', '814c5898-9d96-5be6-a1de-039fd0706eec', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('ada446a3-bf93-5af4-8610-e119175025e7', '55df8d07-f030-50ab-b4b3-162027db786c', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('54f68c03-aa10-54a4-b8e0-4877d76d0945', '8fbe1deb-fb45-5d50-9970-f28f87917b06', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('f02b273e-1f3e-5f2b-ae6f-ac43d5509149', '6f249fca-65da-5202-81cd-8c7f80b19f76', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('76eebb70-addb-5dd5-9db5-f1e66262600b', '43f9c919-27fe-5c31-b4e2-6dd622262bba', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('cdf56972-8464-5fd1-bb1e-82d8da519ba3', '6c5b3c81-71a2-5548-b3fc-e7f2dc93bcd3', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('5f3e802c-fbca-58d2-be05-3b62140990aa', 'f2c82b3d-fcb9-5acf-b0f8-e058722096b1', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('a27cce2b-4a19-5e44-ab97-daa7aa0424a7', 'ad5d549a-d57c-5c31-ae64-b32257b23960', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('99f8531b-7a9c-5e5b-9df6-5e4437c3d23a', '171351f3-ad9f-5390-9b9d-9fa982ab1181', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('3ea37d23-1517-563f-8cb8-d74dd39dfde1', '9b3cdd2f-2b22-5c06-ad38-882ac6eb28ed', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active'),
  ('a0e4481c-9f9b-5de3-aada-d949b564b193', 'b44d5f67-ce7b-5fcb-9d06-2470cc19a766', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001', NOW(), 'active')
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------
-- 4. MEMBERSHIP_ROLES
-- ------------------------------------------------------------
INSERT INTO "public"."membership_roles"
  ("id", "membership_id", "role_id", "created_at")
VALUES
  ('8c8f6c10-8e7a-4f66-9a20-a75cd6fd8004', '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8003', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('0dc79cfe-bc43-5cdc-b1b9-7d7f2cf88b45', '3c5a7d98-90db-5ee6-81a2-078ad062db65', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('5b4cc045-9de7-5c76-ab2b-ff9079509d6d', '84db6e6d-c58f-5743-8594-6fc5b31d9dde', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('eaeefade-d5a6-551b-bfbb-d7938bce65cf', '75945f12-af76-501c-b3fd-f65d09b06ad0', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('0a6f9f5e-f07a-5d22-b8af-ffda594a0890', '00a775e5-ee22-56fd-a13e-85a7cd4645a0', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('43eb6d44-2c62-5a3e-9a65-14b0c2f359ac', 'f5db14ab-673c-57b4-8ba7-69b99cf87b57', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('d21ea298-b7ea-5fcf-a819-4446e1041c04', 'b5c67475-231e-5dc7-8ea7-115f939b6136', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('b0832d35-3fb1-5b50-a2f5-45bff68d0edf', 'd4293eb0-99ad-52b4-b689-38de3bcd1fa4', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('b38c2f39-46d6-5872-8014-3d9351795f01', '29ec5f30-91c7-5123-8457-b08e6fcbe2d7', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('efddb2c9-76ff-5dea-b293-92ac91c52d0f', '401975b9-a305-5d3f-a5e1-055daa795f9c', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('ab4d837c-1255-5b19-8cdf-f88663431899', '5279f984-b6e8-5804-8c8c-e0994eb875be', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('ca7a28ea-8506-5250-bc66-265345005e66', '819ce26a-d610-5b62-9ced-e727606466f2', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('d8a02dbf-f322-5a33-bc04-b39dc5f08107', '34ffaf59-ae02-5595-bd82-9c2b65106e23', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('4f6388f4-4cd0-541d-8ffb-0daa939f1a0a', '5ac3290b-d6dd-58f0-bbae-4379f123b8a6', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('399cab01-2505-5f9d-b5a6-d1c544dc0c90', '7b5bae39-f921-5cb4-ac89-f0b1971e6cb0', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('1d5f80a3-6ff8-5a07-a2d1-92005b62e19e', 'f42d503d-0646-5fb6-a345-142a696da68e', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('faa32e0d-0fca-5f20-ab14-2dcf42b7c9ef', '0c7f59c1-2e48-569a-8e22-df46ab8b6d8b', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('3e2355d3-f7a3-509b-8315-117b62570bdf', '4fb73e69-60b7-57b1-9110-1cd2460831b4', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('d0b44a16-725c-51d1-95ec-4f541cd5af56', '6ed64634-83b6-52ad-abca-c06844ae0642', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('90eaab3e-8112-5933-8266-4dfcdb94be84', '58934ad0-9f79-54e5-b3a5-f3300140b55c', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('a5c39fc5-3603-5b6e-a2ef-c571623e5052', '2d4c2d65-74ad-5f0e-ab41-fbe0b15542a4', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('332fd79a-2ef7-5c66-8e46-0e39377dc9ee', 'ae6deb49-3145-5400-b99d-6672d5fd5dd6', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('4b6d668b-da81-5d69-91ca-a357756941bc', '59c61374-83d9-559b-b25b-970c1b195a2e', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('88e40f04-c958-50c8-a68b-c158353165b3', '7fd06ba8-b680-54a9-b4d5-6582bd619911', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('45e3d159-63b5-5ad0-b67e-3a8837d0a8e0', 'cac944dc-dd53-5475-84d4-412fe9e4e1cb', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('8c0d2806-521e-5cad-b7bd-aa5cbdbc7fc5', 'b7d84aa8-e477-5214-8a5c-0333ca67d1fe', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('7c20d2f9-6873-5b57-8662-011f9b0ff68a', '971843e7-ad75-5ed7-a0f4-f8de1070ebad', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('88099f66-3726-5b82-b4f5-4df16926cf7c', '29a882d0-f37c-540c-9900-5a8c93269197', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('8ab8c5bb-7016-5cfa-a0be-28b118ac1d80', '65cc5183-216e-564e-ab7f-154bfc0ef868', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('7e258ba1-0891-5a37-91fb-bd03eb37b947', '50536e34-0dc3-53fe-b969-bcf93bea4c34', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('3d89058f-dab2-5c55-8124-7d606b180720', '9584167a-8366-5734-b96a-c48a257ecaee', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('9d68f551-4a2a-5848-9902-d0b4a9c2a6ff', '04909b81-b9cd-57e7-ba91-eea0130003c7', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('53eab49d-5ccb-55b7-a8a1-5d5b7c467b85', '677768a3-ef7a-52f0-8bd6-736dea69a5b9', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('dc65a555-c402-5e6a-87f5-7466b2649724', 'fcc9e9ac-04db-57cf-b01b-1168325d8f81', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('78e47fb5-0e39-5bdf-9339-b668347450cb', 'dedfe741-56fd-5032-95c0-eaac28dad7d9', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('b56426ca-280f-50f4-8a21-06311e411d6f', '621f47a0-a6b6-5acb-8546-9075c1660afc', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('04cc90ef-b6d4-5c7d-84c5-1dedffecdf1e', 'ada446a3-bf93-5af4-8610-e119175025e7', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('a8b86528-bb2b-51db-bfba-85b5f0dddf13', '54f68c03-aa10-54a4-b8e0-4877d76d0945', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('6c01edd7-bbcf-5384-80df-2413a98eecb8', 'f02b273e-1f3e-5f2b-ae6f-ac43d5509149', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('315c9458-9d1a-51c3-b072-200ce7a7a037', '76eebb70-addb-5dd5-9db5-f1e66262600b', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('58d41745-992b-5c3f-bfa0-4fbd518a5c67', 'cdf56972-8464-5fd1-bb1e-82d8da519ba3', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('219ea47a-0764-520e-a93c-5f89946f0fc6', '5f3e802c-fbca-58d2-be05-3b62140990aa', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('c12bb77f-a64f-5865-b692-851dd42f5c05', 'a27cce2b-4a19-5e44-ab97-daa7aa0424a7', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('a7f2e6e3-a964-57e1-b761-8c5264e67bfd', '99f8531b-7a9c-5e5b-9df6-5e4437c3d23a', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('d359dda2-6205-584e-a114-e2bea61e9330', '3ea37d23-1517-563f-8cb8-d74dd39dfde1', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW()),
  ('aa4aad31-d7b1-5420-8aab-6eee9a430453', 'a0e4481c-9f9b-5de3-aada-d949b564b193', '8d018d55-46f4-4e67-b6a5-8c216737a374', NOW())
ON CONFLICT DO NOTHING;


-- ------------------------------------------------------------
-- 5. SCHOOL ADMIN USER
-- ------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO "public"."users"
  ("id", "email", "password_hash", "is_email_verified", "created_at", "updated_at", "last_login_at", "is_blocked")
VALUES
  ('8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b1', 'admin@cambridgeschool.edu.in', crypt('CambridgeAdmin@123', gen_salt('bf', 12)), TRUE, NOW(), NOW(), NULL, FALSE)
ON CONFLICT ("email") DO UPDATE
SET
  "password_hash" = EXCLUDED."password_hash",
  "is_email_verified" = TRUE,
  "updated_at" = NOW(),
  "is_blocked" = FALSE;

-- ------------------------------------------------------------
-- 6. SCHOOL ADMIN MEMBERSHIP
-- ------------------------------------------------------------
INSERT INTO "public"."memberships"
  ("id", "user_id", "org_id", "created_at", "status")
VALUES
  ('8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b2',
   (SELECT "id" FROM "public"."users" WHERE "email" = 'admin@cambridgeschool.edu.in' LIMIT 1),
   '8c8f6c10-8e7a-4f66-9a20-a75cd6fd8001',
   NOW(),
   'active')
ON CONFLICT ("id") DO UPDATE
SET
  "user_id" = EXCLUDED."user_id",
  "org_id" = EXCLUDED."org_id",
  "status" = 'active';

-- ------------------------------------------------------------
-- 7. SCHOOL ADMIN ROLE
-- role_id = school_admin from roles_rows.sql
-- ------------------------------------------------------------
INSERT INTO "public"."membership_roles"
  ("id", "membership_id", "role_id", "created_at")
VALUES
  ('8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b3',
   '8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b2',
   'a750dd44-691f-4636-9d73-9aaa47476c87',
   NOW())
ON CONFLICT ("id") DO UPDATE
SET
  "membership_id" = EXCLUDED."membership_id",
  "role_id" = EXCLUDED."role_id";

-- ------------------------------------------------------------
-- 8. VERIFICATION
-- ------------------------------------------------------------
SELECT
  usr."id" AS admin_user_id,
  usr."email",
  usr."is_email_verified",
  usr."is_blocked"
FROM "public"."users" AS usr
WHERE usr."email" = 'admin@cambridgeschool.edu.in';

SELECT
  mem."id" AS admin_membership_id,
  mem."user_id",
  mem."org_id",
  mem."status"
FROM "public"."memberships" AS mem
WHERE mem."id" = '8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b2';

SELECT
  mr."id" AS admin_membership_role_id,
  mr."membership_id",
  mr."role_id"
FROM "public"."membership_roles" AS mr
WHERE mr."id" = '8c8f6c10-8e7a-4f66-9a20-a75cd6fd80b3';

-- ============================================================
-- SEED DATA SUMMARY
-- ============================================================
-- Organization: Cambridge School (CBSE, Bengaluru)
-- Students: 46 (Grade 8, Sections A, B, C)
-- Student Password: Cambridge@123
-- School Admin: admin@cambridgeschool.edu.in
-- Admin Password: CambridgeAdmin@123
-- ============================================================
