-- Seed Soundarya college admin and College Enterprise subscription in SSO.
-- The matching SkillPassport migration must use the same IDs.
BEGIN;

DO $seed$
DECLARE
  v_org_id uuid := '284c9ed9-cd13-584d-b5bc-e198866b917b';
  v_admin_id uuid := '783d8431-a034-5369-ae47-3aca2c4ec618';
  v_membership_id uuid := 'ac5a8887-5058-552b-8d5b-421b61c4bf79';
  v_membership_role_id uuid := 'eb62c537-5e17-5dc8-84b8-238c38d99798';
  v_college_admin_role_id uuid;
  v_effective_membership_id uuid;
BEGIN
  IF EXISTS (SELECT 1 FROM public.organizations AS org WHERE lower(org.name) = lower('Soundarya Institute of Management and Science') AND org.id <> v_org_id) THEN
    RAISE EXCEPTION 'Soundarya organization already exists under a different ID';
  END IF;
  IF EXISTS (SELECT 1 FROM public.users AS usr WHERE lower(usr.email) = 'sims.info@soundaryainstitutions.in' AND usr.id <> v_admin_id) THEN
    RAISE EXCEPTION 'Soundarya admin email already exists under a different ID';
  END IF;

  -- Roles normally come from seed.sql, but migrations run before seeds during
  -- `supabase db reset`. Create this required role here using its canonical ID.
  INSERT INTO public.roles (id,name,description,created_at)
  SELECT 'cd6c98bc-67bc-4e3c-83a6-cdcb2dc6961e','college_admin','College administrator',NOW()
  WHERE NOT EXISTS (
    SELECT 1 FROM public.roles
    WHERE lower(replace(trim(name), ' ', '_')) = 'college_admin'
  )
  ON CONFLICT (id) DO NOTHING;

  SELECT role_row.id INTO v_college_admin_role_id
  FROM public.roles AS role_row
  WHERE lower(replace(trim(role_row.name), ' ', '_')) = 'college_admin'
  LIMIT 1;
  IF v_college_admin_role_id IS NULL THEN
    RAISE EXCEPTION 'college_admin role is required before seeding Soundarya';
  END IF;

  INSERT INTO public.organizations (id, name, slug, created_by, created_at, metadata)
  VALUES (
    v_org_id, 'Soundarya Institute of Management and Science',
    'soundarya-institute-management-science', NULL, NOW(),
    jsonb_build_object(
      'organization_type','college','admin_id',v_admin_id::text,
      'institution_name','Soundarya Institute of Management and Science','short_name','SIMS',
      'academic_year','2026/2027','founded_year',2007,'affiliated_university','Bangalore University',
      'website','https://soundarya.edu.in/','address_line_1','Soundarya Nagar, Sidedahalli, Nagasandra Post, 296, 9th Cross Road, Prakruthi Layout, Siddeshwar Layout, Soundarya Layout',
      'city','Bengaluru','state','Karnataka','postal_code','560073','country','India',
      'information_email','sims.info@soundaryainstitutions.in','admissions_email','admissions@soundaryainstitutions.in',
      'admissions_phone_1','+916269000092','admissions_phone_2','+916269000093',
      'placement_phone','+919606245769','principal_director','Dr. Prakash HS',
      'onboarding_completed',true,'onboarding_source','soundarya_admin_migration'
    )
  )
  ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, slug=EXCLUDED.slug, metadata=EXCLUDED.metadata;

  INSERT INTO public.users (id,email,password_hash,is_email_verified,created_at,updated_at,last_login_at,is_blocked)
  VALUES (v_admin_id,'sims.info@soundaryainstitutions.in','$2b$12$TXc2NhMMjYxKuPoQYdI8UeRRzw5v/XEtEjpcYbYIwomWAZGBeWpny',true,NOW(),NOW(),NULL,false)
  ON CONFLICT (id) DO UPDATE SET email=EXCLUDED.email,password_hash=EXCLUDED.password_hash,is_email_verified=true,updated_at=NOW(),is_blocked=false;

  UPDATE public.organizations SET created_by=v_admin_id WHERE id=v_org_id;

  SELECT mem.id INTO v_effective_membership_id
  FROM public.memberships AS mem
  WHERE mem.user_id=v_admin_id AND mem.org_id=v_org_id
  LIMIT 1;
  IF v_effective_membership_id IS NULL THEN
    v_effective_membership_id := v_membership_id;
    INSERT INTO public.memberships (id,user_id,org_id,created_at,status)
    VALUES (v_effective_membership_id,v_admin_id,v_org_id,NOW(),'active')
    ON CONFLICT (id) DO UPDATE SET user_id=EXCLUDED.user_id,org_id=EXCLUDED.org_id,status='active';
  ELSE
    UPDATE public.memberships SET status='active' WHERE id=v_effective_membership_id;
  END IF;

  INSERT INTO public.membership_roles (id,membership_id,role_id,created_at)
  SELECT v_membership_role_id,v_effective_membership_id,v_college_admin_role_id,NOW()
  WHERE NOT EXISTS (SELECT 1 FROM public.membership_roles AS mr WHERE mr.membership_id=v_effective_membership_id AND mr.role_id=v_college_admin_role_id)
  ON CONFLICT (id) DO UPDATE SET membership_id=EXCLUDED.membership_id,role_id=EXCLUDED.role_id;
END;
$seed$;

-- Products are normally loaded by seed.sql after migrations during a local
-- reset. Ensure the plan's FK parent exists before inserting the plan.
INSERT INTO public.products (id,code,name,description,created_at)
VALUES ('912d5049-e195-46e9-a319-49e3502bf7e7','skillpassport','SkillPassport','Skill development and career advancement platform',NOW())
ON CONFLICT (id) DO UPDATE SET
  code=EXCLUDED.code,
  name=EXCLUDED.name,
  description=EXCLUDED.description;

INSERT INTO public.plans (id,plan_code,name,business_type,applicable_entities,pricing_matrix,base_features,entity_config,display_order,is_active,created_at,updated_at,product_id)
VALUES ('a0000000-0000-4000-8000-000000000023','college_enterprise','College Enterprise','b2b',ARRAY['college'],'{"college":{"yearly":49999,"currency":"INR"}}'::jsonb,'["up_to_5000_learners_or_custom","multi_department_analytics","recruiter_access","advanced_placement_dashboard","bulk_onboarding","dedicated_success_manager"]'::jsonb,'{"college":{"display_name":"College Enterprise","max_users":5000,"storage_limit":"50GB","duration":"yearly"}}'::jsonb,23,true,NOW(),NOW(),'912d5049-e195-46e9-a319-49e3502bf7e7')
ON CONFLICT (id) DO UPDATE SET plan_code=EXCLUDED.plan_code,name=EXCLUDED.name,pricing_matrix=EXCLUDED.pricing_matrix,base_features=EXCLUDED.base_features,entity_config=EXCLUDED.entity_config,is_active=true,updated_at=NOW();

INSERT INTO public.subscriptions (id,user_id,plan_id,organization_id,full_name,email,plan_code,plan_type,plan_amount,billing_cycle,features,status,subscription_start_date,subscription_end_date,is_organization_subscription,organization_type,purchased_by,seat_count,is_bulk_purchase,metadata,created_at,updated_at,product_id)
VALUES ('d3876903-b74e-55d7-910f-90907ea3e11f','783d8431-a034-5369-ae47-3aca2c4ec618','a0000000-0000-4000-8000-000000000023','284c9ed9-cd13-584d-b5bc-e198866b917b','Soundarya College Admin','sims.info@soundaryainstitutions.in','college_enterprise','College Enterprise',49999,'yearly','["up_to_5000_learners_or_custom","multi_department_analytics","recruiter_access","advanced_placement_dashboard","bulk_onboarding","dedicated_success_manager"]'::jsonb,'active',NOW(),NOW()+INTERVAL '1 year',true,'college','783d8431-a034-5369-ae47-3aca2c4ec618',5000,true,'{"institution_name":"Soundarya Institute of Management and Science","short_name":"SIMS","package":"highest","seeded_subscription":true}'::jsonb,NOW(),NOW(),'912d5049-e195-46e9-a319-49e3502bf7e7')
ON CONFLICT (id) DO UPDATE SET user_id=EXCLUDED.user_id,organization_id=EXCLUDED.organization_id,plan_id=EXCLUDED.plan_id,plan_code=EXCLUDED.plan_code,plan_type=EXCLUDED.plan_type,plan_amount=EXCLUDED.plan_amount,features=EXCLUDED.features,status='active',subscription_end_date=EXCLUDED.subscription_end_date,seat_count=EXCLUDED.seat_count,metadata=EXCLUDED.metadata,updated_at=NOW();

COMMIT;
