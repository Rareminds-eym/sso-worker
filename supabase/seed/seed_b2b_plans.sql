-- Seed: B2B (Organization) Plans
-- Adds organizational plans for colleges, schools, and universities.
-- These are the source of truth that sync to skillpassport plans_cache.
--
-- Fixed UUIDs are used so the plans_cache shadow can reference the same IDs.
-- product_id '912d5049-e195-46e9-a319-49e3502bf7e7' = SkillPassport

INSERT INTO public.plans (id, plan_code, name, business_type, applicable_entities, pricing_matrix, base_features, entity_config, display_order, is_active, product_id) VALUES
(
  'a0000000-0000-4000-8000-000000000000',
  'org_freemium',
  'Freemium',
  'b2b',
  ARRAY['college', 'school', 'university', 'all'],
  '{
    "college": {"yearly": 0, "currency": "INR"},
    "school": {"yearly": 0, "currency": "INR"},
    "university": {"yearly": 0, "currency": "INR"},
    "all": {"yearly": 0, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "1_assessment_month", "1gb_storage", "organization_management"]'::jsonb,
  '{
    "college": {"tagline": "Get started for free", "duration": "yearly", "ideal_for": "Colleges exploring digital skill platforms", "max_users": 10, "description": "Free tier to explore basic features and get started with digital skill development", "positioning": "Get started for free", "storage_limit": "1GB", "is_recommended": false,     "display_name": "Freemium"},
    "school": {"tagline": "Get started for free", "duration": "yearly", "ideal_for": "Schools exploring digital skill platforms", "max_users": 10, "description": "Free tier to explore basic features and get started with digital skill development", "positioning": "Get started for free", "storage_limit": "1GB", "is_recommended": false, "display_name": "Freemium"},
    "university": {"tagline": "Get started for free", "duration": "yearly", "ideal_for": "Universities exploring digital skill platforms", "max_users": 10, "description": "Free tier to explore basic features and get started with digital skill development", "positioning": "Get started for free", "storage_limit": "1GB", "is_recommended": false, "display_name": "Freemium"},
    "all": {"tagline": "Get started for free", "duration": "yearly", "ideal_for": "Institutions exploring digital skill platforms", "max_users": 10, "description": "Free tier to explore basic features and get started with digital skill development", "positioning": "Get started for free", "storage_limit": "1GB", "is_recommended": false, "display_name": "Freemium"}
  }'::jsonb,
  9,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),
(
  'a0000000-0000-4000-8000-000000000001',
  'org_starter',
  'Organization Starter',
  'b2b',
  ARRAY['college', 'school', 'university', 'all'],
  '{
    "college": {"yearly": 4999, "currency": "INR"},
    "school": {"yearly": 3999, "currency": "INR"},
    "university": {"yearly": 9999, "currency": "INR"},
    "all": {"yearly": 4999, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "skill_analytics", "portfolio_builder", "5_assessments_month", "3_projects", "5gb_storage", "basic_support", "organization_management", "bulk_learner_import", "basic_reports"]'::jsonb,
  '{
    "college": {"tagline": "Essential tools for your college", "duration": "yearly", "ideal_for": "Small to medium colleges starting their digital journey", "max_users": 100, "description": "Everything a college needs to get started with digital skill development", "positioning": "Essential college management tools", "storage_limit": "5GB", "is_recommended": false, "display_name": "College Starter"},
    "school": {"tagline": "Essential tools for your school", "duration": "yearly", "ideal_for": "Schools beginning their digital transformation", "max_users": 50, "description": "Everything a school needs to get started with digital skill development", "positioning": "Essential school management tools", "storage_limit": "5GB", "is_recommended": false, "display_name": "School Starter"},
    "university": {"tagline": "Essential tools for your university", "duration": "yearly", "ideal_for": "Small to medium universities starting their digital journey", "max_users": 200, "description": "Everything a university needs to get started with digital skill development", "positioning": "Essential university management tools", "storage_limit": "5GB", "is_recommended": false, "display_name": "University Starter"},
    "all": {"tagline": "Essential tools for your institution", "duration": "yearly", "ideal_for": "Small to medium institutions starting their digital journey", "max_users": 100, "description": "Everything your institution needs to get started with digital skill development", "positioning": "Essential institutional management tools", "storage_limit": "5GB", "is_recommended": false, "display_name": "Organization Starter"}
  }'::jsonb,
  10,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),
(
  'a0000000-0000-4000-8000-000000000002',
  'org_professional',
  'Organization Professional',
  'b2b',
  ARRAY['college', 'school', 'university', 'all'],
  '{
    "college": {"yearly": 14999, "currency": "INR"},
    "school": {"yearly": 9999, "currency": "INR"},
    "university": {"yearly": 24999, "currency": "INR"},
    "all": {"yearly": 14999, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "advanced_analytics", "advanced_portfolio", "career_paths", "interview_prep", "resume_builder", "certificates", "10_assessments_month", "10_projects", "10gb_storage", "priority_support", "organization_management", "bulk_learner_import", "advanced_reports", "custom_branding", "api_access", "dedicated_success_manager"]'::jsonb,
  '{
    "college": {"tagline": "Advanced features for growing colleges", "duration": "yearly", "ideal_for": "Growing colleges that need comprehensive tools", "max_users": 500, "description": "Comprehensive tools for colleges serious about learner outcomes", "positioning": "Advanced college management suite", "storage_limit": "10GB", "is_recommended": true, "display_name": "College Professional"},
    "school": {"tagline": "Advanced features for growing schools", "duration": "yearly", "ideal_for": "Growing schools that need comprehensive tools", "max_users": 200, "description": "Comprehensive tools for schools serious about learner outcomes", "positioning": "Advanced school management suite", "storage_limit": "10GB", "is_recommended": true, "display_name": "School Professional"},
    "university": {"tagline": "Advanced features for growing universities", "duration": "yearly", "ideal_for": "Growing universities that need comprehensive tools", "max_users": 1000, "description": "Comprehensive tools for universities serious about learner outcomes", "positioning": "Advanced university management suite", "storage_limit": "10GB", "is_recommended": true, "display_name": "University Professional"},
    "all": {"tagline": "Advanced features for growing institutions", "duration": "yearly", "ideal_for": "Growing institutions that need comprehensive tools", "max_users": 500, "description": "Comprehensive tools for institutions serious about learner outcomes", "positioning": "Advanced institutional management suite", "storage_limit": "10GB", "is_recommended": true, "display_name": "Organization Professional"}
  }'::jsonb,
  11,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),
(
  'a0000000-0000-4000-8000-000000000003',
  'org_enterprise',
  'Organization Enterprise',
  'b2b',
  ARRAY['college', 'school', 'university', 'all'],
  '{
    "college": {"yearly": 49999, "currency": "INR"},
    "school": {"yearly": 29999, "currency": "INR"},
    "university": {"yearly": 99999, "currency": "INR"},
    "all": {"yearly": 49999, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "advanced_analytics", "advanced_portfolio", "all_career_paths", "mock_interviews", "linkedin_opt", "resume_builder", "verified_certs", "unlimited_assessments", "unlimited_projects", "50gb_storage", "priority_support", "mentorship", "placement_assist", "organization_management", "bulk_learner_import", "advanced_reports", "custom_branding", "api_access", "dedicated_success_manager", "white_label", "sso_integration", "custom_integrations", "priority_onboarding"]'::jsonb,
  '{
    "college": {"tagline": "Enterprise-grade solution for colleges", "duration": "yearly", "ideal_for": "Large colleges needing comprehensive enterprise features", "max_users": 2000, "description": "Full-featured enterprise solution for colleges with custom requirements", "positioning": "Enterprise college management platform", "storage_limit": "50GB", "is_recommended": false, "display_name": "College Enterprise"},
    "school": {"tagline": "Enterprise-grade solution for schools", "duration": "yearly", "ideal_for": "Large schools needing comprehensive enterprise features", "max_users": 1000, "description": "Full-featured enterprise solution for schools with custom requirements", "positioning": "Enterprise school management platform", "storage_limit": "50GB", "is_recommended": false, "display_name": "School Enterprise"},
    "university": {"tagline": "Enterprise-grade solution for universities", "duration": "yearly", "ideal_for": "Large universities needing comprehensive enterprise features", "max_users": 5000, "description": "Full-featured enterprise solution for universities with custom requirements", "positioning": "Enterprise university management platform", "storage_limit": "50GB", "is_recommended": false, "display_name": "University Enterprise"},
    "all": {"tagline": "Enterprise-grade solution for institutions", "duration": "yearly", "ideal_for": "Large institutions needing comprehensive enterprise features", "max_users": 2000, "description": "Full-featured enterprise solution for institutions with custom requirements", "positioning": "Enterprise institutional management platform", "storage_limit": "50GB", "is_recommended": false, "display_name": "Organization Enterprise"}
  }'::jsonb,
  12,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
)
ON CONFLICT (plan_code) DO NOTHING;
