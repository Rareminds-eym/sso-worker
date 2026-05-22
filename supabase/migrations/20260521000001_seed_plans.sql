-- Migration: Seed subscription plans
-- Description: Initial seed data for subscription plans (migrated from skillpassport DB)
-- Date: 2026-05-21

-- Insert Freemium plan
INSERT INTO public.plans (
  plan_code,
  name,
  business_type,
  applicable_entities,
  pricing_matrix,
  base_features,
  entity_config,
  display_order,
  is_active,
  created_at,
  updated_at
) VALUES (
  'freemium',
  'Freemium',
  'b2c',
  ARRAY['all']::text[],
  '{
    "all": {"monthly": 0, "yearly": 0, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access"]'::jsonb,
  '{
    "all": {
      "positioning": "Start free. Upgrade anytime to unlock all features.",
      "tagline": "Start free, upgrade anytime",
      "ideal_for": "Users who want to explore the platform",
      "storage_limit": "0GB",
      "duration": "lifetime",
      "is_recommended": false,
      "max_users": 1,
      "description": "Free forever plan with basic features"
    }
  }'::jsonb,
  0,
  true,
  NOW(),
  NOW()
),
(
  'basic',
  'Basic',
  'b2c',
  ARRAY['all']::text[],
  '{
    "all": {"monthly": 499, "yearly": 4999, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "skill_analytics", "portfolio_builder", "5_assessments_month", "3_projects", "5gb_storage", "basic_support"]'::jsonb,
  '{
    "all": {
      "positioning": "Essential tools for individual learning",
      "tagline": "Get started with essential features",
      "ideal_for": "Individual learners starting their journey",
      "storage_limit": "5GB",
      "duration": "monthly",
      "is_recommended": false,
      "max_users": 1,
      "description": "Perfect for individuals who want to build their skills"
    }
  }'::jsonb,
  1,
  true,
  NOW(),
  NOW()
),
(
  'professional',
  'Professional',
  'b2c',
  ARRAY['all']::text[],
  '{
    "all": {"monthly": 999, "yearly": 9999, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "advanced_analytics", "advanced_portfolio", "career_paths", "interview_prep", "resume_builder", "certificates", "10_assessments_month", "10_projects", "10gb_storage", "priority_support"]'::jsonb,
  '{
    "all": {
      "positioning": "Advanced features for serious learners",
      "tagline": "Accelerate your career growth",
      "ideal_for": "Professionals advancing their careers",
      "storage_limit": "10GB",
      "duration": "monthly",
      "is_recommended": true,
      "max_users": 1,
      "description": "Most popular plan with advanced career tools"
    }
  }'::jsonb,
  2,
  true,
  NOW(),
  NOW()
),
(
  'premium',
  'Premium',
  'b2c',
  ARRAY['all']::text[],
  '{
    "all": {"monthly": 1999, "yearly": 19999, "currency": "INR"}
  }'::jsonb,
  '["dashboard_access", "profile_creation", "marketplace_access", "view_pricing", "opportunities_access", "courses_listing_access", "advanced_analytics", "advanced_portfolio", "all_career_paths", "mock_interviews", "linkedin_opt", "resume_builder", "verified_certs", "unlimited_assessments", "unlimited_projects", "50gb_storage", "priority_support", "mentorship", "placement_assist"]'::jsonb,
  '{
    "all": {
      "positioning": "Complete toolkit for maximum career success",
      "tagline": "Everything you need to succeed",
      "ideal_for": "Ambitious professionals seeking comprehensive support",
      "storage_limit": "50GB",
      "duration": "monthly",
      "is_recommended": false,
      "max_users": 1,
      "description": "All features unlocked with premium support"
    }
  }'::jsonb,
  3,
  true,
  NOW(),
  NOW()
)
ON CONFLICT (plan_code) DO UPDATE SET
  name = EXCLUDED.name,
  business_type = EXCLUDED.business_type,
  applicable_entities = EXCLUDED.applicable_entities,
  pricing_matrix = EXCLUDED.pricing_matrix,
  base_features = EXCLUDED.base_features,
  entity_config = EXCLUDED.entity_config,
  display_order = EXCLUDED.display_order,
  is_active = EXCLUDED.is_active,
  updated_at = NOW();

-- Verify the plans were created
DO $$
DECLARE
  plan_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO plan_count
  FROM public.plans
  WHERE is_active = true;
  
  IF plan_count < 4 THEN
    RAISE EXCEPTION 'Expected 4 plans but found %', plan_count;
  ELSE
    RAISE NOTICE '✅ % subscription plans created successfully', plan_count;
  END IF;
END $$;

