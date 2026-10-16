-- DEV & PROD SEED: Canonical Recruiter Plans v2 (B2B - for recruiters and hiring companies)
-- 6 tiers: Free -> Lite -> Starter -> Growth -> Pro -> Enterprise
-- Source of truth for SkillPassport plans_cache sync
-- product_id '912d5049-e195-46e9-a319-49e3502bf7e7' = SkillPassport
-- Date: 2026-10-16

BEGIN;

INSERT INTO public.plans (
  id,
  plan_code,
  name,
  business_type,
  applicable_entities,
  pricing_matrix,
  base_features,
  entity_config,
  display_order,
  is_active,
  product_id
) VALUES
-- ============================================================
-- 1. RECRUITER FREE
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000010',
  'recruiter_free',
  'Recruiter Free',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 0, "monthly": 0, "currency": "INR"}}'::jsonb,
  '[
    "active_job_posts_1",
    "employer_profile",
    "candidate_profile_preview",
    "candidate_invites_25",
    "basic_applicant_tracking",
    "email_support"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "Post the first job and receive applications.",
      "duration": "yearly",
      "ideal_for": "First-time employers, startups, small/local employers",
      "max_users": 1,
      "description": "Free entry plan to test applicant flow with 1 active job post.",
      "display_name": "Free",
      "purchase_mode": "self_serve",
      "is_recommended": false,
      "cta_text": "Post Free Job",
      "capacity": {
        "recruiters": 1,
        "job_postings": 1,
        "candidate_invites": 25,
        "contact_unlocks": 0
      }
    }
  }'::jsonb,
  10,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- 2. RECRUITER LITE
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000020',
  'recruiter_lite',
  'Recruiter Lite',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 2500, "currency": "INR"}}'::jsonb,
  '[
    "active_job_posts_3",
    "contact_unlocks_25",
    "basic_candidate_search",
    "readiness_score_view",
    "candidate_invites_100",
    "basic_shortlist_folder"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For occasional hiring.",
      "duration": "yearly",
      "ideal_for": "Occasional hiring, individual recruiters",
      "max_users": 1,
      "description": "Low-cost paid entry with 3 job posts, 25 contact unlocks and readiness scores.",
      "display_name": "Lite",
      "purchase_mode": "self_serve",
      "is_recommended": false,
      "cta_text": "Start Hiring",
      "capacity": {
        "recruiters": 1,
        "job_postings": 3,
        "candidate_invites": 100,
        "contact_unlocks": 25
      }
    }
  }'::jsonb,
  20,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- 3. RECRUITER STARTER
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000030',
  'recruiter_starter',
  'Recruiter Starter',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 7500, "currency": "INR"}}'::jsonb,
  '[
    "active_job_posts_7",
    "contact_unlocks_60",
    "candidate_search_plus",
    "readiness_score_view",
    "candidate_invites_250",
    "shortlist_folder_with_tags"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "Affordable paid plan with useful sourcing limits.",
      "duration": "yearly",
      "ideal_for": "Small companies hiring a few roles annually",
      "max_users": 1,
      "description": "7 job posts and 60 candidate unlocks for growing small businesses.",
      "display_name": "Starter",
      "purchase_mode": "self_serve",
      "is_recommended": false,
      "is_hidden_from_public_cards": true,
      "cta_text": "Choose Starter",
      "capacity": {
        "recruiters": 1,
        "job_postings": 7,
        "candidate_invites": 250,
        "contact_unlocks": 60
      }
    }
  }'::jsonb,
  30,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- 4. RECRUITER GROWTH (RECOMMENDED)
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000040',
  'recruiter_growth',
  'Recruiter Growth',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 15000, "currency": "INR"}}'::jsonb,
  '[
    "active_job_posts_15",
    "recruiter_seats_3",
    "contact_unlocks_200",
    "advanced_skill_filters",
    "ai_candidate_recommendations",
    "role_wise_hiring_reports",
    "candidate_invites_1000"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For regular hiring teams.",
      "duration": "yearly",
      "ideal_for": "Regular hiring teams, growing SMBs",
      "max_users": 3,
      "description": "Main paid plan with 15 active jobs, 3 recruiter seats, 200 unlocks, and AI matching.",
      "display_name": "Growth",
      "purchase_mode": "self_serve",
      "is_recommended": true,
      "badge": "Most Popular for Active Hiring",
      "cta_text": "Upgrade to Growth",
      "capacity": {
        "recruiters": 3,
        "job_postings": 15,
        "candidate_invites": 1000,
        "contact_unlocks": 200
      }
    }
  }'::jsonb,
  40,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- 5. RECRUITER PRO
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000050',
  'recruiter_pro',
  'Recruiter Pro',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 35000, "currency": "INR"}}'::jsonb,
  '[
    "active_job_posts_40",
    "recruiter_seats_5",
    "contact_unlocks_500",
    "full_assessment_insights",
    "bulk_shortlist_and_invite",
    "advanced_hiring_analytics",
    "candidate_invites_2500"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For high-volume hiring.",
      "duration": "yearly",
      "ideal_for": "High-volume hiring, staffing partners, scaling startups",
      "max_users": 5,
      "description": "Premium sourcing with 40 job posts, 5 seats, 500 unlocks, and full assessment insights.",
      "display_name": "Pro",
      "purchase_mode": "self_serve",
      "is_recommended": false,
      "cta_text": "Go Pro",
      "capacity": {
        "recruiters": 5,
        "job_postings": 40,
        "candidate_invites": 2500,
        "contact_unlocks": 500
      }
    }
  }'::jsonb,
  50,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- 6. RECRUITER ENTERPRISE
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000060',
  'recruiter_enterprise',
  'Recruiter Enterprise',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 75000, "currency": "INR"}}'::jsonb,
  '[
    "custom_seats",
    "custom_hiring_volume",
    "campus_talent_access",
    "ats_api_integration",
    "dedicated_campaigns",
    "dedicated_account_manager"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For campus, bulk and strategic hiring.",
      "duration": "yearly",
      "ideal_for": "Bulk hiring, campus hiring, enterprise teams",
      "max_users": 10,
      "description": "Custom volume hiring with campus access, ATS integration, and dedicated account manager.",
      "display_name": "Enterprise",
      "purchase_mode": "contact_sales",
      "is_recommended": false,
      "price_label": "From INR 75,000 / year",
      "cta_text": "Talk to Sales",
      "cta_link": "mailto:enterprise@skillpassport.com?subject=Recruiter%20Enterprise%20Inquiry",
      "capacity": {
        "recruiters": 10,
        "job_postings": 100,
        "candidate_invites": 10000,
        "contact_unlocks": 2000
      }
    }
  }'::jsonb,
  60,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
)
ON CONFLICT (id) DO UPDATE SET
  plan_code = EXCLUDED.plan_code,
  name = EXCLUDED.name,
  pricing_matrix = EXCLUDED.pricing_matrix,
  base_features = EXCLUDED.base_features,
  entity_config = EXCLUDED.entity_config,
  display_order = EXCLUDED.display_order,
  is_active = true,
  updated_at = NOW();

-- Deactivate legacy recruiter_premium plan if present
UPDATE public.plans
SET is_active = false
WHERE plan_code = 'recruiter_premium'
  AND id NOT IN ('b0000000-0000-4000-8000-000000000010', 'b0000000-0000-4000-8000-000000000020', 'b0000000-0000-4000-8000-000000000030', 'b0000000-0000-4000-8000-000000000040', 'b0000000-0000-4000-8000-000000000050', 'b0000000-0000-4000-8000-000000000060');

COMMIT;
