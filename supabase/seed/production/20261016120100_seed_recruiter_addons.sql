-- DEV & PROD SEED: Recruiter Add-ons & Credit Top-Up Packs Catalog (Spec Sections 6 & 7)
-- Product: SkillPassport ('912d5049-e195-46e9-a319-49e3502bf7e7')
-- Date: 2026-10-16

BEGIN;

INSERT INTO public.addon_catalog (
  id,
  product_id,
  category,
  feature_key,
  feature_name,
  feature_value,
  description,
  price_monthly,
  price_annual,
  target_roles,
  icon,
  display_order,
  is_active,
  created_at,
  updated_at
) VALUES
-- 1. 25 Contact Unlocks (₹1,000)
(
  'c0000000-0000-4000-8000-000000000001',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'capacity',
  'contact_unlocks_25',
  '25 Contact Unlocks',
  '25_unlocks',
  'Entry pack of 25 candidate contact unlocks for occasional sourcing.',
  1000.00,
  1000.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '🔓',
  10,
  true,
  NOW(),
  NOW()
),
-- 2. 100 Contact Unlocks (₹3,500)
(
  'c0000000-0000-4000-8000-000000000002',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'capacity',
  'contact_unlocks_100',
  '100 Contact Unlocks',
  '100_unlocks',
  'Main sourcing top-up pack with 100 candidate contact unlocks.',
  3500.00,
  3500.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '🔓',
  20,
  true,
  NOW(),
  NOW()
),
-- 3. 500 Contact Unlocks (₹15,000)
(
  'c0000000-0000-4000-8000-000000000003',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'capacity',
  'contact_unlocks_500',
  '500 Contact Unlocks',
  '500_unlocks',
  'High-volume sourcing pack of 500 candidate contact unlocks.',
  15000.00,
  15000.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '🚀',
  30,
  true,
  NOW(),
  NOW()
),
-- 4. 1 Job Boost (₹500)
(
  'c0000000-0000-4000-8000-000000000004',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'capacity',
  'job_boost_1',
  '1 Job Boost',
  '1_boost',
  'Single job visibility boost to reach top active candidates.',
  500.00,
  500.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '⚡',
  40,
  true,
  NOW(),
  NOW()
),
-- 5. 10 Job Boosts (₹4,000)
(
  'c0000000-0000-4000-8000-000000000005',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'capacity',
  'job_boost_10',
  '10 Job Boosts',
  '10_boosts',
  'Discounted bundle of 10 job visibility boosts.',
  4000.00,
  4000.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '⚡',
  50,
  true,
  NOW(),
  NOW()
),
-- 6. AI Shortlist for 1 Role (₹2,500)
(
  'c0000000-0000-4000-8000-000000000006',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'learning',
  'ai_shortlist_role',
  'AI Shortlist for 1 Role',
  '1_role_shortlist',
  'Platform-generated candidate shortlist using role criteria and readiness signals.',
  2500.00,
  2500.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '🤖',
  60,
  true,
  NOW(),
  NOW()
),
-- 7. Featured Job (7 Days) (₹2,500)
(
  'c0000000-0000-4000-8000-000000000007',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'branding',
  'featured_job_7d',
  'Featured Job (7 Days)',
  '7_days_featured',
  'Highlighted placement in the learner job feed for 7 days.',
  2500.00,
  2500.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '⭐',
  70,
  true,
  NOW(),
  NOW()
),
-- 8. Featured Employer (30 Days) (₹7,500)
(
  'c0000000-0000-4000-8000-000000000008',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'branding',
  'featured_employer_30d',
  'Featured Employer (30 Days)',
  '30_days_employer_branding',
  'Enhanced employer branding across candidate search and job listings for 30 days.',
  7500.00,
  7500.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '🏢',
  80,
  true,
  NOW(),
  NOW()
),
-- 9. Additional Recruiter Seat (₹2,500/year)
(
  'c0000000-0000-4000-8000-000000000009',
  '912d5049-e195-46e9-a319-49e3502bf7e7',
  'capacity',
  'additional_recruiter_seat',
  'Additional Recruiter Seat',
  '1_recruiter_seat',
  'Add an extra recruiter seat to your active organization subscription.',
  2500.00,
  2500.00,
  ARRAY['recruiter', 'recruiter_admin', 'company_admin'],
  '👤',
  90,
  true,
  NOW(),
  NOW()
)

ON CONFLICT (product_id, feature_key) DO UPDATE SET
  category = EXCLUDED.category,
  feature_name = EXCLUDED.feature_name,
  feature_value = EXCLUDED.feature_value,
  description = EXCLUDED.description,
  price_monthly = EXCLUDED.price_monthly,
  price_annual = EXCLUDED.price_annual,
  target_roles = EXCLUDED.target_roles,
  icon = EXCLUDED.icon,
  display_order = EXCLUDED.display_order,
  is_active = EXCLUDED.is_active,
  updated_at = NOW();

COMMIT;
