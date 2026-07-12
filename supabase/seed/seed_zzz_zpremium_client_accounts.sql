-- ============================================================
-- PREMIUM SUBSCRIPTIONS - CLIENT TEST ACCOUNTS (AUTH DATABASE)
-- Accounts: ramya03@acharya.ac.in, principal.hit@harshainstitute.edu.in
-- Plan: premium ("Career Accelerator", b2c, INR 999/yearly)
-- Subscription IDs are mirrored in the SkillPassport DB's
-- subscription_cache (seed_zzz_zpremium_client_accounts.sql there).
-- Runs after seed_zzz_ramya03_auth.sql / seed_zzz_principal_hit_auth.sql.
-- ============================================================

BEGIN;

INSERT INTO "public"."subscriptions"
  ("id", "user_id", "plan_id", "full_name", "email", "plan_code", "plan_type",
   "plan_amount", "billing_cycle", "features", "status", "auto_renew",
   "subscription_start_date", "subscription_end_date")
VALUES
  ('a1b40c1e-52a3-5e2f-9b71-3f0c6d1e8a01', '3c14e807-1f15-5dec-b361-88fdb7a28820',
   '8460ee67-18ff-4c2e-ac57-7e1f87dc8316', 'Ramya', 'ramya03@acharya.ac.in',
   'premium', 'Premium', 999, 'yearly',
   '["career_builder_features", "interview_readiness_tools", "resume_profile_review", "priority_opportunity_matching", "advanced_portfolio_proof", "career_progress_analytics"]',
   'active', false, '2026-07-11 00:00:00+00', '2027-07-11 00:00:00+00'),
  ('a1b40c1e-52a3-5e2f-9b71-3f0c6d1e8a02', 'eb7313eb-bd50-582b-8da5-412ddf8d1ecd',
   '8460ee67-18ff-4c2e-ac57-7e1f87dc8316', 'Principal HIT', 'principal.hit@harshainstitute.edu.in',
   'premium', 'Premium', 999, 'yearly',
   '["career_builder_features", "interview_readiness_tools", "resume_profile_review", "priority_opportunity_matching", "advanced_portfolio_proof", "career_progress_analytics"]',
   'active', false, '2026-07-11 00:00:00+00', '2027-07-11 00:00:00+00')
ON CONFLICT DO NOTHING;

COMMIT;
