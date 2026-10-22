-- Migration: Safely migrate legacy recruiter subscriptions to v2 plan codes (Auth DB)
-- Context:
--   1. Old 'recruiter_starter' was Free (INR 0) -> Remap to 'recruiter_free'
--   2. Old 'recruiter_pro' (INR 49,990) -> Retain / remap to new 'recruiter_pro' (INR 35,000)
--   3. Old 'recruiter_premium' (INR 99,990) -> Remap to new 'recruiter_pro'
--
-- Idempotent: Can be run multiple times safely.

BEGIN;

-- 1. Remap legacy free recruiter_starter to recruiter_free
UPDATE public.subscriptions
SET
    plan_id = 'b0000000-0000-4000-8000-000000000010',
    plan_code = 'recruiter_free',
    plan_type = 'Recruiter Free',
    plan_amount = 0.00,
    updated_at = NOW()
WHERE plan_code = 'recruiter_starter'
  AND (plan_amount = 0 OR plan_amount IS NULL OR plan_id = 'b0000000-0000-4000-8000-000000000001');

-- 2. Remap legacy recruiter_premium to recruiter_pro
UPDATE public.subscriptions
SET
    plan_id = 'b0000000-0000-4000-8000-000000000050',
    plan_code = 'recruiter_pro',
    plan_type = 'Recruiter Pro',
    updated_at = NOW()
WHERE plan_code = 'recruiter_premium';

-- 3. Update legacy recruiter_pro plan_id pointer
UPDATE public.subscriptions
SET
    plan_id = 'b0000000-0000-4000-8000-000000000050',
    updated_at = NOW()
WHERE plan_code = 'recruiter_pro'
  AND plan_id = 'b0000000-0000-4000-8000-000000000002';

COMMIT;
