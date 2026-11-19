-- LOCAL DEMO ONLY. Keep the machine-readable job-matching grant in SSO.
-- Does not change plans, prices, expiry, or other users' subscriptions.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM public.subscriptions
   WHERE id='9df777e6-f9fd-54c4-bd74-a9d970913e2a'
     AND user_id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c'
     AND email='aaditya.raman10@example.com' AND plan_code='premium'
     AND status='active' AND subscription_end_date>now()) THEN
   RAISE EXCEPTION 'Apply Aaditya local SSO subscription seed first';
 END IF;
END $$;
UPDATE public.subscriptions
SET features=coalesce(features,'[]'::jsonb)||'["ai_job_matching"]'::jsonb, updated_at=now()
WHERE id='9df777e6-f9fd-54c4-bd74-a9d970913e2a'
  AND user_id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c'
  AND email='aaditya.raman10@example.com' AND plan_code='premium'
  AND status='active' AND subscription_end_date>now()
  AND NOT coalesce(features,'[]'::jsonb) @> '["ai_job_matching"]'::jsonb;
COMMIT;
