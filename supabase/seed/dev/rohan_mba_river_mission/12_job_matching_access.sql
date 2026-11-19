-- LOCAL ROHAN DEMO ONLY. Preserve plans, pricing, expiry and other users.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM public.subscriptions WHERE id='af3e7e1f-92a5-535a-aecd-3f5b628beb84' AND user_id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND email='rohan.iyer.mba@example.com' AND plan_code='premium' AND status='active' AND subscription_end_date>now()) THEN
  RAISE EXCEPTION 'Rohan active local Premium subscription is required';
 END IF;
END $$;
UPDATE public.subscriptions SET features=coalesce(features,'[]'::jsonb)||jsonb_build_array('ai_job_matching'),updated_at=now()
WHERE id='af3e7e1f-92a5-535a-aecd-3f5b628beb84' AND user_id='02f0a43d-3c0a-5026-b44f-5d0696e75f19' AND email='rohan.iyer.mba@example.com' AND plan_code='premium' AND status='active' AND subscription_end_date>now()
AND NOT coalesce(features,'[]'::jsonb) ? 'ai_job_matching';
COMMIT;
