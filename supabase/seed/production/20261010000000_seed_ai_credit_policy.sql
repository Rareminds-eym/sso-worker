-- Career AI 30-credit system: seed the active conversion policy.
-- Runs AFTER the table-data seeds (filename sorts last), when the
-- products row exists. Migrations are schema-only; this file is the
-- single place the initial policy row comes from. Idempotent: never
-- duplicates an active policy.
INSERT INTO public.ai_credit_policies (product_id, scope, markup_percent, usd_per_credit, active)
SELECT p.id, 'career_ai', 20, 0.001, true
FROM public.products p
WHERE p.code = 'skillpassport'
  AND NOT EXISTS (
    SELECT 1 FROM public.ai_credit_policies q
    WHERE q.product_id = p.id AND q.scope = 'career_ai' AND q.active = true
  );
