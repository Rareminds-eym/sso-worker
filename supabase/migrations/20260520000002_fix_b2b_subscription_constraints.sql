-- 20260520000002_fix_b2b_subscription_constraints.sql
-- Fixes unique active subscription constraints to allow multiple active B2B subscriptions
-- (An admin can hold a personal plan AND purchase/manage organization subscriptions)

BEGIN;

-- 1. Drop existing overly-restrictive indices
DROP INDEX IF EXISTS public.idx_subscriptions_active_user;
DROP INDEX IF EXISTS public.idx_unique_active_subscription;

-- 2. Re-create indices excluding organization & bulk subscriptions
CREATE UNIQUE INDEX idx_subscriptions_active_user ON public.subscriptions USING btree (user_id) 
WHERE (status = ANY (ARRAY['active'::text, 'pending'::text])) 
  AND (is_organization_subscription IS NOT TRUE)
  AND (is_bulk_purchase IS NOT TRUE);

CREATE UNIQUE INDEX idx_unique_active_subscription ON public.subscriptions USING btree (user_id) 
WHERE (status = ANY (ARRAY['active'::text, 'pending'::text])) 
  AND (is_organization_subscription IS NOT TRUE)
  AND (is_bulk_purchase IS NOT TRUE);

-- 3. Update the postgres trigger function to also exclude B2B subscriptions
CREATE OR REPLACE FUNCTION public.check_duplicate_active_subscription()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'public'
AS $function$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.status = 'active' THEN
    -- Only enforce single-active-subscription rule for personal subscriptions
    IF NEW.is_organization_subscription IS NOT TRUE AND NEW.is_bulk_purchase IS NOT TRUE THEN
        IF EXISTS (
          SELECT 1 FROM public.subscriptions
          WHERE user_id = NEW.user_id
            AND status = 'active'
            AND is_organization_subscription IS NOT TRUE
            AND is_bulk_purchase IS NOT TRUE
            AND id != COALESCE(NEW.id, '00000000-0000-0000-0000-000000000000'::uuid)
        ) THEN
          RAISE EXCEPTION 'User already has an active personal subscription. Cancel the existing one first.'
            USING HINT = 'Cancel existing subscription first', ERRCODE = '23505';
        END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;

COMMIT;
