-- Migration: Update expire_old_subscriptions to handle grace_period
-- The existing function only expired 'active', 'cancelled', 'paused'.
-- It must also expire 'grace_period' subscriptions past their end date.

CREATE OR REPLACE FUNCTION public.expire_old_subscriptions()
RETURNS TABLE(count INTEGER)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  expired_count INTEGER;
BEGIN
  WITH expired_subs AS (
    UPDATE public.subscriptions
    SET
      status = 'expired',
      auto_renew = false,
      updated_at = NOW()
    WHERE
      status IN ('active', 'cancelled', 'paused', 'grace_period')
      AND subscription_end_date < NOW()
      AND subscription_end_date IS NOT NULL
    RETURNING id
  )
  SELECT COUNT(*)::INTEGER INTO expired_count FROM expired_subs;

  RETURN QUERY SELECT expired_count;
END;
$$;
