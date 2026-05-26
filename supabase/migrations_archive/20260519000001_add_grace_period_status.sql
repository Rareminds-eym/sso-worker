-- Migration: Add 'grace_period' to subscription status enum
-- The status was referenced in feature gating & shadow sync but missing
-- from the auth DB CHECK constraint and unique index.

-- 1. Drop and recreate the CHECK constraint with grace_period
ALTER TABLE public.subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_status_check;

ALTER TABLE public.subscriptions
  ADD CONSTRAINT subscriptions_status_check
  CHECK (status IN ('pending', 'active', 'paused', 'cancelled', 'expired', 'grace_period'));

-- 2. Update the unique active subscription index to include grace_period
-- Prevents multiple active/pending/grace_period subs per user
DROP INDEX IF EXISTS idx_unique_active_subscription;

CREATE UNIQUE INDEX idx_unique_active_subscription
  ON public.subscriptions(user_id)
  WHERE status IN ('active', 'pending', 'grace_period');

-- 3. Add grace_period to the status transition trigger validation
-- (The existing trigger function checks old/new status pairs.
--  We need to allow transitions TO and FROM grace_period.)
CREATE OR REPLACE FUNCTION public.validate_subscription_status_transition()
RETURNS TRIGGER AS $$
DECLARE
  valid_transitions jsonb := '{
    "pending":      ["active", "cancelled"],
    "active":       ["paused", "cancelled", "expired", "grace_period"],
    "paused":       ["active", "cancelled", "expired"],
    "grace_period": ["active", "expired", "cancelled"],
    "cancelled":    ["active"],
    "expired":      ["active"]
  }'::jsonb;
  allowed jsonb;
BEGIN
  -- Skip validation on INSERT
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;
  END IF;

  -- Skip if status hasn't changed
  IF OLD.status = NEW.status THEN
    RETURN NEW;
  END IF;

  allowed := valid_transitions -> OLD.status;
  IF allowed IS NULL OR NOT allowed ? NEW.status THEN
    RAISE EXCEPTION 'Invalid status transition from % to %', OLD.status, NEW.status;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
