-- Migration: Create subscriptions table in auth DB
-- Consolidates subscriptions + organization_subscriptions + subscription_cancellations from app DB

CREATE TABLE IF NOT EXISTS public.subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Identity
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  plan_id uuid NOT NULL REFERENCES public.plans(id),
  organization_id uuid,

  -- Subscriber info
  full_name text NOT NULL DEFAULT '',
  email text NOT NULL DEFAULT '',
  phone text,

  -- Plan snapshot (denormalized at subscription time)
  plan_code text NOT NULL,
  plan_type text NOT NULL,
  plan_amount numeric(10,2) NOT NULL DEFAULT 0,
  billing_cycle text NOT NULL DEFAULT 'lifetime',
  features jsonb NOT NULL DEFAULT '[]',

  -- Status
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'paused', 'cancelled', 'expired')),

  -- Razorpay
  razorpay_subscription_id text,
  razorpay_customer_id text,
  razorpay_payment_id text,
  razorpay_order_id text,

  -- Settings
  auto_renew boolean DEFAULT true,
  receipt_url text,

  -- Dates
  subscription_start_date timestamptz,
  subscription_end_date timestamptz,
  cancelled_at timestamptz,
  paused_at timestamptz,
  paused_until timestamptz,
  last_webhook_at timestamptz,

  -- Cancellation details (merged from subscription_cancellations)
  cancellation_reason text,
  cancellation_feedback text,
  cancelled_by text,

  -- Organization fields (merged from organization_subscriptions)
  is_organization_subscription boolean DEFAULT false,
  organization_type text,
  purchased_by uuid,
  seat_count integer DEFAULT 1,
  is_bulk_purchase boolean DEFAULT false,

  -- Metadata
  metadata jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- One active subscription per user (race condition prevention)
CREATE UNIQUE INDEX idx_subscriptions_active_user
  ON public.subscriptions(user_id)
  WHERE status IN ('active', 'pending');

CREATE INDEX idx_subscriptions_user ON public.subscriptions(user_id);
CREATE INDEX idx_subscriptions_plan ON public.subscriptions(plan_id);
CREATE INDEX idx_subscriptions_status ON public.subscriptions(status);
CREATE INDEX idx_subscriptions_org ON public.subscriptions(organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX idx_subscriptions_razorpay_order ON public.subscriptions(razorpay_order_id) WHERE razorpay_order_id IS NOT NULL;

ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;

-- Service-role only access (all writes come from workers)
CREATE POLICY "subscriptions_service_only" ON public.subscriptions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "subscriptions_deny_anon" ON public.subscriptions
  TO anon USING (false) WITH CHECK (false);

CREATE TRIGGER trg_subscriptions_updated_at
  BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Status transition validation
CREATE OR REPLACE FUNCTION public.validate_subscription_status_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO 'public'
AS $$
DECLARE
  old_status text;
  new_status text;
BEGIN
  old_status := OLD.status;
  new_status := NEW.status;

  IF old_status = new_status THEN
    RETURN NEW;
  END IF;

  IF old_status = 'expired' AND new_status IN ('active', 'pending') THEN
    RAISE EXCEPTION 'Cannot reactivate expired subscription. Create a new subscription instead.'
      USING HINT = 'Create new subscription', ERRCODE = '23514';
  END IF;

  IF old_status = 'cancelled' AND new_status NOT IN ('expired', 'cancelled') THEN
    RAISE EXCEPTION 'Cancelled subscription can only transition to expired status'
      USING HINT = 'Create new subscription to reactivate', ERRCODE = '23514';
  END IF;

  IF old_status = 'pending' AND new_status NOT IN ('active', 'expired', 'pending') THEN
    RAISE EXCEPTION 'Pending subscription can only become active or expired'
      USING HINT = 'Invalid status transition', ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_status_transition
  BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.validate_subscription_status_transition();

-- Auto-set cancelled_at timestamp
CREATE OR REPLACE FUNCTION public.auto_set_cancelled_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO 'public'
AS $$
BEGIN
  IF NEW.status = 'cancelled' AND OLD.status != 'cancelled' AND NEW.cancelled_at IS NULL THEN
    NEW.cancelled_at := NOW();
  END IF;
  IF NEW.status != 'cancelled' AND OLD.status = 'cancelled' THEN
    NEW.cancelled_at := NULL;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_auto_set_cancelled_at
  BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.auto_set_cancelled_at();

-- Duplicate active subscription check (INSERT only)
CREATE OR REPLACE FUNCTION public.check_duplicate_active_subscription()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO 'public'
AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.status = 'active' THEN
    IF EXISTS (
      SELECT 1 FROM public.subscriptions
      WHERE user_id = NEW.user_id
        AND status = 'active'
        AND id != COALESCE(NEW.id, '00000000-0000-0000-0000-000000000000'::uuid)
    ) THEN
      RAISE EXCEPTION 'User already has an active subscription. Cancel the existing one first.'
        USING HINT = 'Cancel existing subscription first', ERRCODE = '23505';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_check_duplicate_active
  BEFORE INSERT ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.check_duplicate_active_subscription();

-- Batch job: expire old subscriptions
CREATE OR REPLACE FUNCTION public.expire_old_subscriptions()
RETURNS TABLE(count integer)
LANGUAGE plpgsql
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
      status IN ('active', 'cancelled', 'paused')
      AND subscription_end_date < NOW()
      AND subscription_end_date IS NOT NULL
    RETURNING id
  )
  SELECT COUNT(*)::INTEGER INTO expired_count FROM expired_subs;

  RETURN QUERY SELECT expired_count;
END;
$$;
