-- Migration: Create transactions table in auth DB
-- Consolidates payment_transactions + razorpay_orders + addon_pending_orders from app DB

CREATE TABLE IF NOT EXISTS public.transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- References
  subscription_id uuid REFERENCES public.subscriptions(id),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  organization_id uuid,

  -- Razorpay
  razorpay_order_id text,
  razorpay_payment_id text,
  razorpay_signature text,

  -- Amount
  amount numeric(10,2) NOT NULL,
  currency text NOT NULL DEFAULT 'INR',

  -- Status & type
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'completed', 'failed', 'refunded')),
  transaction_type text DEFAULT 'subscription'
    CHECK (transaction_type IN ('subscription', 'upgrade', 'addon', 'bundle', 'org', 'event')),
  payment_method text,

  -- Org/bulk fields
  organization_type text,
  seat_count integer DEFAULT 1,
  is_bulk_purchase boolean DEFAULT false,

  -- Failure/refund
  failure_reason text,
  refund_id text,

  -- Receipt
  receipt text,
  receipt_url text,

  -- Metadata
  notes jsonb DEFAULT '{}',
  metadata jsonb DEFAULT '{}',

  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE INDEX idx_transactions_user ON public.transactions(user_id);
CREATE INDEX idx_transactions_subscription ON public.transactions(subscription_id);
CREATE INDEX idx_transactions_razorpay_order ON public.transactions(razorpay_order_id) WHERE razorpay_order_id IS NOT NULL;
CREATE INDEX idx_transactions_razorpay_payment ON public.transactions(razorpay_payment_id) WHERE razorpay_payment_id IS NOT NULL;
CREATE INDEX idx_transactions_status ON public.transactions(status);
CREATE INDEX idx_transactions_type ON public.transactions(transaction_type);

ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "transactions_service_only" ON public.transactions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "transactions_deny_anon" ON public.transactions
  TO anon USING (false) WITH CHECK (false);

CREATE TRIGGER trg_transactions_updated_at
  BEFORE UPDATE ON public.transactions
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
