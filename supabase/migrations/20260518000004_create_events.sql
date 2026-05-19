-- Migration: Create events table in auth DB (webhook event store)
-- Enables idempotent webhook processing, replay, and audit trail

CREATE TABLE IF NOT EXISTS public.events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Idempotency
  event_id text UNIQUE NOT NULL,
  event_type text NOT NULL,

  -- Processing
  status text NOT NULL DEFAULT 'received'
    CHECK (status IN ('received', 'processing', 'completed', 'failed', 'skipped')),
  processed_at timestamptz,
  error_message text,
  retry_count integer DEFAULT 0,

  -- Payload
  payload jsonb NOT NULL,

  -- References (extracted from payload for querying)
  user_id uuid,
  subscription_id uuid,
  razorpay_payment_id text,

  created_at timestamptz DEFAULT now()
);

CREATE INDEX idx_events_event_id ON public.events(event_id);
CREATE INDEX idx_events_type_status ON public.events(event_type, status);
CREATE INDEX idx_events_user ON public.events(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_events_created ON public.events(created_at);

ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "events_service_only" ON public.events
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "events_deny_anon" ON public.events
  TO anon USING (false) WITH CHECK (false);
