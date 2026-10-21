-- Career AI 30-credit system: wallet schema (Phase 2).
-- Additive only. RLS enabled with no policies (deny all browser roles;
-- service_role bypasses RLS). All money as numeric(24,12), returned to
-- callers as decimal strings by the SQL functions (never JSON numbers).
--
-- Schema only: no data manipulation. The initial conversion policy row is
-- seeded via supabase/seed/{dev,production}/20261010000000_seed_ai_credit_policy.sql.

-- ── Parent account: one row per (user, product, scope) ───────────────────
CREATE TABLE IF NOT EXISTS public.user_ai_credit_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  product_id uuid NOT NULL REFERENCES public.products(id) ON DELETE RESTRICT,
  scope text NOT NULL DEFAULT 'career_ai',
  granted_credits numeric(24,12) NOT NULL DEFAULT 30 CHECK (granted_credits >= 0),
  spent_credits numeric(24,12) NOT NULL DEFAULT 0 CHECK (spent_credits >= 0),
  -- Durable one-operation guard (concurrency control, NOT a credit hold).
  active_operation_id text NULL,
  active_execution_id text NULL,
  -- Server-controlled snapshot version for cache sync (newer revision wins).
  revision bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT user_ai_credit_accounts_user_product_scope_key
    UNIQUE (user_id, product_id, scope)
);

-- ── Conversion policy: immutable rows, one active per (product, scope) ────
CREATE TABLE IF NOT EXISTS public.ai_credit_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id uuid NOT NULL REFERENCES public.products(id) ON DELETE RESTRICT,
  scope text NOT NULL DEFAULT 'career_ai',
  markup_percent numeric(24,12) NOT NULL CHECK (markup_percent >= 0),
  usd_per_credit numeric(24,12) NOT NULL CHECK (usd_per_credit > 0),
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ai_credit_policies_one_active_idx
  ON public.ai_credit_policies (product_id, scope)
  WHERE active = true;

-- ── Durable root operation: owns session/execution/policy context ─────────
CREATE TABLE IF NOT EXISTS public.ai_credit_operations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES public.user_ai_credit_accounts(id) ON DELETE RESTRICT,
  operation_id text NOT NULL,
  execution_id text NOT NULL,
  session_id uuid NOT NULL,
  action text NOT NULL,
  payload_hash text NOT NULL,
  policy_id uuid NOT NULL REFERENCES public.ai_credit_policies(id) ON DELETE RESTRICT,
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active', 'pending_cost', 'completed', 'failed_no_dispatch', 'resolved_unbillable')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz NULL,
  CONSTRAINT ai_credit_operations_account_operation_key UNIQUE (account_id, operation_id),
  CONSTRAINT ai_credit_operations_account_execution_key UNIQUE (account_id, execution_id)
);

CREATE INDEX IF NOT EXISTS ai_credit_operations_account_created_idx
  ON public.ai_credit_operations (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ai_credit_operations_account_session_idx
  ON public.ai_credit_operations (account_id, session_id, created_at);

-- ── Child invocation: one prepared row per actual AI.run ──────────────────
CREATE TABLE IF NOT EXISTS public.user_ai_usage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  operation_record_id uuid NOT NULL REFERENCES public.ai_credit_operations(id) ON DELETE RESTRICT,
  model text NOT NULL,
  input_tokens bigint NULL CHECK (input_tokens IS NULL OR input_tokens >= 0),
  output_tokens bigint NULL CHECK (output_tokens IS NULL OR output_tokens >= 0),
  invocation_status text NOT NULL DEFAULT 'prepared'
    CHECK (invocation_status IN ('prepared', 'not_dispatched', 'succeeded', 'failed', 'timed_out', 'cancelled', 'unknown')),
  started_at timestamptz NULL,
  duration_ms bigint NULL CHECK (duration_ms IS NULL OR duration_ms >= 0),
  -- Verified Cloudflare Gateway log. UNIQUE when present: same log never charged twice.
  log_id text NULL UNIQUE,
  ai_cost_usd numeric(24,12) NULL CHECK (ai_cost_usd IS NULL OR ai_cost_usd >= 0),
  cost_state text NOT NULL DEFAULT 'pending'
    CHECK (cost_state IN ('pending', 'resolved', 'unresolved', 'not_applicable', 'waived')),
  credits_used numeric(24,12) NULL CHECK (credits_used IS NULL OR credits_used >= 0),
  revision bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  settled_at timestamptz NULL,
  -- Audit trail for explicit operator resolution (waiver). NULL otherwise.
  resolved_by text NULL,
  resolution_reason text NULL
);

CREATE INDEX IF NOT EXISTS user_ai_usage_operation_created_idx
  ON public.user_ai_usage (operation_record_id, created_at);

-- ── Audit ledger: immutable, append-only. Corrections append entries. ──────
CREATE TABLE IF NOT EXISTS public.ai_credit_ledger (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES public.user_ai_credit_accounts(id) ON DELETE RESTRICT,
  usage_id uuid NULL REFERENCES public.user_ai_usage(id) ON DELETE RESTRICT,
  kind text NOT NULL CHECK (kind IN ('grant', 'debit', 'correction')),
  credit_delta numeric(24,12) NOT NULL,
  idempotency_key text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ai_credit_ledger_account_created_idx
  ON public.ai_credit_ledger (account_id, created_at);

-- ── Balance-sync outbox: durable delivery intent for SkillPassport ────────
-- Drained by scheduled() via HTTPS POST (INTERNAL_WEBHOOK_SECRET bearer),
-- mirroring the payment events drain. Never via SYNC_QUEUE (the consumer
-- router is exhaustive and must not change in this phase).
CREATE TABLE IF NOT EXISTS public.ai_credit_sync_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES public.user_ai_credit_accounts(id) ON DELETE RESTRICT,
  revision bigint NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
  attempts integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS ai_credit_sync_outbox_pending_idx
  ON public.ai_credit_sync_outbox (status, created_at) WHERE status IN ('pending', 'failed');

-- ── RLS: deny every browser role; service_role bypasses ───────────────────
ALTER TABLE public.user_ai_credit_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_credit_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_credit_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_ai_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_credit_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_credit_sync_outbox ENABLE ROW LEVEL SECURITY;
