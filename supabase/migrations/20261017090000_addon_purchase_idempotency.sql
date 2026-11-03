-- Migration: Add-on purchase payment idempotency (Auth DB)
-- Context:
--   A Razorpay payment capture for an add-on must be recorded at most once so
--   duplicate webhook/verify retries can never double-grant a purchase.
-- Idempotent: Can be run multiple times safely.

BEGIN;

-- 1. One add-on purchase per Razorpay payment (partial unique index).
--    Same index name and predicate as 20260616110000_add_multi_flow_idempotency.sql,
--    so on databases where that migration already applied, this is a no-op.
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_addon_payment
  ON public.addon_purchases ("razorpay_payment_id")
  WHERE "razorpay_payment_id" IS NOT NULL;

-- 2. Duplicate credit/entitlement grants per payment:
--    NOT ADDED here — no index is genuinely missing in this database.
--    Verified: there is no `user_entitlements` table in the SSO/Auth schema
--    (per-user credit grants live in the application database's credit_ledger,
--    which is already protected by uq_credit_ledger_alloc_ref on
--    (tenant_id, feature_key, reference_id)). There is also no
--    razorpay_subscription_id UNIQUE constraint to reuse on
--    public.addon_purchases; the table only carries razorpay_payment_id.

COMMIT;
