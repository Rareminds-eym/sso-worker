-- Migration: Billing schema completion
-- Phase: 1 of 3 (Expand) — Additive only, no breaking changes
-- Breaking: No
-- Rollback: Safe — DROP the new tables and column
--
-- Context: Completes the Auth DB billing schema by:
--   1. Adding product_id to transactions for product classification
--   2. Creating bundles + bundle_features (migrated from App DB)
--   3. Creating addon_purchases + bundle_purchases (missing tables that handlers need)
--
-- Deployment order:
--   1. Run this migration
--   2. Deploy SSO worker API endpoints (Phase 3)
--   3. Deploy app handler refactoring (Phase 4)

BEGIN;

-- ─── 1. Add product_id to transactions ────────────────────────────

ALTER TABLE public.transactions
  ADD COLUMN IF NOT EXISTS product_id uuid REFERENCES public.products(id);

-- Backfill existing transactions from their subscription's product_id
UPDATE public.transactions t
SET product_id = s.product_id
FROM public.subscriptions s
WHERE t.subscription_id = s.id
  AND t.product_id IS NULL
  AND s.product_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_transactions_product_id
  ON public.transactions(product_id);

-- ─── 2. Create bundles table ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.bundles (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    product_id uuid NOT NULL REFERENCES public.products(id),
    name varchar(255) NOT NULL,
    slug varchar(255) NOT NULL,
    description text,
    target_roles text[] DEFAULT '{}',
    monthly_price numeric(10,2),
    annual_price numeric(10,2),
    discount_percentage integer DEFAULT 0,
    is_active boolean DEFAULT true,
    display_order integer DEFAULT 0,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    CONSTRAINT bundles_unique_slug UNIQUE (product_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_bundles_product_id ON public.bundles(product_id);
CREATE INDEX IF NOT EXISTS idx_bundles_slug ON public.bundles(slug);

-- RLS
ALTER TABLE public.bundles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "bundles_public_read" ON public.bundles
    FOR SELECT USING (is_active = true);

CREATE POLICY "bundles_service_write" ON public.bundles
    FOR ALL USING (true);

-- ─── 3. Create bundle_features table ──────────────────────────────

CREATE TABLE IF NOT EXISTS public.bundle_features (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    bundle_id uuid NOT NULL REFERENCES public.bundles(id) ON DELETE CASCADE,
    feature_key text NOT NULL,
    created_at timestamptz DEFAULT now(),
    CONSTRAINT bundle_features_unique UNIQUE (bundle_id, feature_key)
);

CREATE INDEX IF NOT EXISTS idx_bundle_features_bundle_id
  ON public.bundle_features(bundle_id);
CREATE INDEX IF NOT EXISTS idx_bundle_features_feature_key
  ON public.bundle_features(feature_key);

-- RLS
ALTER TABLE public.bundle_features ENABLE ROW LEVEL SECURITY;

CREATE POLICY "bundle_features_public_read" ON public.bundle_features
    FOR SELECT USING (true);

CREATE POLICY "bundle_features_service_write" ON public.bundle_features
    FOR ALL USING (true);

-- ─── 4. Create addon_purchases table ──────────────────────────────

CREATE TABLE IF NOT EXISTS public.addon_purchases (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES public.users(id),
    product_id uuid REFERENCES public.products(id),
    feature_key text NOT NULL,
    billing_period varchar(20) NOT NULL,
    price_at_purchase numeric(10,2) NOT NULL,
    razorpay_order_id text,
    razorpay_payment_id text,
    razorpay_signature text,
    status varchar(20) NOT NULL DEFAULT 'active',
    start_date timestamptz NOT NULL DEFAULT now(),
    end_date timestamptz,
    auto_renew boolean DEFAULT true,
    cancelled_at timestamptz,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_addon_purchases_user_id
  ON public.addon_purchases(user_id);
CREATE INDEX IF NOT EXISTS idx_addon_purchases_feature_key
  ON public.addon_purchases(feature_key);
CREATE INDEX IF NOT EXISTS idx_addon_purchases_status
  ON public.addon_purchases(status);
CREATE INDEX IF NOT EXISTS idx_addon_purchases_razorpay_order
  ON public.addon_purchases(razorpay_order_id);

-- RLS
ALTER TABLE public.addon_purchases ENABLE ROW LEVEL SECURITY;

CREATE POLICY "addon_purchases_deny_anon" ON public.addon_purchases
    FOR ALL TO anon USING (false);

CREATE POLICY "addon_purchases_service_only" ON public.addon_purchases
    FOR ALL TO service_role USING (true);

-- ─── 5. Create bundle_purchases table ─────────────────────────────

CREATE TABLE IF NOT EXISTS public.bundle_purchases (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES public.users(id),
    product_id uuid REFERENCES public.products(id),
    bundle_id uuid NOT NULL REFERENCES public.bundles(id),
    billing_period varchar(20) NOT NULL,
    price_at_purchase numeric(10,2) NOT NULL,
    discount_applied integer DEFAULT 0,
    razorpay_order_id text,
    razorpay_payment_id text,
    razorpay_signature text,
    status varchar(20) NOT NULL DEFAULT 'active',
    start_date timestamptz NOT NULL DEFAULT now(),
    end_date timestamptz,
    auto_renew boolean DEFAULT true,
    cancelled_at timestamptz,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bundle_purchases_user_id
  ON public.bundle_purchases(user_id);
CREATE INDEX IF NOT EXISTS idx_bundle_purchases_bundle_id
  ON public.bundle_purchases(bundle_id);
CREATE INDEX IF NOT EXISTS idx_bundle_purchases_status
  ON public.bundle_purchases(status);
CREATE INDEX IF NOT EXISTS idx_bundle_purchases_razorpay_order
  ON public.bundle_purchases(razorpay_order_id);

-- RLS
ALTER TABLE public.bundle_purchases ENABLE ROW LEVEL SECURITY;

CREATE POLICY "bundle_purchases_deny_anon" ON public.bundle_purchases
    FOR ALL TO anon USING (false);

CREATE POLICY "bundle_purchases_service_only" ON public.bundle_purchases
    FOR ALL TO service_role USING (true);

COMMIT;