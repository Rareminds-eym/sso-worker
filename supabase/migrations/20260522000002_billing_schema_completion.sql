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

-- ─── 6. Seed bundles and bundle_features ──────────────────────────

DO $$
DECLARE
    sp_product_id uuid;
    v_career_starter_id uuid;
    v_educator_pro_id uuid;
    v_institution_complete_id uuid;
    v_recruiter_suite_id uuid;
BEGIN
    SELECT id INTO sp_product_id FROM public.products WHERE code = 'skillpassport';

    IF sp_product_id IS NULL THEN
        RAISE EXCEPTION 'SkillPassport product not found. Run 20260521000002 first.';
    END IF;

    -- Insert bundles
    INSERT INTO public.bundles (product_id, name, slug, description, target_roles, monthly_price, annual_price, discount_percentage, is_active, display_order)
    VALUES
        (sp_product_id, 'Career Starter', 'career-starter',
         'Career AI + AI Job Matching bundle for students',
         ARRAY['student'], 3558.40, 35584.00, 20, true, 1),

        (sp_product_id, 'Educator Pro', 'educator-pro',
         'Complete toolkit for educators to enhance teaching effectiveness',
         ARRAY['educator'], 518.00, 5180.00, 20, true, 2),

        (sp_product_id, 'Institution Complete', 'institution-complete',
         'Full suite of administrative tools for institutions',
         ARRAY['school_admin', 'college_admin', 'university_admin'], 958.00, 9580.00, 25, true, 3),

        (sp_product_id, 'Recruiter Suite', 'recruiter-suite',
         'Comprehensive recruitment and talent management tools',
         ARRAY['recruiter'], 1037.00, 10370.00, 20, true, 4)
    ON CONFLICT (product_id, slug) DO NOTHING;

    -- Get the inserted bundle IDs
    SELECT id INTO v_career_starter_id FROM public.bundles WHERE slug = 'career-starter' AND product_id = sp_product_id;
    SELECT id INTO v_educator_pro_id FROM public.bundles WHERE slug = 'educator-pro' AND product_id = sp_product_id;
    SELECT id INTO v_institution_complete_id FROM public.bundles WHERE slug = 'institution-complete' AND product_id = sp_product_id;
    SELECT id INTO v_recruiter_suite_id FROM public.bundles WHERE slug = 'recruiter-suite' AND product_id = sp_product_id;

    -- Insert bundle_features
    INSERT INTO public.bundle_features (bundle_id, feature_key) VALUES
        -- Career Starter (2 features)
        (v_career_starter_id, 'career_ai'),
        (v_career_starter_id, 'ai_job_matching'),
        -- Educator Pro (3 features)
        (v_educator_pro_id, 'advanced_analytics'),
        (v_educator_pro_id, 'course_analytics'),
        (v_educator_pro_id, 'educator_ai'),
        -- Institution Complete (4 features)
        (v_institution_complete_id, 'curriculum_builder'),
        (v_institution_complete_id, 'fee_management'),
        (v_institution_complete_id, 'kpi_dashboard'),
        (v_institution_complete_id, 'sso'),
        -- Recruiter Suite (4 features)
        (v_recruiter_suite_id, 'pipeline_management'),
        (v_recruiter_suite_id, 'project_hiring'),
        (v_recruiter_suite_id, 'recruiter_ai'),
        (v_recruiter_suite_id, 'talent_pool_access')
    ON CONFLICT (bundle_id, feature_key) DO NOTHING;

    RAISE NOTICE '✅ Seeded % bundles with % features',
        (SELECT COUNT(*) FROM public.bundles WHERE product_id = sp_product_id),
        (SELECT COUNT(*) FROM public.bundle_features bf
         JOIN public.bundles b ON bf.bundle_id = b.id
         WHERE b.product_id = sp_product_id);
END $$;

COMMIT;
