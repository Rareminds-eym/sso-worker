-- Canonical catalog of admin-dashboard feature keys that can be individually
-- granted/withheld per organization, per product, per role. This is the
-- single source of truth for "what can an admin grant a Hybrid org access
-- to" — sso-worker validates grants against this table (see
-- src/routes/hybrid-subscription.ts's sanitizeHybridFeatures), and
-- skillpassport syncs a read-only cache of it (feature_keys_cache, mirroring
-- the existing plans_cache pattern) for rendering nav gating.
--
-- Scoped by product_id so it can hold features for ANY product (skillpassport,
-- lte, etc.), not just skillpassport's college/school/university admin nav —
-- per product decision, table must be able to hold features across all
-- products even though only skillpassport rows are seeded today.
--
-- Date: 2026-09-25
CREATE TABLE IF NOT EXISTS public.feature_keys (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  product_id uuid NOT NULL REFERENCES public.products(id) ON DELETE CASCADE,
  key text NOT NULL,
  role text NOT NULL,
  nav_group text,
  nav_label text NOT NULL,
  nav_path text NOT NULL,
  display_order integer DEFAULT 0,
  is_active boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  CONSTRAINT feature_keys_product_role_key_unique UNIQUE (product_id, role, key)
);

COMMENT ON TABLE public.feature_keys IS
  'Canonical catalog of grantable admin-dashboard feature keys, scoped per product and role. Source of truth for Hybrid-plan feature grants — see sanitizeHybridFeatures in hybrid-subscription.ts.';
COMMENT ON COLUMN public.feature_keys.key IS
  'Stable machine key, e.g. learner_enrollment. Unique per (product_id, role).';
COMMENT ON COLUMN public.feature_keys.role IS
  'The dashboard role this nav item belongs to, e.g. college_admin, school_admin, university_admin.';
COMMENT ON COLUMN public.feature_keys.is_active IS
  'Soft-disable a key without deleting history. Inactive keys are never offered for granting and never enforced.';

CREATE INDEX IF NOT EXISTS idx_feature_keys_product_role
  ON public.feature_keys (product_id, role)
  WHERE is_active = true;
