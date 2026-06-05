-- Migration: Create addon catalog in auth DB
-- Description: Addon definitions with pricing, descriptions, and metadata.
--              Plan feature keys are already in plans.base_features;
--              this table covers the addon marketplace catalog.
-- Date: 2026-05-22

-- Create addon_catalog table
CREATE TABLE IF NOT EXISTS public.addon_catalog (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    product_id uuid NOT NULL REFERENCES public.products(id),
    category text NOT NULL,
    feature_key text NOT NULL,
    feature_name text NOT NULL,
    feature_value text,
    description text,
    price_monthly numeric(10,2),
    price_annual numeric(10,2),
    target_roles text[] DEFAULT '{}',
    icon text,
    display_order integer DEFAULT 0,
    is_active boolean DEFAULT true,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    CONSTRAINT addon_catalog_category_check 
        CHECK (category = ANY (ARRAY['capacity', 'branding', 'content', 'learning', 'assessments', 'certificates', 'analytics', 'integrations', 'security', 'support'])),
    CONSTRAINT addon_catalog_unique_feature UNIQUE (product_id, feature_key)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_addon_catalog_product_id ON public.addon_catalog(product_id);
CREATE INDEX IF NOT EXISTS idx_addon_catalog_feature_key ON public.addon_catalog(feature_key);
CREATE INDEX IF NOT EXISTS idx_addon_catalog_category ON public.addon_catalog(category);

-- RLS
ALTER TABLE public.addon_catalog ENABLE ROW LEVEL SECURITY;

CREATE POLICY "addon_catalog_public_read" ON public.addon_catalog
    FOR SELECT USING (is_active = true);
