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

-- Seed SkillPassport addons
DO $$
DECLARE
    sp_product_id uuid;
BEGIN
    SELECT id INTO sp_product_id FROM public.products WHERE code = 'skillpassport';
    
    IF sp_product_id IS NULL THEN
        RAISE EXCEPTION 'SkillPassport product not found. Run 20260521000002 first.';
    END IF;

    INSERT INTO public.addon_catalog (
        product_id, category, feature_key, feature_name, feature_value,
        description, price_monthly, price_annual, target_roles, icon, display_order
    ) VALUES
    -- Learning Addons
    (sp_product_id, 'learning', 'advanced_analytics', 'Advanced Analytics', 'Detailed insights and reports',
     'Get detailed analytics on your learning progress, skill gaps, and career trajectory with AI-powered insights',
     299.00, 2999.00, ARRAY['learner', 'educator'], '📊', 1),
    
    (sp_product_id, 'learning', 'mentorship_sessions', 'Mentorship Sessions', '2 sessions per month',
     'One-on-one mentorship sessions with industry experts (2 sessions per month)',
     999.00, 9999.00, ARRAY['learner'], '👨‍🏫', 2),
    
    (sp_product_id, 'learning', 'interview_prep_advanced', 'Advanced Interview Prep', 'Mock interviews + feedback',
     'Advanced interview preparation with mock interviews, feedback, and industry-specific questions',
     499.00, 4999.00, ARRAY['learner'], '💼', 3),
    
    (sp_product_id, 'learning', 'resume_review', 'Professional Resume Review', 'Expert review + rewrite',
     'Get your resume professionally reviewed and rewritten by career experts',
     399.00, 3999.00, ARRAY['learner'], '📄', 4),
    
    (sp_product_id, 'learning', 'linkedin_optimization', 'LinkedIn Profile Optimization', 'Complete profile makeover',
     'Optimize your LinkedIn profile for maximum visibility and recruiter engagement',
     299.00, 2999.00, ARRAY['learner'], '💼', 5),
    
    -- Support Addons
    (sp_product_id, 'support', 'priority_support', 'Priority Support', '24/7 priority support',
     'Get priority support with 24/7 availability and faster response times',
     199.00, 1999.00, ARRAY['learner', 'educator', 'admin'], '🚀', 6),
    
    (sp_product_id, 'support', 'dedicated_account_manager', 'Dedicated Account Manager', 'Personal account manager',
     'Get a dedicated account manager for personalized support and guidance',
     1999.00, 19999.00, ARRAY['admin', 'school_admin', 'college_admin'], '👤', 7),
    
    -- Capacity Addons
    (sp_product_id, 'capacity', 'extra_storage_10gb', 'Extra Storage (10GB)', '10GB additional storage',
     'Add 10GB of additional storage for your projects, certificates, and documents',
     99.00, 999.00, ARRAY['learner', 'educator'], '💾', 8),
    
    (sp_product_id, 'capacity', 'extra_storage_50gb', 'Extra Storage (50GB)', '50GB additional storage',
     'Add 50GB of additional storage for your projects, certificates, and documents',
     299.00, 2999.00, ARRAY['learner', 'educator'], '💾', 9),
    
    (sp_product_id, 'capacity', 'unlimited_assessments', 'Unlimited Assessments', 'No limits on assessments',
     'Take unlimited assessments without any monthly restrictions',
     199.00, 1999.00, ARRAY['learner'], '📝', 10),
    
    -- Certificates Addons
    (sp_product_id, 'certificates', 'verified_certificates', 'Verified Certificates', 'Blockchain-verified certificates',
     'Get blockchain-verified certificates that can be independently verified by employers',
     499.00, 4999.00, ARRAY['learner'], '🎓', 11),
    
    -- Integrations Addons
    (sp_product_id, 'integrations', 'api_access', 'API Access', 'Full API access',
     'Get full API access to integrate SkillPassport with your existing systems',
     999.00, 9999.00, ARRAY['admin', 'school_admin', 'college_admin'], '🔌', 12),
    
    -- Branding Addons
    (sp_product_id, 'branding', 'white_label', 'White Label Branding', 'Custom branding',
     'Remove SkillPassport branding and add your own logo, colors, and domain',
     2999.00, 29999.00, ARRAY['admin', 'school_admin', 'college_admin'], '🎨', 13)
    
    ON CONFLICT (product_id, feature_key) DO NOTHING;

    RAISE NOTICE '✅ Seeded % SkillPassport addons', 
        (SELECT COUNT(*) FROM public.addon_catalog WHERE product_id = sp_product_id);
END $$;
