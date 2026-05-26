-- Migration: Replace addon catalog with new addons
--
-- Removes all existing addons and inserts 3 new ones:
--   1. Career AI
--   2. AI Job Matching
--   3. Video Portfolio
--
-- Uses subquery for product_id — safe for both:
--   - Existing DBs (product exists, inserts proceed)
--   - Fresh DB resets (product seeded later, skips with 0 rows)

BEGIN;

-- Remove all existing addons
DELETE FROM public.addon_catalog;

-- Insert new addons using subquery for product_id
-- On fresh DB resets (product not yet seeded), this simply inserts 0 rows
INSERT INTO public.addon_catalog (id, product_id, category, feature_key, feature_name, feature_value, description, price_monthly, price_annual, target_roles, icon, display_order, is_active, created_at, updated_at)
SELECT gen_random_uuid(), id, 'learning', 'career_ai', 'Career AI', 'AI-powered career guidance', 'AI-powered career guidance and personalized recommendations', 1999, 19990, '{learner}', '🤖', 1, true, now(), now()
FROM public.products WHERE code = 'skillpassport';

INSERT INTO public.addon_catalog (id, product_id, category, feature_key, feature_name, feature_value, description, price_monthly, price_annual, target_roles, icon, display_order, is_active, created_at, updated_at)
SELECT gen_random_uuid(), id, 'learning', 'ai_job_matching', 'AI Job Matching', 'Smart job matching', 'Intelligent job matching that connects you with relevant opportunities', 1999, 19990, '{learner}', '🎯', 2, true, now(), now()
FROM public.products WHERE code = 'skillpassport';

INSERT INTO public.addon_catalog (id, product_id, category, feature_key, feature_name, feature_value, description, price_monthly, price_annual, target_roles, icon, display_order, is_active, created_at, updated_at)
SELECT gen_random_uuid(), id, 'content', 'video_portfolio', 'Video Portfolio', 'Showcase with video', 'Showcase your skills and projects with a professional video portfolio', 499, 4990, '{learner}', '🎬', 3, true, now(), now()
FROM public.products WHERE code = 'skillpassport';

COMMIT;
