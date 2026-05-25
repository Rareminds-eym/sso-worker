-- Migration: Replace addon catalog with new addons
-- 
-- Removes all existing addons and inserts 3 new ones:
--   1. Career AI
--   2. AI Job Matching
--   3. Video Portfolio
--
-- No purchases exist (addon_purchases is empty), so this is safe.

BEGIN;

-- Remove all existing addons
DELETE FROM public.addon_catalog;

-- Insert new addons
INSERT INTO public.addon_catalog (id, product_id, category, feature_key, feature_name, feature_value, description, price_monthly, price_annual, target_roles, icon, display_order, is_active, created_at, updated_at) VALUES
  (gen_random_uuid(), '912d5049-e195-46e9-a319-49e3502bf7e7', 'learning', 'career_ai', 'Career AI', 'AI-powered career guidance', 'AI-powered career guidance and personalized recommendations', 1999, 19990, '{learner}', '🤖', 1, true, now(), now()),
  (gen_random_uuid(), '912d5049-e195-46e9-a319-49e3502bf7e7', 'learning', 'ai_job_matching', 'AI Job Matching', 'Smart job matching', 'Intelligent job matching that connects you with relevant opportunities', 1999, 19990, '{learner}', '🎯', 2, true, now(), now()),
  (gen_random_uuid(), '912d5049-e195-46e9-a319-49e3502bf7e7', 'content', 'video_portfolio', 'Video Portfolio', 'Showcase with video', 'Showcase your skills and projects with a professional video portfolio', 499, 4990, '{learner}', '🎬', 3, true, now(), now());

COMMIT;
