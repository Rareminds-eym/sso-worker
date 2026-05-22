-- Migration: Add product classification to plans
-- Description: Links plans to products (SkillPassport, future products, etc.)
-- Date: 2026-05-21

-- Seed products table
INSERT INTO public.products (code, name, description, created_at)
VALUES 
  ('skillpassport', 'SkillPassport', 'Skill development and career advancement platform', NOW()),
  ('lte', 'Learning Transformation Engine', 'Enterprise learning transformation and training management system', NOW())
ON CONFLICT (code) DO NOTHING;

-- Add product_id column to plans table
ALTER TABLE public.plans 
ADD COLUMN IF NOT EXISTS product_id uuid REFERENCES public.products(id);

-- Create index on product_id
CREATE INDEX IF NOT EXISTS idx_plans_product_id ON public.plans(product_id);

-- Update existing plans to link to SkillPassport product
DO $$
DECLARE
  skillpassport_product_id uuid;
BEGIN
  -- Get SkillPassport product ID
  SELECT id INTO skillpassport_product_id
  FROM public.products
  WHERE code = 'skillpassport';
  
  -- Update all existing plans to link to SkillPassport
  UPDATE public.plans
  SET product_id = skillpassport_product_id
  WHERE product_id IS NULL;
  
  RAISE NOTICE '✅ Linked % plans to SkillPassport product', (SELECT COUNT(*) FROM public.plans WHERE product_id = skillpassport_product_id);
END $$;

-- Make product_id NOT NULL after backfilling
ALTER TABLE public.plans 
ALTER COLUMN product_id SET NOT NULL;

-- Update RLS policies to include product filtering
DROP POLICY IF EXISTS "plans_public_read" ON public.plans;
CREATE POLICY "plans_public_read" ON public.plans
  FOR SELECT USING (is_active = true);

-- Add product_id to subscriptions for direct querying without joins
ALTER TABLE public.subscriptions
ADD COLUMN IF NOT EXISTS product_id uuid REFERENCES public.products(id);

-- Create index on subscriptions.product_id
CREATE INDEX IF NOT EXISTS idx_subscriptions_product_id ON public.subscriptions(product_id);

-- Backfill existing subscriptions from their linked plan's product_id
UPDATE public.subscriptions s
SET product_id = p.product_id
FROM public.plans p
WHERE s.plan_id = p.id AND s.product_id IS NULL;

-- Verify
DO $$
DECLARE
  product_count INTEGER;
  plan_count INTEGER;
  sub_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO product_count FROM public.products;
  SELECT COUNT(*) INTO plan_count FROM public.plans WHERE product_id IS NOT NULL;
  SELECT COUNT(*) INTO sub_count FROM public.subscriptions WHERE product_id IS NOT NULL;
  
  RAISE NOTICE '✅ Products: %, Plans with product: %, Subscriptions with product: %', product_count, plan_count, sub_count;
END $$;
