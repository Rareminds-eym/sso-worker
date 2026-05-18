-- Migration: Create plans table in auth DB
-- Consolidates subscription_plans + subscription_plan_features from app DB

CREATE TABLE IF NOT EXISTS public.plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_code text UNIQUE NOT NULL,
  name text NOT NULL,
  business_type text NOT NULL,
  applicable_entities text[] NOT NULL DEFAULT '{}',
  pricing_matrix jsonb NOT NULL DEFAULT '{}',
  base_features jsonb DEFAULT '[]',
  entity_config jsonb DEFAULT '{}',
  display_order integer DEFAULT 0,
  is_active boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE INDEX idx_plans_code ON public.plans(plan_code);
CREATE INDEX idx_plans_active ON public.plans(is_active) WHERE is_active = true;
CREATE INDEX idx_plans_business_type ON public.plans(business_type);

ALTER TABLE public.plans ENABLE ROW LEVEL SECURITY;

-- Public read access for pricing pages; writes only via service_role
CREATE POLICY "plans_public_read" ON public.plans
  FOR SELECT USING (true);

CREATE POLICY "plans_service_write" ON public.plans
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE TRIGGER trg_plans_updated_at
  BEFORE UPDATE ON public.plans
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
