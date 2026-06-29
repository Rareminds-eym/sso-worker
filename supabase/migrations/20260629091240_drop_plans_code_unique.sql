ALTER TABLE public.plans
ADD CONSTRAINT plans_plan_code_key UNIQUE (plan_code);
