UPDATE public.subscriptions
SET
    plan_id = 'a0000000-0000-4000-8000-000000000023',
    plan_code = 'college_enterprise',
    plan_type = 'College Enterprise',
    plan_amount = 49999.00,
    billing_cycle = 'yearly',
    status = 'active',
    features = '[
        "Up to 5,000 learners or custom",
        "Multi-department analytics",
        "Recruiter access",
        "Advanced placement dashboard",
        "Bulk onboarding",
        "Dedicated success manager"
    ]'::jsonb
WHERE plan_code = 'org_enterprise';
DELETE FROM public.plans
WHERE plan_code IN (
    'org_freemium',
    'org_starter',
    'org_professional',
    'org_enterprise'
);