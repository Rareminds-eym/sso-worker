-- Seed: Recruitment Plans (B2B - for recruiters and hiring companies)
-- 4 tiers: Starter (Free) → Pro → Premium → Enterprise
-- Source of truth for skillpassport plans_cache sync
-- product_id '912d5049-e195-46e9-a319-49e3502bf7e7' = SkillPassport

BEGIN;

INSERT INTO public.plans (
  id, 
  plan_code, 
  name, 
  business_type, 
  applicable_entities, 
  pricing_matrix, 
  base_features, 
  entity_config, 
  display_order, 
  is_active, 
  product_id
) VALUES

-- ============================================================
-- RECRUITER STARTER (FREE)
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000001',
  'recruiter_starter',
  'Recruiter Starter',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 0, "monthly": 0, "currency": "INR"}}'::jsonb,
  '[
    "recruiter_login",
    "talent_pool_access_limited",
    "basic_filters_skills_location",
    "candidate_profile_preview",
    "shortlist_creation",
    "basic_messaging",
    "limited_job_postings_3"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For small employers hiring occasionally",
      "duration": "forever",
      "ideal_for": "SMEs, local employers, first-time hiring partners",
      "max_users": 1,
      "description": "Free tier with basic recruitment features to get started",
      "positioning": "For small employers hiring occasionally",
      "display_name": "Recruiter Starter",
      "storage_limit": "1GB",
      "is_recommended": false,
      "capacity": {
        "recruiters": 1,
        "job_postings": 3,
        "active_searches": 10,
        "monthly_contacts": 20
      },
      "feature_details": {
        "talent_pool": "Limited search (10 per month)",
        "filters": "Basic: skills, location, graduation year",
        "profiles": "Preview only (limited details)",
        "shortlists": "Up to 3 shortlists",
        "messaging": "Basic contact requests",
        "job_postings": "3 active postings",
        "analytics": "None",
        "ai_features": "None"
      }
    }
  }'::jsonb,
  10,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- RECRUITER PRO (MOST POPULAR)
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000002',
  'recruiter_pro',
  'Recruiter Pro',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 49990, "monthly": 4999, "currency": "INR"}}'::jsonb,
  '[
    "everything_in_starter",
    "requisitions_job_management",
    "applicants_list_tracking",
    "ai_match_score",
    "saved_searches",
    "candidate_comparison",
    "interview_scheduling",
    "shareable_shortlists",
    "basic_analytics",
    "export_mini_profiles",
    "unlimited_job_postings"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For active hiring teams",
      "duration": "monthly",
      "ideal_for": "Companies hiring regularly from the talent ecosystem",
      "max_users": 3,
      "description": "Complete recruitment toolkit with AI-powered matching and analytics",
      "positioning": "For active hiring teams",
      "display_name": "Recruiter Pro",
      "storage_limit": "10GB",
      "is_recommended": true,
      "capacity": {
        "recruiters": 3,
        "job_postings": "unlimited",
        "active_searches": "unlimited",
        "monthly_contacts": 200
      },
      "feature_details": {
        "talent_pool": "Unlimited searches with advanced filters",
        "filters": "Advanced: skills, experience, education, projects, assessments",
        "profiles": "Full candidate profiles with work evidence",
        "requisitions": "Job requisition management with approval workflows",
        "applicants": "Applicant tracking with status updates",
        "ai_match": "AI-powered candidate match scoring",
        "shortlists": "Unlimited shareable shortlists",
        "interviews": "Interview scheduling and calendar sync",
        "analytics": "Basic: views, applications, conversion rates",
        "export": "Export candidate mini-profiles (CSV)",
        "messaging": "Unlimited messaging and notifications"
      }
    }
  }'::jsonb,
  20,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- RECRUITER PREMIUM
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000003',
  'recruiter_premium',
  'Recruiter Premium',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 99990, "monthly": 9999, "currency": "INR"}}'::jsonb,
  '[
    "everything_in_pro",
    "ai_recruiter_copilot",
    "external_audited_filter",
    "verified_evidence_tabs",
    "pipeline_kanban",
    "offer_decision_tracking",
    "team_notes_ratings",
    "whatsapp_email_templates",
    "csv_ats_export",
    "advanced_analytics_funnel",
    "time_to_hire_metrics",
    "quality_hire_tracking",
    "geography_analytics"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For serious placement and recruitment partners",
      "duration": "monthly",
      "ideal_for": "Recruitment agencies, corporates, sector-specific hiring drives",
      "max_users": 10,
      "description": "Premium features with AI copilot, verified evidence, and advanced analytics",
      "positioning": "For serious placement and recruitment partners",
      "display_name": "Recruiter Premium",
      "storage_limit": "50GB",
      "is_recommended": false,
      "capacity": {
        "recruiters": 10,
        "job_postings": "unlimited",
        "active_searches": "unlimited",
        "monthly_contacts": "unlimited"
      },
      "feature_details": {
        "ai_copilot": "AI Recruiter Copilot for automated candidate recommendations",
        "verified_work": "Access to external-audited candidate work (projects, assessments, certificates)",
        "evidence_tabs": "Verified evidence tabs: projects, assessments, certificates, videos",
        "pipeline": "Visual pipeline Kanban board for candidate stages",
        "offers": "Offer generation, tracking, and decision management",
        "collaboration": "Team notes, ratings, and collaborative hiring",
        "templates": "WhatsApp and email templates with merge fields",
        "export": "Full CSV export and ATS integration prep",
        "analytics": "Advanced: hiring funnel, time-to-hire, quality metrics, geography heatmaps",
        "reporting": "Custom reports and dashboards"
      }
    }
  }'::jsonb,
  30,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
),

-- ============================================================
-- ENTERPRISE RECRUITMENT SUITE (CUSTOM PRICING)
-- ============================================================
(
  'b0000000-0000-4000-8000-000000000004',
  'recruiter_enterprise',
  'Enterprise Recruitment Suite',
  'b2b',
  ARRAY['recruitment'],
  '{"recruitment": {"yearly": 0, "monthly": 0, "currency": "INR", "custom": true}}'::jsonb,
  '[
    "everything_in_premium",
    "multiple_recruiter_seats",
    "organization_subscription",
    "bulk_hiring_campaigns",
    "campus_placement_workflows",
    "custom_assessment_rubric",
    "branded_hiring_page",
    "api_ats_webhook_integration",
    "compliance_audit_log",
    "dedicated_account_support",
    "custom_reports_dashboards",
    "sso_integration",
    "white_label_options",
    "priority_support_sla"
  ]'::jsonb,
  '{
    "recruitment": {
      "tagline": "For large employers, colleges, universities, and placement partnerships",
      "duration": "custom",
      "ideal_for": "Universities, large corporates, government/CSR placement programs",
      "max_users": "unlimited",
      "description": "Enterprise-grade recruitment suite with custom features and dedicated support",
      "positioning": "For large employers, colleges, universities, and placement partnerships",
      "display_name": "Enterprise Recruitment Suite",
      "storage_limit": "unlimited",
      "is_recommended": false,
      "contact_sales": true,
      "capacity": {
        "recruiters": "unlimited",
        "job_postings": "unlimited",
        "active_searches": "unlimited",
        "monthly_contacts": "unlimited",
        "admin_seats": "unlimited"
      },
      "feature_details": {
        "seats": "Unlimited recruiter seats with role-based permissions",
        "org_level": "Organization-level subscription management",
        "bulk_hiring": "Bulk hiring campaigns with batch processing",
        "campus": "Campus placement workflows (college partnerships)",
        "custom_rubric": "Custom assessment and evaluation rubrics",
        "branding": "Branded hiring page with company logo and colors",
        "integrations": "API access and ATS webhook integrations (Workday, SAP, etc.)",
        "compliance": "Compliance audit logs and GDPR-ready features",
        "support": "Dedicated account manager and priority support",
        "reports": "Custom reports, analytics, and business intelligence",
        "sso": "SSO integration (SAML, OAuth)",
        "white_label": "White-label options for co-branding",
        "sla": "99.9% uptime SLA with priority response"
      }
    }
  }'::jsonb,
  40,
  true,
  '912d5049-e195-46e9-a319-49e3502bf7e7'
)

ON CONFLICT (plan_code) DO UPDATE SET
  name = EXCLUDED.name,
  business_type = EXCLUDED.business_type,
  applicable_entities = EXCLUDED.applicable_entities,
  pricing_matrix = EXCLUDED.pricing_matrix,
  base_features = EXCLUDED.base_features,
  entity_config = EXCLUDED.entity_config,
  display_order = EXCLUDED.display_order,
  is_active = EXCLUDED.is_active,
  updated_at = NOW();

COMMIT;

-- ============================================================
-- VERIFICATION QUERIES
-- ============================================================

-- Verify recruitment plans were inserted
SELECT 
  plan_code, 
  name, 
  (pricing_matrix->'recruitment'->>'monthly')::int as monthly_price,
  (pricing_matrix->'recruitment'->>'yearly')::int as yearly_price,
  (entity_config->'recruitment'->>'is_recommended')::boolean as recommended,
  display_order
FROM public.plans
WHERE applicable_entities @> ARRAY['recruitment']
ORDER BY display_order;

-- Count recruitment plans
SELECT COUNT(*) as recruitment_plan_count
FROM public.plans
WHERE applicable_entities @> ARRAY['recruitment'];
