-- Hybrid is a sales-only catalog entry, not a free or automatically entitled plan.
-- Empty prices and base_features are intentional. Negotiated subscriptions need
-- an accepted quote and explicit entitlements before activation.
-- Apply the SSO migration first; this catalog metadata is preserved by syncPlanCache.
INSERT INTO public.plans (id, plan_code, name, business_type, applicable_entities, pricing_matrix, base_features, entity_config, display_order, is_active, product_id)
VALUES (
  'a0000000-0000-4000-8000-000000000040', 'hybrid', 'Hybrid', 'b2b',
  ARRAY['school', 'college', 'university'],
  '{}'::jsonb, '[]'::jsonb,
  '{
  "all": {
    "purchase_mode": "contact_sales",
    "display_name": "Hybrid",
    "tagline": "Your institution. Your plan.",
    "positioning": "Built around you",
    "description": "Work with our sales team to choose your features, user limits, integrations, support, and billing terms.",
    "price_label": "Custom pricing",
    "sales_email": "marketing@rareminds.in",
    "sales_phone": "+91 9902326951",
    "sales_highlights": [
      "Tailored combination of features",
      "Flexible student and educator licenses",
      "Agreed usage allowances",
      "Optional integrations and onboarding",
      "Personalized support options",
      "Negotiated pricing and contract terms"
    ],
    "terms_note": "Features and services are subject to the agreed proposal.",
    "duration": "custom",
    "is_recommended": false
  }
}'::jsonb,
  40, true, '912d5049-e195-46e9-a319-49e3502bf7e7'
)
ON CONFLICT (plan_code) DO NOTHING;
