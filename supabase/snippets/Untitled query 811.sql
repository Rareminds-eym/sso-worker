SELECT 
  plan_code, 
  name, 
  (pricing_matrix->'recruitment'->>'monthly')::int as monthly_price,
  applicable_entities,
  is_active
FROM public.plans
WHERE applicable_entities @> ARRAY['recruitment']
ORDER BY display_order;
