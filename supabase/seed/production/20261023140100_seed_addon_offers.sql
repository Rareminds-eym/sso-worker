-- Current product configuration only. No customer, order or payment data.
BEGIN;
UPDATE public.addon_catalog SET benefits=CASE WHEN description IS NULL OR btrim(description)='' THEN '{}'::text[] ELSE ARRAY[description] END WHERE cardinality(benefits)=0;
UPDATE public.addon_catalog SET benefits=ARRAY['Smart job matching','Skill-based recommendations','Application tracking'] WHERE feature_key='ai_job_matching';
WITH rules(feature_key,kind,target,quantity,days,requires_org,annual_only) AS (VALUES
 ('contact_unlocks_25','credits','contact_unlocks',25,NULL::integer,true,false),
 ('contact_unlocks_100','credits','contact_unlocks',100,NULL::integer,true,false),
 ('contact_unlocks_500','credits','contact_unlocks',500,NULL::integer,true,false),
 ('job_boost_1','credits','job_boost_credits',1,NULL::integer,true,false),
 ('job_boost_10','credits','job_boost_credits',10,NULL::integer,true,false),
 ('ai_shortlist_role','credits','ai_credits',1,NULL::integer,true,false),
 ('featured_job_7d','opportunity_visibility','featured_job',1,7,true,false),
 ('featured_employer_30d','tenant_visibility','featured_employer',1,30,true,false),
 ('additional_recruiter_seat','numeric_limit','recruiter_seats',1,NULL::integer,true,true)
), config AS (
 SELECT a.id,coalesce(r.kind,'access') kind,coalesce(r.target,a.feature_key) target,coalesce(r.quantity,1) quantity,r.days,coalesce(r.requires_org,false) requires_org,coalesce(r.annual_only,false) annual_only
 FROM public.addon_catalog a LEFT JOIN rules r ON r.feature_key=a.feature_key WHERE a.is_active
)
UPDATE public.addon_catalog a SET currency='INR',minor_unit=2,monthly_enabled=NOT c.annual_only,annual_enabled=true,monthly_label='Monthly',annual_label='Annual',monthly_duration_months=1,annual_duration_months=12,fulfilment_kind=c.kind,target_feature_key=c.target,fulfilment_quantity=c.quantity,fulfilment_duration_days=c.days,requires_organization=c.requires_org,allow_repeat_purchase=c.kind<>'access',updated_at=now()
FROM config c WHERE a.id=c.id;
COMMIT;
