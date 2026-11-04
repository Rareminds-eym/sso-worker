BEGIN;
-- Run after schema migrations and before enabling Zoho processing.
-- Never renumber live receipts or overwrite acknowledged source fences.
LOCK TABLE public.zoho_candidate_administration_operations,public.zoho_candidate_administration_fences IN EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.zoho_candidate_administration_operations o
  JOIN public.zoho_candidate_administration_fences f ON f.source_org_id=o.context->>'sourceOrgId' AND f.external_id=o.context->>'externalId'
  WHERE o.administration_version=0) THEN RAISE EXCEPTION 'Legacy administration requires reconciliation before upgrade'; END IF;
END $$;
WITH numbered AS(SELECT request_id,row_number() OVER(PARTITION BY context->>'sourceOrgId',context->>'externalId' ORDER BY created_at,request_id) version
 FROM public.zoho_candidate_administration_operations WHERE administration_version=0)
UPDATE public.zoho_candidate_administration_operations o SET administration_version=n.version FROM numbered n WHERE n.request_id=o.request_id;
INSERT INTO public.zoho_candidate_administration_fences(source_org_id,external_id,administration_version,latest_request_id,pending_request_id)
SELECT DISTINCT ON(context->>'sourceOrgId',context->>'externalId') context->>'sourceOrgId',context->>'externalId',administration_version,request_id,request_id
 FROM public.zoho_candidate_administration_operations ORDER BY context->>'sourceOrgId',context->>'externalId',administration_version DESC
ON CONFLICT(source_org_id,external_id) DO NOTHING;
COMMIT;
