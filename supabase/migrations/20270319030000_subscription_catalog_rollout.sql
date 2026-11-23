-- PREPARED ONLY. Exact SSO target/payload deployment approval is required.
-- Persists inactive canonical candidates. Does not stage/publish/activate offers,
-- migrate customers, rewrite Hybrid or mutate historical purchases/revisions.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE TABLE public.subscription_catalog_installations (
  operation_id uuid PRIMARY KEY,
  product_id uuid NOT NULL REFERENCES public.products(id),
  actor_id uuid NOT NULL REFERENCES public.users(id),
  command jsonb NOT NULL,
  receipt jsonb NOT NULL,
  installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX subscription_catalog_installations_product_idx ON public.subscription_catalog_installations(product_id);
CREATE INDEX subscription_catalog_installations_actor_idx ON public.subscription_catalog_installations(actor_id);
REVOKE ALL ON public.subscription_catalog_installations FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON public.subscription_catalog_installations TO service_role;
CREATE FUNCTION public.reject_subscription_catalog_installation_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'Catalog installation audit is immutable'; END;
$$;
CREATE TRIGGER subscription_catalog_installations_immutable_rows BEFORE UPDATE OR DELETE ON public.subscription_catalog_installations
FOR EACH ROW EXECUTE FUNCTION public.reject_subscription_catalog_installation_mutation();
CREATE TRIGGER subscription_catalog_installations_immutable_truncate BEFORE TRUNCATE ON public.subscription_catalog_installations
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_catalog_installation_mutation();
REVOKE ALL ON FUNCTION public.reject_subscription_catalog_installation_mutation() FROM PUBLIC,anon,authenticated,service_role;

-- The authenticated owner first validates every BRD profile against current
-- application registry, explicit calendar/roles and exact owner configuration.
CREATE FUNCTION public.install_subscription_catalog_candidates(p_command jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_op uuid; v_product uuid; v_actor uuid; v_hybrid uuid; v_entry jsonb; v_plan jsonb;
  v_id uuid; v_old public.plans%ROWTYPE; v_prior public.subscription_catalog_installations%ROWTYPE;
  v_expected jsonb; v_actual jsonb; v_preserved jsonb; v_after jsonb; v_receipt jsonb;
BEGIN
  IF jsonb_typeof(p_command) IS DISTINCT FROM 'object'
    OR (SELECT count(*) FROM jsonb_object_keys(p_command))<>7
    OR NOT p_command ?& ARRAY['schemaVersion','operationId','actorId','productId','hybridPlanId','approvalReference','entries']
    OR p_command->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR jsonb_typeof(p_command->'approvalReference') IS DISTINCT FROM 'string'
    OR btrim(p_command->>'approvalReference')=''
    OR jsonb_typeof(p_command->'entries') IS DISTINCT FROM 'array'
    OR jsonb_array_length(p_command->'entries')=0
    THEN RAISE EXCEPTION 'Explicit canonical catalog installation required'; END IF;
  v_op:=(p_command->>'operationId')::uuid; v_product:=(p_command->>'productId')::uuid;
  v_actor:=(p_command->>'actorId')::uuid; v_hybrid:=(p_command->>'hybridPlanId')::uuid;
  IF v_op IS NULL OR v_product IS NULL OR v_actor IS NULL OR v_hybrid IS NULL THEN RAISE EXCEPTION 'Exact identities required'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_catalog_installation:'||v_op::text,0));
  SELECT * INTO v_prior FROM public.subscription_catalog_installations WHERE operation_id=v_op;
  IF FOUND THEN
    IF v_prior.command IS DISTINCT FROM p_command THEN RAISE EXCEPTION 'Catalog installation replay conflicts'; END IF;
    RETURN v_prior.receipt;
  END IF;
  -- Canonical product lock also blocks concurrent foreign-key candidate inserts.
  PERFORM id FROM public.products WHERE id=v_product FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Canonical product unavailable'; END IF;
  PERFORM id FROM public.plans WHERE product_id=v_product ORDER BY id FOR UPDATE;
  IF NOT EXISTS(SELECT 1 FROM public.plans WHERE id=v_hybrid AND product_id=v_product) THEN RAISE EXCEPTION 'Retained owner identity unavailable'; END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(p_command->'entries'))<>(SELECT count(DISTINCT x->>'reference') FROM jsonb_array_elements(p_command->'entries') x)
    OR (SELECT count(*) FROM jsonb_array_elements(p_command->'entries'))<>(SELECT count(DISTINCT x#>>'{plan,id}') FROM jsonb_array_elements(p_command->'entries') x)
    OR (SELECT count(*) FROM jsonb_array_elements(p_command->'entries'))<>(SELECT count(DISTINCT x#>>'{plan,plan_code}') FROM jsonb_array_elements(p_command->'entries') x)
    THEN RAISE EXCEPTION 'Duplicate source or canonical identity'; END IF;
  PERFORM id FROM public.subscriptions WHERE product_id=v_product ORDER BY id FOR UPDATE;
  SELECT jsonb_build_object(
    'hybrid',(SELECT to_jsonb(p) FROM public.plans p WHERE p.id=v_hybrid),
    'purchases',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]'::jsonb) FROM public.subscriptions s WHERE s.product_id=v_product),
    'drafts',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id),'[]'::jsonb) FROM public.subscription_plan_drafts d JOIN public.plans p ON p.id=d.plan_id WHERE p.product_id=v_product),
    'publications',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.plan_id),'[]'::jsonb) FROM public.subscription_plan_publications d JOIN public.plans p ON p.id=d.plan_id WHERE p.product_id=v_product),
    'events',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id),'[]'::jsonb) FROM public.subscription_plan_publication_events d JOIN public.plans p ON p.id=d.plan_id WHERE p.product_id=v_product)
  ) INTO v_preserved;
  FOR v_entry IN SELECT value FROM jsonb_array_elements(p_command->'entries') LOOP
    IF jsonb_typeof(v_entry) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(v_entry))<>3
      OR NOT v_entry ?& ARRAY['reference','expected','plan'] OR jsonb_typeof(v_entry->'reference') IS DISTINCT FROM 'string'
      OR btrim(v_entry->>'reference')='' THEN RAISE EXCEPTION 'Exact source entry required'; END IF;
    v_plan:=v_entry->'plan';
    IF jsonb_typeof(v_plan) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(v_plan))<>11
      OR NOT v_plan ?& ARRAY['id','plan_code','product_id','name','business_type','applicable_entities','pricing_matrix','base_features','entity_config','display_order','is_active']
      OR (v_plan->>'product_id')::uuid IS DISTINCT FROM v_product OR v_plan->'is_active' IS DISTINCT FROM 'false'::jsonb
      OR jsonb_typeof(v_plan->'plan_code') IS DISTINCT FROM 'string' OR (v_plan->>'plan_code' ~ '^pln_[0-9a-f]{32}$') IS DISTINCT FROM true
      OR jsonb_typeof(v_plan->'name') IS DISTINCT FROM 'string' OR btrim(v_plan->>'name')=''
      OR jsonb_typeof(v_plan->'business_type') IS DISTINCT FROM 'string' OR btrim(v_plan->>'business_type')=''
      OR jsonb_typeof(v_plan->'applicable_entities') IS DISTINCT FROM 'array' OR jsonb_array_length(v_plan->'applicable_entities')=0
      OR jsonb_typeof(v_plan->'pricing_matrix') IS DISTINCT FROM 'object' OR jsonb_typeof(v_plan->'entity_config') IS DISTINCT FROM 'object'
      OR (v_plan->'base_features'<>'null'::jsonb AND jsonb_typeof(v_plan->'base_features') IS DISTINCT FROM 'array')
      OR (v_plan->'display_order'<>'null'::jsonb AND (jsonb_typeof(v_plan->'display_order') IS DISTINCT FROM 'number'
        OR (v_plan->>'display_order')::numeric<>trunc((v_plan->>'display_order')::numeric)
        OR (v_plan->>'display_order')::numeric NOT BETWEEN -2147483648 AND 2147483647))
      THEN RAISE EXCEPTION 'Inactive generic canonical candidate fields required'; END IF;
    v_id:=(v_plan->>'id')::uuid;
    IF v_id IS NULL OR v_id=v_hybrid THEN RAISE EXCEPTION 'Retained Hybrid cannot be overwritten'; END IF;
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(v_plan->'applicable_entities') a WHERE jsonb_typeof(a) IS DISTINCT FROM 'string' OR btrim(a#>>'{}')='')
      OR jsonb_array_length(v_plan->'applicable_entities')<>(SELECT count(DISTINCT a) FROM jsonb_array_elements(v_plan->'applicable_entities') a)
      THEN RAISE EXCEPTION 'Explicit unique audiences required'; END IF;
    SELECT * INTO v_old FROM public.plans WHERE id=v_id FOR UPDATE;
    v_expected:=v_entry->'expected';
    IF FOUND THEN
      IF jsonb_typeof(v_expected) IS DISTINCT FROM 'object' OR to_jsonb(v_old) IS DISTINCT FROM v_expected
        OR v_old.product_id<>v_product OR v_old.is_active IS DISTINCT FROM false
        OR (to_jsonb(v_old)-'created_at'-'updated_at'-'entity_config') IS DISTINCT FROM (v_plan-'entity_config')
        OR EXISTS(SELECT 1 FROM public.subscriptions WHERE plan_id=v_id)
        OR EXISTS(SELECT 1 FROM public.subscription_plan_publications WHERE plan_id=v_id)
        OR EXISTS(SELECT 1 FROM public.subscription_plan_publication_events WHERE plan_id=v_id)
        THEN RAISE EXCEPTION 'Existing candidate baseline or protected history differs'; END IF;
      IF EXISTS(SELECT 1 FROM jsonb_each(v_old.entity_config) prior WHERE prior.key NOT LIKE 'subscription\_%' ESCAPE '\'
        AND (v_plan->'entity_config'->prior.key) IS DISTINCT FROM prior.value)
        THEN RAISE EXCEPTION 'Unrelated existing owner configuration must be preserved'; END IF;
      UPDATE public.plans SET entity_config=v_plan->'entity_config' WHERE id=v_id;
    ELSE
      IF v_expected IS DISTINCT FROM 'null'::jsonb OR EXISTS(SELECT 1 FROM public.plans WHERE plan_code=v_plan->>'plan_code') THEN RAISE EXCEPTION 'Explicit absence and unique generic code required'; END IF;
      INSERT INTO public.plans(id,plan_code,product_id,name,business_type,applicable_entities,pricing_matrix,base_features,entity_config,display_order,is_active)
        VALUES(v_id,v_plan->>'plan_code',v_product,v_plan->>'name',v_plan->>'business_type',
          ARRAY(SELECT jsonb_array_elements_text(v_plan->'applicable_entities')),v_plan->'pricing_matrix',
          CASE WHEN v_plan->'base_features'='null'::jsonb THEN NULL ELSE v_plan->'base_features' END,
          v_plan->'entity_config',(v_plan->>'display_order')::integer,false);
    END IF;
    SELECT to_jsonb(p)-'created_at'-'updated_at' INTO v_actual FROM public.plans p WHERE p.id=v_id;
    IF v_actual IS DISTINCT FROM v_plan THEN RAISE EXCEPTION 'Persisted canonical candidate differs from validated owner terms'; END IF;
  END LOOP;
  SELECT jsonb_build_object(
    'hybrid',(SELECT to_jsonb(p) FROM public.plans p WHERE p.id=v_hybrid),
    'purchases',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]'::jsonb) FROM public.subscriptions s WHERE s.product_id=v_product),
    'drafts',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id),'[]'::jsonb) FROM public.subscription_plan_drafts d JOIN public.plans p ON p.id=d.plan_id WHERE p.product_id=v_product),
    'publications',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.plan_id),'[]'::jsonb) FROM public.subscription_plan_publications d JOIN public.plans p ON p.id=d.plan_id WHERE p.product_id=v_product),
    'events',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id),'[]'::jsonb) FROM public.subscription_plan_publication_events d JOIN public.plans p ON p.id=d.plan_id WHERE p.product_id=v_product)
  ) INTO v_after;
  IF v_preserved IS DISTINCT FROM v_after THEN RAISE EXCEPTION 'Historical catalog and purchases must be preserved'; END IF;
  v_receipt:=jsonb_build_object('operationId',v_op,'actorId',v_actor,'command',p_command,
    'planIds',(SELECT jsonb_agg(x#>'{plan,id}' ORDER BY ordinal) FROM jsonb_array_elements(p_command->'entries') WITH ORDINALITY r(x,ordinal)));
  INSERT INTO public.subscription_catalog_installations(operation_id,product_id,actor_id,command,receipt) VALUES(v_op,v_product,v_actor,p_command,v_receipt);
  RETURN v_receipt;
END;
$$;
REVOKE ALL ON FUNCTION public.install_subscription_catalog_candidates(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.install_subscription_catalog_candidates(jsonb) TO service_role;

-- Existing staging owner, preserved except explicit free offers have no billing prices.
CREATE OR REPLACE FUNCTION public.stage_subscription_plan_draft(p_draft jsonb, p_staged_by uuid, p_included_credits jsonb DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_id uuid;
  v_plan_id uuid;
  v_product_id uuid;
  v_revision bigint;
  v_plan public.plans%ROWTYPE;
  v_stored public.subscription_plan_drafts%ROWTYPE;
  v_next bigint;
BEGIN
  -- Commercial/feature registry validation belongs to the trusted worker module.
  -- This service-only RPC additionally enforces storage shape and canonical identity.
  IF p_draft IS NULL OR jsonb_typeof(p_draft) IS DISTINCT FROM 'object'
    OR p_staged_by IS NULL THEN
    RAISE EXCEPTION 'Invalid subscription plan draft';
  END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(p_draft)) <> 9
    OR NOT p_draft ?& ARRAY['schemaVersion','id','plan','revisionNumber','name','audiences','purchaseMode','prices','features']
    OR (p_draft->'schemaVersion' IN ('1'::jsonb, '2'::jsonb)) IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'plan') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'Invalid subscription plan draft';
  END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(p_draft->'plan')) <> 3
    OR NOT (p_draft->'plan') ?& ARRAY['id','code','productId']
    OR (p_draft#>>'{plan,code}' ~ '^pln_[0-9a-f]{32}$') IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'revisionNumber') IS DISTINCT FROM 'number'
    OR (p_draft->>'revisionNumber' ~ '^[1-9][0-9]{0,15}$') IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'name') IS DISTINCT FROM 'string'
    OR length(btrim(p_draft->>'name')) = 0
    OR (p_draft->>'purchaseMode' IN ('self_service','contact_sales','free')) IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'audiences') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_draft->'prices') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_draft->'features') IS DISTINCT FROM 'array'
    OR (p_draft->>'purchaseMode'='free' AND p_draft->'prices'<>'[]'::jsonb) THEN
    RAISE EXCEPTION 'Invalid subscription plan draft';
  END IF;
  BEGIN
    v_id := (p_draft->>'id')::uuid;
    v_plan_id := (p_draft#>>'{plan,id}')::uuid;
    v_product_id := (p_draft#>>'{plan,productId}')::uuid;
    v_revision := (p_draft->>'revisionNumber')::bigint;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'Invalid subscription plan draft identity';
  END;
  IF v_id IS NULL OR v_plan_id IS NULL OR v_product_id IS NULL
    OR v_revision NOT BETWEEN 1 AND 9007199254740991 THEN
    RAISE EXCEPTION 'Invalid subscription plan draft identity';
  END IF;

  -- Schema 1 is explicitly unbundled; schema 2 must bind both snapshots in this row.
  IF p_draft->'schemaVersion' = '1'::jsonb THEN
    IF p_included_credits IS NOT NULL THEN RAISE EXCEPTION 'Schema 1 cannot carry bundled credits'; END IF;
  ELSE
    IF p_included_credits IS NULL OR jsonb_typeof(p_included_credits) IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'Schema 2 requires included credit terms';
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(p_included_credits)) <> 5
      OR NOT p_included_credits ?& ARRAY['schemaVersion','id','revisionId','funding','rules']
      OR p_included_credits->'schemaVersion' IS DISTINCT FROM '1'::jsonb
      OR p_included_credits->>'funding' IS DISTINCT FROM 'included'
      OR p_included_credits->>'revisionId' IS DISTINCT FROM v_id::text
      OR jsonb_typeof(p_included_credits->'rules') IS DISTINCT FROM 'array' THEN
      RAISE EXCEPTION 'Invalid included credit binding';
    END IF;
    BEGIN
      IF (p_included_credits->>'id')::uuid IS NULL THEN RAISE EXCEPTION 'Invalid included credit identity'; END IF;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'Invalid included credit identity';
    END;
  END IF;

  -- Serialize writers for one canonical plan; concurrent different plans remain independent.
  SELECT * INTO v_plan FROM public.plans WHERE id = v_plan_id FOR UPDATE;
  IF NOT FOUND OR v_plan.plan_code IS DISTINCT FROM p_draft#>>'{plan,code}'
    OR v_plan.product_id IS DISTINCT FROM v_product_id THEN
    RAISE EXCEPTION 'Subscription plan identity does not match the canonical catalog';
  END IF;

  SELECT * INTO v_stored FROM public.subscription_plan_drafts WHERE id = v_id;
  IF FOUND THEN
    IF v_stored.snapshot IS DISTINCT FROM p_draft OR v_stored.staged_by IS DISTINCT FROM p_staged_by
      OR v_stored.included_credits IS DISTINCT FROM p_included_credits THEN
      RAISE EXCEPTION 'Subscription plan draft replay conflicts with stored evidence';
    END IF;
  ELSE
    SELECT coalesce(max(revision_number), 0) + 1 INTO v_next
      FROM public.subscription_plan_drafts WHERE plan_id = v_plan_id;
    IF v_revision <> v_next THEN
      RAISE EXCEPTION 'Subscription plan draft must use the next revision number';
    END IF;
    INSERT INTO public.subscription_plan_drafts (id, plan_id, revision_number, snapshot, included_credits, staged_by)
      VALUES (v_id, v_plan_id, v_revision, p_draft, p_included_credits, p_staged_by)
      RETURNING * INTO v_stored;
  END IF;
  IF v_stored.included_credits IS NOT NULL THEN
    RETURN jsonb_build_object('draft', v_stored.snapshot, 'includedCredits', v_stored.included_credits,
      'stagedBy', v_stored.staged_by, 'stagedAt', v_stored.staged_at);
  END IF;
  RETURN jsonb_build_object('draft', v_stored.snapshot, 'stagedBy', v_stored.staged_by, 'stagedAt', v_stored.staged_at);
END;
$$;

REVOKE ALL ON FUNCTION public.stage_subscription_plan_draft(jsonb, uuid, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.stage_subscription_plan_draft(jsonb, uuid, jsonb) TO service_role;

COMMIT;
