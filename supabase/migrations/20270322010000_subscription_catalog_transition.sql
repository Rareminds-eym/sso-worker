-- PREPARED SCHEMA ONLY. Applying this source or invoking its data operation
-- requires separate explicit approval for the exact database and payload.
-- No seeds, cohort changes, publication, retirement or customer rewrite here.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE TABLE public.subscription_catalog_transition_operations (
  operation_id uuid PRIMARY KEY,
  product_id uuid NOT NULL REFERENCES public.products(id),
  actor_id uuid NOT NULL REFERENCES public.users(id),
  command jsonb NOT NULL,
  receipt jsonb NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.subscription_catalog_transition_operations FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON public.subscription_catalog_transition_operations TO service_role;

-- Privileged internal owner only. The worker must first authorize a live signed
-- subscription administrator. approvalReference records the separately obtained
-- exact-target approval; its presence is never interpreted as an authorization.
CREATE FUNCTION public.commit_subscription_catalog_transition(p_command jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid; product uuid; hybrid uuid; prior public.subscription_catalog_transition_operations%ROWTYPE;
  expected jsonb; actual jsonb; replacement jsonb; receipt jsonb; ids uuid[];
BEGIN
  IF jsonb_typeof(p_command) IS DISTINCT FROM 'object'
    OR (SELECT count(*) FROM jsonb_object_keys(p_command))<>11
    OR NOT p_command ?& ARRAY['schemaVersion','operationId','productId','actorId','approvalReference','effectiveAt',
      'hybridPlanId','expectedPlans','replacements','retainedSubscriptions','preservation']
    OR p_command->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR p_command->>'preservation' IS DISTINCT FROM 'retain_original_purchases_and_history'
    OR jsonb_typeof(p_command->'approvalReference') IS DISTINCT FROM 'string'
    OR btrim(p_command->>'approvalReference')='' THEN RAISE EXCEPTION 'Explicit transition identity and preservation required'; END IF;
  op:=(p_command->>'operationId')::uuid; product:=(p_command->>'productId')::uuid; hybrid:=(p_command->>'hybridPlanId')::uuid;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_catalog_transition:'||op::text,0));
  SELECT * INTO prior FROM public.subscription_catalog_transition_operations WHERE operation_id=op;
  IF FOUND THEN
    IF prior.command IS DISTINCT FROM p_command THEN RAISE EXCEPTION 'Catalog transition replay conflicts'; END IF;
    RETURN prior.receipt;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_catalog_product:'||product::text,0));
  IF jsonb_typeof(p_command->'effectiveAt') IS DISTINCT FROM 'number'
    OR (p_command->>'effectiveAt')::numeric<>trunc((p_command->>'effectiveAt')::numeric)
    OR (p_command->>'effectiveAt')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (p_command->>'effectiveAt')::numeric>extract(epoch FROM clock_timestamp())*1000
    OR jsonb_typeof(p_command->'expectedPlans') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_command->'replacements') IS DISTINCT FROM 'array'
    OR jsonb_array_length(p_command->'replacements')=0
    OR jsonb_typeof(p_command->'retainedSubscriptions') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Explicit effective cohort required'; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_command->'expectedPlans') x
      WHERE jsonb_typeof(x) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(x))<>3
        OR NOT x ?& ARRAY['id','code','active'] OR jsonb_typeof(x->'active') IS DISTINCT FROM 'boolean')
    OR (SELECT count(*) FROM jsonb_array_elements(p_command->'expectedPlans'))<>(SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(p_command->'expectedPlans') x)
    OR (SELECT count(*) FROM jsonb_array_elements(p_command->'retainedSubscriptions'))<>(SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(p_command->'retainedSubscriptions') x)
    OR (SELECT count(*) FROM jsonb_array_elements(p_command->'replacements'))<>(SELECT count(DISTINCT x->>'legacyPlanId') FROM jsonb_array_elements(p_command->'replacements') x)
    THEN RAISE EXCEPTION 'Duplicate or malformed transition cohort'; END IF;
  SELECT array_agg((x->>'id')::uuid) INTO ids FROM jsonb_array_elements(p_command->'expectedPlans') x;
  -- Lock source/target/Hybrid and all purchase rows in deterministic order. No
  -- purchase table UPDATE occurs anywhere in this operation.
  PERFORM id FROM public.plans WHERE id=ANY(ids) ORDER BY id FOR UPDATE;
  SELECT jsonb_agg(jsonb_build_object('id',id,'code',plan_code,'active',is_active) ORDER BY id)
    INTO actual FROM public.plans WHERE product_id=product AND id=ANY(ids);
  SELECT jsonb_agg(x ORDER BY x->>'id') INTO expected FROM jsonb_array_elements(p_command->'expectedPlans') x;
  IF actual IS DISTINCT FROM expected OR NOT hybrid=ANY(ids)
    OR NOT EXISTS(SELECT 1 FROM public.plans WHERE id=hybrid AND product_id=product) THEN RAISE EXCEPTION 'Fresh exact plan baseline required'; END IF;
  PERFORM id FROM public.subscriptions WHERE product_id=product AND plan_id=ANY(ids) ORDER BY id FOR UPDATE;
  SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'planId',plan_id,'purchasedTerms',jsonb_build_object(
      'planCode',plan_code,'planType',plan_type,'amount',plan_amount,'billingCycle',billing_cycle,'features',features,
      'startsAt',subscription_start_date,'endsAt',subscription_end_date,'revisionId',plan_revision_id,
      'lifecycleState',lifecycle_state,'lifecyclePolicy',lifecycle_policy,'metadata',metadata)) ORDER BY id),'[]'::jsonb)
    INTO actual FROM public.subscriptions WHERE product_id=product AND plan_id=ANY(ids);
  SELECT coalesce(jsonb_agg(x ORDER BY x->>'id'),'[]'::jsonb) INTO expected FROM jsonb_array_elements(p_command->'retainedSubscriptions') x;
  IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Purchase cohort changed; immutable terms must be preserved'; END IF;
  FOR replacement IN SELECT value FROM jsonb_array_elements(p_command->'replacements') LOOP
    IF jsonb_typeof(replacement) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(replacement))<>3
      OR NOT replacement ?& ARRAY['legacyPlanId','planId','revisionId']
      OR (replacement->>'legacyPlanId')::uuid=hybrid OR (replacement->>'planId')::uuid=hybrid
      OR replacement->'legacyPlanId'=replacement->'planId'
      OR NOT (replacement->>'legacyPlanId')::uuid=ANY(ids) OR NOT (replacement->>'planId')::uuid=ANY(ids)
      OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_command->'replacements') x WHERE x->'legacyPlanId'=replacement->'planId')
      OR NOT EXISTS(SELECT 1 FROM public.plans WHERE id=(replacement->>'legacyPlanId')::uuid AND product_id=product AND is_active)
      OR NOT EXISTS(SELECT 1 FROM public.plans WHERE id=(replacement->>'planId')::uuid AND product_id=product AND is_active)
      OR NOT EXISTS(SELECT 1 FROM public.subscription_plan_publications p JOIN public.plans t ON t.id=p.plan_id
        WHERE p.plan_id=(replacement->>'planId')::uuid AND p.revision_id=(replacement->>'revisionId')::uuid AND t.product_id=product)
      THEN RAISE EXCEPTION 'Exact published replacement and preserved Hybrid required'; END IF;
  END LOOP;
  UPDATE public.plans SET is_active=false WHERE id IN (SELECT (x->>'legacyPlanId')::uuid FROM jsonb_array_elements(p_command->'replacements') x);
  receipt:=jsonb_build_object('operationId',op,'command',p_command,
    'retiredPlanIds',(SELECT jsonb_agg(x->'legacyPlanId' ORDER BY ordinal) FROM jsonb_array_elements(p_command->'replacements') WITH ORDINALITY r(x,ordinal)),
    'preservedSubscriptionIds',(SELECT coalesce(jsonb_agg(x->'id' ORDER BY ordinal),'[]'::jsonb) FROM jsonb_array_elements(p_command->'retainedSubscriptions') WITH ORDINALITY r(x,ordinal)));
  INSERT INTO public.subscription_catalog_transition_operations(operation_id,product_id,actor_id,command,receipt)
    VALUES(op,product,(p_command->>'actorId')::uuid,p_command,receipt);
  RETURN receipt;
END;
$$;
REVOKE ALL ON FUNCTION public.commit_subscription_catalog_transition(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.commit_subscription_catalog_transition(jsonb) TO service_role;

-- Explicit identity migration, separate from offer retirement. The signed owner
-- must verify the retained Hybrid UUID and exact target approval before calling.
CREATE FUNCTION public.commit_subscription_hybrid_identity_transition(p_command jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid; product uuid; hybrid uuid; prior public.subscription_catalog_transition_operations%ROWTYPE;
  actual jsonb; expected jsonb; purchase_before jsonb; purchase_after jsonb; receipt jsonb;
BEGIN
  IF jsonb_typeof(p_command) IS DISTINCT FROM 'object'
    OR (SELECT count(*) FROM jsonb_object_keys(p_command))<>11
    OR NOT p_command ?& ARRAY['schemaVersion','operationId','productId','actorId','approvalReference','effectiveAt',
      'hybridPlanId','expectedCode','targetCode','retainedSubscriptions','preservation']
    OR p_command->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR p_command->>'preservation' IS DISTINCT FROM 'retain_original_purchases_and_history'
    OR jsonb_typeof(p_command->'approvalReference') IS DISTINCT FROM 'string'
    OR btrim(p_command->>'approvalReference')=''
    OR jsonb_typeof(p_command->'expectedCode') IS DISTINCT FROM 'string'
    OR btrim(p_command->>'expectedCode')='' OR p_command->>'expectedCode'<>btrim(p_command->>'expectedCode')
    OR p_command->>'expectedCode' ~ '^pln_[0-9a-f]{32}$'
    OR jsonb_typeof(p_command->'targetCode') IS DISTINCT FROM 'string'
    OR (p_command->>'targetCode' ~ '^pln_[0-9a-f]{32}$') IS DISTINCT FROM true
    OR jsonb_typeof(p_command->'retainedSubscriptions') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_command->'effectiveAt') IS DISTINCT FROM 'number'
    OR (p_command->>'effectiveAt')::numeric<>trunc((p_command->>'effectiveAt')::numeric)
    OR (p_command->>'effectiveAt')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (p_command->>'effectiveAt')::numeric>extract(epoch FROM clock_timestamp())*1000
    THEN RAISE EXCEPTION 'Exact effective legacy to opaque identity transition required'; END IF;
  op:=(p_command->>'operationId')::uuid; product:=(p_command->>'productId')::uuid; hybrid:=(p_command->>'hybridPlanId')::uuid;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_catalog_transition:'||op::text,0));
  SELECT * INTO prior FROM public.subscription_catalog_transition_operations WHERE operation_id=op;
  IF FOUND THEN
    IF prior.command IS DISTINCT FROM p_command THEN RAISE EXCEPTION 'Identity transition replay conflicts'; END IF;
    RETURN prior.receipt;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_catalog_product:'||product::text,0));
  PERFORM id FROM public.plans WHERE product_id=product ORDER BY id FOR UPDATE;
  IF NOT EXISTS(SELECT 1 FROM public.plans WHERE id=hybrid AND product_id=product AND plan_code=p_command->>'expectedCode')
    OR EXISTS(SELECT 1 FROM public.plans WHERE plan_code=p_command->>'targetCode')
    THEN RAISE EXCEPTION 'Canonical identity baseline or target code differs'; END IF;
  PERFORM id FROM public.subscriptions WHERE product_id=product AND plan_id=hybrid ORDER BY id FOR UPDATE;
  SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]'::jsonb) INTO purchase_before
    FROM public.subscriptions s WHERE s.product_id=product AND s.plan_id=hybrid;
  SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'planId',plan_id,'purchasedTerms',jsonb_build_object(
      'planCode',plan_code,'planType',plan_type,'amount',plan_amount,'billingCycle',billing_cycle,'features',features,
      'startsAt',subscription_start_date,'endsAt',subscription_end_date,'revisionId',plan_revision_id,
      'lifecycleState',lifecycle_state,'lifecyclePolicy',lifecycle_policy,'metadata',metadata)) ORDER BY id),'[]'::jsonb)
    INTO actual FROM public.subscriptions WHERE product_id=product AND plan_id=hybrid;
  SELECT coalesce(jsonb_agg(x ORDER BY x->>'id'),'[]'::jsonb) INTO expected FROM jsonb_array_elements(p_command->'retainedSubscriptions') x;
  IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact Hybrid purchase cohort required'; END IF;
  UPDATE public.plans SET plan_code=p_command->>'targetCode' WHERE id=hybrid AND product_id=product AND plan_code=p_command->>'expectedCode';
  IF NOT FOUND THEN RAISE EXCEPTION 'Canonical identity compare and set failed'; END IF;
  SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]'::jsonb) INTO purchase_after
    FROM public.subscriptions s WHERE s.product_id=product AND s.plan_id=hybrid;
  IF purchase_before IS DISTINCT FROM purchase_after THEN RAISE EXCEPTION 'Identity transition must preserve every purchased column'; END IF;
  receipt:=jsonb_build_object('operationId',op,'command',p_command,
    'plan',jsonb_build_object('id',hybrid,'code',p_command->>'targetCode','productId',product),
    'preservedSubscriptionIds',(SELECT coalesce(jsonb_agg(x->'id' ORDER BY ordinal),'[]'::jsonb)
      FROM jsonb_array_elements(p_command->'retainedSubscriptions') WITH ORDINALITY r(x,ordinal)));
  INSERT INTO public.subscription_catalog_transition_operations(operation_id,product_id,actor_id,command,receipt)
    VALUES(op,product,(p_command->>'actorId')::uuid,p_command,receipt);
  RETURN receipt;
END;
$$;
REVOKE ALL ON FUNCTION public.commit_subscription_hybrid_identity_transition(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.commit_subscription_hybrid_identity_transition(jsonb) TO service_role;

-- Separate from installation and publication. The signed publication owner
-- independently re-reads/verifies the immutable application projection before
-- this RPC. The exact canonical snapshot binds that owner proof across the CAS.
CREATE FUNCTION public.commit_subscription_catalog_availability(p_command jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_op uuid; v_product uuid; v_hybrid uuid; v_entry jsonb; v_plan public.plans%ROWTYPE;
  v_prior public.subscription_catalog_transition_operations%ROWTYPE; v_canonical jsonb;
  v_purchases jsonb; v_after jsonb; v_receipt jsonb;
BEGIN
  IF jsonb_typeof(p_command) IS DISTINCT FROM 'object'
    OR (SELECT count(*) FROM jsonb_object_keys(p_command))<>8
    OR NOT p_command ?& ARRAY['schemaVersion','operationId','productId','actorId','approvalReference','effectiveAt','hybridPlanId','entries']
    OR p_command->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR jsonb_typeof(p_command->'approvalReference') IS DISTINCT FROM 'string' OR btrim(p_command->>'approvalReference')=''
    OR jsonb_typeof(p_command->'effectiveAt') IS DISTINCT FROM 'number'
    OR (p_command->>'effectiveAt')::numeric<>trunc((p_command->>'effectiveAt')::numeric)
    OR (p_command->>'effectiveAt')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (p_command->>'effectiveAt')::numeric>extract(epoch FROM clock_timestamp())*1000
    OR jsonb_typeof(p_command->'entries') IS DISTINCT FROM 'array' OR jsonb_array_length(p_command->'entries')=0
    THEN RAISE EXCEPTION 'Exact effective availability operation required'; END IF;
  v_op:=(p_command->>'operationId')::uuid; v_product:=(p_command->>'productId')::uuid; v_hybrid:=(p_command->>'hybridPlanId')::uuid;
  IF v_op IS NULL OR v_product IS NULL OR v_hybrid IS NULL OR (p_command->>'actorId')::uuid IS NULL THEN RAISE EXCEPTION 'Exact owner identities required'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_catalog_transition:'||v_op::text,0));
  SELECT * INTO v_prior FROM public.subscription_catalog_transition_operations WHERE operation_id=v_op;
  IF FOUND THEN
    IF v_prior.command IS DISTINCT FROM p_command THEN RAISE EXCEPTION 'Availability replay conflicts'; END IF;
    RETURN v_prior.receipt;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_catalog_product:'||v_product::text,0));
  PERFORM id FROM public.products WHERE id=v_product FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Canonical product unavailable'; END IF;
  PERFORM id FROM public.plans WHERE product_id=v_product ORDER BY id FOR UPDATE;
  IF NOT EXISTS(SELECT 1 FROM public.plans WHERE id=v_hybrid AND product_id=v_product) THEN RAISE EXCEPTION 'Retained owner identity unavailable'; END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(p_command->'entries'))<>(SELECT count(DISTINCT x->>'planId') FROM jsonb_array_elements(p_command->'entries') x)
    OR (SELECT count(*) FROM jsonb_array_elements(p_command->'entries'))<>(SELECT count(DISTINCT x->>'revisionId') FROM jsonb_array_elements(p_command->'entries') x)
    THEN RAISE EXCEPTION 'Duplicate availability identity'; END IF;
  PERFORM id FROM public.subscriptions WHERE product_id=v_product ORDER BY id FOR UPDATE;
  SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]'::jsonb) INTO v_purchases FROM public.subscriptions s WHERE product_id=v_product;
  FOR v_entry IN SELECT value FROM jsonb_array_elements(p_command->'entries') LOOP
    IF jsonb_typeof(v_entry) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(v_entry))<>4
      OR NOT v_entry ?& ARRAY['planId','revisionId','expectedActive','expectedCanonical']
      OR v_entry->'expectedActive' IS DISTINCT FROM 'false'::jsonb
      OR jsonb_typeof(v_entry->'expectedCanonical') IS DISTINCT FROM 'object'
      OR (SELECT count(*) FROM jsonb_object_keys(v_entry->'expectedCanonical'))<>5
      OR NOT (v_entry->'expectedCanonical') ?& ARRAY['id','code','productId','audiences','configuration']
      OR (v_entry->>'planId')::uuid=v_hybrid THEN RAISE EXCEPTION 'Exact inactive non-Hybrid availability entry required'; END IF;
    SELECT * INTO v_plan FROM public.plans WHERE id=(v_entry->>'planId')::uuid AND product_id=v_product FOR UPDATE;
    IF NOT FOUND OR v_plan.is_active IS DISTINCT FROM false OR v_plan.plan_code !~ '^pln_[0-9a-f]{32}$' THEN RAISE EXCEPTION 'Canonical offer state changed'; END IF;
    v_canonical:=jsonb_build_object('id',v_plan.id,'code',v_plan.plan_code,'productId',v_plan.product_id,
      'audiences',to_jsonb(v_plan.applicable_entities),'configuration',v_plan.entity_config);
    IF v_canonical IS DISTINCT FROM v_entry->'expectedCanonical'
      OR NOT EXISTS(SELECT 1 FROM public.subscription_plan_publications p
        JOIN public.subscription_plan_publication_events e ON e.plan_id=p.plan_id AND e.revision_id=p.revision_id
        WHERE p.plan_id=v_plan.id AND p.revision_id=(v_entry->>'revisionId')::uuid AND e.canonical_plan=v_canonical)
      THEN RAISE EXCEPTION 'Exact owner-verified publication or canonical configuration changed'; END IF;
    UPDATE public.plans SET is_active=true WHERE id=v_plan.id AND product_id=v_product AND is_active=false;
    IF NOT FOUND THEN RAISE EXCEPTION 'Availability compare and set failed'; END IF;
  END LOOP;
  SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]'::jsonb) INTO v_after FROM public.subscriptions s WHERE product_id=v_product;
  IF v_after IS DISTINCT FROM v_purchases THEN RAISE EXCEPTION 'Availability must preserve every purchased column'; END IF;
  v_receipt:=jsonb_build_object('operationId',v_op,'command',p_command,
    'activatedPlanIds',(SELECT jsonb_agg(x->'planId' ORDER BY ordinal) FROM jsonb_array_elements(p_command->'entries') WITH ORDINALITY r(x,ordinal)));
  INSERT INTO public.subscription_catalog_transition_operations(operation_id,product_id,actor_id,command,receipt)
    VALUES(v_op,v_product,(p_command->>'actorId')::uuid,p_command,v_receipt);
  RETURN v_receipt;
END;
$$;
REVOKE ALL ON FUNCTION public.commit_subscription_catalog_availability(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.commit_subscription_catalog_availability(jsonb) TO service_role;
COMMIT;
