-- Owner decision 1a (2026-11-21): adopt the retained Hybrid plan as a sales-led catalog offer.
-- One atomic command: the existing legacy-to-opaque identity transition plus the owner subscription
-- configuration. Unrelated existing configuration keys are kept; purchases are compared, never rewritten.
-- Staging and publication remain separate signed operations. Schema-only; applying it changes no rows.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';
CREATE TABLE public.subscription_hybrid_offer_adoptions (
  operation_id uuid PRIMARY KEY,
  product_id uuid NOT NULL REFERENCES public.products(id),
  actor_id uuid NOT NULL REFERENCES public.users(id),
  command jsonb NOT NULL,
  receipt jsonb NOT NULL,
  adopted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX subscription_hybrid_offer_adoptions_product_idx ON public.subscription_hybrid_offer_adoptions(product_id);
CREATE INDEX subscription_hybrid_offer_adoptions_actor_idx ON public.subscription_hybrid_offer_adoptions(actor_id);
REVOKE ALL ON public.subscription_hybrid_offer_adoptions FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON public.subscription_hybrid_offer_adoptions TO service_role;
CREATE FUNCTION public.reject_subscription_hybrid_offer_adoption_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'Hybrid offer adoption audit is immutable'; END;
$$;
CREATE TRIGGER subscription_hybrid_offer_adoptions_immutable_rows BEFORE UPDATE OR DELETE ON public.subscription_hybrid_offer_adoptions
FOR EACH ROW EXECUTE FUNCTION public.reject_subscription_hybrid_offer_adoption_mutation();
CREATE TRIGGER subscription_hybrid_offer_adoptions_immutable_truncate BEFORE TRUNCATE ON public.subscription_hybrid_offer_adoptions
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_hybrid_offer_adoption_mutation();
REVOKE ALL ON FUNCTION public.reject_subscription_hybrid_offer_adoption_mutation() FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.adopt_subscription_hybrid_catalog_offer(p_command jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid; product uuid; hybrid uuid; actor uuid; prior public.subscription_hybrid_offer_adoptions%ROWTYPE;
  v_plan public.plans%ROWTYPE; identity_receipt jsonb; receipt jsonb; v_after public.plans%ROWTYPE;
BEGIN
  IF jsonb_typeof(p_command) IS DISTINCT FROM 'object'
    OR (SELECT count(*) FROM jsonb_object_keys(p_command))<>9
    OR NOT p_command ?& ARRAY['schemaVersion','operationId','productId','actorId','approvalReference','hybridPlanId',
      'identity','expectedConfiguration','configuration']
    OR p_command->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR jsonb_typeof(p_command->'approvalReference') IS DISTINCT FROM 'string' OR btrim(p_command->>'approvalReference')=''
    OR jsonb_typeof(p_command->'identity') IS DISTINCT FROM 'object'
    OR jsonb_typeof(p_command->'expectedConfiguration') IS DISTINCT FROM 'object'
    OR jsonb_typeof(p_command->'configuration') IS DISTINCT FROM 'object'
    -- Only owner subscription sections are written; the prior row must hold none of them.
    OR EXISTS(SELECT 1 FROM jsonb_object_keys(p_command->'configuration') k WHERE k NOT LIKE 'subscription\_%')
    OR NOT EXISTS(SELECT 1 FROM jsonb_object_keys(p_command->'configuration'))
    OR EXISTS(SELECT 1 FROM jsonb_object_keys(p_command->'expectedConfiguration') k WHERE k LIKE 'subscription\_%')
    THEN RAISE EXCEPTION 'Exact Hybrid catalog adoption command required'; END IF;
  op:=(p_command->>'operationId')::uuid; product:=(p_command->>'productId')::uuid;
  hybrid:=(p_command->>'hybridPlanId')::uuid; actor:=(p_command->>'actorId')::uuid;
  IF (p_command#>>'{identity,operationId}')::uuid IS NOT DISTINCT FROM op
    OR (p_command#>>'{identity,productId}')::uuid IS DISTINCT FROM product
    OR (p_command#>>'{identity,actorId}')::uuid IS DISTINCT FROM actor
    OR (p_command#>>'{identity,hybridPlanId}')::uuid IS DISTINCT FROM hybrid
    THEN RAISE EXCEPTION 'Identity transition scope differs from the adoption'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_hybrid_offer_adoption:'||op::text,0));
  SELECT * INTO prior FROM public.subscription_hybrid_offer_adoptions WHERE operation_id=op;
  IF FOUND THEN
    IF prior.command IS DISTINCT FROM p_command THEN RAISE EXCEPTION 'Hybrid adoption replay conflicts'; END IF;
    RETURN prior.receipt;
  END IF;
  SELECT * INTO v_plan FROM public.plans WHERE id=hybrid AND product_id=product FOR UPDATE;
  IF NOT FOUND OR v_plan.is_active IS DISTINCT FROM true
    OR v_plan.entity_config IS DISTINCT FROM p_command->'expectedConfiguration'
    THEN RAISE EXCEPTION 'Hybrid configuration baseline differs'; END IF;
  -- Validates, compares and records the purchase cohort, then sets the opaque canonical code.
  identity_receipt:=public.commit_subscription_hybrid_identity_transition(p_command->'identity');
  UPDATE public.plans SET entity_config=v_plan.entity_config || (p_command->'configuration')
    WHERE id=hybrid AND product_id=product AND plan_code=p_command#>>'{identity,targetCode}';
  IF NOT FOUND THEN RAISE EXCEPTION 'Hybrid configuration compare and set failed'; END IF;
  SELECT * INTO v_after FROM public.plans WHERE id=hybrid;
  IF v_after.applicable_entities IS DISTINCT FROM v_plan.applicable_entities OR v_after.is_active IS DISTINCT FROM true
    OR v_after.business_type IS DISTINCT FROM v_plan.business_type OR v_after.name IS DISTINCT FROM v_plan.name
    THEN RAISE EXCEPTION 'Hybrid identity fields must be preserved'; END IF;
  receipt:=jsonb_build_object('operationId',op,'identity',identity_receipt,
    'plan',jsonb_build_object('id',hybrid,'code',v_after.plan_code,'productId',product),
    'configurationKeys',(SELECT jsonb_agg(k ORDER BY k) FROM jsonb_object_keys(p_command->'configuration') k));
  INSERT INTO public.subscription_hybrid_offer_adoptions(operation_id,product_id,actor_id,command,receipt) VALUES(op,product,actor,p_command,receipt);
  RETURN receipt;
END;
$$;
REVOKE ALL ON FUNCTION public.adopt_subscription_hybrid_catalog_offer(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.adopt_subscription_hybrid_catalog_offer(jsonb) TO service_role;
COMMIT;
