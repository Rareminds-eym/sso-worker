-- Bind promo quotes to the server-authorized delta and immutable published price.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE OR REPLACE FUNCTION public.issue_subscription_commerce_quote(p_identity jsonb,p_quote jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid:=(p_identity->>'operationId')::uuid; old public.subscription_commerce_operations%ROWTYPE;
  publication jsonb; draft jsonb; policy jsonb; selected jsonb; receipt jsonb; current_state jsonb; period_end numeric; source_publication jsonb; starts_paid_period boolean:=false; promo_adjustment numeric:=0; expected_amount numeric;
BEGIN
  IF jsonb_typeof(p_quote) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Complete commerce quote required'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(p_quote))<>20 OR NOT p_quote ?& ARRAY[
    'id','actorId','subscriptionId','productId','subject','audience','stateVersion','expectedRevisionId','planId','revisionId',
    'purpose','referenceId','priceId','amountMinor','currency','minorUnit','periodStartsAt','periodEndsAt','createdAt','validUntil']
    OR EXISTS(SELECT 1 FROM jsonb_each(p_quote) item WHERE item.key IN ('id','actorId','subscriptionId','productId','audience','expectedRevisionId','planId','revisionId','purpose','currency') AND jsonb_typeof(item.value) IS DISTINCT FROM 'string')
    OR EXISTS(SELECT 1 FROM jsonb_each(p_quote) item WHERE item.key IN ('stateVersion','amountMinor','minorUnit','periodStartsAt','periodEndsAt','createdAt','validUntil')
      AND CASE WHEN jsonb_typeof(item.value)='number' THEN (item.value#>>'{}')::numeric NOT BETWEEN 0 AND 9007199254740991 OR (item.value#>>'{}')::numeric<>trunc((item.value#>>'{}')::numeric) ELSE true END)
    OR p_quote->>'purpose' NOT IN ('purchase','renew','upgrade','retake') OR p_quote->>'currency'!~'^[A-Z]{3}$'
    OR (p_quote->>'amountMinor')::numeric<1 OR (p_quote->>'minorUnit')::numeric>length('9007199254740991')
    OR (p_quote->>'periodStartsAt')::numeric>=(p_quote->>'periodEndsAt')::numeric THEN RAISE EXCEPTION 'Malformed commerce quote'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_operation:'||op::text,0));
  SELECT * INTO old FROM public.subscription_commerce_operations WHERE operation_id=op;
  IF FOUND THEN
    IF old.identity IS DISTINCT FROM p_identity OR old.evidence IS DISTINCT FROM p_quote THEN RAISE EXCEPTION 'Commerce quote replay conflicts'; END IF;
    RETURN old.receipt;
  END IF;
  PERFORM public.assert_subscription_commerce_scope(p_identity,p_quote);
  IF p_quote->>'purpose'='purchase' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_purchase:'||(p_quote->'subject')::text||':'||(p_quote->>'productId'),0));
    IF EXISTS(SELECT 1 FROM public.subscriptions r WHERE r.product_id=(p_quote->>'productId')::uuid
      AND r.status IN ('active','pending','grace_period','paused')
      AND CASE WHEN p_quote#>>'{subject,kind}'='organization'
        THEN r.organization_id=(p_quote#>>'{subject,id}')::uuid AND r.is_organization_subscription IS TRUE
        ELSE r.user_id=(p_quote#>>'{subject,id}')::uuid AND r.is_organization_subscription IS NOT TRUE END)
      THEN RAISE EXCEPTION 'Existing subscription requires explicit lifecycle transition'; END IF;
  END IF;
  SELECT e.canonical_plan,d.snapshot INTO publication,draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id AND d.plan_id=e.plan_id
    WHERE e.revision_id=(p_quote->>'revisionId')::uuid AND e.plan_id=(p_quote->>'planId')::uuid;
  policy:=publication#>'{configuration,subscription_commerce}';
  IF publication IS NULL OR publication->'productId' IS DISTINCT FROM p_quote->'productId' OR draft->>'purchaseMode'<>'self_service'
    OR jsonb_typeof(publication#>'{configuration,subscription_lifecycle}') IS DISTINCT FROM 'object'
    OR publication#>'{configuration,subscription_lifecycle,productId}' IS DISTINCT FROM p_quote->'productId'
    OR publication#>>'{configuration,subscription_lifecycle,billing}'='not_applicable'
    OR (publication->'audiences' ? (p_quote->>'audience')) IS DISTINCT FROM true OR policy->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR p_quote->>'id' IS DISTINCT FROM op::text OR p_identity#>>'{request,kind}'<>'quote'
    OR p_identity#>'{request,revisionId}' IS DISTINCT FROM p_quote->'revisionId'
    OR p_identity#>'{request,purpose}' IS DISTINCT FROM p_quote->'purpose'
    OR (p_quote->>'amountMinor')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (p_quote->>'amountMinor')::numeric<>trunc((p_quote->>'amountMinor')::numeric)
    OR (p_quote->>'createdAt')::numeric>extract(epoch FROM clock_timestamp())*1000
    OR (p_quote->>'validUntil')::numeric<>(p_quote->>'createdAt')::numeric+(policy->>'quoteValidityMs')::numeric THEN
    RAISE EXCEPTION 'Commerce quote publication or policy differs';
  END IF;
  IF p_quote->>'purpose'<>'purchase' THEN
    SELECT lifecycle_state INTO current_state FROM public.subscriptions WHERE id=(p_quote->>'subscriptionId')::uuid;
    SELECT e.canonical_plan INTO source_publication FROM public.subscription_plan_publication_events e
      WHERE e.revision_id=(current_state->>'revisionId')::uuid AND e.plan_id=(current_state->>'planId')::uuid;
    starts_paid_period:=coalesce(p_quote->>'purpose'='upgrade'
      AND source_publication#>>'{configuration,subscription_lifecycle,billing}'='not_applicable'
      AND EXISTS(SELECT 1 FROM public.subscription_plan_drafts d WHERE d.id=(current_state->>'revisionId')::uuid AND d.snapshot->>'purchaseMode'='free')
      AND jsonb_typeof(publication#>'{configuration,subscription_lifecycle}')='object'
      AND publication#>>'{configuration,subscription_lifecycle,productId}'=p_quote->>'productId'
      AND publication#>>'{configuration,subscription_lifecycle,billing}' IS DISTINCT FROM 'not_applicable',false);
    IF NOT starts_paid_period AND NOT EXISTS(SELECT 1 FROM public.subscriptions WHERE id=(p_quote->>'subscriptionId')::uuid
      AND lifecycle_policy=publication#>'{configuration,subscription_lifecycle}') THEN RAISE EXCEPTION 'Target lifecycle policy differs'; END IF;
  END IF;
  IF p_quote->>'purpose'='retake' THEN
    IF p_quote->'amountMinor' IS DISTINCT FROM policy#>'{retake,amountMinor}' OR p_quote->'currency' IS DISTINCT FROM policy#>'{retake,currency}'
      OR p_quote->'minorUnit' IS DISTINCT FROM policy#>'{retake,minorUnit}' OR policy#>'{retake,everyRetake}' IS DISTINCT FROM 'true'::jsonb
      OR p_quote->'priceId' IS DISTINCT FROM 'null'::jsonb OR p_quote->'referenceId' IS DISTINCT FROM p_identity#>'{request,referenceId}'
      OR current_state->>'status' IS DISTINCT FROM 'active' OR current_state->'planId' IS DISTINCT FROM p_quote->'planId'
      OR current_state->'revisionId' IS DISTINCT FROM p_quote->'revisionId'
      OR current_state->'periodStartsAt' IS DISTINCT FROM p_quote->'periodStartsAt' OR current_state->'periodEndsAt' IS DISTINCT FROM p_quote->'periodEndsAt'
      OR (p_quote->>'createdAt')::numeric>=(current_state->>'periodEndsAt')::numeric
      OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(draft->'prices') x WHERE (x->>'amountMinor')::numeric>0 AND x->'audiences' ? (p_quote->>'audience')) THEN RAISE EXCEPTION 'Retake policy differs'; END IF;
  ELSE
    SELECT value INTO selected FROM jsonb_array_elements(draft->'prices') WHERE value->'id'=p_quote->'priceId';
    -- The service-only identity records the BFF-authorized accepted-price delta.
    -- Derive the final amount from the immutable published price; never trust a quote amount alone.
    IF (p_identity->'request') ? 'priceAdjustmentMinor' THEN
      IF p_quote->>'purpose' NOT IN ('purchase','upgrade')
        OR jsonb_typeof(p_identity#>'{request,priceAdjustmentMinor}') IS DISTINCT FROM 'number' THEN
        RAISE EXCEPTION 'Invalid commerce promo adjustment';
      END IF;
      promo_adjustment:=(p_identity#>>'{request,priceAdjustmentMinor}')::numeric;
      IF promo_adjustment<>trunc(promo_adjustment) OR promo_adjustment NOT BETWEEN -9007199254740991 AND 1000000 THEN
        RAISE EXCEPTION 'Invalid commerce promo adjustment';
      END IF;
    END IF;
    expected_amount:=(selected->>'amountMinor')::numeric+promo_adjustment;
    IF expected_amount NOT BETWEEN 1 AND 9007199254740991 THEN RAISE EXCEPTION 'Invalid adjusted commerce price'; END IF;
    IF selected IS NULL OR selected->>'quantityBasis'<>'subscription' OR NOT (selected->'audiences' ? (p_quote->>'audience'))
      OR selected->'currency' IS DISTINCT FROM p_quote->'currency' OR selected->'minorUnit' IS DISTINCT FROM p_quote->'minorUnit'
      OR expected_amount IS DISTINCT FROM (p_quote->>'amountMinor')::numeric OR p_quote->'referenceId' IS DISTINCT FROM 'null'::jsonb
      OR p_quote->'priceId' IS DISTINCT FROM p_identity#>'{request,priceId}' THEN RAISE EXCEPTION 'Published price differs'; END IF;
    IF p_quote->>'purpose'='upgrade' THEN
      IF current_state->>'status' IS DISTINCT FROM 'active' OR current_state->'scheduledChange' IS DISTINCT FROM 'null'::jsonb
        OR current_state->'revisionId'=p_quote->'revisionId'
        OR (current_state->'periodEndsAt'<>'null'::jsonb AND (p_quote->>'createdAt')::numeric>=(current_state->>'periodEndsAt')::numeric)
        OR NOT EXISTS(SELECT 1 FROM public.subscription_plan_publication_events e,
          LATERAL jsonb_array_elements(e.canonical_plan#>'{configuration,subscription_revision_changes}') c
          WHERE e.revision_id IN ((current_state->>'revisionId')::uuid,(p_quote->>'revisionId')::uuid)
            AND e.canonical_plan->'productId'=p_quote->'productId' AND c->'fromRevisionId'=current_state->'revisionId'
            AND c->'toRevisionId'=p_quote->'revisionId' AND c->>'operation'='upgrade') THEN RAISE EXCEPTION 'Approved upgrade required'; END IF;
    END IF;
    IF p_quote->>'purpose'='upgrade' AND NOT starts_paid_period THEN
      IF current_state->'periodStartsAt' IS DISTINCT FROM p_quote->'periodStartsAt'
        OR current_state->'periodEndsAt' IS DISTINCT FROM p_quote->'periodEndsAt' THEN RAISE EXCEPTION 'Paid upgrade period differs'; END IF;
    ELSE
      period_end:=extract(epoch FROM ((to_timestamp((p_quote->>'periodStartsAt')::numeric/1000) AT TIME ZONE 'UTC'
        + CASE selected->>'intervalUnit' WHEN 'month' THEN make_interval(months=>(selected->>'intervalCount')::integer)
          WHEN 'year' THEN make_interval(years=>(selected->>'intervalCount')::integer) END) AT TIME ZONE 'UTC'))*1000;
      IF period_end IS DISTINCT FROM (p_quote->>'periodEndsAt')::numeric THEN RAISE EXCEPTION 'Configured billing period differs'; END IF;
      IF p_quote->>'purpose'='purchase' THEN
        IF p_quote->'periodStartsAt' IS DISTINCT FROM p_quote->'createdAt' OR p_quote->'expectedRevisionId' IS DISTINCT FROM p_quote->'revisionId' THEN RAISE EXCEPTION 'Initial purchase anchor differs'; END IF;
      ELSIF starts_paid_period THEN
        IF p_quote->'periodStartsAt' IS DISTINCT FROM p_quote->'createdAt' THEN RAISE EXCEPTION 'First paid period anchor differs'; END IF;
      ELSE
        IF p_quote->'periodStartsAt' IS DISTINCT FROM (CASE WHEN current_state->'trialEndsAt'='null'::jsonb THEN current_state->'periodEndsAt' ELSE current_state->'trialEndsAt' END)
          OR (p_quote->>'createdAt')::numeric<(p_quote->>'periodStartsAt')::numeric
          OR p_quote->'revisionId' IS DISTINCT FROM (CASE WHEN current_state->'scheduledChange'='null'::jsonb THEN current_state->'revisionId' ELSE current_state#>'{scheduledChange,revisionId}' END) THEN RAISE EXCEPTION 'Renewal anchor or scheduled revision differs'; END IF;
      END IF;
    END IF;
  END IF;
  receipt:=jsonb_build_object('kind','quote','operationId',op,'quote',p_quote);
  INSERT INTO public.subscription_commerce_operations(operation_id,identity,evidence,receipt) VALUES(op,p_identity,p_quote,receipt);
  INSERT INTO public.subscription_commerce_quotes(id,quote) VALUES(op,p_quote);
  RETURN receipt;
END;
$$;

COMMIT;
