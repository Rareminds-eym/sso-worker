-- Complete checkout preparation. Apply only as an explicitly approved deployment.
-- Existing revisions, quotes, captures and operation evidence remain immutable.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE OR REPLACE FUNCTION public.issue_subscription_commerce_quote(p_identity jsonb,p_quote jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid:=(p_identity->>'operationId')::uuid; old public.subscription_commerce_operations%ROWTYPE;
  publication jsonb; draft jsonb; policy jsonb; selected jsonb; receipt jsonb; current_state jsonb; period_end numeric; source_publication jsonb; starts_paid_period boolean:=false;
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
    IF selected IS NULL OR selected->>'quantityBasis'<>'subscription' OR NOT (selected->'audiences' ? (p_quote->>'audience'))
      OR selected->'currency' IS DISTINCT FROM p_quote->'currency' OR selected->'minorUnit' IS DISTINCT FROM p_quote->'minorUnit'
      OR selected->'amountMinor' IS DISTINCT FROM p_quote->'amountMinor' OR p_quote->'referenceId' IS DISTINCT FROM 'null'::jsonb
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

CREATE OR REPLACE FUNCTION public.commit_subscription_lifecycle(p_identity jsonb, p_decision jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_op uuid; v_actor uuid; v_state jsonb; v_next jsonb; v_request jsonb; v_policy jsonb;
  v_row public.subscriptions%ROWTYPE; v_old public.subscription_lifecycle_operations%ROWTYPE;
  v_tx public.transactions%ROWTYPE; v_quote jsonb; v_settlement jsonb; v_transaction uuid;
  v_target jsonb; v_scheduled jsonb; v_currency jsonb; v_minor integer; v_amount numeric;
  v_receipt jsonb; v_at timestamptz; v_operation text; v_current_publication jsonb;
  v_expected_downgraded_at jsonb; v_effective_downgrade numeric; v_starts_paid_period boolean:=false; v_target_draft jsonb;
BEGIN
  IF jsonb_typeof(p_identity) IS DISTINCT FROM 'object' OR jsonb_typeof(p_decision) IS DISTINCT FROM 'object'
    OR NOT p_identity ?& ARRAY['operationId','state','request','policy','actorId','subject','quote','settlement','approval','revisionChanges']
    OR ((SELECT count(*) FROM jsonb_object_keys(p_identity)) <> 10
      AND NOT ((SELECT count(*) FROM jsonb_object_keys(p_identity))=11 AND p_identity ? 'capture'))
    OR NOT p_decision ?& ARRAY['expectedVersion','expectedRevisionId','next','access','retryAt','audit']
    OR (SELECT count(*) FROM jsonb_object_keys(p_decision)) <> 6
    OR jsonb_typeof(p_decision->'audit') IS DISTINCT FROM 'object'
    OR jsonb_typeof(p_decision->'retryAt') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invalid lifecycle identity'; END IF;
  v_op := (p_identity->>'operationId')::uuid; v_actor := (p_identity->>'actorId')::uuid;
  v_state := p_identity->'state'; v_request := p_identity->'request'; v_policy := p_identity->'policy'; v_next := p_decision->'next';
  v_operation := v_request->>'operation';
  IF v_op IS NULL OR v_actor IS NULL THEN RAISE EXCEPTION 'Lifecycle identity required'; END IF;
  -- Operation lock precedes the subscription lock; exact replay is read before current-state CAS.
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_lifecycle_operation:' || v_op::text,0));
  SELECT * INTO v_old FROM public.subscription_lifecycle_operations WHERE operation_id = v_op;
  IF FOUND THEN
    IF v_old.kind <> 'transition' OR v_old.identity IS DISTINCT FROM p_identity THEN RAISE EXCEPTION 'Lifecycle replay conflicts'; END IF;
    RETURN v_old.receipt;
  END IF;
  SELECT * INTO v_row FROM public.subscriptions WHERE id = (v_state->>'id')::uuid FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Existing lifecycle subscription required'; END IF;
  PERFORM public.assert_subscription_lifecycle_binding(v_row);
  SELECT canonical_plan INTO v_current_publication FROM public.subscription_plan_publication_events WHERE revision_id=v_row.plan_revision_id AND plan_id=v_row.plan_id;
  SELECT e.canonical_plan,d.snapshot INTO v_target,v_target_draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id AND d.plan_id=e.plan_id
    WHERE e.plan_id=(v_next->>'planId')::uuid AND e.revision_id=(v_next->>'revisionId')::uuid;
  IF jsonb_typeof(p_identity->'revisionChanges') IS DISTINCT FROM 'array'
    OR EXISTS(SELECT value FROM jsonb_array_elements(p_identity->'revisionChanges')
      EXCEPT SELECT value FROM jsonb_array_elements(coalesce(v_current_publication#>'{configuration,subscription_revision_changes}','[]'::jsonb)
        ||coalesce(v_target#>'{configuration,subscription_revision_changes}','[]'::jsonb)))
    OR EXISTS(SELECT value FROM jsonb_array_elements(coalesce(v_current_publication#>'{configuration,subscription_revision_changes}','[]'::jsonb))
      EXCEPT SELECT value FROM jsonb_array_elements(p_identity->'revisionChanges')) THEN RAISE EXCEPTION 'Exact owner-published revision directions required'; END IF;
  v_starts_paid_period:=coalesce(v_operation='upgrade' AND v_policy->>'billing'='not_applicable'
    AND EXISTS(SELECT 1 FROM public.subscription_plan_drafts WHERE id=v_row.plan_revision_id AND snapshot->>'purchaseMode'='free')
    AND v_target_draft->>'purchaseMode'='self_service'
    AND jsonb_typeof(v_target#>'{configuration,subscription_lifecycle}')='object'
    AND v_target#>>'{configuration,subscription_lifecycle,productId}'=v_state->>'productId'
    AND v_target#>>'{configuration,subscription_lifecycle,billing}' IS DISTINCT FROM 'not_applicable',false);
  IF v_operation IN ('upgrade','downgrade') AND NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_identity->'revisionChanges') change
      WHERE change->'fromRevisionId'=v_state->'revisionId' AND change->>'operation'=v_operation
        AND change->'toRevisionId'=CASE WHEN v_operation='upgrade' THEN p_identity#>'{quote,revisionId}' ELSE v_request->'targetRevisionId' END
  ) THEN RAISE EXCEPTION 'Owner-published transition direction required'; END IF;
  IF v_row.lifecycle_state IS DISTINCT FROM v_state OR v_row.lifecycle_policy IS DISTINCT FROM v_policy
    OR v_request->'subject' IS DISTINCT FROM v_state->'subject' OR p_identity->'subject' IS DISTINCT FROM v_state->'subject'
    OR v_request->'subscriptionId' IS DISTINCT FROM v_state->'id'
    OR v_request->'expectedVersion' IS DISTINCT FROM v_state->'version' OR v_request->'expectedRevisionId' IS DISTINCT FROM v_state->'revisionId'
    OR p_decision->'expectedVersion' IS DISTINCT FROM v_state->'version' OR p_decision->'expectedRevisionId' IS DISTINCT FROM v_state->'revisionId'
    OR v_next->'id' IS DISTINCT FROM v_state->'id' OR v_next->'subject' IS DISTINCT FROM v_state->'subject'
    OR v_next->'productId' IS DISTINCT FROM v_state->'productId'
    OR (v_next->>'version')::numeric IS DISTINCT FROM (v_state->>'version')::numeric + 1
    OR p_decision#>>'{audit,actorId}' IS DISTINCT FROM v_actor::text
    OR p_decision#>'{audit,policyId}' IS DISTINCT FROM v_policy->'id'
    OR p_decision#>'{audit,policyVersion}' IS DISTINCT FROM v_policy->'version'
    OR p_decision#>>'{audit,operation}' IS DISTINCT FROM v_operation
    OR p_decision#>'{audit,reason}' IS DISTINCT FROM v_request->'reason'
    OR length(btrim(v_request->>'reason')) = 0
    OR (p_decision#>>'{audit,at}')::numeric > extract(epoch FROM clock_timestamp()) * 1000
    OR v_operation NOT IN ('upgrade','renew','downgrade','cancel','expire','payment_failed','suspend','reactivate') THEN
    RAISE EXCEPTION 'Lifecycle CAS, subject, policy or audit differs';
  END IF;
  IF p_identity->'approval' IS DISTINCT FROM 'null'::jsonb OR v_request ? 'approvalId'
    OR (v_operation='suspend' AND (v_policy->>'suspensionApprovalRequired')::boolean)
    OR (v_operation='reactivate' AND (v_policy->>'reactivationApprovalRequired')::boolean) THEN RAISE EXCEPTION 'Lifecycle approval owner is unavailable'; END IF;
  SELECT canonical_plan INTO v_target FROM public.subscription_plan_publication_events
    WHERE plan_id=(v_next->>'planId')::uuid AND revision_id=(v_next->>'revisionId')::uuid;
  IF v_target IS NULL OR v_target->>'productId' IS DISTINCT FROM v_state->>'productId'
    OR v_target->>'id' IS DISTINCT FROM v_next->>'planId'
    OR (NOT v_starts_paid_period AND v_target#>'{configuration,subscription_lifecycle}' IS DISTINCT FROM v_policy) THEN RAISE EXCEPTION 'Published target and exact policy required'; END IF;
  IF v_next->'scheduledChange' IS DISTINCT FROM 'null'::jsonb THEN
    SELECT canonical_plan INTO v_scheduled FROM public.subscription_plan_publication_events
      WHERE plan_id=(v_next#>>'{scheduledChange,planId}')::uuid AND revision_id=(v_next#>>'{scheduledChange,revisionId}')::uuid;
    IF v_scheduled IS NULL OR v_scheduled->>'productId' IS DISTINCT FROM v_state->>'productId' THEN RAISE EXCEPTION 'Published scheduled target required'; END IF;
  END IF;
  IF v_starts_paid_period THEN
    IF v_next ? 'validity' OR v_next->'renewalEnabled' IS DISTINCT FROM 'true'::jsonb
      OR ((v_target#>'{configuration,subscription_lifecycle}' ? 'readOnlyDurationMs')
        AND v_next->'downgradedAt' IS DISTINCT FROM 'null'::jsonb)
      OR ((NOT (v_target#>'{configuration,subscription_lifecycle}' ? 'readOnlyDurationMs')) AND v_next ? 'downgradedAt')
      THEN RAISE EXCEPTION 'First paid period state differs'; END IF;
  ELSIF v_policy ? 'readOnlyDurationMs' THEN
    IF jsonb_typeof(p_decision#>'{audit,at}') IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'Invalid lifecycle retention event time'; END IF;
    IF (p_decision#>>'{audit,at}')::numeric NOT BETWEEN 0 AND 9007199254740991
      OR (p_decision#>>'{audit,at}')::numeric <> trunc((p_decision#>>'{audit,at}')::numeric) THEN RAISE EXCEPTION 'Invalid lifecycle retention event time'; END IF;
    v_expected_downgraded_at := v_state->'downgradedAt';
    IF v_operation='downgrade' AND v_request->>'timing'='immediate' THEN
      v_effective_downgrade := (p_decision#>>'{audit,at}')::numeric;
    ELSIF v_operation='renew' AND v_state->'scheduledChange' <> 'null'::jsonb THEN
      v_effective_downgrade := (v_state#>>'{scheduledChange,effectiveAt}')::numeric;
    END IF;
    IF v_effective_downgrade IS NOT NULL THEN
      IF v_expected_downgraded_at='null'::jsonb THEN v_expected_downgraded_at := to_jsonb(v_effective_downgrade);
      ELSE v_expected_downgraded_at := to_jsonb(least((v_expected_downgraded_at#>>'{}')::numeric,v_effective_downgrade)); END IF;
    END IF;
    IF v_next->'downgradedAt' IS DISTINCT FROM v_expected_downgraded_at THEN RAISE EXCEPTION 'Lifecycle retention clock differs'; END IF;
  END IF;
  IF p_identity ? 'capture' AND v_operation NOT IN ('upgrade','renew') THEN RAISE EXCEPTION 'Capture evidence applies only to paid lifecycle settlement'; END IF;
  IF v_operation IN ('upgrade','renew') THEN
    v_quote := p_identity->'quote'; v_settlement := p_identity->'settlement';
    -- JSON null/missing numerics produce SQL NULL in comparisons. Validate the exact
    -- payment envelopes before any binding/expiry comparison so malformed evidence
    -- cannot make a rejection predicate unknown and pass through PL/pgSQL IF.
    IF jsonb_typeof(v_quote) IS DISTINCT FROM 'object' OR jsonb_typeof(v_settlement) IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'Invalid lifecycle payment evidence';
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(v_quote)) <> 13
      OR NOT v_quote ?& ARRAY['id','subscriptionId','subject','stateVersion','operation','planId','revisionId','productId','currency','amountMinor','periodStartsAt','periodEndsAt','validUntil']
      OR (SELECT count(*) FROM jsonb_object_keys(v_settlement)) <> 12
      OR NOT v_settlement ?& ARRAY['id','quoteId','subscriptionId','subject','stateVersion','revisionId','amountMinor','currency','operation','kind','recordedAt','validUntil']
      OR EXISTS (SELECT 1 FROM jsonb_each(v_quote) item WHERE item.key IN ('id','subscriptionId','operation','planId','revisionId','productId','currency') AND jsonb_typeof(item.value) IS DISTINCT FROM 'string')
      OR EXISTS (SELECT 1 FROM jsonb_each(v_settlement) item WHERE item.key IN ('id','quoteId','subscriptionId','revisionId','currency','operation','kind') AND jsonb_typeof(item.value) IS DISTINCT FROM 'string')
      OR EXISTS (SELECT 1 FROM jsonb_each(v_quote) item WHERE item.key IN ('stateVersion','amountMinor','periodStartsAt','periodEndsAt','validUntil')
        AND CASE WHEN jsonb_typeof(item.value)='number' THEN
          (item.value#>>'{}')::numeric NOT BETWEEN 0 AND 9007199254740991 OR (item.value#>>'{}')::numeric <> trunc((item.value#>>'{}')::numeric) ELSE true END)
      OR EXISTS (SELECT 1 FROM jsonb_each(v_settlement) item WHERE item.key IN ('stateVersion','amountMinor','recordedAt','validUntil')
        AND NOT (item.key='validUntil' AND item.value='null'::jsonb)
        AND CASE WHEN jsonb_typeof(item.value)='number' THEN
          (item.value#>>'{}')::numeric NOT BETWEEN 0 AND 9007199254740991 OR (item.value#>>'{}')::numeric <> trunc((item.value#>>'{}')::numeric) ELSE true END) THEN
      RAISE EXCEPTION 'Invalid lifecycle payment evidence';
    END IF;
    IF v_settlement->>'kind' IS DISTINCT FROM 'verified_payment' THEN RAISE EXCEPTION 'Approved invoice owner is unavailable'; END IF;
    IF p_identity ? 'capture' AND NOT EXISTS(
      SELECT 1 FROM public.subscription_commerce_captures c
      JOIN public.subscription_commerce_quotes q ON q.id=c.quote_id AND q.provider_order_id=c.provider_order_id
      JOIN public.subscription_commerce_settlements s ON s.quote_id=q.id AND s.provider_payment_id=c.provider_payment_id
      WHERE s.id=(v_settlement->>'id')::uuid AND q.id=(v_quote->>'id')::uuid
        AND q.quote->'actorId'=p_identity->'actorId'
        AND public.subscription_commerce_has_timely_capture(v_quote,c.provider_payment_id,s.id)
        AND p_identity->'capture'=jsonb_build_object('eventId',c.event_id,'actorId',q.quote->'actorId','quoteId',q.id,'settlementId',s.id,
          'productId',q.quote->'productId','subscriptionId',q.quote->'subscriptionId','subject',q.quote->'subject','stateVersion',q.quote->'stateVersion',
          'revisionId',q.quote->'revisionId','amountMinor',c.amount_minor,'currency',c.currency,'providerPaymentId',c.provider_payment_id,
          'providerOrderId',c.provider_order_id,'capturedAt',c.captured_at_ms,'paymentCreatedAt',c.payment_created_at_ms,'quoteCreatedAt',q.quote->'createdAt')
    ) THEN RAISE EXCEPTION 'Lifecycle capture witness differs from immutable payment owner'; END IF;
    IF v_settlement->'quoteId' IS DISTINCT FROM v_quote->'id' OR v_request->'quoteId' IS DISTINCT FROM v_quote->'id'
      OR v_request->'settlementId' IS DISTINCT FROM v_settlement->'id'
      OR v_quote->'subscriptionId' IS DISTINCT FROM v_state->'id' OR v_settlement->'subscriptionId' IS DISTINCT FROM v_state->'id'
      OR v_quote->'subject' IS DISTINCT FROM v_state->'subject' OR v_settlement->'subject' IS DISTINCT FROM v_state->'subject'
      OR v_quote->'stateVersion' IS DISTINCT FROM v_state->'version' OR v_settlement->'stateVersion' IS DISTINCT FROM v_state->'version'
      OR v_quote->'productId' IS DISTINCT FROM v_state->'productId' OR v_quote->'revisionId' IS DISTINCT FROM v_next->'revisionId'
      OR v_quote->'planId' IS DISTINCT FROM v_next->'planId' OR v_settlement->'revisionId' IS DISTINCT FROM v_next->'revisionId'
      OR v_quote->>'operation' IS DISTINCT FROM v_operation OR v_settlement->>'operation' IS DISTINCT FROM v_operation
      OR v_quote->'currency' IS DISTINCT FROM v_settlement->'currency' OR v_quote->'amountMinor' IS DISTINCT FROM v_settlement->'amountMinor'
      OR v_quote->'periodStartsAt' IS DISTINCT FROM v_next->'periodStartsAt' OR v_quote->'periodEndsAt' IS DISTINCT FROM v_next->'periodEndsAt'
      OR ((v_quote->>'validUntil')::numeric <= extract(epoch FROM clock_timestamp()) * 1000
        AND (NOT (p_identity ? 'capture') OR NOT public.subscription_commerce_has_timely_capture(v_quote,NULL,(v_settlement->>'id')::uuid)))
      OR (v_settlement->>'recordedAt')::numeric > (p_decision#>>'{audit,at}')::numeric
      OR (v_settlement->'validUntil' <> 'null'::jsonb AND (v_settlement->>'validUntil')::numeric <= extract(epoch FROM clock_timestamp()) * 1000) THEN RAISE EXCEPTION 'Settlement lifecycle binding differs'; END IF;
    SELECT value INTO v_currency FROM jsonb_array_elements(v_target#>'{configuration,subscription_authoring,currencies}') WHERE value->>'code'=v_quote->>'currency';
    IF v_currency IS NULL THEN RAISE EXCEPTION 'Explicit published currency required'; END IF;
    v_minor := (v_currency->>'minorUnit')::integer;
    -- The decision engine exposes safe-integer minor amounts; higher precision cannot represent
    -- any nonzero numeric(10,2) owner amount in that public contract.
    IF v_minor IS NULL OR v_minor < 0 OR v_minor > length('9007199254740991') THEN RAISE EXCEPTION 'Currency precision exceeds exact execution bounds'; END IF;
    v_transaction := (v_settlement->>'id')::uuid;
    SELECT * INTO v_tx FROM public.transactions WHERE id=v_transaction FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Completed transaction owner required'; END IF;
    v_amount := v_tx.amount * power(10::numeric,v_minor);
    IF v_tx.status <> 'completed' OR v_tx.subscription_id IS DISTINCT FROM v_row.id OR v_tx.product_id IS DISTINCT FROM v_row.product_id
      OR v_tx.user_id IS DISTINCT FROM v_row.user_id OR v_tx.organization_id IS DISTINCT FROM v_row.organization_id
      OR v_tx.transaction_type IS DISTINCT FROM (CASE WHEN v_operation='upgrade' THEN 'upgrade' ELSE 'subscription' END)
      OR v_tx.currency IS DISTINCT FROM v_quote->>'currency' OR v_amount <> trunc(v_amount)
      OR v_amount IS DISTINCT FROM (v_quote->>'amountMinor')::numeric
      OR (v_state#>>'{subject,kind}'='organization' AND v_tx.organization_id IS DISTINCT FROM (v_state#>>'{subject,id}')::uuid)
      OR (v_state#>>'{subject,kind}'='user' AND v_tx.user_id IS DISTINCT FROM (v_state#>>'{subject,id}')::uuid)
      OR floor(extract(epoch FROM v_tx.updated_at)*1000) IS DISTINCT FROM (v_settlement->>'recordedAt')::numeric
      OR v_tx.metadata->'subscription_lifecycle' IS DISTINCT FROM jsonb_build_object('productId',v_state->'productId','quote',v_quote,'settlement',v_settlement,'currencyMinorUnit',v_minor) THEN
      RAISE EXCEPTION 'Completed transaction evidence differs';
    END IF;
    -- Unique transaction_id additionally serializes competing subscription/operation claims.
    IF EXISTS (SELECT 1 FROM public.subscription_lifecycle_operations WHERE transaction_id=v_transaction) THEN RAISE EXCEPTION 'Settlement already consumed'; END IF;
  ELSIF p_identity->'quote' IS DISTINCT FROM 'null'::jsonb OR p_identity->'settlement' IS DISTINCT FROM 'null'::jsonb THEN
    RAISE EXCEPTION 'Settlement is not applicable to lifecycle operation';
  END IF;
  -- The trusted worker's existing decision engine owns business transitions. SQL verifies owner
  -- evidence and an exact CAS; it does not add alternate business rules or silently recover errors.
  v_at := clock_timestamp();
  v_receipt := jsonb_build_object('operationId',v_op,'decision',p_decision,'committedAt',v_at);
  INSERT INTO public.subscription_lifecycle_operations(operation_id,subscription_id,actor_id,transaction_id,kind,identity,receipt,committed_at)
    VALUES(v_op,v_row.id,v_actor,v_transaction,'transition',p_identity,v_receipt,v_at);
  INSERT INTO public.subscription_lifecycle_effect_intents(operation_id,payload)
    VALUES(v_op,jsonb_build_object('subscriptionId',v_row.id,'audit',p_decision->'audit','retryAt',p_decision->'retryAt','access',p_decision->'access','notification',jsonb_build_object('operation',v_operation,'subject',v_state->'subject')));
  UPDATE public.subscriptions SET lifecycle_state=v_next,
    lifecycle_policy=CASE WHEN v_starts_paid_period THEN v_target#>'{configuration,subscription_lifecycle}' ELSE v_row.lifecycle_policy END,
    plan_code=CASE WHEN v_operation IN ('upgrade','renew') THEN v_target->>'code' ELSE v_row.plan_code END,
    plan_type=CASE WHEN v_operation IN ('upgrade','renew') THEN v_target_draft->>'name' ELSE v_row.plan_type END,
    features=CASE WHEN v_operation IN ('upgrade','renew') THEN v_target_draft->'features' ELSE v_row.features END,
    plan_amount=CASE WHEN v_operation IN ('upgrade','renew') THEN v_tx.amount ELSE v_row.plan_amount END,
    billing_cycle=CASE WHEN v_operation IN ('upgrade','renew') THEN
      (SELECT CASE value->>'intervalUnit' WHEN 'month' THEN 'monthly' WHEN 'year' THEN 'yearly' END
        FROM public.subscription_commerce_quotes cq, LATERAL jsonb_array_elements(v_target_draft->'prices') value
        WHERE cq.id=(v_quote->>'id')::uuid AND value->'id'=cq.quote->'priceId') ELSE v_row.billing_cycle END,
    razorpay_order_id=CASE WHEN v_operation IN ('upgrade','renew') THEN v_tx.razorpay_order_id ELSE v_row.razorpay_order_id END,
    razorpay_payment_id=CASE WHEN v_operation IN ('upgrade','renew') THEN v_tx.razorpay_payment_id ELSE v_row.razorpay_payment_id END,
    plan_id=(v_next->>'planId')::uuid,
    metadata=CASE WHEN v_operation IN ('renew','upgrade')
      AND (v_starts_paid_period OR (v_quote->>'periodEndsAt')::numeric>(v_row.metadata#>>'{subscription_execution,subscriptionEndsAt}')::numeric)
      THEN jsonb_set(v_row.metadata,'{subscription_execution,subscriptionEndsAt}',v_quote->'periodEndsAt') ELSE v_row.metadata END,
    plan_revision_id=(v_next->>'revisionId')::uuid, status=v_next->>'status',auto_renew=(v_next->>'renewalEnabled')::boolean,
    paused_at=CASE WHEN v_operation='suspend' THEN to_timestamp((p_decision#>>'{audit,at}')::numeric/1000) WHEN v_operation='reactivate' THEN NULL ELSE v_row.paused_at END,
    cancellation_reason=CASE WHEN v_operation='cancel' THEN v_request->>'reason' ELSE v_row.cancellation_reason END,
    cancelled_by=CASE WHEN v_operation='cancel' THEN v_actor::text ELSE v_row.cancelled_by END,
    subscription_start_date=to_timestamp((v_next->>'periodStartsAt')::numeric/1000),
    subscription_end_date=to_timestamp((v_next->>'periodEndsAt')::numeric/1000),
    cancelled_at=CASE WHEN v_next->'cancelledAt'='null'::jsonb THEN NULL ELSE to_timestamp((v_next->>'cancelledAt')::numeric/1000) END
    WHERE id=v_row.id AND lifecycle_state=v_state AND plan_revision_id=(v_state->>'revisionId')::uuid;
  IF NOT FOUND THEN RAISE EXCEPTION 'Lifecycle compare-and-set failed'; END IF;
  RETURN v_receipt;
END;
$$;

CREATE OR REPLACE FUNCTION public.guard_subscription_lifecycle_binding()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    IF EXISTS (SELECT 1 FROM public.subscriptions WHERE lifecycle_state IS NOT NULL) THEN RAISE EXCEPTION 'Bound subscriptions cannot be truncated'; END IF;
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF OLD.lifecycle_state IS NOT NULL THEN RAISE EXCEPTION 'Bound subscription cannot be deleted'; END IF;
    RETURN OLD;
  END IF;
  IF NEW.lifecycle_state IS NULL THEN
    IF TG_OP = 'UPDATE' AND OLD.lifecycle_state IS NOT NULL THEN RAISE EXCEPTION 'Lifecycle binding cannot be removed'; END IF;
    RETURN NEW;
  END IF;
  PERFORM public.assert_subscription_lifecycle_binding(NEW);
  IF TG_OP = 'INSERT' THEN RAISE EXCEPTION 'Lifecycle initialization requires an existing subscription'; END IF;
  IF OLD.lifecycle_state IS NULL THEN
    IF NOT EXISTS (SELECT 1 FROM public.subscription_lifecycle_operations o WHERE o.subscription_id = NEW.id AND o.kind = 'initialize'
      AND o.receipt->'state' = NEW.lifecycle_state AND o.receipt->'policy' = NEW.lifecycle_policy
      AND (o.receipt->>'activatedAt')::timestamptz = NEW.lifecycle_activated_at) THEN
      RAISE EXCEPTION 'Explicit initialization evidence required';
    END IF;
  ELSE
    IF NEW.lifecycle_activated_at IS DISTINCT FROM OLD.lifecycle_activated_at THEN RAISE EXCEPTION 'Lifecycle activation is immutable'; END IF;
    IF NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
      OR NEW.is_organization_subscription IS DISTINCT FROM OLD.is_organization_subscription OR NEW.product_id IS DISTINCT FROM OLD.product_id THEN RAISE EXCEPTION 'Lifecycle subscriber identity is immutable'; END IF;
    IF NEW.metadata->'subscription_execution' IS DISTINCT FROM OLD.metadata->'subscription_execution' THEN
      -- A paid renewal/upgrade may extend, never shorten or reassign, purchased coverage.
      -- The immutable operation is inserted by the settlement-verifying commit in this transaction.
      IF NOT EXISTS (SELECT 1 FROM public.subscription_lifecycle_operations o
        WHERE o.subscription_id=NEW.id AND o.kind='transition' AND o.transaction_id IS NOT NULL
          AND o.identity->'state'=OLD.lifecycle_state AND o.receipt#>'{decision,next}'=NEW.lifecycle_state
          AND o.receipt#>>'{decision,audit,operation}' IN ('renew','upgrade')
          AND o.identity#>'{quote,periodEndsAt}'=NEW.metadata#>'{subscription_execution,subscriptionEndsAt}'
          AND ((NEW.metadata#>>'{subscription_execution,subscriptionEndsAt}')::numeric>(OLD.metadata#>>'{subscription_execution,subscriptionEndsAt}')::numeric
            OR (OLD.lifecycle_policy->>'billing'='not_applicable' AND o.receipt#>>'{decision,audit,operation}'='upgrade'
              AND OLD.metadata#>'{subscription_execution,subscriptionEndsAt}'='null'::jsonb))
          AND NEW.metadata->'subscription_execution'=jsonb_set(OLD.metadata->'subscription_execution','{subscriptionEndsAt}',o.identity#>'{quote,periodEndsAt}')) THEN
        RAISE EXCEPTION 'Paid contract amendment evidence required';
      END IF;
    END IF;
    IF NEW.lifecycle_state IS DISTINCT FROM OLD.lifecycle_state OR NEW.lifecycle_policy IS DISTINCT FROM OLD.lifecycle_policy THEN
      IF NOT EXISTS (SELECT 1 FROM public.subscription_lifecycle_operations o WHERE o.subscription_id = NEW.id AND o.kind = 'transition'
        AND o.identity->'state' = OLD.lifecycle_state AND o.identity->'policy' = OLD.lifecycle_policy
        AND o.receipt#>'{decision,next}' = NEW.lifecycle_state
        AND o.receipt#>'{decision,audit,policyId}' = OLD.lifecycle_policy->'id'
        AND (NEW.lifecycle_policy = OLD.lifecycle_policy OR (OLD.lifecycle_policy->>'billing'='not_applicable'
          AND o.receipt#>>'{decision,audit,operation}'='upgrade' AND o.transaction_id IS NOT NULL
          AND NEW.lifecycle_policy->>'billing' IS DISTINCT FROM 'not_applicable'
          AND EXISTS(SELECT 1 FROM public.subscription_plan_publication_events e
            WHERE e.revision_id=NEW.plan_revision_id AND e.plan_id=NEW.plan_id
              AND e.canonical_plan#>'{configuration,subscription_lifecycle}'=NEW.lifecycle_policy)))) THEN
        RAISE EXCEPTION 'Atomic lifecycle transition evidence required';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- The old monetary recorder is private. Only the atomic owner API is executable by the worker.
ALTER FUNCTION public.settle_subscription_commerce_payment(jsonb,jsonb,jsonb,jsonb) RENAME TO record_subscription_commerce_payment;
REVOKE ALL ON FUNCTION public.record_subscription_commerce_payment(jsonb,jsonb,jsonb,jsonb) FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.settle_subscription_commerce_payment(p_identity jsonb,p_settlement jsonb,p_order jsonb,p_payment jsonb,
  p_lifecycle_identity jsonb DEFAULT NULL,p_lifecycle_decision jsonb DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb; q jsonb; activation jsonb;
BEGIN
  SELECT quote INTO q FROM public.subscription_commerce_quotes WHERE id=(p_identity#>>'{request,quoteId}')::uuid;
  IF q->>'purpose' IN ('upgrade','renew') THEN
    IF jsonb_typeof(p_lifecycle_identity) IS DISTINCT FROM 'object' OR jsonb_typeof(p_lifecycle_decision) IS DISTINCT FROM 'object'
      OR p_lifecycle_identity->'operationId' IS DISTINCT FROM p_identity->'operationId'
      OR p_lifecycle_identity->'actorId' IS DISTINCT FROM p_identity->'actorId'
      OR p_lifecycle_identity->'subject' IS DISTINCT FROM p_identity->'subject'
      OR p_lifecycle_identity#>'{request,operation}' IS DISTINCT FROM q->'purpose'
      OR p_lifecycle_identity#>'{request,quoteId}' IS DISTINCT FROM q->'id'
      OR p_lifecycle_identity#>'{request,settlementId}' IS DISTINCT FROM p_settlement->'id' THEN
      RAISE EXCEPTION 'Atomic paid lifecycle decision required'; END IF;
  ELSIF p_lifecycle_identity IS NOT NULL OR p_lifecycle_decision IS NOT NULL THEN
    RAISE EXCEPTION 'Lifecycle decision is not applicable to this checkout';
  END IF;
  result:=public.record_subscription_commerce_payment(p_identity,p_settlement,p_order,p_payment);
  IF q->>'purpose' IN ('upgrade','renew') THEN
    activation:=public.commit_subscription_lifecycle(p_lifecycle_identity,p_lifecycle_decision);
    IF activation#>'{decision,next,revisionId}' IS DISTINCT FROM q->'revisionId' THEN RAISE EXCEPTION 'Paid activation revision differs'; END IF;
  END IF;
  RETURN result;
END;
$$;
REVOKE ALL ON FUNCTION public.settle_subscription_commerce_payment(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.settle_subscription_commerce_payment(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb) TO service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
