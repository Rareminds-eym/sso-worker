-- PREPARED ONLY: target-specific approval is required before applying this migration.
-- No customer backfill, charges, refunds, deployment or provider call is performed here.
-- REVIEWED PREPARATION / STILL UNEXECUTED
-- Target: the existing local SSO database identified by sso-worker/supabase/config.toml,
-- independently matched to audit-evidence/local-subscription-db-audit/candidate-local-baseline.json.
-- Do not redirect these checks to remote QA/staging/production or start any service without
-- the user's separate approval for that exact target and action.
-- Before runtime acceptance, the SSO worker needs a PAYMENT_WORKER service binding to the
-- existing payment worker's named PaymentService entrypoint for the same approved environment.
-- Source Env typing does not configure a binding. The payment worker's bare default config
-- describes production; do not start it as a substitute for a reviewed local configuration.
-- Require an explicit quoteValidityMs and signed audience/role eligibility in retained terms.
-- Require a purchase-attributed monetary usage owner and transactional valuation cutoff;
-- this migration intentionally does not fabricate usage, tariffs, users, credentials or receipts.
--
-- Rollback-only acceptance preparation: extend scripts/checks/subscription-execution-sql.mjs
-- to compose publication + lifecycle + this migration inside ONE outer transaction, stripping
-- only the reviewed outer BEGIN/COMMIT statements. Add synthetic functional fixtures for:
-- initial quote/order/capture/initialization, renew and upgrade envelope fulfillment, paid
-- retake evidence and exact replay; foreign actor/product/subject/revision/version rejection;
-- two competing orders/settlements; malformed JSON/null/numeric payment rejection; missing,
-- incomplete, stale, future and foreign usage rejection; exact seven-day boundary; prior
-- refunds and overusage; pending/failed refunds preserving access and processed partial refund
-- cancellation revoking access through current/credit/domain/lifecycle owners. Inspect grants
-- and denied-role/direct-write controls. End with ROLLBACK and independently compare existing
-- schema, migration history and commercial-row fingerprints. The current harness does not yet
-- include this migration: its prior success is not commerce SQL evidence.
--
-- Uncertain-result recovery preparation (never repeat a mutation to infer its outcome):
-- 1. Read the existing operation identity/receipt. Exact committed replay returns its receipt.
-- 2. For pending orders, the payment owner can read getOrdersByReceipt(quote.id). Exactly one
--    order must match quote amount/currency/receipt/notes before a specifically authorized
--    privileged reconciliation calls complete_subscription_commerce_order with the ORIGINAL
--    reserved identity. Zero/multiple/mismatched results remain explicit reconciliation errors.
-- 3. For pending refunds, obtain the provider refund ID from provider evidence, call getRefund,
--    then use refund_confirm. Its notes must bind the original operation and settlement. Pending
--    or failed states never revoke access; only a positive processed result does so. A provider
--    receipt alone is not settlement proof. No automatic recovery/retry job is installed.
-- 4. An exception in a rollback-only fixture aborts its transaction. Inspect post-connection
--    fingerprints independently before attributing differences or proposing any recovery action.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE TABLE public.subscription_commerce_operations (
  operation_id uuid PRIMARY KEY, identity jsonb NOT NULL, evidence jsonb NOT NULL,
  receipt jsonb, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.subscription_commerce_quotes (
  id uuid PRIMARY KEY REFERENCES public.subscription_commerce_operations(operation_id),
  quote jsonb NOT NULL, provider_order_id text UNIQUE, order_operation_id uuid UNIQUE
);
CREATE TABLE public.subscription_commerce_settlements (
  id uuid PRIMARY KEY REFERENCES public.transactions(id), quote_id uuid NOT NULL UNIQUE REFERENCES public.subscription_commerce_quotes(id),
  subscription_id uuid NOT NULL REFERENCES public.subscriptions(id), product_id uuid NOT NULL REFERENCES public.products(id),
  subject jsonb NOT NULL, purpose text NOT NULL CHECK(purpose IN ('purchase','renew','upgrade','retake')),
  reference_id uuid, amount_minor bigint NOT NULL CHECK(amount_minor>0), currency text NOT NULL,
  provider_payment_id text NOT NULL UNIQUE, settled_at timestamptz NOT NULL, evidence jsonb NOT NULL,
  CHECK((purpose='retake')=(reference_id IS NOT NULL))
);
-- A monetary usage owner must write complete purchase-attributed valuations. Missing evidence
-- is deliberately an error; allocating credits or counting requests is not currency valuation.
CREATE TABLE public.subscription_commerce_usage_valuations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), settlement_id uuid NOT NULL REFERENCES public.subscription_commerce_settlements(id),
  subscription_id uuid NOT NULL REFERENCES public.subscriptions(id), product_id uuid NOT NULL REFERENCES public.products(id),
  subject jsonb NOT NULL, currency text NOT NULL, amount_minor bigint NOT NULL CHECK(amount_minor>=0),
  complete boolean NOT NULL, through_at timestamptz NOT NULL, source_evidence jsonb NOT NULL,
  UNIQUE(settlement_id,through_at), CHECK(jsonb_typeof(source_evidence)='object' AND source_evidence<>'{}'::jsonb)
);
CREATE TABLE public.subscription_commerce_refunds (
  provider_refund_id text PRIMARY KEY, operation_id uuid NOT NULL UNIQUE REFERENCES public.subscription_commerce_operations(operation_id),
  settlement_id uuid NOT NULL REFERENCES public.subscription_commerce_settlements(id),
  subscription_id uuid NOT NULL REFERENCES public.subscriptions(id), product_id uuid NOT NULL REFERENCES public.products(id),
  subject jsonb NOT NULL, amount_minor bigint NOT NULL CHECK(amount_minor>0), status text NOT NULL CHECK(status IN ('pending','processed','failed')),
  provider_evidence jsonb NOT NULL, cancelled_at timestamptz, CHECK((status='processed')=(cancelled_at IS NOT NULL))
);
CREATE INDEX subscription_commerce_refunds_subscription_idx ON public.subscription_commerce_refunds(subscription_id,status);
CREATE INDEX subscription_commerce_usage_settlement_idx ON public.subscription_commerce_usage_valuations(settlement_id,through_at DESC);
REVOKE ALL ON TABLE public.subscription_commerce_operations,public.subscription_commerce_quotes,public.subscription_commerce_settlements,
  public.subscription_commerce_usage_valuations,public.subscription_commerce_refunds FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON TABLE public.subscription_commerce_operations,public.subscription_commerce_quotes,public.subscription_commerce_settlements,
  public.subscription_commerce_usage_valuations,public.subscription_commerce_refunds TO service_role;

CREATE FUNCTION public.assert_subscription_commerce_scope(p_identity jsonb,p_quote jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE r public.subscriptions%ROWTYPE; req jsonb:=p_identity->'request';
BEGIN
  IF jsonb_typeof(p_identity) IS DISTINCT FROM 'object' OR jsonb_typeof(req) IS DISTINCT FROM 'object'
    OR p_identity->'actorId' IS DISTINCT FROM p_quote->'actorId' OR p_identity->'subject' IS DISTINCT FROM p_quote->'subject'
    OR p_identity->'productId' IS DISTINCT FROM p_quote->'productId' OR p_identity->'audience' IS DISTINCT FROM p_quote->'audience'
    OR req->'subject' IS DISTINCT FROM p_quote->'subject' OR req->'subscriptionId' IS DISTINCT FROM p_quote->'subscriptionId'
    OR req->'expectedVersion' IS DISTINCT FROM p_quote->'stateVersion' OR req->'expectedRevisionId' IS DISTINCT FROM p_quote->'expectedRevisionId'
    OR (p_quote->>'validUntil')::numeric <= extract(epoch FROM clock_timestamp())*1000 THEN
    RAISE EXCEPTION 'Commerce scope, CAS or expiry differs';
  END IF;
  SELECT * INTO r FROM public.subscriptions WHERE id=(p_quote->>'subscriptionId')::uuid FOR UPDATE;
  IF p_quote->>'purpose'='purchase' THEN
    IF FOUND OR p_quote->'stateVersion'<>'0'::jsonb THEN RAISE EXCEPTION 'Purchase requires unused subscription identity'; END IF;
  ELSE
    IF NOT FOUND OR r.product_id::text IS DISTINCT FROM p_quote->>'productId'
      OR r.lifecycle_state->'version' IS DISTINCT FROM p_quote->'stateVersion'
      OR r.lifecycle_state->'revisionId' IS DISTINCT FROM p_quote->'expectedRevisionId'
      OR r.lifecycle_state->'subject' IS DISTINCT FROM p_quote->'subject' THEN RAISE EXCEPTION 'Commerce subscription state differs'; END IF;
    PERFORM public.assert_subscription_lifecycle_binding(r);
    IF EXISTS(SELECT 1 FROM public.subscription_commerce_refunds WHERE subscription_id=r.id AND status='processed') THEN RAISE EXCEPTION 'Refunded cancellation has no subscription access'; END IF;
  END IF;
END;
$$;

CREATE FUNCTION public.issue_subscription_commerce_quote(p_identity jsonb,p_quote jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid:=(p_identity->>'operationId')::uuid; old public.subscription_commerce_operations%ROWTYPE;
  publication jsonb; draft jsonb; policy jsonb; selected jsonb; receipt jsonb; current_state jsonb; period_end numeric;
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
  SELECT e.canonical_plan,d.snapshot INTO publication,draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id AND d.plan_id=e.plan_id
    WHERE e.revision_id=(p_quote->>'revisionId')::uuid AND e.plan_id=(p_quote->>'planId')::uuid;
  policy:=publication#>'{configuration,subscription_commerce}';
  IF publication IS NULL OR publication->'productId' IS DISTINCT FROM p_quote->'productId' OR draft->>'purchaseMode'<>'self_service'
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
    IF NOT EXISTS(SELECT 1 FROM public.subscriptions WHERE id=(p_quote->>'subscriptionId')::uuid
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
        OR current_state->'periodStartsAt' IS DISTINCT FROM p_quote->'periodStartsAt' OR current_state->'periodEndsAt' IS DISTINCT FROM p_quote->'periodEndsAt'
        OR current_state->'revisionId'=p_quote->'revisionId' OR (p_quote->>'createdAt')::numeric>=(current_state->>'periodEndsAt')::numeric
        OR NOT EXISTS(SELECT 1 FROM public.subscription_plan_publication_events e,
          LATERAL jsonb_array_elements(e.canonical_plan#>'{configuration,subscription_revision_changes}') c
          WHERE e.revision_id=(current_state->>'revisionId')::uuid AND c->'fromRevisionId'=current_state->'revisionId'
            AND c->'toRevisionId'=p_quote->'revisionId' AND c->>'operation'='upgrade') THEN RAISE EXCEPTION 'Approved current-period upgrade required'; END IF;
    ELSE
      period_end:=extract(epoch FROM ((to_timestamp((p_quote->>'periodStartsAt')::numeric/1000) AT TIME ZONE 'UTC'
        + CASE selected->>'intervalUnit' WHEN 'month' THEN make_interval(months=>(selected->>'intervalCount')::integer)
          WHEN 'year' THEN make_interval(years=>(selected->>'intervalCount')::integer) END) AT TIME ZONE 'UTC'))*1000;
      IF period_end IS DISTINCT FROM (p_quote->>'periodEndsAt')::numeric THEN RAISE EXCEPTION 'Configured billing period differs'; END IF;
      IF p_quote->>'purpose'='purchase' THEN
        IF p_quote->'periodStartsAt' IS DISTINCT FROM p_quote->'createdAt' OR p_quote->'expectedRevisionId' IS DISTINCT FROM p_quote->'revisionId' THEN RAISE EXCEPTION 'Initial purchase anchor differs'; END IF;
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

CREATE FUNCTION public.reserve_subscription_commerce_operation(p_identity jsonb,p_evidence jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid:=(p_identity->>'operationId')::uuid; q public.subscription_commerce_quotes%ROWTYPE;
  s public.subscription_commerce_settlements%ROWTYPE; u public.subscription_commerce_usage_valuations%ROWTYPE; r public.subscriptions%ROWTYPE; refunded numeric; paid numeric; amount numeric; window_ms numeric;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_operation:'||op::text,0));
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_operations WHERE operation_id=op) THEN RAISE EXCEPTION 'Operation already reserved; reconcile without repeating external mutation'; END IF;
  IF p_identity#>>'{request,kind}' IN ('order','settle') THEN
    SELECT * INTO q FROM public.subscription_commerce_quotes WHERE id=(p_evidence->>'quoteId')::uuid FOR UPDATE;
    IF NOT FOUND OR p_identity#>'{request,quoteId}' IS DISTINCT FROM to_jsonb(q.id) THEN RAISE EXCEPTION 'Issued quote required'; END IF;
    PERFORM public.assert_subscription_commerce_scope(p_identity,q.quote);
    IF p_identity#>>'{request,kind}'='order' THEN
      IF q.order_operation_id IS NOT NULL THEN RAISE EXCEPTION 'Order already reserved'; END IF;
      UPDATE public.subscription_commerce_quotes SET order_operation_id=op WHERE id=q.id;
    ELSIF q.provider_order_id IS NULL OR EXISTS(SELECT 1 FROM public.subscription_commerce_settlements WHERE quote_id=q.id) THEN RAISE EXCEPTION 'Unsettled issued order required';
    END IF;
  ELSIF p_identity#>>'{request,kind}'='refund' THEN
    SELECT * INTO s FROM public.subscription_commerce_settlements WHERE id=(p_evidence->>'settlementId')::uuid FOR UPDATE;
    IF NOT FOUND OR s.purpose='retake' OR s.subscription_id::text IS DISTINCT FROM p_identity#>>'{request,subscriptionId}'
      OR s.subject IS DISTINCT FROM p_identity->'subject' OR s.product_id::text IS DISTINCT FROM p_identity->>'productId' THEN RAISE EXCEPTION 'Refund settlement owner differs'; END IF;
    SELECT * INTO r FROM public.subscriptions WHERE id=s.subscription_id FOR UPDATE;
    IF NOT FOUND OR r.lifecycle_state->'version' IS DISTINCT FROM p_identity#>'{request,expectedVersion}'
      OR r.lifecycle_state->'revisionId' IS DISTINCT FROM p_identity#>'{request,expectedRevisionId}'
      OR r.lifecycle_state->'subject' IS DISTINCT FROM s.subject THEN RAISE EXCEPTION 'Refund subscription CAS differs'; END IF;
    IF EXISTS(SELECT 1 FROM public.subscription_commerce_operations WHERE identity#>>'{request,kind}'='refund' AND evidence->'settlementId'=p_evidence->'settlementId' AND receipt IS NULL)
      OR EXISTS(SELECT 1 FROM public.subscription_commerce_refunds WHERE settlement_id=s.id AND status<>'processed') THEN RAISE EXCEPTION 'Prior refund is uncertain'; END IF;
    SELECT * INTO u FROM public.subscription_commerce_usage_valuations WHERE settlement_id=s.id ORDER BY through_at DESC LIMIT 1;
    IF NOT FOUND OR NOT u.complete OR u.currency<>s.currency OR u.subject<>s.subject OR u.product_id<>s.product_id OR u.subscription_id<>s.subscription_id
      OR to_jsonb(u)-'id'-'source_evidence' IS DISTINCT FROM p_evidence->'usage'
      OR extract(epoch FROM u.through_at)*1000 IS DISTINCT FROM (p_evidence->>'requestedAt')::numeric
      OR (p_evidence->>'requestedAt')::numeric>extract(epoch FROM clock_timestamp())*1000 THEN RAISE EXCEPTION 'Current complete attributable usage required'; END IF;
    SELECT (e.canonical_plan#>>'{configuration,subscription_commerce,refundWindowMs}')::numeric INTO window_ms
      FROM public.subscription_commerce_quotes cq JOIN public.subscription_plan_publication_events e ON e.revision_id=(cq.quote->>'revisionId')::uuid WHERE cq.id=s.quote_id;
    IF (p_evidence->>'requestedAt')::numeric<extract(epoch FROM s.settled_at)*1000
      OR (p_evidence->>'requestedAt')::numeric-extract(epoch FROM s.settled_at)*1000>window_ms THEN RAISE EXCEPTION 'Outside refund window'; END IF;
    SELECT coalesce(sum(amount_minor),0) INTO refunded FROM public.subscription_commerce_refunds WHERE settlement_id=s.id AND status='processed';
    paid:=s.amount_minor; amount:=greatest(0,least(paid-refunded,paid-u.amount_minor-refunded));
    IF amount<=0 OR amount IS DISTINCT FROM (p_evidence->>'amountMinor')::numeric THEN RAISE EXCEPTION 'Refund amount differs'; END IF;
  ELSE RAISE EXCEPTION 'Unsupported commerce reservation'; END IF;
  INSERT INTO public.subscription_commerce_operations(operation_id,identity,evidence) VALUES(op,p_identity,p_evidence);
END;
$$;

CREATE FUNCTION public.complete_subscription_commerce_order(p_identity jsonb,p_order jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE o public.subscription_commerce_operations%ROWTYPE; q public.subscription_commerce_quotes%ROWTYPE; result jsonb;
BEGIN
  SELECT * INTO o FROM public.subscription_commerce_operations WHERE operation_id=(p_identity->>'operationId')::uuid FOR UPDATE;
  IF NOT FOUND OR o.identity IS DISTINCT FROM p_identity OR p_identity#>>'{request,kind}'<>'order' THEN RAISE EXCEPTION 'Exact reserved order required'; END IF;
  IF o.receipt IS NOT NULL THEN RETURN o.receipt; END IF;
  SELECT * INTO q FROM public.subscription_commerce_quotes WHERE id=(o.evidence->>'quoteId')::uuid FOR UPDATE;
  PERFORM public.assert_subscription_commerce_scope(p_identity,q.quote);
  IF q.order_operation_id<>o.operation_id OR q.provider_order_id IS NOT NULL OR p_order->>'id'!~'^order_[A-Za-z0-9]+$'
    OR p_order->'amount' IS DISTINCT FROM q.quote->'amountMinor' OR p_order->'currency' IS DISTINCT FROM q.quote->'currency'
    OR p_order->>'receipt' IS DISTINCT FROM q.id::text OR p_order#>>'{notes,subscription_quote_id}' IS DISTINCT FROM q.id::text
    OR p_order#>'{notes,subscription_id}' IS DISTINCT FROM q.quote->'subscriptionId' THEN RAISE EXCEPTION 'Provider order differs'; END IF;
  result:=jsonb_build_object('kind','order','operationId',o.operation_id,'quoteId',q.id,'order',p_order);
  UPDATE public.subscription_commerce_quotes SET provider_order_id=p_order->>'id' WHERE id=q.id;
  UPDATE public.subscription_commerce_operations SET receipt=result WHERE operation_id=o.operation_id;
  RETURN result;
END;
$$;

CREATE FUNCTION public.settle_subscription_commerce_payment(p_identity jsonb,p_settlement jsonb,p_order jsonb,p_payment jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE o public.subscription_commerce_operations%ROWTYPE; cq public.subscription_commerce_quotes%ROWTYPE;
  q jsonb; s jsonb; publication jsonb; draft jsonb; policy jsonb; price jsonb; state jsonb; result jsonb; envelope jsonb;
  tx uuid:=(p_settlement->>'id')::uuid; owner_id uuid:=(p_identity->>'actorId')::uuid; org uuid;
  sub uuid; at_ms numeric; starts timestamptz; ends timestamptz; amount numeric; buyer_email text;
BEGIN
  SELECT * INTO o FROM public.subscription_commerce_operations WHERE operation_id=(p_identity->>'operationId')::uuid FOR UPDATE;
  IF NOT FOUND OR o.identity IS DISTINCT FROM p_identity OR p_identity#>>'{request,kind}'<>'settle' THEN RAISE EXCEPTION 'Exact settlement reservation required'; END IF;
  IF o.receipt IS NOT NULL THEN RETURN o.receipt; END IF;
  SELECT * INTO cq FROM public.subscription_commerce_quotes WHERE id=(o.evidence->>'quoteId')::uuid FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Issued quote required'; END IF;
  q:=cq.quote; sub:=(q->>'subscriptionId')::uuid;
  PERFORM public.assert_subscription_commerce_scope(p_identity,q);
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_payment:'||(p_payment->>'id'),0));
  IF p_settlement->>'id' IS DISTINCT FROM o.operation_id::text OR p_settlement->>'quoteId' IS DISTINCT FROM cq.id::text
    OR p_settlement->'subscriptionId' IS DISTINCT FROM q->'subscriptionId' OR p_settlement->'productId' IS DISTINCT FROM q->'productId'
    OR p_settlement->'subject' IS DISTINCT FROM q->'subject' OR p_settlement->'purpose' IS DISTINCT FROM q->'purpose'
    OR p_settlement->'referenceId' IS DISTINCT FROM q->'referenceId' OR p_settlement->'amountMinor' IS DISTINCT FROM q->'amountMinor'
    OR p_settlement->'currency' IS DISTINCT FROM q->'currency' OR p_settlement->'providerPaymentId' IS DISTINCT FROM p_payment->'id'
    OR (CASE WHEN p_identity#>'{request,reconcile}'='true'::jsonb THEN (p_identity->'request') ? 'paymentId'
      ELSE (p_identity->'request') ? 'reconcile' OR p_identity#>'{request,paymentId}' IS DISTINCT FROM p_payment->'id' END)
    OR p_order->>'id' IS DISTINCT FROM cq.provider_order_id OR p_payment->'order_id' IS DISTINCT FROM p_order->'id'
    OR p_payment->>'status' IS DISTINCT FROM 'captured' OR p_payment->'captured' IS DISTINCT FROM 'true'::jsonb
    OR p_payment->'amount' IS DISTINCT FROM q->'amountMinor' OR p_payment->'currency' IS DISTINCT FROM q->'currency'
    OR (p_payment ? 'amount_refunded' AND p_payment->'amount_refunded' IS DISTINCT FROM '0'::jsonb)
    OR p_order->>'status' IS DISTINCT FROM 'paid' OR p_order->'amount' IS DISTINCT FROM q->'amountMinor'
    OR p_order->'currency' IS DISTINCT FROM q->'currency' OR p_order->>'receipt' IS DISTINCT FROM cq.id::text
    OR p_order#>>'{notes,subscription_quote_id}' IS DISTINCT FROM cq.id::text
    OR p_order#>'{notes,subscription_id}' IS DISTINCT FROM q->'subscriptionId'
    OR (p_settlement->>'settledAt')::numeric>extract(epoch FROM clock_timestamp())*1000
    OR (p_settlement->>'settledAt')::numeric<(q->>'createdAt')::numeric
    OR EXISTS(SELECT 1 FROM public.transactions WHERE razorpay_payment_id=p_payment->>'id') THEN RAISE EXCEPTION 'Verified captured payment identity differs or is consumed'; END IF;
  SELECT e.canonical_plan,d.snapshot INTO publication,draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id WHERE e.revision_id=(q->>'revisionId')::uuid AND e.plan_id=(q->>'planId')::uuid;
  IF publication IS NULL OR publication->'productId' IS DISTINCT FROM q->'productId' THEN RAISE EXCEPTION 'Retained publication required'; END IF;
  policy:=publication#>'{configuration,subscription_lifecycle}';
  at_ms:=(p_settlement->>'settledAt')::numeric;
  starts:=to_timestamp((q->>'periodStartsAt')::numeric/1000); ends:=to_timestamp((q->>'periodEndsAt')::numeric/1000);
  amount:=(q->>'amountMinor')::numeric/power(10::numeric,(q->>'minorUnit')::integer);
  IF amount<>round(amount,2) THEN RAISE EXCEPTION 'Transaction owner cannot represent currency precision'; END IF;
  IF q#>>'{subject,kind}'='organization' THEN org:=(q#>>'{subject,id}')::uuid;
  ELSIF q#>>'{subject,kind}'<>'user' OR q#>>'{subject,id}'<>owner_id::text THEN RAISE EXCEPTION 'Purchase subject differs'; END IF;
  IF q->>'purpose'='purchase' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_purchase:'||(q->'subject')::text||':'||(q->>'productId'),0));
    IF EXISTS(SELECT 1 FROM public.subscriptions WHERE product_id=(q->>'productId')::uuid AND status IN ('active','pending','grace_period','paused')
      AND CASE WHEN org IS NULL THEN user_id=owner_id AND is_organization_subscription IS NOT TRUE ELSE organization_id=org AND is_organization_subscription IS TRUE END) THEN RAISE EXCEPTION 'Existing subscription requires explicit lifecycle transition'; END IF;
    SELECT email INTO buyer_email FROM public.users WHERE id=owner_id AND is_blocked=false AND is_email_verified=true;
    IF buyer_email IS NULL THEN RAISE EXCEPTION 'Live verified purchaser required'; END IF;
    SELECT value INTO price FROM jsonb_array_elements(draft->'prices') WHERE value->'id'=q->'priceId';
    INSERT INTO public.subscriptions(id,user_id,organization_id,is_organization_subscription,purchased_by,plan_id,product_id,email,
      plan_code,plan_type,plan_amount,billing_cycle,features,status,auto_renew,subscription_start_date,subscription_end_date,
      razorpay_order_id,razorpay_payment_id,metadata)
      VALUES(sub,owner_id,org,org IS NOT NULL,owner_id,(q->>'planId')::uuid,(q->>'productId')::uuid,buyer_email,
        publication->>'code',draft->>'name',amount,CASE price->>'intervalUnit' WHEN 'month' THEN 'monthly' WHEN 'year' THEN 'yearly' END,
        draft->'features','active',true,starts,ends,cq.provider_order_id,p_payment->>'id',
        jsonb_build_object('subscription_execution',jsonb_build_object('audience',q->'audience','subscriptionEndsAt',q->'periodEndsAt'),'subscription_purchase_quote',q));
    state:=jsonb_build_object('id',sub,'subject',q->'subject','planId',q->'planId','revisionId',q->'revisionId','productId',q->'productId',
      'version',1,'status','active','periodStartsAt',q->'periodStartsAt','periodEndsAt',q->'periodEndsAt',
      'trialEndsAt',NULL,'renewalEnabled',true,'cancelledAt',NULL,'paymentFailedAt',NULL,'scheduledChange',NULL);
    IF policy ? 'readOnlyDurationMs' THEN state:=state||jsonb_build_object('downgradedAt',NULL); END IF;
    PERFORM public.initialize_subscription_lifecycle(o.operation_id,state,policy,owner_id,starts);
  END IF;
  envelope:=jsonb_build_object('subscription_commerce',jsonb_build_object('quote',q,'settlement',p_settlement));
  IF q->>'purpose' IN ('renew','upgrade') THEN
    s:=jsonb_build_object('id',tx,'quoteId',q->'id','subscriptionId',q->'subscriptionId','subject',q->'subject','stateVersion',q->'stateVersion',
      'revisionId',q->'revisionId','amountMinor',q->'amountMinor','currency',q->'currency','operation',q->'purpose',
      'kind','verified_payment','recordedAt',p_settlement->'settledAt','validUntil',NULL);
    envelope:=envelope||jsonb_build_object('subscription_lifecycle',jsonb_build_object('productId',q->'productId','quote',jsonb_build_object(
      'id',q->'id','planId',q->'planId','revisionId',q->'revisionId','productId',q->'productId','subscriptionId',q->'subscriptionId',
      'subject',q->'subject','stateVersion',q->'stateVersion','operation',q->'purpose','amountMinor',q->'amountMinor','currency',q->'currency',
      'periodStartsAt',q->'periodStartsAt','periodEndsAt',q->'periodEndsAt','validUntil',q->'validUntil'),'settlement',s,'currencyMinorUnit',q->'minorUnit'));
  END IF;
  INSERT INTO public.transactions(id,subscription_id,user_id,organization_id,product_id,razorpay_order_id,razorpay_payment_id,
    amount,currency,status,transaction_type,payment_method,metadata,updated_at)
    SELECT tx,sub,r.user_id,r.organization_id,r.product_id,cq.provider_order_id,p_payment->>'id',amount,q->>'currency','completed',
      CASE q->>'purpose' WHEN 'upgrade' THEN 'upgrade' WHEN 'retake' THEN 'addon' ELSE 'subscription' END,p_payment->>'method',envelope,to_timestamp(at_ms/1000)
      FROM public.subscriptions r WHERE r.id=sub;
  IF NOT FOUND THEN RAISE EXCEPTION 'Settlement subscription owner required'; END IF;
  INSERT INTO public.subscription_commerce_settlements(id,quote_id,subscription_id,product_id,subject,purpose,reference_id,amount_minor,currency,provider_payment_id,settled_at,evidence)
    VALUES(tx,cq.id,sub,(q->>'productId')::uuid,q->'subject',q->>'purpose',(q->>'referenceId')::uuid,(q->>'amountMinor')::bigint,q->>'currency',p_payment->>'id',to_timestamp(at_ms/1000),p_settlement);
  result:=jsonb_build_object('kind','settlement','operationId',o.operation_id,'quoteId',cq.id,'settlement',p_settlement);
  UPDATE public.subscription_commerce_operations SET receipt=result WHERE operation_id=o.operation_id;
  RETURN result;
END;
$$;

CREATE FUNCTION public.confirm_subscription_commerce_refund(p_identity jsonb,p_settlement_id uuid,p_refund jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE o public.subscription_commerce_operations%ROWTYPE; s public.subscription_commerce_settlements%ROWTYPE;
  existing public.subscription_commerce_refunds%ROWTYPE; confirmation public.subscription_commerce_operations%ROWTYPE;
  result jsonb; op uuid; command_id uuid:=(p_identity->>'operationId')::uuid; status text; cancelled timestamptz;
BEGIN
  IF p_identity#>>'{request,kind}' NOT IN ('refund','refund_confirm') OR p_identity#>>'{request,kind}' IS NULL
    OR p_identity#>>'{request,settlementId}' IS DISTINCT FROM p_settlement_id::text THEN RAISE EXCEPTION 'Explicit refund operation identity required'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_operation:'||command_id::text,0));
  IF p_identity#>>'{request,kind}'='refund_confirm' THEN
    SELECT * INTO confirmation FROM public.subscription_commerce_operations WHERE operation_id=command_id FOR UPDATE;
    IF FOUND THEN
      IF confirmation.identity IS DISTINCT FROM p_identity THEN RAISE EXCEPTION 'Refund confirmation replay conflicts'; END IF;
      RETURN confirmation.receipt;
    END IF;
  END IF;
  op:=(p_refund#>>'{notes,subscription_refund_operation_id}')::uuid;
  SELECT * INTO o FROM public.subscription_commerce_operations WHERE operation_id=op FOR UPDATE;
  SELECT * INTO s FROM public.subscription_commerce_settlements WHERE id=p_settlement_id FOR UPDATE;
  IF o.operation_id IS NULL OR s.id IS NULL OR o.identity#>>'{request,kind}'<>'refund'
    OR o.evidence->>'settlementId' IS DISTINCT FROM s.id::text
    OR o.identity->'actorId' IS DISTINCT FROM p_identity->'actorId' OR o.identity->'subject' IS DISTINCT FROM p_identity->'subject'
    OR o.identity->'productId' IS DISTINCT FROM p_identity->'productId' OR o.identity->'audience' IS DISTINCT FROM p_identity->'audience'
    OR o.identity#>'{request,subscriptionId}' IS DISTINCT FROM p_identity#>'{request,subscriptionId}'
    OR (p_identity#>>'{request,kind}'='refund' AND o.identity IS DISTINCT FROM p_identity)
    OR (p_identity#>>'{request,kind}'='refund_confirm' AND p_identity#>'{request,refundId}' IS DISTINCT FROM p_refund->'id')
    OR p_refund->>'payment_id' IS DISTINCT FROM s.provider_payment_id OR p_refund->>'id'!~'^rfnd_[A-Za-z0-9]+$'
    OR p_refund->'amount' IS DISTINCT FROM o.evidence->'amountMinor' OR p_refund->>'currency' IS DISTINCT FROM s.currency
    OR p_refund#>>'{notes,subscription_settlement_id}' IS DISTINCT FROM s.id::text THEN RAISE EXCEPTION 'Refund owner evidence differs'; END IF;
  status:=p_refund->>'status';
  IF status NOT IN ('pending','processed','failed') OR status IS NULL THEN RAISE EXCEPTION 'Unknown provider refund state'; END IF;
  SELECT * INTO existing FROM public.subscription_commerce_refunds WHERE provider_refund_id=p_refund->>'id' FOR UPDATE;
  IF FOUND AND (existing.operation_id<>op OR existing.settlement_id<>s.id OR existing.amount_minor<>(p_refund->>'amount')::bigint
    OR (existing.status='processed' AND status<>'processed')) THEN RAISE EXCEPTION 'Refund identity or terminal state conflicts'; END IF;
  IF status='processed' THEN cancelled:=coalesce(existing.cancelled_at,clock_timestamp()); END IF;
  INSERT INTO public.subscription_commerce_refunds(provider_refund_id,operation_id,settlement_id,subscription_id,product_id,subject,amount_minor,status,provider_evidence,cancelled_at)
    VALUES(p_refund->>'id',op,s.id,s.subscription_id,s.product_id,s.subject,(p_refund->>'amount')::bigint,status,p_refund,cancelled)
    ON CONFLICT(provider_refund_id) DO UPDATE SET status=EXCLUDED.status,provider_evidence=EXCLUDED.provider_evidence,cancelled_at=EXCLUDED.cancelled_at;
  result:=jsonb_build_object('kind','refund','operationId',op,'settlementId',s.id,'refundId',p_refund->'id','amountMinor',p_refund->'amount','status',status,'accessRevoked',status='processed');
  UPDATE public.subscription_commerce_operations SET receipt=result WHERE operation_id=op;
  IF p_identity#>>'{request,kind}'='refund_confirm' THEN
    INSERT INTO public.subscription_commerce_operations(operation_id,identity,evidence,receipt)
      VALUES(command_id,p_identity,jsonb_build_object('originalOperationId',op,'settlementId',s.id,'refundId',p_refund->'id'),result);
  END IF;
  RETURN result;
END;
$$;

CREATE FUNCTION public.guard_refunded_subscription_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_refunds WHERE subscription_id=OLD.id AND status='processed') THEN
    RAISE EXCEPTION 'Refunded cancellation has no subscription mutation authority';
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER zzz_subscription_refunded_cancellation BEFORE UPDATE OR DELETE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.guard_refunded_subscription_mutation();
-- Immutable financial evidence cannot be rewritten by legacy direct transaction writers.
CREATE FUNCTION public.guard_subscription_commerce_transaction()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_settlements WHERE id=OLD.id) THEN RAISE EXCEPTION 'Commerce settlement transaction is immutable'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END;
$$;
CREATE TRIGGER subscription_commerce_transaction_immutable BEFORE UPDATE OR DELETE ON public.transactions
  FOR EACH ROW EXECUTE FUNCTION public.guard_subscription_commerce_transaction();

REVOKE ALL ON FUNCTION public.assert_subscription_commerce_scope(jsonb,jsonb),public.guard_refunded_subscription_mutation(),public.guard_subscription_commerce_transaction() FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.issue_subscription_commerce_quote(jsonb,jsonb),public.reserve_subscription_commerce_operation(jsonb,jsonb),
  public.complete_subscription_commerce_order(jsonb,jsonb),public.settle_subscription_commerce_payment(jsonb,jsonb,jsonb,jsonb),public.confirm_subscription_commerce_refund(jsonb,uuid,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.issue_subscription_commerce_quote(jsonb,jsonb),public.reserve_subscription_commerce_operation(jsonb,jsonb),
  public.complete_subscription_commerce_order(jsonb,jsonb),public.settle_subscription_commerce_payment(jsonb,jsonb,jsonb,jsonb),public.confirm_subscription_commerce_refund(jsonb,uuid,jsonb) TO service_role;
COMMIT;
