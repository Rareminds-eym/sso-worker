-- PREPARED ONLY. Do not apply without explicit approval for the exact SSO target.
-- No initialization/backfill is executed. Existing unbound subscriptions remain unchanged.
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '15s';

ALTER TABLE public.subscriptions
  ADD COLUMN lifecycle_state jsonb,
  ADD COLUMN lifecycle_policy jsonb,
  ADD COLUMN lifecycle_activated_at timestamptz,
  ADD COLUMN plan_revision_id uuid REFERENCES public.subscription_plan_drafts(id) ON DELETE RESTRICT,
  ADD CONSTRAINT subscription_lifecycle_all_or_none CHECK (
    (lifecycle_state IS NULL AND lifecycle_policy IS NULL AND lifecycle_activated_at IS NULL AND plan_revision_id IS NULL)
    OR (lifecycle_state IS NOT NULL AND lifecycle_policy IS NOT NULL AND lifecycle_activated_at IS NOT NULL AND plan_revision_id IS NOT NULL));
CREATE INDEX subscriptions_plan_revision_idx ON public.subscriptions(plan_revision_id) WHERE plan_revision_id IS NOT NULL;

CREATE TABLE public.subscription_lifecycle_operations (
  operation_id uuid PRIMARY KEY,
  subscription_id uuid NOT NULL REFERENCES public.subscriptions(id) ON DELETE RESTRICT,
  actor_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  transaction_id uuid UNIQUE REFERENCES public.transactions(id) ON DELETE RESTRICT,
  kind text NOT NULL CHECK (kind IN ('initialize', 'transition')),
  identity jsonb NOT NULL CHECK (jsonb_typeof(identity) = 'object'),
  receipt jsonb NOT NULL CHECK (jsonb_typeof(receipt) = 'object'),
  committed_at timestamptz NOT NULL
);
CREATE INDEX subscription_lifecycle_operations_subscription_idx ON public.subscription_lifecycle_operations(subscription_id);
CREATE INDEX subscription_lifecycle_operations_actor_idx ON public.subscription_lifecycle_operations(actor_id);

-- Intents are durable evidence only. No retry, email or other delivery is invoked by these functions.
CREATE TABLE public.subscription_lifecycle_effect_intents (
  operation_id uuid PRIMARY KEY REFERENCES public.subscription_lifecycle_operations(operation_id) ON DELETE RESTRICT,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object')
);
REVOKE ALL ON TABLE public.subscription_lifecycle_operations, public.subscription_lifecycle_effect_intents FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.subscription_lifecycle_operations, public.subscription_lifecycle_effect_intents TO service_role;

CREATE FUNCTION public.reject_subscription_lifecycle_evidence_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN RAISE EXCEPTION 'Subscription lifecycle evidence is immutable'; END;
$$;
CREATE TRIGGER subscription_lifecycle_operations_immutable_rows BEFORE UPDATE OR DELETE ON public.subscription_lifecycle_operations
  FOR EACH ROW EXECUTE FUNCTION public.reject_subscription_lifecycle_evidence_mutation();
CREATE TRIGGER subscription_lifecycle_operations_immutable_truncate BEFORE TRUNCATE ON public.subscription_lifecycle_operations
  FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_lifecycle_evidence_mutation();
CREATE TRIGGER subscription_lifecycle_effect_intents_immutable_rows BEFORE UPDATE OR DELETE ON public.subscription_lifecycle_effect_intents
  FOR EACH ROW EXECUTE FUNCTION public.reject_subscription_lifecycle_evidence_mutation();
CREATE TRIGGER subscription_lifecycle_effect_intents_immutable_truncate BEFORE TRUNCATE ON public.subscription_lifecycle_effect_intents
  FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_lifecycle_evidence_mutation();

CREATE FUNCTION public.assert_subscription_lifecycle_binding(p_row public.subscriptions)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE s jsonb := p_row.lifecycle_state; v_publication jsonb; v_subject jsonb; v_execution jsonb; v_change jsonb;
  v_retention_start numeric; v_retention_duration numeric;
BEGIN
  IF s IS NULL THEN RAISE EXCEPTION 'Subscription lifecycle is not initialized'; END IF;
  IF jsonb_typeof(s) IS DISTINCT FROM 'object' OR jsonb_typeof(p_row.lifecycle_policy) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Lifecycle objects required'; END IF;
  IF (s ? 'downgradedAt') IS DISTINCT FROM (p_row.lifecycle_policy ? 'readOnlyDurationMs') THEN
    RAISE EXCEPTION 'Lifecycle retention state marker differs';
  END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(s)) <> (14 + CASE WHEN s ? 'downgradedAt' THEN 1 ELSE 0 END)
    OR NOT s ?& ARRAY['id','subject','planId','revisionId','productId','version','status','periodStartsAt','periodEndsAt','trialEndsAt','renewalEnabled','cancelledAt','paymentFailedAt','scheduledChange']
    OR jsonb_typeof(s->'subject') IS DISTINCT FROM 'object'
    OR jsonb_typeof(s->'renewalEnabled') IS DISTINCT FROM 'boolean'
    OR jsonb_typeof(s->'version') IS DISTINCT FROM 'number'
    OR jsonb_typeof(s->'periodStartsAt') IS DISTINCT FROM 'number'
    OR jsonb_typeof(s->'periodEndsAt') IS DISTINCT FROM 'number'
    OR EXISTS (SELECT 1 FROM jsonb_each(s) item WHERE item.key IN ('trialEndsAt','cancelledAt','paymentFailedAt','downgradedAt') AND jsonb_typeof(item.value) NOT IN ('number','null'))
    OR (s->'scheduledChange' <> 'null'::jsonb AND jsonb_typeof(s->'scheduledChange') IS DISTINCT FROM 'object')
    OR (s->'cancelledAt' <> 'null'::jsonb) IS DISTINCT FROM (s->>'status'='cancelled') THEN
    RAISE EXCEPTION 'Complete lifecycle state shape required';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_each(s) item WHERE item.key IN ('version','periodStartsAt','periodEndsAt','trialEndsAt','cancelledAt','paymentFailedAt','downgradedAt')
    AND item.value <> 'null'::jsonb AND ((item.value#>>'{}')::numeric NOT BETWEEN 0 AND 9007199254740991 OR (item.value#>>'{}')::numeric <> trunc((item.value#>>'{}')::numeric)))
    OR (s->>'periodStartsAt')::numeric > extract(epoch FROM clock_timestamp())*1000
    OR (s->'trialEndsAt' <> 'null'::jsonb AND ((s->>'trialEndsAt')::numeric <= (s->>'periodStartsAt')::numeric OR (s->>'trialEndsAt')::numeric > (s->>'periodEndsAt')::numeric))
    OR EXISTS (SELECT 1 FROM jsonb_each(s) item WHERE item.key IN ('cancelledAt','paymentFailedAt') AND item.value <> 'null'::jsonb
      AND ((item.value#>>'{}')::numeric < (s->>'periodStartsAt')::numeric OR (item.value#>>'{}')::numeric > extract(epoch FROM clock_timestamp())*1000))
    OR (s->'cancelledAt' <> 'null'::jsonb AND s->'renewalEnabled' <> 'false'::jsonb) THEN RAISE EXCEPTION 'Lifecycle event or integer bounds differ'; END IF;
  IF s ? 'downgradedAt' AND s->'downgradedAt' <> 'null'::jsonb AND
    ((s->>'downgradedAt')::numeric < extract(epoch FROM p_row.lifecycle_activated_at)*1000
      OR (s->>'downgradedAt')::numeric > extract(epoch FROM clock_timestamp())*1000) THEN
    RAISE EXCEPTION 'Lifecycle downgrade event outside activation bounds';
  END IF;
  IF p_row.lifecycle_policy ? 'readOnlyDurationMs' THEN
    IF jsonb_typeof(p_row.lifecycle_policy->'readOnlyDurationMs') IS DISTINCT FROM 'number'
      OR jsonb_typeof(p_row.lifecycle_policy->'graceDurationMs') IS DISTINCT FROM 'number'
      OR p_row.lifecycle_policy->>'graceAccess' IS DISTINCT FROM 'read_only'
      OR p_row.lifecycle_policy->>'expiredAccess' IS DISTINCT FROM 'read_only' THEN
      RAISE EXCEPTION 'Invalid finite lifecycle retention policy';
    END IF;
    v_retention_duration := (p_row.lifecycle_policy->>'readOnlyDurationMs')::numeric;
    v_retention_start := CASE WHEN s->'trialEndsAt'='null'::jsonb THEN (s->>'periodEndsAt')::numeric ELSE (s->>'trialEndsAt')::numeric END;
    IF s->'downgradedAt' <> 'null'::jsonb THEN v_retention_start := least(v_retention_start,(s->>'downgradedAt')::numeric); END IF;
    IF v_retention_duration NOT BETWEEN 1 AND 9007199254740991 OR v_retention_duration <> trunc(v_retention_duration)
      OR (p_row.lifecycle_policy->>'graceDurationMs')::numeric NOT BETWEEN 0 AND v_retention_duration
      OR (p_row.lifecycle_policy->>'graceDurationMs')::numeric <> trunc((p_row.lifecycle_policy->>'graceDurationMs')::numeric)
      OR v_retention_start + v_retention_duration > 9007199254740991 THEN
      RAISE EXCEPTION 'Invalid finite lifecycle retention policy';
    END IF;
  END IF;
  v_change := s->'scheduledChange';
  IF v_change <> 'null'::jsonb THEN
    IF (SELECT count(*) FROM jsonb_object_keys(v_change)) <> 4 OR NOT v_change ?& ARRAY['planId','revisionId','productId','effectiveAt']
      OR v_change->'productId' IS DISTINCT FROM s->'productId' OR v_change->'revisionId' = s->'revisionId'
      OR v_change->'effectiveAt' IS DISTINCT FROM (CASE WHEN s->'trialEndsAt'='null'::jsonb THEN s->'periodEndsAt' ELSE s->'trialEndsAt' END)
      OR NOT EXISTS (SELECT 1 FROM public.subscription_plan_publication_events WHERE plan_id=(v_change->>'planId')::uuid AND revision_id=(v_change->>'revisionId')::uuid AND canonical_plan->>'productId'=s->>'productId') THEN RAISE EXCEPTION 'Lifecycle scheduled publication or boundary differs'; END IF;
  END IF;
  SELECT e.canonical_plan INTO v_publication
    FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id = e.revision_id AND d.plan_id = e.plan_id
    JOIN public.plans p ON p.id = e.plan_id
    WHERE e.revision_id = p_row.plan_revision_id AND e.plan_id = p_row.plan_id
      AND p.product_id::text = s->>'productId'
      AND d.snapshot#>>'{plan,productId}' = s->>'productId';
  v_subject := CASE WHEN p_row.is_organization_subscription IS TRUE
    THEN jsonb_build_object('kind','organization','id',p_row.organization_id)
    ELSE jsonb_build_object('kind','user','id',p_row.user_id) END;
  IF v_publication IS NULL OR v_publication->>'id' IS DISTINCT FROM p_row.plan_id::text
    OR v_publication->>'productId' IS DISTINCT FROM s->>'productId'
    OR v_publication#>'{configuration,subscription_lifecycle}' IS DISTINCT FROM p_row.lifecycle_policy
    OR jsonb_typeof(s) IS DISTINCT FROM 'object'
    OR s->>'id' IS DISTINCT FROM p_row.id::text
    OR s->>'productId' IS DISTINCT FROM p_row.product_id::text
    OR s->'subject' IS DISTINCT FROM v_subject
    OR s->>'planId' IS DISTINCT FROM p_row.plan_id::text
    OR s->>'revisionId' IS DISTINCT FROM p_row.plan_revision_id::text
    OR s->>'status' IS DISTINCT FROM p_row.status
    OR s->'renewalEnabled' IS DISTINCT FROM to_jsonb(p_row.auto_renew)
    OR (s->>'periodStartsAt')::numeric IS DISTINCT FROM extract(epoch FROM p_row.subscription_start_date) * 1000
    OR (s->>'periodEndsAt')::numeric IS DISTINCT FROM extract(epoch FROM p_row.subscription_end_date) * 1000
    OR (s->>'cancelledAt')::numeric IS DISTINCT FROM extract(epoch FROM p_row.cancelled_at) * 1000
    OR (s->>'periodStartsAt')::numeric >= (s->>'periodEndsAt')::numeric
    OR (s->>'version')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (s->>'version')::numeric <> trunc((s->>'version')::numeric)
    OR (s->>'productId')::uuid IS NULL
    OR p_row.lifecycle_policy->>'productId' IS DISTINCT FROM s->>'productId' THEN
    RAISE EXCEPTION 'Subscription lifecycle binding or retained policy differs';
  END IF;
  v_execution := p_row.metadata->'subscription_execution';
  IF jsonb_typeof(v_execution) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Explicit subscription commercial binding required'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(v_execution)) <> 2 OR NOT v_execution ?& ARRAY['audience','subscriptionEndsAt']
    OR jsonb_typeof(v_execution->'audience') IS DISTINCT FROM 'string' OR length(btrim(v_execution->>'audience'))=0
    OR ((v_publication->'audiences') ? (v_execution->>'audience')) IS DISTINCT FROM true
    OR jsonb_typeof(v_execution->'subscriptionEndsAt') IS DISTINCT FROM 'number'
    OR (v_execution->>'subscriptionEndsAt')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (v_execution->>'subscriptionEndsAt')::numeric <> trunc((v_execution->>'subscriptionEndsAt')::numeric)
    OR (v_execution->>'subscriptionEndsAt')::numeric < (s->>'periodEndsAt')::numeric
    OR NOT isfinite(p_row.lifecycle_activated_at)
    OR extract(epoch FROM p_row.lifecycle_activated_at)*1000 NOT BETWEEN 0 AND (s->>'periodStartsAt')::numeric
    OR extract(epoch FROM p_row.lifecycle_activated_at)*1000 <> trunc(extract(epoch FROM p_row.lifecycle_activated_at)*1000)
    OR p_row.lifecycle_activated_at > clock_timestamp() THEN RAISE EXCEPTION 'Subscription commercial binding or activation anchor differs'; END IF;
END;
$$;

-- Bound records cannot be silently changed by legacy webhooks/jobs/direct writes.
-- Matching protected evidence can only be inserted by the service-only definer RPCs below.
CREATE FUNCTION public.guard_subscription_lifecycle_binding()
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
          AND (NEW.metadata#>>'{subscription_execution,subscriptionEndsAt}')::numeric>(OLD.metadata#>>'{subscription_execution,subscriptionEndsAt}')::numeric
          AND NEW.metadata->'subscription_execution'=jsonb_set(OLD.metadata->'subscription_execution','{subscriptionEndsAt}',o.identity#>'{quote,periodEndsAt}')) THEN
        RAISE EXCEPTION 'Paid contract amendment evidence required';
      END IF;
    END IF;
    IF NEW.lifecycle_state IS DISTINCT FROM OLD.lifecycle_state OR NEW.lifecycle_policy IS DISTINCT FROM OLD.lifecycle_policy THEN
      IF NOT EXISTS (SELECT 1 FROM public.subscription_lifecycle_operations o WHERE o.subscription_id = NEW.id AND o.kind = 'transition'
        AND o.identity->'state' = OLD.lifecycle_state AND o.identity->'policy' = OLD.lifecycle_policy
        AND o.receipt#>'{decision,next}' = NEW.lifecycle_state
        AND o.receipt#>'{decision,audit,policyId}' = OLD.lifecycle_policy->'id'
        AND NEW.lifecycle_policy = OLD.lifecycle_policy) THEN
        RAISE EXCEPTION 'Atomic lifecycle transition evidence required';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
-- Run after existing mirror-mutating triggers; final row binding is checked before persistence.
CREATE TRIGGER zz_subscription_lifecycle_binding BEFORE INSERT OR UPDATE OR DELETE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.guard_subscription_lifecycle_binding();
-- The retained legacy trigger continues to govern unbound subscriptions. Explicitly bound rows
-- use their immutable decision evidence above, avoiding two competing transition rule sets.
DROP TRIGGER trg_validate_status_transition ON public.subscriptions;
CREATE TRIGGER trg_validate_status_transition BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW WHEN (OLD.lifecycle_state IS NULL) EXECUTE FUNCTION public.validate_subscription_status_transition();
CREATE TRIGGER subscription_lifecycle_no_truncate BEFORE TRUNCATE ON public.subscriptions
  FOR EACH STATEMENT EXECUTE FUNCTION public.guard_subscription_lifecycle_binding();

CREATE FUNCTION public.guard_consumed_subscription_transaction()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    IF EXISTS (SELECT 1 FROM public.subscription_lifecycle_operations WHERE transaction_id IS NOT NULL) THEN RAISE EXCEPTION 'Consumed lifecycle transactions cannot be truncated'; END IF;
    RETURN NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM public.subscription_lifecycle_operations WHERE transaction_id = OLD.id) THEN
    RAISE EXCEPTION 'Consumed lifecycle transaction is immutable';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER subscription_lifecycle_consumed_transaction BEFORE UPDATE OR DELETE ON public.transactions
  FOR EACH ROW EXECUTE FUNCTION public.guard_consumed_subscription_transaction();
CREATE TRIGGER subscription_lifecycle_transactions_no_truncate BEFORE TRUNCATE ON public.transactions
  FOR EACH STATEMENT EXECUTE FUNCTION public.guard_consumed_subscription_transaction();

CREATE FUNCTION public.initialize_subscription_lifecycle(p_operation_id uuid, p_state jsonb, p_policy jsonb, p_actor_id uuid, p_activated_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_row public.subscriptions%ROWTYPE; v_old public.subscription_lifecycle_operations%ROWTYPE;
  v_identity jsonb; v_receipt jsonb; v_at timestamptz := clock_timestamp();
BEGIN
  IF p_operation_id IS NULL OR p_actor_id IS NULL OR p_activated_at IS NULL OR jsonb_typeof(p_state) IS DISTINCT FROM 'object' OR jsonb_typeof(p_policy) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Explicit lifecycle initialization inputs required'; END IF;
  IF p_state->'version' IS DISTINCT FROM '1'::jsonb THEN RAISE EXCEPTION 'Initialization version must be one'; END IF;
  v_identity := jsonb_build_object('operationId',p_operation_id,'state',p_state,'policy',p_policy,'actorId',p_actor_id,'activatedAt',p_activated_at);
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_lifecycle_operation:' || p_operation_id::text,0));
  SELECT * INTO v_old FROM public.subscription_lifecycle_operations WHERE operation_id = p_operation_id;
  IF FOUND THEN
    IF v_old.kind <> 'initialize' OR v_old.identity IS DISTINCT FROM v_identity THEN RAISE EXCEPTION 'Lifecycle initialization replay conflicts'; END IF;
    RETURN v_old.receipt;
  END IF;
  SELECT * INTO v_row FROM public.subscriptions WHERE id = (p_state->>'id')::uuid FOR UPDATE;
  IF NOT FOUND OR v_row.lifecycle_state IS NOT NULL THEN RAISE EXCEPTION 'Exact existing unbound subscription required'; END IF;
  v_row.lifecycle_state := p_state; v_row.lifecycle_policy := p_policy;
  v_row.lifecycle_activated_at := p_activated_at; v_row.plan_revision_id := (p_state->>'revisionId')::uuid;
  PERFORM public.assert_subscription_lifecycle_binding(v_row);
  v_receipt := jsonb_build_object('operationId',p_operation_id,'state',p_state,'policy',p_policy,'activatedAt',p_activated_at);
  INSERT INTO public.subscription_lifecycle_operations(operation_id,subscription_id,actor_id,kind,identity,receipt,committed_at)
    VALUES(p_operation_id,v_row.id,p_actor_id,'initialize',v_identity,v_receipt,v_at);
  UPDATE public.subscriptions SET lifecycle_state=p_state,lifecycle_policy=p_policy,lifecycle_activated_at=p_activated_at,plan_revision_id=v_row.plan_revision_id WHERE id=v_row.id;
  RETURN v_receipt;
END;
$$;

CREATE FUNCTION public.commit_subscription_lifecycle(p_identity jsonb, p_decision jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_op uuid; v_actor uuid; v_state jsonb; v_next jsonb; v_request jsonb; v_policy jsonb;
  v_row public.subscriptions%ROWTYPE; v_old public.subscription_lifecycle_operations%ROWTYPE;
  v_tx public.transactions%ROWTYPE; v_quote jsonb; v_settlement jsonb; v_transaction uuid;
  v_target jsonb; v_scheduled jsonb; v_currency jsonb; v_minor integer; v_amount numeric;
  v_receipt jsonb; v_at timestamptz; v_operation text; v_current_publication jsonb;
  v_expected_downgraded_at jsonb; v_effective_downgrade numeric;
BEGIN
  IF jsonb_typeof(p_identity) IS DISTINCT FROM 'object' OR jsonb_typeof(p_decision) IS DISTINCT FROM 'object'
    OR NOT p_identity ?& ARRAY['operationId','state','request','policy','actorId','subject','quote','settlement','approval','revisionChanges']
    OR (SELECT count(*) FROM jsonb_object_keys(p_identity)) <> 10
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
  IF v_current_publication#>'{configuration,subscription_revision_changes}' IS DISTINCT FROM p_identity->'revisionChanges'
    OR jsonb_typeof(p_identity->'revisionChanges') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Retained revision direction configuration required'; END IF;
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
    OR v_target#>'{configuration,subscription_lifecycle}' IS DISTINCT FROM v_policy THEN RAISE EXCEPTION 'Published target and exact policy required'; END IF;
  IF v_next->'scheduledChange' IS DISTINCT FROM 'null'::jsonb THEN
    SELECT canonical_plan INTO v_scheduled FROM public.subscription_plan_publication_events
      WHERE plan_id=(v_next#>>'{scheduledChange,planId}')::uuid AND revision_id=(v_next#>>'{scheduledChange,revisionId}')::uuid;
    IF v_scheduled IS NULL OR v_scheduled->>'productId' IS DISTINCT FROM v_state->>'productId' THEN RAISE EXCEPTION 'Published scheduled target required'; END IF;
  END IF;
  IF v_policy ? 'readOnlyDurationMs' THEN
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
      OR (v_quote->>'validUntil')::numeric <= extract(epoch FROM clock_timestamp()) * 1000
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
  UPDATE public.subscriptions SET lifecycle_state=v_next, plan_id=(v_next->>'planId')::uuid,
    metadata=CASE WHEN v_operation IN ('renew','upgrade')
      AND (v_quote->>'periodEndsAt')::numeric>(v_row.metadata#>>'{subscription_execution,subscriptionEndsAt}')::numeric
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

REVOKE ALL ON FUNCTION public.reject_subscription_lifecycle_evidence_mutation(), public.assert_subscription_lifecycle_binding(public.subscriptions), public.guard_subscription_lifecycle_binding(), public.guard_consumed_subscription_transaction() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.initialize_subscription_lifecycle(uuid,jsonb,jsonb,uuid,timestamptz), public.commit_subscription_lifecycle(jsonb,jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.initialize_subscription_lifecycle(uuid,jsonb,jsonb,uuid,timestamptz), public.commit_subscription_lifecycle(jsonb,jsonb) TO service_role;
COMMIT;
