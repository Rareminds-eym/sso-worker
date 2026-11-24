-- PREPARATION ONLY. Applying this migration requires specific target approval.
-- A retained subscription_commerce_usage policy must explicitly choose ONE basis.
-- time_proportional_service values elapsed purchased service, never credits or requests.
-- recorded_usage accepts only a complete, owner-routed purchase ledger established
-- at settlement. Historical accounts cannot be synthesized during refund processing.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE TABLE public.subscription_commerce_usage_accounts (
  settlement_id uuid PRIMARY KEY REFERENCES public.subscription_commerce_settlements(id),
  owner_key text NOT NULL CHECK(length(owner_key)>0),
  source_evidence jsonb NOT NULL CHECK(jsonb_typeof(source_evidence)='object' AND source_evidence<>'{}'::jsonb),
  opened_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.subscription_commerce_usage_events (
  settlement_id uuid NOT NULL REFERENCES public.subscription_commerce_usage_accounts(settlement_id),
  event_id uuid NOT NULL, owner_key text NOT NULL, amount_minor bigint NOT NULL CHECK(amount_minor>=0),
  currency text NOT NULL CHECK(currency~'^[A-Z]{3}$'),
  source_evidence jsonb NOT NULL CHECK(jsonb_typeof(source_evidence)='object' AND source_evidence<>'{}'::jsonb),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(settlement_id,event_id)
);
CREATE TABLE public.subscription_commerce_refund_freezes (
  operation_id uuid PRIMARY KEY REFERENCES public.subscription_commerce_operations(operation_id),
  settlement_id uuid NOT NULL UNIQUE REFERENCES public.subscription_commerce_settlements(id),
  subscription_id uuid NOT NULL REFERENCES public.subscriptions(id),
  product_id uuid NOT NULL REFERENCES public.products(id), subject jsonb NOT NULL,
  through_at timestamptz NOT NULL, policy jsonb NOT NULL, valuation_id uuid NOT NULL UNIQUE REFERENCES public.subscription_commerce_usage_valuations(id)
);
CREATE INDEX subscription_commerce_refund_freezes_subscription_idx ON public.subscription_commerce_refund_freezes(subscription_id);
REVOKE ALL ON public.subscription_commerce_usage_accounts,public.subscription_commerce_usage_events,public.subscription_commerce_refund_freezes FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON public.subscription_commerce_usage_accounts,public.subscription_commerce_usage_events,public.subscription_commerce_refund_freezes TO service_role;

-- Refund reservation and state writers serialize on the same subscription row.
-- A request authorized before the freeze cannot mutate its retained terms later.
CREATE FUNCTION public.guard_subscription_commerce_refund_freeze()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_refund_freezes WHERE subscription_id=OLD.id) THEN
    RAISE EXCEPTION 'Refund-frozen subscription cannot mutate';
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER zzy_subscription_commerce_refund_freeze BEFORE UPDATE OR DELETE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.guard_subscription_commerce_refund_freeze();
REVOKE ALL ON FUNCTION public.guard_subscription_commerce_refund_freeze() FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.assert_subscription_commerce_scope(p_identity jsonb,p_quote jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE r public.subscriptions%ROWTYPE; req jsonb:=p_identity->'request';
BEGIN
  IF jsonb_typeof(p_identity) IS DISTINCT FROM 'object' OR jsonb_typeof(req) IS DISTINCT FROM 'object'
    OR p_identity->'actorId' IS DISTINCT FROM p_quote->'actorId' OR p_identity->'subject' IS DISTINCT FROM p_quote->'subject'
    OR p_identity->'productId' IS DISTINCT FROM p_quote->'productId' OR p_identity->'audience' IS DISTINCT FROM p_quote->'audience'
    OR req->'subject' IS DISTINCT FROM p_quote->'subject' OR req->'subscriptionId' IS DISTINCT FROM p_quote->'subscriptionId'
    OR req->'expectedVersion' IS DISTINCT FROM p_quote->'stateVersion' OR req->'expectedRevisionId' IS DISTINCT FROM p_quote->'expectedRevisionId'
    OR ((p_quote->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())*1000
      AND (req->>'kind' IS DISTINCT FROM 'settle'
        OR NOT public.subscription_commerce_has_timely_capture(p_quote,req->>'paymentId',NULL))) THEN
    RAISE EXCEPTION 'Commerce scope CAS or expiry differs';
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
    IF EXISTS(SELECT 1 FROM public.subscription_commerce_refund_freezes WHERE subscription_id=r.id)
      OR EXISTS(SELECT 1 FROM public.subscription_commerce_refunds WHERE subscription_id=r.id AND status='processed') THEN
      RAISE EXCEPTION 'Refund-frozen or cancelled subscription has no mutation authority';
    END IF;
  END IF;
END;
$$;

-- Internal monetary usage owner entrypoint, never an end-user amount API. The
-- caller must have opened the account in the SAME settlement transaction after
-- proving every billable owner routes its usage here; no late historical opening.
CREATE FUNCTION public.open_subscription_commerce_usage_account(p_settlement_id uuid,p_owner_key text,p_source_evidence jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE s public.subscription_commerce_settlements%ROWTYPE; basis jsonb; old public.subscription_commerce_usage_accounts%ROWTYPE; settlement_xid bigint;
BEGIN
  SELECT * INTO s FROM public.subscription_commerce_settlements WHERE id=p_settlement_id FOR UPDATE;
  IF NOT FOUND OR s.purpose='retake' THEN RAISE EXCEPTION 'Usage account requires original settlement transaction'; END IF;
  SELECT xmin::text::bigint INTO settlement_xid FROM public.subscription_commerce_settlements WHERE id=s.id;
  IF settlement_xid<>txid_current()%4294967296 THEN RAISE EXCEPTION 'Usage account requires original settlement transaction'; END IF;
  SELECT e.canonical_plan#>'{configuration,subscription_commerce_usage}' INTO basis
    FROM public.subscription_commerce_quotes q JOIN public.subscription_plan_publication_events e ON e.revision_id=(q.quote->>'revisionId')::uuid WHERE q.id=s.quote_id;
  IF basis IS DISTINCT FROM jsonb_build_object('schemaVersion',1,'basis','recorded_usage')
    OR p_owner_key IS NULL OR length(p_owner_key)=0 OR jsonb_typeof(p_source_evidence) IS DISTINCT FROM 'object' OR p_source_evidence='{}'::jsonb THEN RAISE EXCEPTION 'Explicit complete monetary owner required'; END IF;
  SELECT * INTO old FROM public.subscription_commerce_usage_accounts WHERE settlement_id=s.id;
  IF FOUND THEN
    IF old.owner_key IS DISTINCT FROM p_owner_key OR old.source_evidence IS DISTINCT FROM p_source_evidence THEN RAISE EXCEPTION 'Usage account replay differs'; END IF;
    RETURN;
  END IF;
  INSERT INTO public.subscription_commerce_usage_accounts(settlement_id,owner_key,source_evidence) VALUES(s.id,p_owner_key,p_source_evidence);
END;
$$;

CREATE FUNCTION public.record_subscription_commerce_usage(p_settlement_id uuid,p_event_id uuid,p_owner_key text,p_amount_minor bigint,p_currency text,p_source_evidence jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE s public.subscription_commerce_settlements%ROWTYPE; a public.subscription_commerce_usage_accounts%ROWTYPE; old public.subscription_commerce_usage_events%ROWTYPE;
BEGIN
  SELECT * INTO s FROM public.subscription_commerce_settlements WHERE id=p_settlement_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Purchase settlement required'; END IF;
  PERFORM 1 FROM public.subscriptions WHERE id=s.subscription_id FOR UPDATE;
  SELECT * INTO s FROM public.subscription_commerce_settlements WHERE id=p_settlement_id FOR UPDATE;
  SELECT * INTO a FROM public.subscription_commerce_usage_accounts WHERE settlement_id=s.id;
  IF NOT FOUND OR a.owner_key IS DISTINCT FROM p_owner_key OR s.currency IS DISTINCT FROM p_currency
    OR p_event_id IS NULL OR p_amount_minor IS NULL OR p_amount_minor<0 OR p_amount_minor>9007199254740991
    OR jsonb_typeof(p_source_evidence) IS DISTINCT FROM 'object' OR p_source_evidence='{}'::jsonb THEN RAISE EXCEPTION 'Complete purchase monetary attribution required'; END IF;
  SELECT * INTO old FROM public.subscription_commerce_usage_events WHERE settlement_id=s.id AND event_id=p_event_id;
  IF FOUND THEN
    IF old.owner_key IS DISTINCT FROM p_owner_key OR old.amount_minor IS DISTINCT FROM p_amount_minor OR old.currency IS DISTINCT FROM p_currency
      OR old.source_evidence IS DISTINCT FROM p_source_evidence THEN RAISE EXCEPTION 'Usage event replay differs'; END IF;
    RETURN;
  END IF;
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_refund_freezes WHERE subscription_id=s.subscription_id)
    OR EXISTS(SELECT 1 FROM public.subscription_commerce_refunds WHERE subscription_id=s.subscription_id AND status='processed') THEN RAISE EXCEPTION 'Refund-frozen purchase cannot consume service'; END IF;
  INSERT INTO public.subscription_commerce_usage_events(settlement_id,event_id,owner_key,amount_minor,currency,source_evidence)
    VALUES(s.id,p_event_id,p_owner_key,p_amount_minor,p_currency,p_source_evidence);
END;
$$;

CREATE FUNCTION public.freeze_subscription_commerce_refund(p_identity jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE s public.subscription_commerce_settlements%ROWTYPE; r public.subscriptions%ROWTYPE; q jsonb; policy jsonb;
  op uuid:=(p_identity->>'operationId')::uuid; at_ms numeric; start_ms numeric; end_ms numeric; usage_minor numeric; refunded numeric; amount numeric;
  at_time timestamptz; valuation public.subscription_commerce_usage_valuations%ROWTYPE; usage jsonb;
BEGIN
  IF p_identity#>>'{request,kind}' IS DISTINCT FROM 'refund' THEN RAISE EXCEPTION 'Explicit refund identity required'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_operation:'||op::text,0));
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_operations WHERE operation_id=op) THEN RAISE EXCEPTION 'Refund already reserved; reconcile existing provider operation'; END IF;
  SELECT * INTO r FROM public.subscriptions WHERE id=(p_identity#>>'{request,subscriptionId}')::uuid FOR UPDATE;
  SELECT * INTO s FROM public.subscription_commerce_settlements WHERE id=(p_identity#>>'{request,settlementId}')::uuid FOR UPDATE;
  IF r.id IS NULL OR s.id IS NULL OR s.subscription_id<>r.id OR s.purpose='retake'
    OR s.product_id::text IS DISTINCT FROM p_identity->>'productId' OR s.subject IS DISTINCT FROM p_identity->'subject'
    OR r.lifecycle_state->'subject' IS DISTINCT FROM s.subject THEN RAISE EXCEPTION 'Refund purchase owner differs'; END IF;
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_refund_freezes WHERE subscription_id=r.id) THEN RAISE EXCEPTION 'Purchase usage already frozen; reconcile refund'; END IF;
  SELECT cq.quote,e.canonical_plan#>'{configuration,subscription_commerce_usage}' INTO q,policy
    FROM public.subscription_commerce_quotes cq JOIN public.subscription_plan_publication_events e ON e.revision_id=(cq.quote->>'revisionId')::uuid WHERE cq.id=s.quote_id;
  at_ms:=floor(extract(epoch FROM clock_timestamp())*1000); at_time:=to_timestamp(at_ms/1000);
  IF policy=jsonb_build_object('schemaVersion',1,'basis','time_proportional_service') THEN
    start_ms:=(q->>'periodStartsAt')::numeric; end_ms:=(q->>'periodEndsAt')::numeric;
    IF s.purpose='upgrade' THEN start_ms:=greatest(start_ms,extract(epoch FROM s.settled_at)*1000); END IF;
    IF start_ms IS NULL OR end_ms IS NULL OR start_ms>=end_ms OR at_time<s.settled_at THEN RAISE EXCEPTION 'Actual paid coverage required'; END IF;
    usage_minor:=floor(s.amount_minor::numeric*greatest(0,least(end_ms-start_ms,at_ms-start_ms))/(end_ms-start_ms));
  ELSIF policy=jsonb_build_object('schemaVersion',1,'basis','recorded_usage') THEN
    IF NOT EXISTS(SELECT 1 FROM public.subscription_commerce_usage_accounts WHERE settlement_id=s.id) THEN RAISE EXCEPTION 'Complete purchase monetary owner unavailable'; END IF;
    SELECT coalesce(sum(amount_minor),0) INTO usage_minor FROM public.subscription_commerce_usage_events WHERE settlement_id=s.id;
  ELSE RAISE EXCEPTION 'Explicit retained monetary usage basis required'; END IF;
  IF usage_minor NOT BETWEEN 0 AND 9007199254740991 THEN RAISE EXCEPTION 'Usage valuation outside exact currency range'; END IF;
  INSERT INTO public.subscription_commerce_usage_valuations(settlement_id,subscription_id,product_id,subject,currency,amount_minor,complete,through_at,source_evidence)
    VALUES(s.id,r.id,s.product_id,s.subject,s.currency,usage_minor,true,at_time,
      jsonb_build_object('policy',policy,'quoteId',s.quote_id,'settlementId',s.id,'coverageStartsAt',start_ms,'coverageEndsAt',end_ms,'operationId',op)) RETURNING * INTO valuation;
  usage:=to_jsonb(valuation)-'id'-'source_evidence';
  SELECT coalesce(sum(amount_minor),0) INTO refunded FROM public.subscription_commerce_refunds WHERE settlement_id=s.id AND status='processed';
  amount:=greatest(0,least(s.amount_minor-refunded,s.amount_minor-usage_minor-refunded));
  -- The original owner validates live CAS, scope, refund window, uncertain prior
  -- refunds and exact frozen evidence. Failure rolls back this entire transaction.
  PERFORM public.reserve_subscription_commerce_operation(p_identity,jsonb_build_object('settlementId',s.id,'amountMinor',amount,'usage',usage,'requestedAt',at_ms));
  INSERT INTO public.subscription_commerce_refund_freezes(operation_id,settlement_id,subscription_id,product_id,subject,through_at,policy,valuation_id)
    VALUES(op,s.id,r.id,s.product_id,s.subject,at_time,policy,valuation.id);
  RETURN jsonb_build_object('amountMinor',amount,'usage',usage,'requestedAt',at_ms);
END;
$$;

-- Entry contracts retain explicit validity and included institution capacity.
-- Negotiated contracts reference the EXISTING Hybrid owner's subscription; this
-- table does not replace that owner's price, seats, features or commercial dates.
CREATE TABLE public.subscription_commerce_entry_contracts (
  id uuid PRIMARY KEY, product_id uuid NOT NULL REFERENCES public.products(id),
  revision_id uuid NOT NULL REFERENCES public.subscription_plan_drafts(id), subject jsonb NOT NULL,
  audience text NOT NULL, starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL CHECK(ends_at>starts_at),
  included_learner_capacity integer CHECK(included_learner_capacity>0),
  source_subscription_id uuid UNIQUE REFERENCES public.subscriptions(id),
  recorded_by uuid NOT NULL REFERENCES public.users(id), source_evidence jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(jsonb_typeof(source_evidence)='object' AND source_evidence<>'{}'::jsonb),
  CHECK(jsonb_typeof(subject)='object' AND subject->>'kind' IN ('user','organization') AND subject ? 'id'),
  CHECK((subject->>'kind'='organization')=(included_learner_capacity IS NOT NULL))
);
REVOKE ALL ON public.subscription_commerce_entry_contracts FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON public.subscription_commerce_entry_contracts TO service_role;

-- Invoked only by the authenticated subscription administrator owner after its
-- live role and target checks. No HTTP amount/duration input reaches activation.
CREATE FUNCTION public.record_subscription_commerce_entry_contract(p_contract jsonb,p_actor_id uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE id uuid:=(p_contract->>'id')::uuid; old public.subscription_commerce_entry_contracts%ROWTYPE;
  source public.subscriptions%ROWTYPE; publication jsonb; draft jsonb; starts timestamptz; ends timestamptz;
BEGIN
  IF jsonb_typeof(p_contract) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(p_contract))<>11
    OR NOT p_contract ?& ARRAY['id','productId','revisionId','subject','audience','startsAt','endsAt','includedLearnerCapacity','sourceSubscriptionId','sourceEvidence','schemaVersion']
    OR p_contract->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR p_actor_id IS NULL
    OR jsonb_typeof(p_contract->'sourceEvidence') IS DISTINCT FROM 'object' OR p_contract->'sourceEvidence'='{}'::jsonb
    OR jsonb_typeof(p_contract->'startsAt') IS DISTINCT FROM 'number' OR jsonb_typeof(p_contract->'endsAt') IS DISTINCT FROM 'number'
    OR (p_contract->>'startsAt')::numeric NOT BETWEEN 0 AND 9007199254740991
    OR (p_contract->>'endsAt')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (p_contract->>'startsAt')::numeric<>trunc((p_contract->>'startsAt')::numeric)
    OR (p_contract->>'endsAt')::numeric<>trunc((p_contract->>'endsAt')::numeric) THEN RAISE EXCEPTION 'Explicit entry contract required'; END IF;
  starts:=to_timestamp((p_contract->>'startsAt')::numeric/1000); ends:=to_timestamp((p_contract->>'endsAt')::numeric/1000);
  SELECT e.canonical_plan,d.snapshot INTO publication,draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id WHERE e.revision_id=(p_contract->>'revisionId')::uuid;
  IF publication IS NULL OR publication->'productId' IS DISTINCT FROM p_contract->'productId'
    OR (publication->'audiences' ? (p_contract->>'audience')) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Retained contract publication differs'; END IF;
  IF p_contract->'sourceSubscriptionId'='null'::jsonb THEN
    IF draft->>'purchaseMode' IS DISTINCT FROM 'free' OR draft->'prices' IS DISTINCT FROM '[]'::jsonb
      OR publication#>'{configuration,subscription_entry}' IS DISTINCT FROM jsonb_build_object('schemaVersion',1,'validity','owner_contract_required') THEN RAISE EXCEPTION 'Free entry requires explicit owner validity'; END IF;
  ELSE
    SELECT * INTO source FROM public.subscriptions WHERE subscriptions.id=(p_contract->>'sourceSubscriptionId')::uuid FOR UPDATE;
    IF NOT FOUND OR draft->>'purchaseMode' IS DISTINCT FROM 'contact_sales' OR source.plan_id::text IS DISTINCT FROM publication->>'id'
      OR source.product_id::text IS DISTINCT FROM p_contract->>'productId' OR source.status<>'active'
      OR source.subscription_start_date IS DISTINCT FROM starts OR source.subscription_end_date IS DISTINCT FROM ends
      OR source.is_organization_subscription IS NOT TRUE OR source.organization_id::text IS DISTINCT FROM p_contract#>>'{subject,id}'
      OR p_contract#>>'{subject,kind}' IS DISTINCT FROM 'organization'
      OR to_jsonb(source.seat_count) IS DISTINCT FROM p_contract->'includedLearnerCapacity' THEN RAISE EXCEPTION 'Existing negotiated owner terms differ'; END IF;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_entry_contract:'||id::text,0));
  SELECT * INTO old FROM public.subscription_commerce_entry_contracts c WHERE c.id=id;
  IF FOUND THEN
    IF old.product_id::text IS DISTINCT FROM p_contract->>'productId' OR old.revision_id::text IS DISTINCT FROM p_contract->>'revisionId'
      OR old.subject IS DISTINCT FROM p_contract->'subject' OR old.audience IS DISTINCT FROM p_contract->>'audience'
      OR old.starts_at IS DISTINCT FROM starts OR old.ends_at IS DISTINCT FROM ends OR old.recorded_by IS DISTINCT FROM p_actor_id
      OR to_jsonb(old.included_learner_capacity) IS DISTINCT FROM nullif(p_contract->'includedLearnerCapacity','null'::jsonb)
      OR old.source_subscription_id IS DISTINCT FROM (p_contract->>'sourceSubscriptionId')::uuid OR old.source_evidence IS DISTINCT FROM p_contract->'sourceEvidence' THEN RAISE EXCEPTION 'Entry contract replay differs'; END IF;
    RETURN id;
  END IF;
  INSERT INTO public.subscription_commerce_entry_contracts(id,product_id,revision_id,subject,audience,starts_at,ends_at,included_learner_capacity,source_subscription_id,recorded_by,source_evidence)
    VALUES(id,(p_contract->>'productId')::uuid,(p_contract->>'revisionId')::uuid,p_contract->'subject',p_contract->>'audience',starts,ends,
      (p_contract->>'includedLearnerCapacity')::integer,(p_contract->>'sourceSubscriptionId')::uuid,p_actor_id,p_contract->'sourceEvidence');
  RETURN id;
END;
$$;

CREATE FUNCTION public.activate_subscription_commerce_contract(p_identity jsonb,p_contract_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE c public.subscription_commerce_entry_contracts%ROWTYPE; old public.subscription_commerce_operations%ROWTYPE;
  existing public.subscriptions%ROWTYPE; publication jsonb; draft jsonb; policy jsonb; state jsonb; result jsonb; buyer_email text;
  op uuid:=(p_identity->>'operationId')::uuid; sub uuid:=(p_identity#>>'{request,subscriptionId}')::uuid;
  actor uuid:=(p_identity->>'actorId')::uuid; organization uuid; start_ms numeric; end_ms numeric;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_operation:'||op::text,0));
  SELECT * INTO old FROM public.subscription_commerce_operations WHERE operation_id=op;
  IF FOUND THEN
    IF old.identity IS DISTINCT FROM p_identity OR old.receipt IS NULL THEN RAISE EXCEPTION 'Activation replay differs or remains pending'; END IF;
    RETURN old.receipt;
  END IF;
  SELECT * INTO c FROM public.subscription_commerce_entry_contracts WHERE id=p_contract_id FOR UPDATE;
  IF NOT FOUND OR p_identity#>>'{request,kind}' IS DISTINCT FROM 'activate'
    OR p_identity#>>'{request,contractId}' IS DISTINCT FROM c.id::text OR p_identity#>'{request,expectedVersion}' IS DISTINCT FROM '0'::jsonb
    OR p_identity#>>'{request,expectedRevisionId}' IS DISTINCT FROM c.revision_id::text
    OR p_identity->>'productId' IS DISTINCT FROM c.product_id::text OR p_identity->'subject' IS DISTINCT FROM c.subject
    OR p_identity#>'{request,subject}' IS DISTINCT FROM c.subject OR p_identity->>'audience' IS DISTINCT FROM c.audience
    OR clock_timestamp()<c.starts_at OR clock_timestamp()>=c.ends_at THEN RAISE EXCEPTION 'Live owner entry contract required'; END IF;
  SELECT e.canonical_plan,d.snapshot INTO publication,draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id WHERE e.revision_id=c.revision_id;
  IF publication IS NULL OR publication->>'productId' IS DISTINCT FROM c.product_id::text
    OR (publication->'audiences' ? c.audience) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Contract publication unavailable'; END IF;
  IF c.subject->>'kind'='organization' THEN organization:=(c.subject->>'id')::uuid;
  ELSIF c.subject->>'kind'<>'user' OR c.subject->>'id' IS DISTINCT FROM actor::text THEN RAISE EXCEPTION 'Contract purchaser differs'; END IF;
  SELECT email INTO buyer_email FROM public.users WHERE id=actor AND is_blocked=false AND is_email_verified=true;
  IF buyer_email IS NULL THEN RAISE EXCEPTION 'Live verified purchaser required'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_purchase:'||c.subject::text||':'||c.product_id::text,0));
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_operations WHERE identity#>>'{request,kind}'='activate' AND evidence->>'contractId'=c.id::text) THEN RAISE EXCEPTION 'Entry contract already consumed'; END IF;
  start_ms:=extract(epoch FROM c.starts_at)*1000; end_ms:=extract(epoch FROM c.ends_at)*1000;
  IF c.source_subscription_id IS NULL THEN
    IF draft->>'purchaseMode' IS DISTINCT FROM 'free' OR draft->'prices' IS DISTINCT FROM '[]'::jsonb
      OR publication#>'{configuration,subscription_entry}' IS DISTINCT FROM jsonb_build_object('schemaVersion',1,'validity','owner_contract_required') THEN RAISE EXCEPTION 'Free owner entry unavailable'; END IF;
    IF EXISTS(SELECT 1 FROM public.subscriptions WHERE id=sub OR (product_id=c.product_id AND status IN ('active','pending','grace_period','paused')
      AND CASE WHEN organization IS NULL THEN user_id=actor AND is_organization_subscription IS NOT TRUE ELSE organization_id=organization AND is_organization_subscription IS TRUE END)) THEN RAISE EXCEPTION 'Existing subscription requires explicit transition'; END IF;
    INSERT INTO public.subscriptions(id,user_id,organization_id,is_organization_subscription,purchased_by,plan_id,product_id,email,plan_code,plan_type,
      plan_amount,billing_cycle,features,status,auto_renew,subscription_start_date,subscription_end_date,seat_count,metadata)
      VALUES(sub,actor,organization,organization IS NOT NULL,c.recorded_by,(publication->>'id')::uuid,c.product_id,buyer_email,publication->>'code',draft->>'name',
        0,'contract',draft->'features','active',false,c.starts_at,c.ends_at,c.included_learner_capacity,
        jsonb_build_object('subscription_execution',jsonb_build_object('audience',c.audience,'subscriptionEndsAt',end_ms),'subscription_entry_contract',c.id));
  ELSE
    IF sub<>c.source_subscription_id THEN RAISE EXCEPTION 'Negotiated activation must retain existing subscription identity'; END IF;
    SELECT * INTO existing FROM public.subscriptions WHERE id=sub FOR UPDATE;
    IF NOT FOUND OR existing.lifecycle_state IS NOT NULL OR draft->>'purchaseMode' IS DISTINCT FROM 'contact_sales'
      OR existing.plan_id::text IS DISTINCT FROM publication->>'id' OR existing.product_id<>c.product_id OR existing.status<>'active'
      OR existing.organization_id IS DISTINCT FROM organization OR existing.is_organization_subscription IS NOT TRUE
      OR existing.subscription_start_date IS DISTINCT FROM c.starts_at OR existing.subscription_end_date IS DISTINCT FROM c.ends_at
      OR existing.seat_count IS DISTINCT FROM c.included_learner_capacity THEN RAISE EXCEPTION 'Existing negotiated terms changed'; END IF;
    UPDATE public.subscriptions SET metadata=metadata||jsonb_build_object('subscription_execution',jsonb_build_object('audience',c.audience,'subscriptionEndsAt',end_ms),'subscription_entry_contract',c.id) WHERE id=sub;
  END IF;
  policy:=publication#>'{configuration,subscription_lifecycle}';
  state:=jsonb_build_object('id',sub,'subject',c.subject,'planId',publication->'id','revisionId',c.revision_id,'productId',c.product_id,
    'version',1,'status','active','periodStartsAt',start_ms,'periodEndsAt',end_ms,'trialEndsAt',NULL,
    'renewalEnabled',CASE WHEN c.source_subscription_id IS NULL THEN false ELSE existing.auto_renew END,'cancelledAt',NULL,'paymentFailedAt',NULL,'scheduledChange',NULL);
  IF policy ? 'readOnlyDurationMs' THEN state:=state||jsonb_build_object('downgradedAt',NULL); END IF;
  PERFORM public.initialize_subscription_lifecycle(op,state,policy,actor,c.starts_at);
  result:=jsonb_build_object('kind','activation','operationId',op,'contractId',c.id,'subscriptionId',sub,'productId',c.product_id,'subject',c.subject,'revisionId',c.revision_id);
  INSERT INTO public.subscription_commerce_operations(operation_id,identity,evidence,receipt) VALUES(op,p_identity,jsonb_build_object('contractId',c.id),result);
  RETURN result;
END;
$$;

REVOKE ALL ON FUNCTION public.record_subscription_commerce_entry_contract(jsonb,uuid),public.activate_subscription_commerce_contract(jsonb,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.record_subscription_commerce_entry_contract(jsonb,uuid),public.activate_subscription_commerce_contract(jsonb,uuid) TO service_role;
REVOKE ALL ON FUNCTION public.open_subscription_commerce_usage_account(uuid,text,jsonb),public.record_subscription_commerce_usage(uuid,uuid,text,bigint,text,jsonb),public.freeze_subscription_commerce_refund(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.open_subscription_commerce_usage_account(uuid,text,jsonb),public.record_subscription_commerce_usage(uuid,uuid,text,bigint,text,jsonb),public.freeze_subscription_commerce_refund(jsonb) TO service_role;
-- A retake is an independent purchase under retained non-free terms. Negotiated
-- Hybrid subscriptions prove payment through their existing commercial owner,
-- rather than manufacturing a public monthly price for a negotiated contract.
CREATE FUNCTION public.issue_subscription_commerce_retake_quote(p_identity jsonb,p_quote jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid:=(p_identity->>'operationId')::uuid; old public.subscription_commerce_operations%ROWTYPE;
  subscription public.subscriptions%ROWTYPE; publication jsonb; draft jsonb; policy jsonb; result jsonb;
BEGIN
  IF jsonb_typeof(p_quote) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(p_quote))<>20
    OR NOT p_quote ?& ARRAY['id','actorId','subscriptionId','productId','subject','audience','stateVersion','expectedRevisionId','planId','revisionId','purpose','referenceId','priceId','amountMinor','currency','minorUnit','periodStartsAt','periodEndsAt','createdAt','validUntil']
    OR p_quote->>'purpose' IS DISTINCT FROM 'retake' OR p_identity#>>'{request,kind}' IS DISTINCT FROM 'quote'
    OR p_identity#>>'{request,purpose}' IS DISTINCT FROM 'retake' OR p_quote->>'id' IS DISTINCT FROM op::text
    OR p_identity#>'{request,revisionId}' IS DISTINCT FROM p_quote->'revisionId'
    OR p_identity#>'{request,referenceId}' IS DISTINCT FROM p_quote->'referenceId'
    OR jsonb_typeof(p_quote->'referenceId') IS DISTINCT FROM 'string' OR (p_quote->>'referenceId')::uuid IS NULL
    OR p_quote->'priceId' IS DISTINCT FROM 'null'::jsonb
    OR EXISTS(SELECT 1 FROM jsonb_each(p_quote) v WHERE v.key IN ('stateVersion','amountMinor','minorUnit','periodStartsAt','periodEndsAt','createdAt','validUntil')
      AND CASE WHEN jsonb_typeof(v.value)='number' THEN (v.value#>>'{}')::numeric NOT BETWEEN 0 AND 9007199254740991 OR (v.value#>>'{}')::numeric<>trunc((v.value#>>'{}')::numeric) ELSE true END)
    THEN RAISE EXCEPTION 'Exact retake quote required'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_operation:'||op::text,0));
  SELECT * INTO old FROM public.subscription_commerce_operations WHERE operation_id=op;
  IF FOUND THEN
    IF old.identity IS DISTINCT FROM p_identity OR old.evidence IS DISTINCT FROM p_quote THEN RAISE EXCEPTION 'Retake quote replay differs'; END IF;
    RETURN old.receipt;
  END IF;
  PERFORM public.assert_subscription_commerce_scope(p_identity,p_quote);
  SELECT * INTO subscription FROM public.subscriptions WHERE id=(p_quote->>'subscriptionId')::uuid FOR UPDATE;
  SELECT e.canonical_plan,d.snapshot INTO publication,draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id AND d.plan_id=e.plan_id
    WHERE e.revision_id=(p_quote->>'revisionId')::uuid AND e.plan_id=(p_quote->>'planId')::uuid;
  policy:=publication#>'{configuration,subscription_commerce}';
  IF publication IS NULL OR publication->'productId' IS DISTINCT FROM p_quote->'productId'
    OR (publication->'audiences' ? (p_quote->>'audience')) IS DISTINCT FROM true
    OR draft->>'purchaseMode' NOT IN ('self_service','contact_sales') OR draft->>'purchaseMode' IS NULL
    OR subscription.lifecycle_policy IS DISTINCT FROM publication#>'{configuration,subscription_lifecycle}'
    OR subscription.lifecycle_state->>'status' IS DISTINCT FROM 'active'
    OR subscription.lifecycle_state->'planId' IS DISTINCT FROM p_quote->'planId'
    OR subscription.lifecycle_state->'revisionId' IS DISTINCT FROM p_quote->'revisionId'
    OR subscription.lifecycle_state->'periodStartsAt' IS DISTINCT FROM p_quote->'periodStartsAt'
    OR subscription.lifecycle_state->'periodEndsAt' IS DISTINCT FROM p_quote->'periodEndsAt'
    OR (p_quote->>'createdAt')::numeric>=(subscription.lifecycle_state->>'periodEndsAt')::numeric
    OR (p_quote->>'createdAt')::numeric>extract(epoch FROM clock_timestamp())*1000
    OR (p_quote->>'validUntil')::numeric IS DISTINCT FROM (p_quote->>'createdAt')::numeric+(policy->>'quoteValidityMs')::numeric
    OR policy->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR policy#>'{retake,everyRetake}' IS DISTINCT FROM 'true'::jsonb
    OR p_quote->'amountMinor' IS DISTINCT FROM policy#>'{retake,amountMinor}'
    OR (p_quote->>'amountMinor')::numeric<1 OR p_quote->'currency' IS DISTINCT FROM policy#>'{retake,currency}'
    OR p_quote->>'currency'!~'^[A-Z]{3}$' OR p_quote->'minorUnit' IS DISTINCT FROM policy#>'{retake,minorUnit}'
    OR (draft->>'purchaseMode'='contact_sales' AND (subscription.plan_amount IS NULL OR subscription.plan_amount<=0))
    OR (draft->>'purchaseMode'='self_service' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(draft->'prices') p
      WHERE (p->>'amountMinor')::numeric>0 AND p->'audiences' ? (p_quote->>'audience')))
    THEN RAISE EXCEPTION 'Retained paid retake terms differ'; END IF;
  IF EXISTS(SELECT 1 FROM public.subscription_commerce_refund_freezes WHERE subscription_id=subscription.id) THEN RAISE EXCEPTION 'Refund-frozen subscription cannot buy a retake'; END IF;
  result:=jsonb_build_object('kind','quote','operationId',op,'quote',p_quote);
  INSERT INTO public.subscription_commerce_operations(operation_id,identity,evidence,receipt) VALUES(op,p_identity,p_quote,result);
  INSERT INTO public.subscription_commerce_quotes(id,quote) VALUES(op,p_quote);
  RETURN result;
END;
$$;
REVOKE ALL ON FUNCTION public.issue_subscription_commerce_retake_quote(jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.issue_subscription_commerce_retake_quote(jsonb,jsonb) TO service_role;

-- The original paid settlement INSERT predates included learner licensing and
-- does not name seat_count. Derive it BEFORE that INSERT from the exact issued
-- quote's immutable revision. Lifecycle renew/upgrade updates use their target
-- revision, so a new paid institution term cannot keep a stale seat quantity.
CREATE FUNCTION public.bind_subscription_included_learner_capacity()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE quote jsonb; publication jsonb; draft jsonb; grant_value jsonb;
  revision uuid; matches integer; capacity numeric; contract public.subscription_commerce_entry_contracts%ROWTYPE;
BEGIN
  IF NEW.is_organization_subscription IS NOT TRUE THEN RETURN NEW; END IF;
  IF TG_OP='INSERT' AND NEW.metadata ? 'subscription_purchase_quote' THEN
    SELECT q.quote INTO quote FROM public.subscription_commerce_quotes q
      WHERE q.id=(NEW.metadata#>>'{subscription_purchase_quote,id}')::uuid;
    IF quote IS NULL OR quote IS DISTINCT FROM NEW.metadata->'subscription_purchase_quote'
      OR quote->>'purpose' IS DISTINCT FROM 'purchase' OR quote->>'subscriptionId' IS DISTINCT FROM NEW.id::text
      OR quote->>'productId' IS DISTINCT FROM NEW.product_id::text OR quote->>'planId' IS DISTINCT FROM NEW.plan_id::text
      OR quote#>>'{subject,kind}' IS DISTINCT FROM 'organization'
      OR quote#>>'{subject,id}' IS DISTINCT FROM NEW.organization_id::text THEN RAISE EXCEPTION 'Included capacity requires exact purchased organization terms'; END IF;
    revision:=(quote->>'revisionId')::uuid;
  ELSIF NEW.plan_revision_id IS NOT NULL THEN
    revision:=NEW.plan_revision_id;
    IF NEW.lifecycle_state->>'revisionId' IS DISTINCT FROM revision::text
      OR NEW.lifecycle_state->>'planId' IS DISTINCT FROM NEW.plan_id::text
      OR NEW.lifecycle_state->>'productId' IS DISTINCT FROM NEW.product_id::text
      OR NEW.lifecycle_state#>>'{subject,kind}' IS DISTINCT FROM 'organization'
      OR NEW.lifecycle_state#>>'{subject,id}' IS DISTINCT FROM NEW.organization_id::text THEN RAISE EXCEPTION 'Included capacity lifecycle owner differs'; END IF;
  ELSE RETURN NEW;
  END IF;
  SELECT e.canonical_plan,d.snapshot INTO publication,draft FROM public.subscription_plan_publication_events e
    JOIN public.subscription_plan_drafts d ON d.id=e.revision_id AND d.plan_id=e.plan_id
    WHERE e.revision_id=revision AND e.plan_id=NEW.plan_id;
  IF publication IS NULL OR publication->>'productId' IS DISTINCT FROM NEW.product_id::text
    OR jsonb_typeof(draft->'features') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Included capacity publication unavailable'; END IF;
  SELECT count(*) INTO matches FROM jsonb_array_elements(draft->'features') g WHERE g->>'key'='included_learner_capacity';
  -- Other organization offerings have their own seat owner, not learner capacity.
  IF matches=0 THEN RETURN NEW; END IF;
  IF matches<>1 THEN RAISE EXCEPTION 'Ambiguous included learner capacity'; END IF;
  SELECT g INTO grant_value FROM jsonb_array_elements(draft->'features') g WHERE g->>'key'='included_learner_capacity';
  IF grant_value->>'type' IS DISTINCT FROM 'numeric_limit' OR grant_value->'enabled' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'Enabled included learner capacity required'; END IF;
  IF grant_value#>>'{limit,kind}'='contract_required' THEN
    SELECT * INTO contract FROM public.subscription_commerce_entry_contracts c
      WHERE c.id=(NEW.metadata->>'subscription_entry_contract')::uuid AND c.source_subscription_id=NEW.id
        AND c.revision_id=revision AND c.product_id=NEW.product_id
        AND c.subject=jsonb_build_object('kind','organization','id',NEW.organization_id);
    IF NOT FOUND OR draft->>'purchaseMode' IS DISTINCT FROM 'contact_sales'
      OR contract.included_learner_capacity IS DISTINCT FROM NEW.seat_count
      OR contract.starts_at IS DISTINCT FROM NEW.subscription_start_date OR contract.ends_at IS DISTINCT FROM NEW.subscription_end_date THEN
      RAISE EXCEPTION 'Exact negotiated learner capacity owner required';
    END IF;
    capacity:=contract.included_learner_capacity;
  ELSE
    IF grant_value#>>'{limit,kind}' IS DISTINCT FROM 'finite' OR jsonb_typeof(grant_value#>'{limit,value}') IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'Finite included learner capacity required'; END IF;
    capacity:=(grant_value#>>'{limit,value}')::numeric;
  END IF;
  IF capacity IS NULL OR capacity<>trunc(capacity) OR capacity NOT BETWEEN 1 AND 2147483647 THEN RAISE EXCEPTION 'Included learner capacity outside persisted range'; END IF;
  IF TG_OP='UPDATE' AND OLD.seat_count IS NOT NULL AND capacity<OLD.seat_count THEN
    -- App usage is in another DB. A reduction requires its coordinated resource
    -- owner; silently retaining old seats or reducing occupied seats is invalid.
    RAISE EXCEPTION 'Learner capacity reduction requires coordinated resource ownership';
  END IF;
  NEW.seat_count:=capacity::integer;
  IF jsonb_typeof(NEW.metadata) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Subscription capacity metadata owner required'; END IF;
  NEW.metadata:=jsonb_set(NEW.metadata,'{subscription_included_learner_capacity}',jsonb_build_object('revisionId',revision,'quantity',capacity,'source','published_revision'));
  RETURN NEW;
END;
$$;
CREATE TRIGGER subscription_included_learner_capacity BEFORE INSERT OR UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.bind_subscription_included_learner_capacity();
REVOKE ALL ON FUNCTION public.bind_subscription_included_learner_capacity() FROM PUBLIC,anon,authenticated,service_role;
-- Accepted only by the private consumer of the payment worker's HMAC-verified
-- queue. API callers cannot insert capture evidence or supply capture timestamps.
CREATE TABLE public.subscription_commerce_captures (
  event_id text PRIMARY KEY CHECK(event_id~'^[a-f0-9]{64}$'),
  quote_id uuid NOT NULL UNIQUE REFERENCES public.subscription_commerce_quotes(id),
  provider_payment_id text NOT NULL UNIQUE CHECK(provider_payment_id~'^pay_[A-Za-z0-9]+$'),
  provider_order_id text NOT NULL CHECK(provider_order_id~'^order_[A-Za-z0-9]+$'),
  captured_at_ms bigint NOT NULL, payment_created_at_ms bigint NOT NULL,
  amount_minor bigint NOT NULL CHECK(amount_minor>0),currency text NOT NULL CHECK(currency~'^[A-Z]{3}$'),
  envelope jsonb NOT NULL, received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.subscription_commerce_captures FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON public.subscription_commerce_captures TO service_role;
CREATE FUNCTION public.record_subscription_commerce_capture(p_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE c jsonb:=p_event->'capture'; payment jsonb:=p_event#>'{payload,payload,payment,entity}';
  q public.subscription_commerce_quotes%ROWTYPE; old public.subscription_commerce_captures%ROWTYPE;
  id text:=p_event->>'event_id'; captured numeric; created numeric; received numeric; result jsonb;
BEGIN
  IF jsonb_typeof(p_event) IS DISTINCT FROM 'object' OR p_event->>'event_type' IS DISTINCT FROM 'payment.captured'
    OR p_event#>>'{payload,event}' IS DISTINCT FROM 'payment.captured'
    OR p_event#>>'{verification,kind}' IS DISTINCT FROM 'razorpay_hmac_sha256'
    OR id IS NULL OR id!~'^[a-f0-9]{64}$' OR p_event#>>'{verification,bodySha256}' IS DISTINCT FROM id
    OR jsonb_typeof(c) IS DISTINCT FROM 'object' OR jsonb_typeof(payment) IS DISTINCT FROM 'object'
    OR c->>'paymentId' IS DISTINCT FROM payment->>'id' OR c->>'orderId' IS DISTINCT FROM payment->>'order_id'
    OR c->'amountMinor' IS DISTINCT FROM payment->'amount' OR c->'currency' IS DISTINCT FROM payment->'currency'
    OR payment->>'entity' IS DISTINCT FROM 'payment' OR payment->>'status' IS DISTINCT FROM 'captured'
    OR payment->'captured' IS DISTINCT FROM 'true'::jsonb OR payment->'amount_refunded' IS DISTINCT FROM '0'::jsonb
    OR c->>'paymentId'!~'^pay_[A-Za-z0-9]+$' OR c->>'orderId'!~'^order_[A-Za-z0-9]+$'
    OR c->>'currency'!~'^[A-Z]{3}$'
    OR EXISTS(SELECT 1 FROM jsonb_each(c) v WHERE v.key IN ('capturedAt','paymentCreatedAt','amountMinor')
      AND CASE WHEN jsonb_typeof(v.value)='number' THEN (v.value#>>'{}')::numeric NOT BETWEEN 1 AND 9007199254740991 OR (v.value#>>'{}')::numeric<>trunc((v.value#>>'{}')::numeric) ELSE true END)
    THEN RAISE EXCEPTION 'Exact verified captured event required'; END IF;
  captured:=(c->>'capturedAt')::numeric;created:=(c->>'paymentCreatedAt')::numeric;received:=(p_event#>>'{verification,receivedAt}')::numeric;
  IF captured IS NULL OR created IS NULL OR received IS NULL OR created>captured OR captured>received
    OR received>extract(epoch FROM clock_timestamp())*1000
    OR captured IS DISTINCT FROM (p_event#>>'{payload,created_at}')::numeric*1000
    OR created IS DISTINCT FROM (payment->>'created_at')::numeric*1000 THEN RAISE EXCEPTION 'Capture event timestamp differs'; END IF;
  SELECT * INTO q FROM public.subscription_commerce_quotes WHERE provider_order_id=c->>'orderId' FOR UPDATE;
  IF NOT FOUND OR c->'amountMinor' IS DISTINCT FROM q.quote->'amountMinor' OR c->'currency' IS DISTINCT FROM q.quote->'currency'
    OR captured<(q.quote->>'createdAt')::numeric
    -- Provider timestamps have one-second precision. Require the whole event
    -- second inside the quote; never round a potentially late capture backwards.
    OR captured+999>=(q.quote->>'validUntil')::numeric THEN RAISE EXCEPTION 'Capture outside exact issued quote'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_capture:'||(c->>'paymentId'),0));
  SELECT * INTO old FROM public.subscription_commerce_captures WHERE event_id=id OR quote_id=q.id OR provider_payment_id=c->>'paymentId';
  IF FOUND THEN
    IF old.event_id IS DISTINCT FROM id OR old.quote_id<>q.id OR old.provider_payment_id IS DISTINCT FROM c->>'paymentId'
      OR old.provider_order_id IS DISTINCT FROM c->>'orderId' OR old.captured_at_ms IS DISTINCT FROM captured
      OR old.payment_created_at_ms IS DISTINCT FROM created OR old.amount_minor IS DISTINCT FROM (c->>'amountMinor')::numeric
      OR old.currency IS DISTINCT FROM c->>'currency' OR old.envelope->'payload' IS DISTINCT FROM p_event->'payload'
      THEN RAISE EXCEPTION 'Capture replay conflicts'; END IF;
  ELSE
    INSERT INTO public.subscription_commerce_captures(event_id,quote_id,provider_payment_id,provider_order_id,captured_at_ms,payment_created_at_ms,amount_minor,currency,envelope)
      VALUES(id,q.id,c->>'paymentId',c->>'orderId',captured,created,(c->>'amountMinor')::bigint,c->>'currency',p_event);
  END IF;
  result:=jsonb_build_object('eventId',id,'quoteId',q.id,'paymentId',c->>'paymentId','productId',q.quote->'productId','subscriptionId',q.quote->'subscriptionId','capturedAt',captured);
  RETURN result;
END;
$$;
REVOKE ALL ON FUNCTION public.record_subscription_commerce_capture(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.record_subscription_commerce_capture(jsonb) TO service_role;

-- A private predicate, not a client expiry override. It joins the retained signed
-- capture to the exact issued commercial terms; lifecycle use additionally joins
-- the completed settlement identity. New quote/order/refund owners never use it.
CREATE FUNCTION public.subscription_commerce_has_timely_capture(p_quote jsonb,p_payment_id text,p_settlement_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
  SELECT EXISTS(
    SELECT 1 FROM public.subscription_commerce_captures c
    JOIN public.subscription_commerce_quotes q ON q.id=c.quote_id AND q.provider_order_id=c.provider_order_id
    WHERE q.id=(p_quote->>'id')::uuid AND (p_payment_id IS NULL OR c.provider_payment_id=p_payment_id)
      AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['id','subscriptionId','productId','subject','planId','revisionId','stateVersion','amountMinor','currency','periodStartsAt','periodEndsAt','validUntil']) k
        WHERE q.quote->k IS DISTINCT FROM p_quote->k)
      AND q.quote->>'purpose'=CASE WHEN p_quote ? 'operation' THEN p_quote->>'operation' ELSE p_quote->>'purpose' END
      AND c.amount_minor=(q.quote->>'amountMinor')::bigint AND c.currency=q.quote->>'currency'
      AND c.captured_at_ms>=(q.quote->>'createdAt')::bigint AND c.captured_at_ms+999<(q.quote->>'validUntil')::bigint
      AND c.payment_created_at_ms<=c.captured_at_ms
      AND (p_settlement_id IS NULL OR EXISTS(
        SELECT 1 FROM public.subscription_commerce_settlements s WHERE s.id=p_settlement_id
          AND s.quote_id=q.id AND s.provider_payment_id=c.provider_payment_id AND s.amount_minor=c.amount_minor AND s.currency=c.currency
          AND s.subscription_id=(q.quote->>'subscriptionId')::uuid AND s.product_id=(q.quote->>'productId')::uuid
          AND s.subject=q.quote->'subject' AND s.purpose=q.quote->>'purpose'
          AND extract(epoch FROM s.settled_at)*1000=c.captured_at_ms
      ))
  );
$$;
REVOKE ALL ON FUNCTION public.subscription_commerce_has_timely_capture(jsonb,text,uuid) FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.guard_subscription_commerce_capture_settlement()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE q jsonb; capture public.subscription_commerce_captures%ROWTYPE;
BEGIN
  SELECT quote INTO q FROM public.subscription_commerce_quotes WHERE id=NEW.quote_id;
  SELECT * INTO capture FROM public.subscription_commerce_captures WHERE quote_id=NEW.quote_id;
  IF FOUND THEN
    IF NOT public.subscription_commerce_has_timely_capture(q,NEW.provider_payment_id,NULL)
      OR extract(epoch FROM NEW.settled_at)*1000 IS DISTINCT FROM capture.captured_at_ms
      OR NEW.evidence->'settledAt' IS DISTINCT FROM to_jsonb(capture.captured_at_ms) THEN
      RAISE EXCEPTION 'Settlement must retain exact signed capture time and identity';
    END IF;
  ELSIF (q->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())*1000 THEN
    RAISE EXCEPTION 'Expired settlement requires exact retained signed capture';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER subscription_commerce_capture_settlement BEFORE INSERT ON public.subscription_commerce_settlements
  FOR EACH ROW EXECUTE FUNCTION public.guard_subscription_commerce_capture_settlement();
REVOKE ALL ON FUNCTION public.guard_subscription_commerce_capture_settlement() FROM PUBLIC,anon,authenticated,service_role;
-- Preserve the existing lifecycle CAS, policy, currency, transaction ownership,
-- audit and replay checks. Only its paid quote expiry predicate admits an exact
-- retained signed capture joined to the already completed settlement.
CREATE OR REPLACE FUNCTION public.commit_subscription_lifecycle(p_identity jsonb, p_decision jsonb)
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
COMMIT;
