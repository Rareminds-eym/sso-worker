-- PREPARED ONLY: explicit approval is required before applying to any database.
-- Adds free signup intent and activation authority. No backfill or existing purchase rewrite.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';

CREATE TABLE public.subscription_free_entry_intents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  product_id uuid NOT NULL REFERENCES public.products(id),
  subject jsonb NOT NULL,
  audience text NOT NULL,
  organization_type text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(product_id,subject),
  CHECK(jsonb_typeof(subject)='object' AND subject->>'kind' IN ('user','organization') AND subject ? 'id')
);
CREATE TABLE public.subscription_free_entry_activations (
  intent_id uuid PRIMARY KEY REFERENCES public.subscription_free_entry_intents(id),
  subscription_id uuid NOT NULL UNIQUE REFERENCES public.subscriptions(id),
  product_id uuid NOT NULL REFERENCES public.products(id),
  revision_id uuid NOT NULL REFERENCES public.subscription_plan_drafts(id),
  subject jsonb NOT NULL,
  activated_at timestamptz NOT NULL,
  UNIQUE(product_id,subject,revision_id)
);
REVOKE ALL ON public.subscription_free_entry_intents,public.subscription_free_entry_activations FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT ON public.subscription_free_entry_intents,public.subscription_free_entry_activations TO service_role;
-- Preserve the existing signup owner's cleanup of an unverified account after
-- session issuance fails. Successful activation evidence remains immutable.
CREATE FUNCTION public.guard_free_entry_intent_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF TG_OP='DELETE' AND NOT EXISTS(SELECT 1 FROM public.users WHERE id=OLD.user_id)
    AND NOT EXISTS(SELECT 1 FROM public.subscription_free_entry_activations WHERE intent_id=OLD.id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Free signup intent is immutable';
END;
$$;
REVOKE ALL ON FUNCTION public.guard_free_entry_intent_mutation() FROM PUBLIC,anon,authenticated,service_role;
CREATE TRIGGER subscription_free_intents_immutable BEFORE UPDATE OR DELETE ON public.subscription_free_entry_intents
  FOR EACH ROW EXECUTE FUNCTION public.guard_free_entry_intent_mutation();
CREATE TRIGGER subscription_free_activations_immutable BEFORE UPDATE OR DELETE ON public.subscription_free_entry_activations
  FOR EACH ROW EXECUTE FUNCTION public.reject_subscription_lifecycle_evidence_mutation();
CREATE TRIGGER subscription_free_intents_no_truncate BEFORE TRUNCATE ON public.subscription_free_entry_intents
  FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_lifecycle_evidence_mutation();
CREATE TRIGGER subscription_free_activations_no_truncate BEFORE TRUNCATE ON public.subscription_free_entry_activations
  FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_lifecycle_evidence_mutation();

CREATE OR REPLACE FUNCTION public.assert_subscription_lifecycle_binding(p_row public.subscriptions)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE s jsonb := p_row.lifecycle_state; v_publication jsonb; v_subject jsonb; v_execution jsonb; v_change jsonb;
  v_retention_start numeric; v_retention_duration numeric;
BEGIN
  IF s IS NULL THEN RAISE EXCEPTION 'Subscription lifecycle is not initialized'; END IF;
  IF jsonb_typeof(s) IS DISTINCT FROM 'object' OR jsonb_typeof(p_row.lifecycle_policy) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Lifecycle objects required'; END IF;
  IF (s ? 'downgradedAt') IS DISTINCT FROM (p_row.lifecycle_policy ? 'readOnlyDurationMs') THEN
    RAISE EXCEPTION 'Lifecycle retention state marker differs';
  END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(s)) <> (14 + CASE WHEN s ? 'downgradedAt' THEN 1 ELSE 0 END + CASE WHEN s ? 'validity' THEN 1 ELSE 0 END)
    OR NOT s ?& ARRAY['id','subject','planId','revisionId','productId','version','status','periodStartsAt','periodEndsAt','trialEndsAt','renewalEnabled','cancelledAt','paymentFailedAt','scheduledChange']
    OR jsonb_typeof(s->'subject') IS DISTINCT FROM 'object'
    OR jsonb_typeof(s->'renewalEnabled') IS DISTINCT FROM 'boolean'
    OR jsonb_typeof(s->'version') IS DISTINCT FROM 'number'
    OR jsonb_typeof(s->'periodStartsAt') IS DISTINCT FROM 'number'
    OR jsonb_typeof(s->'periodEndsAt') NOT IN ('number','null')
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
  IF s->'periodEndsAt'='null'::jsonb THEN
    IF s->>'validity' IS DISTINCT FROM 'perpetual'
      OR v_publication#>'{configuration,subscription_entry}' IS DISTINCT FROM '{"schemaVersion":1,"validity":"perpetual"}'::jsonb
      OR s->'renewalEnabled' IS DISTINCT FROM 'false'::jsonb OR s->'trialEndsAt' IS DISTINCT FROM 'null'::jsonb
      OR s->'scheduledChange' IS DISTINCT FROM 'null'::jsonb OR s->'paymentFailedAt' IS DISTINCT FROM 'null'::jsonb
      OR s->>'status' IN ('expired','grace_period') OR p_row.subscription_end_date IS NOT NULL
      OR NOT EXISTS (SELECT 1 FROM public.subscription_plan_drafts d WHERE d.id=p_row.plan_revision_id AND d.snapshot->>'purchaseMode'='free' AND d.snapshot->'prices'='[]'::jsonb)
      OR NOT EXISTS (SELECT 1 FROM public.subscription_free_entry_activations a WHERE a.subscription_id=p_row.id
        AND a.product_id=p_row.product_id AND a.revision_id=p_row.plan_revision_id AND a.subject=s->'subject') THEN
      RAISE EXCEPTION 'Perpetual lifecycle requires exact free activation evidence';
    END IF;
  ELSIF s ? 'validity' THEN RAISE EXCEPTION 'Finite lifecycle cannot claim perpetual validity'; END IF;
  v_execution := p_row.metadata->'subscription_execution';
  IF jsonb_typeof(v_execution) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Explicit subscription commercial binding required'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(v_execution)) <> 2 OR NOT v_execution ?& ARRAY['audience','subscriptionEndsAt']
    OR jsonb_typeof(v_execution->'audience') IS DISTINCT FROM 'string' OR length(btrim(v_execution->>'audience'))=0
    OR ((v_publication->'audiences') ? (v_execution->>'audience')) IS DISTINCT FROM true
    OR (s->'periodEndsAt'='null'::jsonb AND v_execution->'subscriptionEndsAt' IS DISTINCT FROM 'null'::jsonb)
    OR (s->'periodEndsAt'<>'null'::jsonb AND jsonb_typeof(v_execution->'subscriptionEndsAt') IS DISTINCT FROM 'number')
    OR (v_execution->>'subscriptionEndsAt')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR (v_execution->>'subscriptionEndsAt')::numeric <> trunc((v_execution->>'subscriptionEndsAt')::numeric)
    OR (v_execution->>'subscriptionEndsAt')::numeric < (s->>'periodEndsAt')::numeric
    OR NOT isfinite(p_row.lifecycle_activated_at)
    OR extract(epoch FROM p_row.lifecycle_activated_at)*1000 NOT BETWEEN 0 AND (s->>'periodStartsAt')::numeric
    OR extract(epoch FROM p_row.lifecycle_activated_at)*1000 <> trunc(extract(epoch FROM p_row.lifecycle_activated_at)*1000)
    OR p_row.lifecycle_activated_at > clock_timestamp() THEN RAISE EXCEPTION 'Subscription commercial binding or activation anchor differs'; END IF;
END;
$$;

-- The existing signup primitives remain the identity/role owners. This wrapper
-- records the intended free audience in the SAME transaction, before mutable
-- user metadata could later be mistaken for entitlement authority.
CREATE FUNCTION public.signup_with_subscription_entry(p_kind text,p_signup jsonb,p_policy jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb; binding jsonb; product uuid; recipient jsonb; role_name text:=p_signup->>'p_role';
BEGIN
  IF p_kind NOT IN ('organization','member') OR p_policy->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR jsonb_typeof(p_signup) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Validated signup policy required'; END IF;
  binding:=CASE WHEN p_kind='organization' THEN p_policy->'signupRoles'->role_name ELSE p_policy->'memberRoles'->role_name END;
  IF jsonb_typeof(binding) IS DISTINCT FROM 'object' OR jsonb_typeof(binding->'audience') IS DISTINCT FROM 'string'
    OR length(btrim(binding->>'audience'))=0 OR NOT binding ? 'organizationType' THEN RAISE EXCEPTION 'Configured signup role required'; END IF;
  SELECT id INTO STRICT product FROM public.products WHERE code=p_policy->>'productCode';
  IF p_kind='organization' THEN
    IF jsonb_typeof(binding->'organizationType') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'Explicit organization type required'; END IF;
    result:=public.signup_user(p_signup->>'p_email',p_signup->>'p_password_hash',p_signup->>'p_org_name',p_signup->>'p_org_slug',role_name,p_signup->'p_user_metadata');
    recipient:=jsonb_build_object('kind','organization','id',result->'org_id');
    UPDATE public.organizations SET metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object('organization_type',binding->'organizationType')
      WHERE id=(result->>'org_id')::uuid AND created_by=(result->>'user_id')::uuid;
    IF NOT FOUND THEN RAISE EXCEPTION 'Signup organization owner differs'; END IF;
  ELSE
    IF binding->'organizationType' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Personal signup cannot set organization type'; END IF;
    result:=public.signup_member(p_signup->>'p_email',p_signup->>'p_password_hash',role_name,(p_signup->>'p_org_id')::uuid,p_signup->'p_user_metadata');
    recipient:=jsonb_build_object('kind','user','id',result->'user_id');
  END IF;
  INSERT INTO public.subscription_free_entry_intents(user_id,product_id,subject,audience,organization_type)
    VALUES((result->>'user_id')::uuid,product,recipient,binding->>'audience',binding->>'organizationType');
  RETURN result;
END;
$$;

-- Token verification and activation use this same authority. Locking the complete
-- product/subject serializes different requests, not just a caller operation id.
CREATE FUNCTION public.activate_published_free_subscription(p_intent_id uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE intent public.subscription_free_entry_intents%ROWTYPE; prior public.subscription_free_entry_activations%ROWTYPE;
  purchaser public.users%ROWTYPE; membership uuid; publications jsonb; selected jsonb; canonical jsonb; draft jsonb; entry jsonb;
  revision uuid; sub uuid:=gen_random_uuid(); operation uuid:=gen_random_uuid(); organization uuid; starts timestamptz;
  start_ms numeric; end_ms numeric; ends timestamptz; policy jsonb; state jsonb; capacity integer; features jsonb; grant_value jsonb;
BEGIN
  SELECT * INTO STRICT intent FROM public.subscription_free_entry_intents WHERE id=p_intent_id;
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription_commerce_purchase:'||intent.subject::text||':'||intent.product_id::text,0));
  SELECT * INTO STRICT purchaser FROM public.users WHERE id=intent.user_id AND is_email_verified=true AND is_blocked=false;
  IF purchaser.user_metadata->>'must_change_password'='true' THEN RAISE EXCEPTION 'Account activation required'; END IF;
  IF intent.subject->>'kind'='organization' THEN
    organization:=(intent.subject->>'id')::uuid;
    IF NOT EXISTS(SELECT 1 FROM public.organizations o WHERE o.id=organization AND o.deleted_at IS NULL
      AND o.created_by=intent.user_id AND o.metadata->>'organization_type'=intent.organization_type) THEN RAISE EXCEPTION 'Live signup organization required'; END IF;
    SELECT m.id INTO membership FROM public.memberships m WHERE m.user_id=intent.user_id AND m.org_id=organization AND m.status='active';
  ELSE
    IF intent.subject->>'id' IS DISTINCT FROM intent.user_id::text THEN RAISE EXCEPTION 'Personal signup subject differs'; END IF;
    IF NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.organizations o ON o.id=m.org_id
      WHERE m.user_id=intent.user_id AND m.status='active' AND o.deleted_at IS NULL) THEN RAISE EXCEPTION 'Active personal signup membership required'; END IF;
  END IF;
  IF organization IS NOT NULL AND membership IS NULL THEN RAISE EXCEPTION 'Active signup membership required'; END IF;
  SELECT * INTO prior FROM public.subscription_free_entry_activations WHERE intent_id=intent.id;
  IF FOUND THEN
    IF NOT EXISTS(SELECT 1 FROM public.subscriptions s WHERE s.id=prior.subscription_id AND s.product_id=intent.product_id
      AND s.lifecycle_state->'subject'=intent.subject)
      OR NOT EXISTS(SELECT 1 FROM public.subscription_lifecycle_operations o WHERE o.subscription_id=prior.subscription_id AND o.kind='initialize'
        AND o.receipt#>>'{state,revisionId}'=prior.revision_id::text AND o.receipt#>'{state,subject}'=intent.subject) THEN RAISE EXCEPTION 'Free activation replay evidence differs'; END IF;
    RETURN prior.subscription_id;
  END IF;
  -- Select only the latest publication for each available plan. Multiple eligible
  -- free offers are an error, never a first-row choice or a legacy-cache substitute.
  SELECT jsonb_agg(jsonb_build_object('canonical',e.canonical_plan,'draft',d.snapshot,'revision',e.revision_id)) INTO publications
    FROM public.subscription_plan_publication_events e JOIN public.subscription_plan_drafts d ON d.id=e.revision_id AND d.plan_id=e.plan_id
    JOIN public.plans p ON p.id=e.plan_id AND p.product_id=intent.product_id AND p.is_active=true
    WHERE e.canonical_plan->>'productId'=intent.product_id::text AND e.canonical_plan->'audiences' ? intent.audience
      AND d.snapshot->>'purchaseMode'='free' AND d.snapshot->'prices'='[]'::jsonb
      AND NOT EXISTS(SELECT 1 FROM public.subscription_plan_publication_events newer JOIN public.subscription_plan_drafts nd ON nd.id=newer.revision_id
        WHERE newer.plan_id=e.plan_id AND (nd.snapshot->>'revisionNumber')::integer>(d.snapshot->>'revisionNumber')::integer);
  IF publications IS NULL OR jsonb_array_length(publications)<>1 THEN RAISE EXCEPTION 'Exactly one published free offer required'; END IF;
  selected:=publications->0; canonical:=selected->'canonical'; draft:=selected->'draft'; revision:=(selected->>'revision')::uuid;
  IF canonical->>'id' IS DISTINCT FROM draft#>>'{plan,id}' OR canonical->>'productId' IS DISTINCT FROM draft#>>'{plan,productId}'
    OR draft->>'id' IS DISTINCT FROM revision::text THEN RAISE EXCEPTION 'Free publication identity differs'; END IF;
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(canonical#>'{configuration,subscription_commerce_eligibility,bindings}') b
    WHERE b->>'audience'=intent.audience AND b->>'subjectKind'=intent.subject->>'kind'
      AND EXISTS(SELECT 1 FROM public.membership_roles mr JOIN public.roles r ON r.id=mr.role_id JOIN public.memberships m ON m.id=mr.membership_id
        WHERE m.user_id=intent.user_id AND m.status='active' AND (organization IS NULL OR m.org_id=organization) AND b->'roles' ? r.name)) THEN RAISE EXCEPTION 'Free signup role is no longer eligible'; END IF;
  entry:=canonical#>'{configuration,subscription_entry}';
  starts:=date_trunc('milliseconds',clock_timestamp()); start_ms:=extract(epoch FROM starts)*1000;
  IF entry='{"schemaVersion":1,"validity":"perpetual"}'::jsonb THEN end_ms:=NULL; ends:=NULL;
  ELSIF entry->'schemaVersion'='1'::jsonb AND entry->>'validity'='fixed_duration'
    AND (SELECT count(*) FROM jsonb_object_keys(entry))=3 AND jsonb_typeof(entry->'durationDays')='number'
    AND (entry->>'durationDays')::numeric BETWEEN 1 AND 3650 AND (entry->>'durationDays')::numeric=trunc((entry->>'durationDays')::numeric) THEN
    end_ms:=start_ms+(entry->>'durationDays')::numeric*24*60*60*1000; ends:=to_timestamp(end_ms/1000);
  ELSE RAISE EXCEPTION 'Published free validity required'; END IF;
  IF EXISTS(SELECT 1 FROM public.subscriptions s WHERE s.product_id=intent.product_id AND s.status IN ('active','pending','paused','grace_period')
    AND CASE WHEN organization IS NULL THEN s.user_id=intent.user_id AND s.is_organization_subscription IS NOT TRUE
      ELSE s.organization_id=organization AND s.is_organization_subscription IS TRUE END) THEN RAISE EXCEPTION 'Existing subscription requires an explicit transition'; END IF;
  features:=draft->'features';
  IF organization IS NOT NULL AND EXISTS(SELECT 1 FROM jsonb_array_elements(features) g WHERE g->>'key'='included_learner_capacity') THEN
    IF (SELECT count(*) FROM jsonb_array_elements(features) g WHERE g->>'key'='included_learner_capacity')<>1 THEN RAISE EXCEPTION 'Ambiguous trial capacity'; END IF;
    SELECT g INTO grant_value FROM jsonb_array_elements(features) g WHERE g->>'key'='included_learner_capacity';
    IF grant_value->>'type' IS DISTINCT FROM 'numeric_limit' OR grant_value->'enabled' IS DISTINCT FROM 'true'::jsonb
      OR grant_value#>>'{limit,kind}' IS DISTINCT FROM 'finite' OR jsonb_typeof(grant_value#>'{limit,value}') IS DISTINCT FROM 'number'
      OR (grant_value#>>'{limit,value}')::numeric NOT BETWEEN 1 AND 2147483647
      OR (grant_value#>>'{limit,value}')::numeric<>trunc((grant_value#>>'{limit,value}')::numeric) THEN RAISE EXCEPTION 'Published trial capacity required'; END IF;
    capacity:=(grant_value#>>'{limit,value}')::integer;
  END IF;
  INSERT INTO public.subscriptions(id,user_id,organization_id,is_organization_subscription,purchased_by,plan_id,product_id,email,plan_code,plan_type,
    plan_amount,billing_cycle,features,status,auto_renew,subscription_start_date,subscription_end_date,seat_count,metadata)
    VALUES(sub,intent.user_id,organization,organization IS NOT NULL,intent.user_id,(canonical->>'id')::uuid,intent.product_id,purchaser.email,canonical->>'code',draft->>'name',
      0,'free',features,'active',false,starts,ends,capacity,jsonb_build_object('subscription_execution',jsonb_build_object('audience',intent.audience,'subscriptionEndsAt',end_ms)));
  INSERT INTO public.subscription_free_entry_activations(intent_id,subscription_id,product_id,revision_id,subject,activated_at)
    VALUES(intent.id,sub,intent.product_id,revision,intent.subject,starts);
  policy:=canonical#>'{configuration,subscription_lifecycle}';
  state:=jsonb_build_object('id',sub,'subject',intent.subject,'planId',canonical->'id','revisionId',revision,'productId',intent.product_id,'version',1,
    'status','active','periodStartsAt',start_ms,'periodEndsAt',end_ms,'trialEndsAt',CASE WHEN entry->>'validity'='fixed_duration' THEN end_ms ELSE NULL END,
    'renewalEnabled',false,'cancelledAt',NULL,'paymentFailedAt',NULL,'scheduledChange',NULL);
  IF end_ms IS NULL THEN state:=state||jsonb_build_object('validity','perpetual'); END IF;
  IF policy ? 'readOnlyDurationMs' THEN state:=state||jsonb_build_object('downgradedAt',NULL); END IF;
  PERFORM public.initialize_subscription_lifecycle(operation,state,policy,intent.user_id,starts);
  RETURN sub;
END;
$$;

CREATE FUNCTION public.verify_email_with_subscription_entry(p_token_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE verification public.email_verifications%ROWTYPE; intent record; ids jsonb:='[]'::jsonb; sub uuid;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Hashed verification token required'; END IF;
  SELECT * INTO verification FROM public.email_verifications WHERE token_hash=p_token_hash FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('error','Invalid verification token','status',404); END IF;
  IF verification.used THEN RETURN jsonb_build_object('error','Token already used','status',410); END IF;
  IF verification.expires_at<=clock_timestamp() THEN RETURN jsonb_build_object('error','Token expired','status',410); END IF;
  -- Serialize two distinct verification links for the same account too.
  PERFORM 1 FROM public.users WHERE id=verification.user_id AND is_blocked=false FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Live verification account required'; END IF;
  UPDATE public.users SET is_email_verified=true WHERE id=verification.user_id;
  FOR intent IN SELECT id FROM public.subscription_free_entry_intents WHERE user_id=verification.user_id ORDER BY id LOOP
    sub:=public.activate_published_free_subscription(intent.id); ids:=ids||jsonb_build_array(sub);
  END LOOP;
  UPDATE public.email_verifications SET used=true WHERE id=verification.id;
  RETURN jsonb_build_object('verified',true,'userId',verification.user_id,'subscriptionIds',ids);
END;
$$;

REVOKE ALL ON FUNCTION public.signup_with_subscription_entry(text,jsonb,jsonb),public.activate_published_free_subscription(uuid),public.verify_email_with_subscription_entry(text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.signup_with_subscription_entry(text,jsonb,jsonb),public.activate_published_free_subscription(uuid),public.verify_email_with_subscription_entry(text) TO service_role;
COMMIT;
