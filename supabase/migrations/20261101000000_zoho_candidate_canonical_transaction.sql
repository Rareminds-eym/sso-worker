BEGIN;

CREATE TABLE public.zoho_candidate_links (
  source_org_id text NOT NULL CHECK(source_org_id ~ '^\d{1,40}$'),
  external_id text NOT NULL CHECK(external_id ~ '^\d{1,40}$'),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(source_org_id,external_id)
);
CREATE TABLE public.zoho_candidate_receipts (
  operation_id uuid PRIMARY KEY,
  receipt_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  connection_id uuid NOT NULL,
  record_id uuid NOT NULL,
  record_revision integer NOT NULL CHECK(record_revision>0),
  approved_context jsonb NOT NULL CHECK(jsonb_typeof(approved_context)='object'),
  source_hash text NOT NULL CHECK(source_hash ~ '^[a-f0-9]{64}$'),
  user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
  state text NOT NULL DEFAULT 'projection_pending' CHECK(state IN ('projection_pending','completed')),
  identity_outcome text NOT NULL CHECK(identity_outcome IN ('created','existing_access_preserved')),
  activation_state text NOT NULL CHECK(activation_state IN ('activation_pending','existing_sign_in_preserved')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(connection_id,record_id,record_revision)
);
CREATE TABLE public.zoho_candidate_outbox (
  operation_id uuid PRIMARY KEY REFERENCES public.zoho_candidate_receipts(operation_id),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  event_type text NOT NULL DEFAULT 'zoho.candidate.canonical_committed' CHECK(event_type='zoho.candidate.canonical_committed'),
  payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=131072 AND payload->>'emailPolicy'='forbidden'),
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);
REVOKE ALL ON public.zoho_candidate_links,public.zoho_candidate_receipts,public.zoho_candidate_outbox FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.zoho_find_candidate_receipt(p_operation uuid,p_source_hash text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
  SELECT jsonb_build_object('state',r.state,'operationId',r.operation_id,'sourceHash',r.source_hash,
    'targetId',r.user_id,'receiptId',r.receipt_id,'emailPolicy','forbidden') ||
    CASE WHEN r.state='completed' THEN '{}'::jsonb ELSE jsonb_build_object(
      'identityOutcome',r.identity_outcome,'activationState',r.activation_state) END
  FROM public.zoho_candidate_receipts r WHERE r.operation_id=p_operation AND r.source_hash=p_source_hash AND r.user_id IS NOT NULL;
$$;

-- The private existing-SSO entrypoint checks the independent live claim immediately
-- before this transaction. Canonical human proof and all local effects are checked here.
-- Prevent creating private recruiting identities in a browser-readable canonical
-- database. This checks actual grants and RPC reachability without relying on RLS.
CREATE FUNCTION public.zoho_assert_private_identity_boundary() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF EXISTS (
    WITH RECURSIVE protected(oid) AS (
      SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname IN ('users','memberships','membership_roles','membership_products','subscriptions')
      UNION
      SELECT r.ev_class FROM protected p
        JOIN pg_depend d ON d.refobjid=p.oid AND d.refclassid='pg_class'::regclass
          AND d.classid='pg_rewrite'::regclass
        JOIN pg_rewrite r ON r.oid=d.objid WHERE r.ev_class<>p.oid
    )
    SELECT 1 FROM protected p CROSS JOIN (VALUES ('anon'),('authenticated')) AS browser(role)
    WHERE has_table_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE,DELETE')
       OR has_any_column_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE')
  ) OR EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
      AND (has_schema_privilege('anon',n.oid,'USAGE') AND has_function_privilege('anon',p.oid,'EXECUTE')
        OR has_schema_privilege('authenticated',n.oid,'USAGE') AND has_function_privilege('authenticated',p.oid,'EXECUTE'))
  ) THEN
    RAISE EXCEPTION 'Private identity requires a verified server-only data boundary' USING ERRCODE='42501';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_assert_private_identity_boundary() FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.zoho_provision_candidate(p_grant jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
#variable_conflict use_variable
DECLARE op uuid; actor uuid; target uuid; email text; display_name text; u public.users;
  plan public.plans; product uuid; learner_role uuid; membership uuid; subscription uuid;
  linked public.zoho_candidate_links; prior public.zoho_candidate_receipts; candidate_count integer;
  outcome text; activation text; projection jsonb; approved_context jsonb;
BEGIN
  IF jsonb_typeof(p_grant) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(p_grant))<>19
    OR NOT p_grant ?& ARRAY['claimed','operationId','lease','leaseExpiresAt','approvalExpiresAt','actorId','connectionId','sourceOrgId','publisherOrganizationId','recordId','revision','configRevision','sourceHash','action','module','externalId','data','targetId','emailPolicy']
    OR NOT public.zoho_validate_import_approval(p_grant) OR p_grant->>'module' IS DISTINCT FROM 'Candidates'
    OR p_grant->>'action' IS DISTINCT FROM 'provision_candidate' THEN
    RAISE EXCEPTION 'Canonical approval unavailable' USING ERRCODE='22023';
  END IF;
  approved_context:=p_grant-ARRAY['claimed','operationId','lease','leaseExpiresAt','approvalExpiresAt','data'];
  op:=(p_grant->>'operationId')::uuid; actor:=(p_grant->>'actorId')::uuid; target:=(p_grant->>'targetId')::uuid;
  email:=p_grant->'data'->>'email'; display_name:=p_grant->'data'->>'name';
  IF (SELECT count(*) FROM jsonb_object_keys(p_grant->'data'))<>2 OR email IS NULL OR display_name IS NULL
    OR email<>lower(trim(email)) OR length(email)>320 OR email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    OR length(trim(display_name)) NOT BETWEEN 2 AND 150 OR display_name<>trim(display_name) THEN
    RAISE EXCEPTION 'Candidate fields require review' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('zoho-operation:'||op::text,0));
  SELECT * INTO prior FROM public.zoho_candidate_receipts WHERE operation_id=op;
  IF FOUND THEN
    IF prior.approved_context<>approved_context OR prior.source_hash<>p_grant->>'sourceHash' OR prior.connection_id<>(p_grant->>'connectionId')::uuid
      OR prior.record_id<>(p_grant->>'recordId')::uuid OR prior.record_revision<>(p_grant->>'revision')::integer
      OR (target IS NOT NULL AND target<>prior.user_id) THEN
      RAISE EXCEPTION 'Operation conflict' USING ERRCODE='40001';
    END IF;
    RETURN public.zoho_find_candidate_receipt(op,prior.source_hash);
  END IF;
  -- Hold matching human evidence while mutating, so revocation serializes with commit.
  PERFORM 1 FROM public.zoho_import_approvals a WHERE a.actor_id=actor AND a.connection_id=(p_grant->>'connectionId')::uuid
    AND a.revoked_at IS NULL AND a.expires_at>clock_timestamp() AND EXISTS(
      SELECT 1 FROM jsonb_array_elements(a.manifest->'items') i WHERE i->>'recordId'=p_grant->>'recordId'
        AND i->>'revision'=p_grant->>'revision' AND i->>'sourceHash'=p_grant->>'sourceHash') FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Approval changed' USING ERRCODE='40001'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('zoho-email:'||email,0));
  PERFORM pg_advisory_xact_lock(hashtextextended('zoho-source:'||(p_grant->>'sourceOrgId')||':'||(p_grant->>'externalId'),0));
  SELECT * INTO linked FROM public.zoho_candidate_links
    WHERE source_org_id=p_grant->>'sourceOrgId' AND external_id=p_grant->>'externalId' FOR UPDATE;
  IF FOUND AND (target IS NULL OR linked.user_id<>target) THEN
    RAISE EXCEPTION 'Source identity linkage requires review' USING ERRCODE='22023';
  END IF;
  SELECT count(*) INTO candidate_count FROM public.users WHERE lower(trim(users.email))=email;
  IF candidate_count>1 THEN RAISE EXCEPTION 'Ambiguous canonical identity' USING ERRCODE='22023'; END IF;
  SELECT * INTO u FROM public.users WHERE lower(trim(users.email))=email FOR UPDATE;
  IF FOUND THEN
    IF target IS DISTINCT FROM u.id OR u.is_blocked IS DISTINCT FROM false THEN
      RAISE EXCEPTION 'Canonical target requires review' USING ERRCODE='22023';
    END IF;
  ELSIF target IS NOT NULL THEN RAISE EXCEPTION 'Canonical target changed' USING ERRCODE='40001';
  END IF;
  SELECT id INTO STRICT product FROM public.products WHERE code='skillpassport';
  IF u.id IS NULL THEN
    SELECT * INTO STRICT plan FROM public.plans WHERE plan_code='freemium' FOR SHARE;
    IF plan.is_active IS DISTINCT FROM true OR plan.product_id<>product OR plan.business_type<>'b2c'
      OR NOT ('all'=ANY(plan.applicable_entities) OR 'learner'=ANY(plan.applicable_entities))
      OR jsonb_typeof(plan.pricing_matrix->'all'->'monthly') IS DISTINCT FROM 'number'
      OR jsonb_typeof(plan.pricing_matrix->'all'->'yearly') IS DISTINCT FROM 'number'
      OR (plan.pricing_matrix->'all'->>'monthly')::numeric<>0
      OR (plan.pricing_matrix->'all'->>'yearly')::numeric<>0
      OR jsonb_typeof(plan.base_features) IS DISTINCT FROM 'array'
      OR NOT plan.base_features @> '["learner_profile_creation","basic_opportunity_view"]'::jsonb THEN
      RAISE EXCEPTION 'Discover catalog requires validation' USING ERRCODE='22023';
    END IF;
    SELECT id INTO STRICT learner_role FROM public.roles WHERE name='learner';
    PERFORM 1 FROM public.organizations WHERE id='00000000-0000-0000-0000-000000000001'::uuid;
    IF NOT FOUND THEN RAISE EXCEPTION 'Independent learner context unavailable' USING ERRCODE='22023'; END IF;
    -- Membership product grants only take effect inside an enabled organization product.
    PERFORM 1 FROM public.organization_products WHERE org_id='00000000-0000-0000-0000-000000000001'::uuid
      AND product_id=product AND active IS TRUE FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Independent learner product is unavailable' USING ERRCODE='22023'; END IF;
    BEGIN
      -- An invalid password-hash sentinel grants no password login; ownership remains unverified.
      PERFORM public.zoho_assert_private_identity_boundary();
      INSERT INTO public.users(email,password_hash,is_email_verified,is_blocked,user_metadata)
      VALUES(email,'!zoho-import-no-password!',false,false,jsonb_build_object('first_name',split_part(display_name,' ',1),
        'last_name',trim(substr(display_name,length(split_part(display_name,' ',1))+1)),'role','learner','activation_pending',true)) RETURNING * INTO u;
    EXCEPTION WHEN unique_violation THEN
      -- A concurrent normal signup winning this identity invalidates the reviewed create intent.
      RAISE EXCEPTION 'Canonical identity changed; review the winning account' USING ERRCODE='40001';
    END;
    INSERT INTO public.memberships(user_id,org_id,status) VALUES(u.id,'00000000-0000-0000-0000-000000000001','active') RETURNING id INTO membership;
    INSERT INTO public.membership_roles(membership_id,role_id) VALUES(membership,learner_role);
    INSERT INTO public.membership_products(membership_id,product_id) VALUES(membership,product);
    INSERT INTO public.subscriptions(user_id,plan_id,full_name,email,plan_code,plan_type,plan_amount,billing_cycle,features,status,
      auto_renew,subscription_start_date,is_organization_subscription,is_bulk_purchase,product_id,metadata)
    VALUES(u.id,plan.id,display_name,email,'freemium',plan.name,0,'lifetime',plan.base_features,'active',false,now(),false,false,product,
      '{"origin":"zoho_recruit","emailPolicy":"forbidden"}') RETURNING id INTO subscription;
    outcome:='created'; activation:='activation_pending';
  ELSE
    -- Existing roles, credentials, verification, profiles and subscriptions stay intact.
    -- Additional contexts and sponsorship-only access need their reviewed resolver before support.
    -- One and the same active learner membership must carry usable product access.
    -- Hold all contributing rows through commit so concurrent revocation serializes.
    PERFORM 1 FROM public.memberships m JOIN public.membership_roles mr ON mr.membership_id=m.id
      JOIN public.roles r ON r.id=mr.role_id
      JOIN public.membership_products mp ON mp.membership_id=m.id AND mp.product_id=product
      JOIN public.organization_products org_product ON org_product.org_id=m.org_id AND org_product.product_id=product
      WHERE m.user_id=u.id AND m.status='active' AND r.name='learner' AND org_product.active IS TRUE
      ORDER BY m.id LIMIT 1 FOR SHARE OF m,mr,r,mp,org_product;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Existing learner product context requires review' USING ERRCODE='22023';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM public.subscriptions s JOIN public.plans p ON p.id=s.plan_id
        WHERE s.user_id=u.id AND p.product_id=product AND s.status IN ('active','grace_period')
          AND s.is_organization_subscription IS NOT TRUE AND s.is_bulk_purchase IS NOT TRUE
          AND (s.subscription_end_date IS NULL OR s.subscription_end_date>clock_timestamp())) THEN
      RAISE EXCEPTION 'Existing learner context or entitlement requires review' USING ERRCODE='22023';
    END IF;
    outcome:='existing_access_preserved'; activation:='existing_sign_in_preserved';
  END IF;
  INSERT INTO public.zoho_candidate_links(source_org_id,external_id,user_id)
    VALUES(p_grant->>'sourceOrgId',p_grant->>'externalId',u.id) ON CONFLICT(source_org_id,external_id) DO NOTHING;
  INSERT INTO public.zoho_candidate_receipts(operation_id,connection_id,record_id,record_revision,approved_context,source_hash,user_id,identity_outcome,activation_state)
    VALUES(op,(p_grant->>'connectionId')::uuid,(p_grant->>'recordId')::uuid,(p_grant->>'revision')::integer,approved_context,p_grant->>'sourceHash',u.id,outcome,activation);
  projection:=jsonb_build_object('operationId',op,'sourceHash',p_grant->>'sourceHash','userId',u.id,'email',u.email,
    'name',display_name,'identityOutcome',outcome,'activationState',activation,'emailPolicy','forbidden','subscriptionId',subscription,
    'membershipId',membership,'organizationId',CASE WHEN outcome='created' THEN '00000000-0000-0000-0000-000000000001' ELSE NULL END,
    'userUpdatedAt',u.updated_at,'userMetadata',CASE WHEN outcome='created' THEN u.user_metadata ELSE NULL END,'isEmailVerified',u.is_email_verified,'version',1);
  INSERT INTO public.zoho_candidate_outbox(operation_id,user_id,payload) VALUES(op,u.id,projection);
  IF (p_grant->>'leaseExpiresAt')::timestamptz<=clock_timestamp() OR NOT public.zoho_validate_import_approval(p_grant) THEN
    RAISE EXCEPTION 'Execution authority expired' USING ERRCODE='40001';
  END IF;
  RETURN public.zoho_find_candidate_receipt(op,p_grant->>'sourceHash');
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_provision_candidate(jsonb),public.zoho_find_candidate_receipt(uuid,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_provision_candidate(jsonb),public.zoho_find_candidate_receipt(uuid,text) TO service_role;
COMMIT;
