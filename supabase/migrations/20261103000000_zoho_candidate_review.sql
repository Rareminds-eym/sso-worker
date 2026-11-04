BEGIN;

-- Nonunique: detect legacy case-variant collisions instead of silently merging identities.
CREATE INDEX users_zoho_canonical_email ON public.users(lower(trim(email)));

-- Review evidence contains source identity data and is server-only without RLS.
CREATE TABLE public.zoho_candidate_reviews (
  actor_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  review_hash text NOT NULL CHECK(review_hash ~ '^[a-f0-9]{64}$'),
  context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=4096),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now()+interval '10 minutes'),
  PRIMARY KEY(actor_id,review_hash)
);
CREATE INDEX zoho_candidate_reviews_expiry ON public.zoho_candidate_reviews(expires_at);
REVOKE ALL ON public.zoho_candidate_reviews FROM PUBLIC,anon,authenticated,service_role;

-- Only the digest of sensitive canonical rows leaves this function. Public review
-- fields expose exact supported behavior, never credentials, metadata or session state.
CREATE FUNCTION public.zoho_candidate_review_snapshot(p_context jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
#variable_conflict use_variable
DECLARE email text; u public.users; product uuid; matched integer; linked uuid; private_state jsonb;
  decision text:='blocked'; blockers jsonb:='[]'; learner_access boolean:=false;
  plans jsonb:='[]'; personal integer:=0; paid boolean:=false; organization_access boolean:=false;
  identity jsonb; entitlements jsonb; body jsonb; catalog boolean:=false;
BEGIN
  IF jsonb_typeof(p_context) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(p_context))<>10
    OR NOT p_context ?& ARRAY['connectionId','sourceOrgId','recordId','revision','configRevision','sourceHash','externalId','data','targetId','emailPolicy']
    OR p_context->>'emailPolicy' IS DISTINCT FROM 'forbidden' OR jsonb_typeof(p_context->'data') IS DISTINCT FROM 'object'
    OR jsonb_typeof(p_context->'data'->'email') IS DISTINCT FROM 'string' OR jsonb_typeof(p_context->'data'->'name') IS DISTINCT FROM 'string'
    OR (SELECT count(*) FROM jsonb_object_keys(p_context->'data'))<>2 OR NOT (p_context->'data') ?& ARRAY['email','name']
    OR (p_context->>'connectionId')::uuid IS NULL OR (p_context->>'recordId')::uuid IS NULL
    OR coalesce(p_context->>'revision','') !~ '^[1-9][0-9]{0,9}$' OR coalesce(p_context->>'configRevision','') !~ '^[1-9][0-9]{0,9}$'
    OR (p_context->>'revision')::bigint>2147483647 OR (p_context->>'configRevision')::bigint>2147483647
    OR coalesce(p_context->>'sourceOrgId','') !~ '^\d{1,40}$' OR coalesce(p_context->>'externalId','') !~ '^\d{1,40}$'
    OR p_context->>'sourceHash' IS DISTINCT FROM encode(sha256(convert_to((p_context->'data')::text,'UTF8')),'hex')
    OR (p_context->'targetId'<>'null'::jsonb AND (p_context->>'targetId')::uuid IS NULL) THEN RETURN NULL; END IF;
  email:=p_context->'data'->>'email';
  IF email IS NULL OR email<>lower(trim(email)) OR length(email)>320 OR email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    OR p_context->'data'->>'name' IS NULL OR length(trim(p_context->'data'->>'name')) NOT BETWEEN 2 AND 150
    OR p_context->'data'->>'name'<>trim(p_context->'data'->>'name') THEN RETURN NULL; END IF;
  SELECT count(*) INTO matched FROM public.users WHERE lower(trim(users.email))=email;
  IF matched=1 THEN SELECT * INTO u FROM public.users WHERE lower(trim(users.email))=email; END IF;
  SELECT user_id INTO linked FROM public.zoho_candidate_links WHERE source_org_id=p_context->>'sourceOrgId' AND external_id=p_context->>'externalId';
  SELECT id INTO product FROM public.products WHERE code='skillpassport';
  IF product IS NULL THEN blockers:=blockers||'"product_unavailable"'::jsonb; END IF;
  IF matched>1 THEN blockers:=blockers||'"ambiguous_identity"'::jsonb; END IF;
  IF p_context->>'targetId' IS NOT NULL AND (p_context->>'targetId')::uuid IS DISTINCT FROM u.id THEN blockers:=blockers||'"target_changed"'::jsonb; END IF;
  IF linked IS NOT NULL AND linked IS DISTINCT FROM u.id THEN blockers:=blockers||'"source_link_changed"'::jsonb; END IF;
  IF u.id IS NOT NULL THEN
    IF u.is_blocked IS DISTINCT FROM false THEN blockers:=blockers||'"account_blocked"'::jsonb; END IF;
    SELECT EXISTS(SELECT 1 FROM public.memberships m JOIN public.membership_roles mr ON mr.membership_id=m.id
      JOIN public.roles r ON r.id=mr.role_id JOIN public.membership_products mp ON mp.membership_id=m.id AND mp.product_id=product
      JOIN public.organization_products op ON op.org_id=m.org_id AND op.product_id=product AND op.active IS TRUE
      WHERE m.user_id=u.id AND m.status='active' AND r.name='learner') INTO learner_access;
    SELECT count(*),coalesce(jsonb_agg(DISTINCT s.plan_code ORDER BY s.plan_code) FILTER(WHERE s.status IN ('active','grace_period')
        AND (s.subscription_end_date IS NULL OR s.subscription_end_date>statement_timestamp())),'[]'),
      coalesce(bool_or(s.plan_amount>0) FILTER(WHERE s.status IN ('active','grace_period')
        AND (s.subscription_end_date IS NULL OR s.subscription_end_date>statement_timestamp())),false)
      INTO personal,plans,paid FROM public.subscriptions s JOIN public.plans p ON p.id=s.plan_id
      WHERE s.user_id=u.id AND p.product_id=product AND s.is_organization_subscription IS NOT TRUE AND s.is_bulk_purchase IS NOT TRUE;
    SELECT EXISTS(SELECT 1 FROM public.memberships m WHERE m.user_id=u.id AND m.org_id<>'00000000-0000-0000-0000-000000000001' AND m.status='active') INTO organization_access;
    IF NOT learner_access THEN blockers:=blockers||'"learner_product_context_requires_review"'::jsonb; END IF;
    IF NOT EXISTS(SELECT 1 FROM public.subscriptions s JOIN public.plans p ON p.id=s.plan_id WHERE s.user_id=u.id AND p.product_id=product
      AND s.status IN ('active','grace_period') AND s.is_organization_subscription IS NOT TRUE AND s.is_bulk_purchase IS NOT TRUE
      AND (s.subscription_end_date IS NULL OR s.subscription_end_date>statement_timestamp())) THEN blockers:=blockers||'"personal_entitlement_requires_review"'::jsonb; END IF;
    -- Projection copies every personal row, including cancelled history. None
    -- may require a version invented by the import or an implicit catalog repair.
    IF EXISTS(SELECT 1 FROM public.subscriptions s JOIN public.plans p ON p.id=s.plan_id
      WHERE s.user_id=u.id AND p.product_id=product AND s.is_organization_subscription IS NOT TRUE
        AND s.is_bulk_purchase IS NOT TRUE AND (s.updated_at IS NULL OR p.updated_at IS NULL)) THEN
      blockers:=blockers||'"projection_versions_unavailable"'::jsonb;
    END IF;
    IF personal>25 THEN blockers:=blockers||'"subscription_projection_limit"'::jsonb; END IF;
    IF blockers='[]'::jsonb THEN decision:='preserve_existing'; END IF;
  ELSIF matched=0 THEN
    SELECT EXISTS(SELECT 1 FROM public.plans p WHERE p.plan_code='freemium' AND p.product_id=product AND p.is_active IS TRUE AND p.business_type='b2c'
      AND ('all'=ANY(p.applicable_entities) OR 'learner'=ANY(p.applicable_entities))
      AND p.pricing_matrix->'all'->'monthly'='0'::jsonb AND p.pricing_matrix->'all'->'yearly'='0'::jsonb
      AND p.base_features @> '["learner_profile_creation","basic_opportunity_view"]'::jsonb)
      AND EXISTS(SELECT 1 FROM public.organization_products WHERE org_id='00000000-0000-0000-0000-000000000001' AND product_id=product AND active IS TRUE)
      AND EXISTS(SELECT 1 FROM public.roles WHERE name='learner') INTO catalog;
    IF NOT catalog THEN blockers:=blockers||'"discover_catalog_unavailable"'::jsonb; END IF;
    IF EXISTS(SELECT 1 FROM public.plans p WHERE p.plan_code='freemium' AND p.product_id=product AND p.updated_at IS NULL) THEN
      blockers:=blockers||'"discover_plan_version_unavailable"'::jsonb;
    END IF;
    IF blockers='[]'::jsonb THEN decision:='create'; END IF;
  END IF;
  identity:=jsonb_build_object('outcome',CASE WHEN matched>1 THEN 'ambiguous_identity' WHEN u.id IS NULL THEN 'new_identity' ELSE 'existing_identity' END,
    'targetId',u.id,'email',email,'name',p_context->'data'->>'name',
    'activationState',CASE WHEN decision='create' THEN 'activation_pending' WHEN decision='preserve_existing' THEN
      CASE WHEN coalesce(u.user_metadata->>'activation_pending','false')='true' THEN 'activation_pending' ELSE 'existing_sign_in_preserved' END ELSE 'blocked' END,
    'profileAction',CASE WHEN decision='create' THEN 'create' ELSE 'preserve' END);
  entitlements:=jsonb_build_object('action',CASE WHEN decision='create' THEN 'grant_discover' WHEN decision='preserve_existing' THEN 'preserve' ELSE 'blocked' END,
    'planCodes',CASE WHEN decision='create' THEN '["freemium"]'::jsonb ELSE plans END,'learnerAccess',(decision='create' OR learner_access),
    'paidAccessPreserved',paid,'organizationAccessPreserved',organization_access);
  -- Ordered complete relevant rows catch preference/security/entitlement/catalog drift.
  private_state:=jsonb_build_object('users',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id),'[]') FROM public.users x WHERE lower(trim(x.email))=email),
    'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]') FROM public.memberships m WHERE m.user_id=u.id),
    'roles',(SELECT coalesce(jsonb_agg(to_jsonb(mr) ORDER BY mr.membership_id,mr.role_id),'[]') FROM public.membership_roles mr JOIN public.memberships m ON m.id=mr.membership_id WHERE m.user_id=u.id),
    'products',(SELECT coalesce(jsonb_agg(to_jsonb(mp) ORDER BY mp.membership_id,mp.product_id),'[]') FROM public.membership_products mp JOIN public.memberships m ON m.id=mp.membership_id WHERE m.user_id=u.id),
    'organizationProducts',(SELECT coalesce(jsonb_agg(to_jsonb(op) ORDER BY op.org_id,op.product_id),'[]') FROM public.organization_products op WHERE op.product_id=product
      AND (op.org_id='00000000-0000-0000-0000-000000000001' OR op.org_id IN(SELECT m.org_id FROM public.memberships m WHERE m.user_id=u.id))),
    'subscriptions',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]') FROM public.subscriptions s WHERE s.user_id=u.id),
    'plans',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]') FROM public.plans p WHERE p.product_id=product
      AND ((u.id IS NULL AND p.plan_code='freemium') OR p.id IN(SELECT sub.plan_id FROM public.subscriptions sub WHERE sub.user_id=u.id))),
    'roleDefinitions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]') FROM public.roles r WHERE (u.id IS NULL AND r.name='learner')
      OR r.id IN(SELECT mr.role_id FROM public.membership_roles mr JOIN public.memberships m ON m.id=mr.membership_id WHERE m.user_id=u.id)),
    'product',(SELECT to_jsonb(p) FROM public.products p WHERE p.id=product),
    'linkedUser',linked);
  body:=jsonb_build_object('version',1,'recordId',p_context->'recordId','revision',p_context->'revision','sourceHash',p_context->'sourceHash',
    'configRevision',p_context->'configRevision','targetId',p_context->'targetId','decision',decision,'identity',identity,'entitlements',entitlements,'blockers',blockers);
  RETURN body||jsonb_build_object('reviewHash',encode(sha256(convert_to(jsonb_build_object('context',p_context,'state',private_state,'review',body)::text,'UTF8')),'hex'));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_candidate_review_snapshot(jsonb) FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.zoho_preview_candidate_review(p_actor uuid,p_context jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE snapshot jsonb; expiry timestamptz;
BEGIN
  IF NOT public.zoho_is_active_import_approver(p_actor) THEN RETURN NULL; END IF;
  snapshot:=public.zoho_candidate_review_snapshot(p_context);
  IF snapshot IS NULL THEN RETURN NULL; END IF;
  INSERT INTO public.zoho_candidate_reviews(actor_id,review_hash,context) VALUES(p_actor,snapshot->>'reviewHash',p_context)
    ON CONFLICT(actor_id,review_hash) DO UPDATE SET expires_at=clock_timestamp()+interval '10 minutes';
  SELECT expires_at INTO expiry FROM public.zoho_candidate_reviews WHERE actor_id=p_actor AND review_hash=snapshot->>'reviewHash';
  RETURN snapshot||jsonb_build_object('expiresAt',expiry);
END;
$$;
CREATE FUNCTION public.zoho_verify_candidate_review(p_actor uuid,p_context jsonb,p_review_hash text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
  SELECT public.zoho_is_active_import_approver(p_actor) AND EXISTS(
    SELECT 1 FROM public.zoho_candidate_reviews r WHERE r.actor_id=p_actor AND r.review_hash=p_review_hash AND r.context=p_context AND r.expires_at>statement_timestamp()
      AND public.zoho_candidate_review_snapshot(r.context)->>'reviewHash'=r.review_hash
      AND public.zoho_candidate_review_snapshot(r.context)->>'decision' IN ('create','preserve_existing'));
$$;
REVOKE ALL ON FUNCTION public.zoho_preview_candidate_review(uuid,jsonb),public.zoho_verify_candidate_review(uuid,jsonb,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_preview_candidate_review(uuid,jsonb),public.zoho_verify_candidate_review(uuid,jsonb,text) TO service_role;

CREATE OR REPLACE FUNCTION public.zoho_record_import_approval(p_actor uuid,p_manifest jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE existing public.zoho_import_approvals; normalized jsonb; item jsonb;
BEGIN
  IF NOT public.zoho_is_active_import_approver(p_actor) OR p_manifest IS NULL THEN RETURN false; END IF;
  IF jsonb_typeof(p_manifest) IS DISTINCT FROM 'object' OR
    (SELECT count(*) FROM jsonb_object_keys(p_manifest))<>8 OR
    NOT p_manifest ?& ARRAY['requestId','connectionId','sourceOrgId','publisherOrganizationId','configRevision','items','reason','emailPolicy'] OR
    p_manifest->>'emailPolicy' IS DISTINCT FROM 'forbidden' OR jsonb_typeof(p_manifest->'items') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['requestId','connectionId','sourceOrgId','publisherOrganizationId','configRevision','reason','emailPolicy']) k WHERE p_manifest->>k IS NULL) THEN RETURN false; END IF;
  IF jsonb_array_length(p_manifest->'items') NOT BETWEEN 1 AND 50 OR
    length(trim(p_manifest->>'reason')) NOT BETWEEN 3 AND 500 OR p_manifest->>'reason'<>trim(p_manifest->>'reason') OR
    p_manifest->>'sourceOrgId' !~ '^\d{1,40}$' OR (p_manifest->>'configRevision')::integer<1 OR
    (p_manifest->>'publisherOrganizationId')::uuid IS NULL OR (p_manifest->>'connectionId')::uuid IS NULL OR
    (p_manifest->>'requestId')::uuid IS NULL THEN RETURN false; END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(p_manifest->'items') LOOP
    IF EXISTS(SELECT 1 FROM unnest(ARRAY['recordId','revision','sourceHash','module','externalId']) k WHERE item->>k IS NULL) THEN RETURN false; END IF;
    IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>(CASE WHEN item->>'module'='Candidates' THEN 7 ELSE 6 END) OR
      NOT item ?& ARRAY['recordId','revision','sourceHash','module','externalId','targetId'] OR
      (item->>'recordId')::uuid IS NULL OR (item->>'revision')::integer<1 OR
      item->>'sourceHash' !~ '^[a-f0-9]{64}$' OR item->>'module' NOT IN ('Candidates','Job_Openings') OR
      item->>'externalId' !~ '^\d{1,40}$' OR
      (item->'targetId'<>'null'::jsonb AND (item->>'targetId')::uuid IS NULL) THEN RETURN false; END IF;
    IF item->>'module'='Candidates' AND NOT EXISTS(
      SELECT 1 FROM public.zoho_candidate_reviews r WHERE r.actor_id=p_actor AND r.review_hash=item->>'candidateReviewHash'
        AND r.expires_at>clock_timestamp() AND r.context->>'connectionId'=p_manifest->>'connectionId'
        AND r.context->>'sourceOrgId'=p_manifest->>'sourceOrgId' AND r.context->>'recordId'=item->>'recordId'
        AND r.context->>'revision'=item->>'revision' AND r.context->>'configRevision'=p_manifest->>'configRevision'
        AND r.context->>'sourceHash'=item->>'sourceHash' AND r.context->>'externalId'=item->>'externalId'
        AND r.context->'targetId'=item->'targetId' AND public.zoho_verify_candidate_review(p_actor,r.context,r.review_hash)
    ) THEN RETURN false; END IF;
  END LOOP;
  IF (SELECT count(DISTINCT value->>'recordId') FROM jsonb_array_elements(p_manifest->'items'))<>jsonb_array_length(p_manifest->'items') THEN RETURN false; END IF;
  SELECT jsonb_set(p_manifest,'{items}',jsonb_agg(value ORDER BY value->>'recordId')) INTO normalized FROM jsonb_array_elements(p_manifest->'items');
  -- Concurrent identical retries converge; the original expiry never extends.
  INSERT INTO public.zoho_import_approvals(actor_id,connection_id,request_id,manifest)
    VALUES(p_actor,(p_manifest->>'connectionId')::uuid,(p_manifest->>'requestId')::uuid,normalized)
    ON CONFLICT(connection_id,request_id) DO NOTHING;
  SELECT * INTO STRICT existing FROM public.zoho_import_approvals
    WHERE connection_id=(p_manifest->>'connectionId')::uuid AND request_id=(p_manifest->>'requestId')::uuid;
  RETURN existing.actor_id=p_actor AND existing.manifest=normalized AND existing.revoked_at IS NULL AND existing.expires_at>clock_timestamp();
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION public.zoho_validate_import_approval(p_grant jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF p_grant IS NULL OR EXISTS(SELECT 1 FROM unnest(ARRAY['operationId','lease','leaseExpiresAt','actorId','connectionId','sourceOrgId','publisherOrganizationId','recordId','revision','configRevision','sourceHash','action','module','externalId','emailPolicy']) k WHERE p_grant->>k IS NULL) OR NOT p_grant ? 'targetId' THEN RETURN false; END IF;
  IF (p_grant->>'operationId')::uuid IS NULL OR (p_grant->>'lease')::uuid IS NULL THEN RETURN false; END IF;
  IF jsonb_typeof(p_grant) IS DISTINCT FROM 'object' OR p_grant->>'emailPolicy' IS DISTINCT FROM 'forbidden' OR
    p_grant->'claimed' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(p_grant->'data') IS DISTINCT FROM 'object' OR
    (p_grant->>'leaseExpiresAt')::timestamptz<=statement_timestamp() OR
    p_grant->>'sourceHash' IS DISTINCT FROM encode(sha256(convert_to((p_grant->'data')::text,'UTF8')),'hex') OR
    NOT public.zoho_is_active_import_approver((p_grant->>'actorId')::uuid) OR
    NOT ((p_grant->>'module'='Candidates' AND p_grant->>'action'='provision_candidate') OR
         (p_grant->>'module'='Job_Openings' AND p_grant->>'action'='apply_job')) THEN RETURN false; END IF;
  RETURN EXISTS(SELECT 1 FROM public.zoho_import_approvals a CROSS JOIN LATERAL jsonb_array_elements(a.manifest->'items') item
    WHERE a.actor_id=(p_grant->>'actorId')::uuid AND a.connection_id=(p_grant->>'connectionId')::uuid
      AND a.revoked_at IS NULL AND a.expires_at>=greatest((p_grant->>'leaseExpiresAt')::timestamptz,statement_timestamp())
      AND a.manifest->>'sourceOrgId'=p_grant->>'sourceOrgId'
      AND a.manifest->>'publisherOrganizationId'=p_grant->>'publisherOrganizationId'
      AND (a.manifest->>'configRevision')::integer=(p_grant->>'configRevision')::integer
      AND item->>'recordId'=p_grant->>'recordId' AND item->>'revision'=p_grant->>'revision'
      AND item->>'sourceHash'=p_grant->>'sourceHash' AND item->>'module'=p_grant->>'module'
      AND item->>'externalId'=p_grant->>'externalId' AND item->'targetId'=p_grant->'targetId'
      AND (item->>'module'<>'Candidates' OR (item->>'candidateReviewHash' ~ '^[a-f0-9]{64}$' AND item->>'candidateReviewHash'=p_grant->>'candidateReviewHash')));
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_record_import_approval(uuid,jsonb),public.zoho_validate_import_approval(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_record_import_approval(uuid,jsonb),public.zoho_validate_import_approval(jsonb) TO service_role;

CREATE OR REPLACE FUNCTION public.zoho_provision_candidate(p_grant jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
#variable_conflict use_variable
DECLARE op uuid; actor uuid; target uuid; email text; display_name text; u public.users;
  plan public.plans; product uuid; learner_role uuid; membership uuid; subscription uuid;
  linked public.zoho_candidate_links; prior public.zoho_candidate_receipts; candidate_count integer;
  outcome text; activation text; projection jsonb; approved_context jsonb; review_context jsonb; reviewed jsonb;
BEGIN
  IF jsonb_typeof(p_grant) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(p_grant))<>20
    OR NOT p_grant ?& ARRAY['claimed','operationId','lease','leaseExpiresAt','approvalExpiresAt','actorId','connectionId','sourceOrgId','publisherOrganizationId','recordId','revision','configRevision','sourceHash','action','module','externalId','data','targetId','emailPolicy','candidateReviewHash']
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
  IF FOUND AND target IS NOT NULL AND linked.user_id<>target THEN
    RAISE EXCEPTION 'Source identity linkage requires review' USING ERRCODE='22023';
  END IF;
  SELECT count(*) INTO candidate_count FROM public.users WHERE lower(trim(users.email))=email;
  IF candidate_count>1 THEN RAISE EXCEPTION 'Ambiguous canonical identity' USING ERRCODE='22023'; END IF;
  SELECT * INTO u FROM public.users WHERE lower(trim(users.email))=email FOR UPDATE;
  IF FOUND THEN
    IF (target IS NOT NULL AND target IS DISTINCT FROM u.id) OR u.is_blocked IS DISTINCT FROM false THEN
      RAISE EXCEPTION 'Canonical target requires review' USING ERRCODE='22023';
    END IF;
  ELSIF target IS NOT NULL THEN RAISE EXCEPTION 'Canonical target changed' USING ERRCODE='40001';
  END IF;
  -- Lock all rows contributing to the reviewed canonical decision. Locking the
  -- user also fences FK-backed membership/subscription inserts until commit.
  PERFORM 1 FROM public.products p WHERE p.code='skillpassport' FOR SHARE;
  PERFORM 1 FROM public.roles r WHERE (u.id IS NULL AND r.name='learner') OR r.id IN(
    SELECT mr.role_id FROM public.membership_roles mr JOIN public.memberships m ON m.id=mr.membership_id WHERE m.user_id=u.id) ORDER BY r.id FOR SHARE;
  PERFORM 1 FROM public.memberships m WHERE m.user_id=u.id ORDER BY m.id FOR UPDATE;
  PERFORM 1 FROM public.membership_roles mr JOIN public.memberships m ON m.id=mr.membership_id WHERE m.user_id=u.id ORDER BY mr.membership_id,mr.role_id FOR SHARE OF mr;
  PERFORM 1 FROM public.membership_products mp JOIN public.memberships m ON m.id=mp.membership_id WHERE m.user_id=u.id ORDER BY mp.membership_id,mp.product_id FOR SHARE OF mp;
  PERFORM 1 FROM public.subscriptions s WHERE s.user_id=u.id ORDER BY s.id FOR SHARE;
  PERFORM 1 FROM public.plans p WHERE p.product_id IN(SELECT id FROM public.products WHERE code='skillpassport') ORDER BY p.id FOR SHARE;
  PERFORM 1 FROM public.organization_products op WHERE op.product_id IN(SELECT id FROM public.products WHERE code='skillpassport') ORDER BY op.org_id FOR SHARE;
  review_context:=jsonb_build_object('connectionId',p_grant->'connectionId','sourceOrgId',p_grant->'sourceOrgId','recordId',p_grant->'recordId',
    'revision',p_grant->'revision','configRevision',p_grant->'configRevision','sourceHash',p_grant->'sourceHash','externalId',p_grant->'externalId',
    'data',p_grant->'data','targetId',p_grant->'targetId','emailPolicy','forbidden');
  -- This repeats all version-readiness checks under the contributing row locks
  -- before any identity, entitlement, source-link, receipt or outbox mutation.
  reviewed:=public.zoho_candidate_review_snapshot(review_context);
  IF reviewed IS NULL OR reviewed->>'reviewHash' IS DISTINCT FROM p_grant->>'candidateReviewHash'
    OR reviewed->>'decision' NOT IN ('create','preserve_existing') THEN
    RAISE EXCEPTION 'Canonical candidate review changed' USING ERRCODE='40001';
  END IF;
  SELECT id INTO STRICT product FROM public.products WHERE code='skillpassport' FOR SHARE;
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
    outcome:='existing_access_preserved'; activation:=CASE WHEN coalesce(u.user_metadata->>'activation_pending','false')='true' THEN 'activation_pending' ELSE 'existing_sign_in_preserved' END;
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

COMMIT;
