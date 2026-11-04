BEGIN;

-- Purpose-scoped connector administration, independent of platform-account deletion.
-- Protected source references retain only the metadata required to deny replay.
CREATE TABLE public.zoho_candidate_suppressions (
 source_org_id text NOT NULL CHECK(source_org_id ~ '^\d{1,40}$'),
 external_id text NOT NULL CHECK(external_id ~ '^\d{1,40}$'),
 -- Intentionally no cascading identity FK: account deletion must not release replay suppression.
 user_id uuid NOT NULL,
 erased_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 released_at timestamptz,
 PRIMARY KEY(source_org_id,external_id)
);
CREATE TABLE public.zoho_candidate_erased_operations (
 operation_id uuid PRIMARY KEY,
 erased_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.zoho_candidate_administration_reviews (
 actor_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
 review_hash text NOT NULL CHECK(review_hash ~ '^[a-f0-9]{64}$'),
 context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=4096),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes',
 PRIMARY KEY(actor_id,review_hash)
);
CREATE INDEX zoho_candidate_administration_reviews_expiry ON public.zoho_candidate_administration_reviews(expires_at);
CREATE TABLE public.zoho_candidate_administration_operations (
 request_id uuid PRIMARY KEY,
 actor_id uuid NOT NULL REFERENCES public.users(id),
 context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=4096),
 review_hash text NOT NULL CHECK(review_hash ~ '^[a-f0-9]{64}$'),
 receipt jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.zoho_candidate_suppressions,public.zoho_candidate_erased_operations,
 public.zoho_candidate_administration_reviews,public.zoho_candidate_administration_operations FROM PUBLIC,anon,authenticated,service_role;
CREATE INDEX zoho_candidate_receipts_source ON public.zoho_candidate_receipts
 ((approved_context->>'sourceOrgId'),(approved_context->>'externalId'),operation_id);
CREATE INDEX zoho_candidate_reviews_source ON public.zoho_candidate_reviews
 ((context->>'sourceOrgId'),(context->>'externalId'));

ALTER FUNCTION public.zoho_candidate_review_snapshot(jsonb) RENAME TO zoho_candidate_review_snapshot_before_administration;
CREATE FUNCTION public.zoho_candidate_review_snapshot(p_context jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 result:=public.zoho_candidate_review_snapshot_before_administration(p_context);
 IF result IS NOT NULL AND result->'identity'->>'targetId' IS NOT NULL AND NOT EXISTS(
   SELECT 1 FROM public.users u JOIN public.memberships m ON m.user_id=u.id AND m.status='active'
    JOIN public.membership_roles mr ON mr.membership_id=m.id JOIN public.roles r ON r.id=mr.role_id
   WHERE u.id=(result->'identity'->>'targetId')::uuid AND r.name=u.user_metadata->>'role') THEN
  result:=result||jsonb_build_object('decision','blocked','blockers',(result->'blockers')||'"primary_role_assignment_unavailable"'::jsonb,
   'reviewHash',encode(sha256(convert_to(result::text||':primary_role_assignment_unavailable','UTF8')),'hex'));
 END IF;
 IF result IS NOT NULL AND EXISTS(SELECT 1 FROM public.zoho_candidate_suppressions
   WHERE source_org_id=p_context->>'sourceOrgId' AND external_id=p_context->>'externalId' AND released_at IS NULL) THEN
  result:=result||jsonb_build_object('decision','blocked','blockers',(result->'blockers')||'"connector_erasure_suppressed"'::jsonb,
    'reviewHash',encode(sha256(convert_to(result::text||':connector_erasure_suppressed','UTF8')),'hex'));
 END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION public.zoho_candidate_review_snapshot(jsonb),public.zoho_candidate_review_snapshot_before_administration(jsonb) FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.zoho_candidate_administration_snapshot(p_actor uuid,p_context jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
#variable_conflict use_variable
DECLARE target uuid; action text; u public.users; product uuid; platform uuid:='00000000-0000-0000-0000-000000000001';
 linked uuid; blocked boolean:=false; learner boolean; entitled boolean; discover boolean; evidence boolean;
 membership uuid; plan public.plans; body jsonb; state jsonb; grant_free boolean:=false;
BEGIN
 IF NOT public.zoho_is_active_import_approver(p_actor) OR jsonb_typeof(p_context) IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(p_context))<>7
  OR NOT p_context ?& ARRAY['action','sourceOrgId','externalId','targetId','reason','emailPolicy','acknowledgeIndependentDiscover']
  OR jsonb_typeof(p_context->'action') IS DISTINCT FROM 'string'
  OR coalesce(p_context->>'action','') NOT IN ('establish_learner_context','erase_connector','release_suppression')
  OR jsonb_typeof(p_context->'sourceOrgId') IS DISTINCT FROM 'string' OR jsonb_typeof(p_context->'externalId') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_context->'targetId') IS DISTINCT FROM 'string'
  OR coalesce(p_context->>'sourceOrgId','') !~ '^\d{1,40}$' OR coalesce(p_context->>'externalId','') !~ '^\d{1,40}$'
  OR p_context->>'emailPolicy' IS DISTINCT FROM 'forbidden' OR jsonb_typeof(p_context->'reason') IS DISTINCT FROM 'string'
  OR length(trim(p_context->>'reason')) NOT BETWEEN 3 AND 500 OR trim(p_context->>'reason')<>p_context->>'reason'
  OR p_context->'acknowledgeIndependentDiscover' IS DISTINCT FROM to_jsonb(p_context->>'action'='establish_learner_context')
 THEN RETURN NULL; END IF;
 target:=(p_context->>'targetId')::uuid; action:=p_context->>'action';
 SELECT * INTO u FROM public.users WHERE id=target;
 IF NOT FOUND OR (action='establish_learner_context' AND u.is_blocked IS DISTINCT FROM false) THEN RETURN NULL; END IF;
 SELECT id INTO product FROM public.products WHERE code='skillpassport';
 SELECT user_id INTO linked FROM public.zoho_candidate_links WHERE source_org_id=p_context->>'sourceOrgId' AND external_id=p_context->>'externalId';
 IF linked IS NOT NULL AND linked<>target THEN RETURN NULL; END IF;
 IF action='establish_learner_context' THEN
  -- Source/identity provenance comes from a fresh source-bound canonical review, not an arbitrary target supplied by the browser.
  IF (SELECT count(*) FROM public.users WHERE lower(trim(email))=lower(trim(u.email)))<>1 THEN RETURN NULL; END IF;
  SELECT EXISTS(SELECT 1 FROM public.zoho_candidate_reviews r
    CROSS JOIN LATERAL (SELECT public.zoho_candidate_review_snapshot(r.context) AS value) current_review
    WHERE r.actor_id=p_actor AND r.expires_at>statement_timestamp()
    AND r.context->>'sourceOrgId'=p_context->>'sourceOrgId' AND r.context->>'externalId'=p_context->>'externalId'
    AND r.context->'data'->>'email'=lower(trim(u.email))
    AND (r.context->>'targetId' IS NULL OR r.context->>'targetId'=target::text)
    AND current_review.value->'identity'->>'targetId'=target::text AND current_review.value->>'reviewHash'=r.review_hash
    AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(current_review.value->'blockers') blocker
      WHERE blocker NOT IN ('learner_product_context_requires_review','personal_entitlement_requires_review'))) INTO evidence;
  SELECT EXISTS(SELECT 1 FROM public.zoho_candidate_suppressions WHERE source_org_id=p_context->>'sourceOrgId'
    AND external_id=p_context->>'externalId' AND released_at IS NULL) INTO blocked;
  IF NOT evidence OR blocked OR product IS NULL THEN RETURN NULL; END IF;
  SELECT EXISTS(SELECT 1 FROM public.memberships m JOIN public.membership_roles mr ON mr.membership_id=m.id
    JOIN public.roles r ON r.id=mr.role_id AND r.name='learner'
    JOIN public.membership_products mp ON mp.membership_id=m.id AND mp.product_id=product
    JOIN public.organization_products op ON op.org_id=m.org_id AND op.product_id=product AND op.active IS TRUE
    WHERE m.user_id=target AND m.status='active') INTO learner;
  SELECT id INTO membership FROM public.memberships WHERE user_id=target AND org_id=platform AND status='active';
  IF NOT learner AND (EXISTS(SELECT 1 FROM public.memberships WHERE user_id=target AND org_id=platform AND status<>'active')
    OR NOT EXISTS(SELECT 1 FROM public.organization_products WHERE org_id=platform AND product_id=product AND active IS TRUE)
    OR NOT EXISTS(SELECT 1 FROM public.roles WHERE name='learner')) THEN RETURN NULL; END IF;
  SELECT EXISTS(SELECT 1 FROM public.subscriptions s JOIN public.plans p ON p.id=s.plan_id AND p.product_id=product
    WHERE s.user_id=target AND s.status IN ('active','grace_period') AND s.is_organization_subscription IS NOT TRUE
      AND s.is_bulk_purchase IS NOT TRUE AND (s.subscription_end_date IS NULL OR s.subscription_end_date>statement_timestamp())) INTO entitled;
  grant_free:=NOT entitled;
  IF grant_free THEN
   SELECT * INTO plan FROM public.plans WHERE plan_code='freemium' AND product_id=product;
   discover:=plan.id IS NOT NULL AND plan.is_active IS TRUE AND plan.business_type='b2c' AND plan.updated_at IS NOT NULL
     AND ('all'=ANY(plan.applicable_entities) OR 'learner'=ANY(plan.applicable_entities))
     AND plan.pricing_matrix->'all'->'monthly'='0'::jsonb AND plan.pricing_matrix->'all'->'yearly'='0'::jsonb
     AND plan.base_features @> '["learner_profile_creation","basic_opportunity_view"]'::jsonb;
   -- Respect the canonical global personal-subscription uniqueness rule; never cancel or replace a competing product/paid plan.
   IF discover IS DISTINCT FROM true OR EXISTS(SELECT 1 FROM public.subscriptions WHERE user_id=target AND status='active'
      AND is_organization_subscription IS NOT TRUE AND is_bulk_purchase IS NOT TRUE) THEN RETURN NULL; END IF;
  END IF;
 ELSE
  IF linked IS DISTINCT FROM target THEN RETURN NULL; END IF;
  IF action='release_suppression' AND NOT EXISTS(SELECT 1 FROM public.zoho_candidate_suppressions
    WHERE source_org_id=p_context->>'sourceOrgId' AND external_id=p_context->>'externalId' AND user_id=target AND released_at IS NULL) THEN RETURN NULL; END IF;
 END IF;
 state:=jsonb_build_object('user',to_jsonb(u),
  'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]') FROM public.memberships m WHERE m.user_id=target),
  'roles',(SELECT coalesce(jsonb_agg(to_jsonb(mr) ORDER BY mr.membership_id,mr.role_id),'[]') FROM public.membership_roles mr JOIN public.memberships m ON m.id=mr.membership_id WHERE m.user_id=target),
  'products',(SELECT coalesce(jsonb_agg(to_jsonb(mp) ORDER BY mp.membership_id,mp.product_id),'[]') FROM public.membership_products mp JOIN public.memberships m ON m.id=mp.membership_id WHERE m.user_id=target),
  'subscriptions',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]') FROM public.subscriptions s WHERE s.user_id=target),
  'catalog',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]') FROM public.plans p WHERE p.product_id=product),
  'organizationProducts',(SELECT coalesce(jsonb_agg(to_jsonb(op) ORDER BY op.id),'[]') FROM public.organization_products op WHERE op.product_id=product),
  'sourceLink',linked,'suppression',(SELECT to_jsonb(s) FROM public.zoho_candidate_suppressions s WHERE source_org_id=p_context->>'sourceOrgId' AND external_id=p_context->>'externalId'),
  'operations',(SELECT coalesce(jsonb_agg(r.operation_id ORDER BY r.operation_id),'[]') FROM public.zoho_candidate_receipts r WHERE r.approved_context->>'sourceOrgId'=p_context->>'sourceOrgId' AND r.approved_context->>'externalId'=p_context->>'externalId'));
 body:=jsonb_build_object('version',1,'scope','connector_only','action',action,'targetId',target,'sourceOrgId',p_context->>'sourceOrgId',
  'externalId',p_context->>'externalId','allowed',true,'emailPolicy','forbidden','canonicalAccountPreserved',true,
  'changes',jsonb_build_object('addIndependentLearnerContext',action='establish_learner_context' AND NOT learner,
    'grantDiscover',grant_free,'preservePrimaryRole',true,'preserveExistingAccess',true,
    'eraseConnectorPayloads',action='erase_connector','suppressSource',action='erase_connector',
    'releaseSourceSuppression',action='release_suppression','restoreOldData',false));
 RETURN body||jsonb_build_object('reviewHash',encode(sha256(convert_to(jsonb_build_object('actor',p_actor,'context',p_context,'state',state,'body',body)::text,'UTF8')),'hex'));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public.zoho_candidate_administration_snapshot(uuid,jsonb) FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.zoho_preview_candidate_administration(p_actor uuid,p_context jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE snapshot jsonb; expiry timestamptz;
BEGIN
 snapshot:=public.zoho_candidate_administration_snapshot(p_actor,p_context);
 IF snapshot IS NULL THEN RETURN NULL; END IF;
 INSERT INTO public.zoho_candidate_administration_reviews(actor_id,review_hash,context) VALUES(p_actor,snapshot->>'reviewHash',p_context)
 ON CONFLICT(actor_id,review_hash) DO UPDATE SET expires_at=clock_timestamp()+interval '10 minutes';
 SELECT expires_at INTO expiry FROM public.zoho_candidate_administration_reviews WHERE actor_id=p_actor AND review_hash=snapshot->>'reviewHash';
 RETURN snapshot||jsonb_build_object('expiresAt',expiry);
END $$;

CREATE FUNCTION public.zoho_find_candidate_administration(p_actor uuid,p_request uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT receipt FROM public.zoho_candidate_administration_operations WHERE request_id=p_request AND actor_id=p_actor AND public.zoho_is_active_import_approver(p_actor);
$$;

CREATE FUNCTION public.zoho_execute_candidate_administration(p_actor uuid,p_context jsonb,p_review_hash text,p_request uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
#variable_conflict use_variable
DECLARE prior public.zoho_candidate_administration_operations; snapshot jsonb; target uuid; product uuid; role_id uuid; membership uuid;
 plan public.plans; u public.users; receipt jsonb; action text; linked uuid; erased_ids jsonb:='[]'; erased_count integer:=0;
BEGIN
 IF p_request IS NULL OR NOT public.zoho_is_active_import_approver(p_actor) THEN RAISE EXCEPTION 'Administration authority unavailable' USING ERRCODE='22023'; END IF;
 -- Serialize human authority revocation with the transaction, including the actor's role membership.
 PERFORM 1 FROM public.users a JOIN public.memberships m ON m.user_id=a.id
  JOIN public.membership_roles mr ON mr.membership_id=m.id JOIN public.roles r ON r.id=mr.role_id
  WHERE a.id=p_actor AND a.is_blocked IS FALSE AND m.status='active' AND m.org_id='00000000-0000-0000-0000-000000000001'
    AND r.name='super_admin' FOR SHARE OF a,m,mr,r;
 IF NOT FOUND THEN RAISE EXCEPTION 'Administration authority unavailable' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zoho-administration:'||p_request::text,0));
 SELECT * INTO prior FROM public.zoho_candidate_administration_operations WHERE request_id=p_request;
 IF FOUND THEN
  IF prior.actor_id<>p_actor OR prior.context IS DISTINCT FROM p_context OR prior.review_hash IS DISTINCT FROM p_review_hash THEN
   RAISE EXCEPTION 'Administration request conflict' USING ERRCODE='40001'; END IF;
  RETURN prior.receipt;
 END IF;
 -- Same source fence as provisioning: queued work cannot race connector erasure.
 PERFORM pg_advisory_xact_lock(hashtextextended('zoho-source:'||(p_context->>'sourceOrgId')||':'||(p_context->>'externalId'),0));
 target:=(p_context->>'targetId')::uuid;
 SELECT * INTO u FROM public.users WHERE id=target FOR UPDATE;
 PERFORM 1 FROM public.memberships WHERE user_id=target ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.membership_roles mr JOIN public.memberships m ON m.id=mr.membership_id WHERE m.user_id=target FOR SHARE OF mr;
 PERFORM 1 FROM public.membership_products mp JOIN public.memberships m ON m.id=mp.membership_id WHERE m.user_id=target FOR SHARE OF mp;
 PERFORM 1 FROM public.subscriptions WHERE user_id=target ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.products WHERE code='skillpassport' FOR SHARE;
 PERFORM 1 FROM public.roles WHERE name='learner' FOR SHARE;
 PERFORM 1 FROM public.plans WHERE product_id IN(SELECT id FROM public.products WHERE code='skillpassport') ORDER BY id FOR SHARE;
 PERFORM 1 FROM public.organization_products WHERE product_id IN(SELECT id FROM public.products WHERE code='skillpassport') ORDER BY id FOR SHARE;
 snapshot:=public.zoho_candidate_administration_snapshot(p_actor,p_context);
 IF snapshot IS NULL OR snapshot->>'reviewHash' IS DISTINCT FROM p_review_hash OR NOT EXISTS(
  SELECT 1 FROM public.zoho_candidate_administration_reviews WHERE actor_id=p_actor AND review_hash=p_review_hash AND context=p_context AND expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'Administration review changed' USING ERRCODE='40001'; END IF;
 action:=p_context->>'action';
 IF action='establish_learner_context' THEN
  PERFORM public.zoho_assert_private_identity_boundary();
  SELECT id INTO STRICT product FROM public.products WHERE code='skillpassport';
  IF (snapshot->'changes'->>'addIndependentLearnerContext')::boolean THEN
   SELECT id INTO STRICT role_id FROM public.roles WHERE name='learner';
   INSERT INTO public.memberships(user_id,org_id,status) VALUES(target,'00000000-0000-0000-0000-000000000001','active')
    ON CONFLICT(user_id,org_id) DO NOTHING;
   SELECT id INTO STRICT membership FROM public.memberships WHERE user_id=target AND org_id='00000000-0000-0000-0000-000000000001' AND status='active';
   INSERT INTO public.membership_roles(membership_id,role_id) VALUES(membership,role_id) ON CONFLICT DO NOTHING;
   INSERT INTO public.membership_products(membership_id,product_id) VALUES(membership,product) ON CONFLICT DO NOTHING;
  END IF;
  IF (snapshot->'changes'->>'grantDiscover')::boolean THEN
   SELECT * INTO STRICT plan FROM public.plans WHERE plan_code='freemium' AND product_id=product;
   INSERT INTO public.subscriptions(user_id,plan_id,full_name,email,plan_code,plan_type,plan_amount,billing_cycle,features,status,
    auto_renew,subscription_start_date,is_organization_subscription,is_bulk_purchase,product_id,metadata)
   VALUES(target,plan.id,coalesce(nullif(trim(concat_ws(' ',u.user_metadata->>'first_name',u.user_metadata->>'last_name')),''),'Learner'),
    u.email,'freemium',plan.name,0,'lifetime',plan.base_features,'active',false,clock_timestamp(),false,false,product,
    jsonb_build_object('origin','zoho_recruit_reviewed_learner_context','emailPolicy','forbidden','administrationRequestId',p_request));
  END IF;
 ELSE
  IF action='erase_connector' THEN
   INSERT INTO public.zoho_candidate_suppressions(source_org_id,external_id,user_id) VALUES(p_context->>'sourceOrgId',p_context->>'externalId',target)
    ON CONFLICT(source_org_id,external_id) DO UPDATE SET erased_at=clock_timestamp(),released_at=NULL;
   INSERT INTO public.zoho_candidate_erased_operations(operation_id) SELECT operation_id FROM public.zoho_candidate_receipts
    WHERE approved_context->>'sourceOrgId'=p_context->>'sourceOrgId' AND approved_context->>'externalId'=p_context->>'externalId' ON CONFLICT DO NOTHING;
   DELETE FROM public.zoho_candidate_outbox o USING public.zoho_candidate_receipts r WHERE o.operation_id=r.operation_id
    AND r.approved_context->>'sourceOrgId'=p_context->>'sourceOrgId' AND r.approved_context->>'externalId'=p_context->>'externalId';
   DELETE FROM public.zoho_candidate_reviews WHERE context->>'sourceOrgId'=p_context->>'sourceOrgId' AND context->>'externalId'=p_context->>'externalId';
   UPDATE public.zoho_import_approvals a SET revoked_at=clock_timestamp() WHERE a.revoked_at IS NULL AND a.manifest->>'sourceOrgId'=p_context->>'sourceOrgId'
    AND EXISTS(SELECT 1 FROM jsonb_array_elements(a.manifest->'items') i WHERE i->>'module'='Candidates' AND i->>'externalId'=p_context->>'externalId');
   SELECT count(*) INTO erased_count FROM public.zoho_candidate_receipts WHERE approved_context->>'sourceOrgId'=p_context->>'sourceOrgId'
     AND approved_context->>'externalId'=p_context->>'externalId';
   SELECT coalesce(jsonb_agg(operation_id ORDER BY operation_id),'[]') INTO erased_ids FROM (
     SELECT operation_id FROM public.zoho_candidate_receipts WHERE approved_context->>'sourceOrgId'=p_context->>'sourceOrgId'
       AND approved_context->>'externalId'=p_context->>'externalId' ORDER BY operation_id LIMIT 500) refs;
  ELSE
   UPDATE public.zoho_candidate_suppressions SET released_at=clock_timestamp() WHERE source_org_id=p_context->>'sourceOrgId'
    AND external_id=p_context->>'externalId' AND user_id=target AND released_at IS NULL;
   IF NOT FOUND THEN RAISE EXCEPTION 'Suppression changed' USING ERRCODE='40001'; END IF;
  END IF;
 END IF;
 receipt:=jsonb_build_object('version',1,'requestId',p_request,'action',action,'state','completed','targetId',target,
  'sourceOrgId',p_context->>'sourceOrgId','externalId',p_context->>'externalId','emailPolicy','forbidden',
  'canonicalAccountPreserved',true,'scope','connector_only','oldDataRestored',false,
  'erasedOperationIds',erased_ids,'moreErasedOperations',erased_count>500);
 INSERT INTO public.zoho_candidate_administration_operations(request_id,actor_id,context,review_hash,receipt) VALUES(p_request,p_actor,p_context,p_review_hash,receipt);
 DELETE FROM public.zoho_candidate_administration_reviews WHERE actor_id=p_actor AND review_hash=p_review_hash;
 RETURN receipt;
END $$;

REVOKE ALL ON FUNCTION public.zoho_preview_candidate_administration(uuid,jsonb),public.zoho_execute_candidate_administration(uuid,jsonb,text,uuid),
 public.zoho_find_candidate_administration(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_preview_candidate_administration(uuid,jsonb),public.zoho_execute_candidate_administration(uuid,jsonb,text,uuid),
 public.zoho_find_candidate_administration(uuid,uuid) TO service_role;

ALTER FUNCTION public.zoho_provision_candidate(jsonb) RENAME TO zoho_provision_candidate_before_administration;
CREATE FUNCTION public.zoho_provision_candidate(p_grant jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('zoho-source:'||(p_grant->>'sourceOrgId')||':'||(p_grant->>'externalId'),0));
 IF EXISTS(SELECT 1 FROM public.zoho_candidate_suppressions WHERE source_org_id=p_grant->>'sourceOrgId' AND external_id=p_grant->>'externalId' AND released_at IS NULL)
  OR EXISTS(SELECT 1 FROM public.zoho_candidate_erased_operations WHERE operation_id=(p_grant->>'operationId')::uuid) THEN
  RAISE EXCEPTION 'Connector source suppressed' USING ERRCODE='22023'; END IF;
 RETURN public.zoho_provision_candidate_before_administration(p_grant);
END $$;
REVOKE ALL ON FUNCTION public.zoho_provision_candidate_before_administration(jsonb),public.zoho_provision_candidate(jsonb) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.zoho_provision_candidate(jsonb) TO service_role;

ALTER FUNCTION public.zoho_get_candidate_projection(uuid,text) RENAME TO zoho_get_candidate_projection_before_administration;
CREATE FUNCTION public.zoho_get_candidate_projection(p_operation uuid,p_source_hash text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb; body jsonb; learner jsonb; primary_context jsonb;
BEGIN
 IF EXISTS(SELECT 1 FROM public.zoho_candidate_erased_operations WHERE operation_id=p_operation) THEN RETURN NULL; END IF;
 result:=public.zoho_get_candidate_projection_before_administration(p_operation,p_source_hash);
 IF result IS NULL THEN RETURN NULL; END IF;
 body:=(result->>'snapshot')::jsonb;
 -- Metadata labels cannot grant application roles. Prove the primary label
 -- against an actual currently active canonical membership/role assignment.
 SELECT jsonb_build_object('membershipId',m.id,'organizationId',m.org_id,'role',r.name) INTO primary_context
 FROM public.memberships m JOIN public.membership_roles mr ON mr.membership_id=m.id JOIN public.roles r ON r.id=mr.role_id
 WHERE m.user_id=(body->>'targetId')::uuid AND m.status='active' AND r.name=body->'user'->>'primaryRole'
 ORDER BY m.org_id,m.id LIMIT 1;
 IF primary_context IS NULL THEN RETURN NULL; END IF;
 SELECT jsonb_build_object('version',1,'role','learner','productCode','skillpassport','membershipId',m.id,'organizationId',m.org_id,'active',true,
   'source',(SELECT jsonb_build_object('sourceOrgId',approved_context->>'sourceOrgId','externalId',approved_context->>'externalId')
     FROM public.zoho_candidate_receipts WHERE operation_id=p_operation)) INTO learner
 FROM public.memberships m JOIN public.membership_roles mr ON mr.membership_id=m.id JOIN public.roles r ON r.id=mr.role_id AND r.name='learner'
 JOIN public.membership_products mp ON mp.membership_id=m.id JOIN public.products p ON p.id=mp.product_id AND p.code='skillpassport'
 JOIN public.organization_products op ON op.org_id=m.org_id AND op.product_id=p.id AND op.active IS TRUE
 WHERE m.user_id=(body->>'targetId')::uuid AND m.status='active' ORDER BY m.org_id,m.id LIMIT 1;
 IF learner IS NULL THEN RETURN NULL; END IF;
 learner:=learner||jsonb_build_object('primaryContext',primary_context);
 body:=body||jsonb_build_object('learnerContext',learner);
 RETURN result||jsonb_build_object('snapshot',body::text,'projectionHash',encode(sha256(convert_to(body::text,'UTF8')),'hex'));
END $$;
REVOKE ALL ON FUNCTION public.zoho_get_candidate_projection_before_administration(uuid,text),public.zoho_get_candidate_projection(uuid,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.zoho_get_candidate_projection(uuid,text) TO service_role;

ALTER FUNCTION public.zoho_find_candidate_receipt(uuid,text) RENAME TO zoho_find_candidate_receipt_before_administration;
CREATE FUNCTION public.zoho_find_candidate_receipt(p_operation uuid,p_source_hash text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT public.zoho_find_candidate_receipt_before_administration(p_operation,p_source_hash)
 WHERE NOT EXISTS(SELECT 1 FROM public.zoho_candidate_erased_operations WHERE operation_id=p_operation);
$$;
REVOKE ALL ON FUNCTION public.zoho_find_candidate_receipt_before_administration(uuid,text),public.zoho_find_candidate_receipt(uuid,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.zoho_find_candidate_receipt(uuid,text) TO service_role;

CREATE FUNCTION public.zoho_list_candidate_erased_operations(p_actor uuid,p_request uuid,p_after uuid DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE operation public.zoho_candidate_administration_operations; ids jsonb; more boolean;
BEGIN
 IF NOT public.zoho_is_active_import_approver(p_actor) THEN RETURN NULL; END IF;
 SELECT * INTO operation FROM public.zoho_candidate_administration_operations WHERE request_id=p_request AND actor_id=p_actor AND context->>'action'='erase_connector';
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT coalesce(jsonb_agg(operation_id ORDER BY operation_id),'[]') INTO ids FROM (
   SELECT r.operation_id FROM public.zoho_candidate_receipts r JOIN public.zoho_candidate_erased_operations e ON e.operation_id=r.operation_id
   WHERE r.approved_context->>'sourceOrgId'=operation.context->>'sourceOrgId' AND r.approved_context->>'externalId'=operation.context->>'externalId'
     AND (p_after IS NULL OR r.operation_id>p_after) ORDER BY r.operation_id LIMIT 500) refs;
 SELECT count(*)>500 INTO more FROM public.zoho_candidate_receipts r JOIN public.zoho_candidate_erased_operations e ON e.operation_id=r.operation_id
   WHERE r.approved_context->>'sourceOrgId'=operation.context->>'sourceOrgId' AND r.approved_context->>'externalId'=operation.context->>'externalId'
     AND (p_after IS NULL OR r.operation_id>p_after);
 RETURN jsonb_build_object('version',1,'requestId',p_request,'sourceOrgId',operation.context->>'sourceOrgId','externalId',operation.context->>'externalId',
   'targetId',operation.context->>'targetId','action','erase_connector','state','completed','scope','connector_only',
   'canonicalAccountPreserved',true,'oldDataRestored',false,'erasedOperationIds',ids,'moreErasedOperations',more,'emailPolicy','forbidden');
END $$;
REVOKE ALL ON FUNCTION public.zoho_list_candidate_erased_operations(uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_list_candidate_erased_operations(uuid,uuid,uuid) TO service_role;

ALTER FUNCTION public.zoho_cleanup_candidate_reviews() RENAME TO zoho_cleanup_candidate_reviews_before_administration;
CREATE FUNCTION public.zoho_cleanup_candidate_reviews() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE removed integer; existing_removed integer;
BEGIN
 existing_removed:=public.zoho_cleanup_candidate_reviews_before_administration();
 WITH expired AS(SELECT actor_id,review_hash FROM public.zoho_candidate_administration_reviews WHERE expires_at<=clock_timestamp()
   ORDER BY expires_at,actor_id,review_hash LIMIT 500 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.zoho_candidate_administration_reviews r USING expired e WHERE r.actor_id=e.actor_id AND r.review_hash=e.review_hash;
 GET DIAGNOSTICS removed=ROW_COUNT;
 RETURN existing_removed+removed;
END $$;
REVOKE ALL ON FUNCTION public.zoho_cleanup_candidate_reviews_before_administration(),public.zoho_cleanup_candidate_reviews() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.zoho_cleanup_candidate_reviews() TO service_role;

ALTER FUNCTION public.zoho_assert_private_identity_boundary() RENAME TO zoho_assert_private_identity_boundary_before_administration;
CREATE FUNCTION public.zoho_assert_private_identity_boundary() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM public.zoho_assert_private_identity_boundary_before_administration();
 IF EXISTS(WITH RECURSIVE protected(oid) AS(
   SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN(
    'zoho_candidate_suppressions','zoho_candidate_erased_operations','zoho_candidate_administration_reviews','zoho_candidate_administration_operations')
   UNION SELECT r.ev_class FROM protected p JOIN pg_depend d ON d.refobjid=p.oid AND d.refclassid='pg_class'::regclass
    AND d.classid='pg_rewrite'::regclass JOIN pg_rewrite r ON r.oid=d.objid WHERE r.ev_class<>p.oid)
   SELECT 1 FROM protected p CROSS JOIN(VALUES('anon'),('authenticated')) browser(role)
   WHERE has_table_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE,DELETE') OR has_any_column_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE')) THEN
  RAISE EXCEPTION 'Private identity requires a verified server-only data boundary' USING ERRCODE='42501'; END IF;
END $$;
REVOKE ALL ON FUNCTION public.zoho_assert_private_identity_boundary_before_administration(),public.zoho_assert_private_identity_boundary() FROM PUBLIC,anon,authenticated,service_role;

ALTER FUNCTION public.zoho_candidate_runtime_ready() RENAME TO zoho_candidate_runtime_ready_before_administration;
CREATE FUNCTION public.zoho_candidate_runtime_ready() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE signature text; function_oid oid;
BEGIN
 IF public.zoho_candidate_runtime_ready_before_administration() IS DISTINCT FROM true THEN RETURN false; END IF;
 FOREACH signature IN ARRAY ARRAY['public.zoho_preview_candidate_administration(uuid,jsonb)',
  'public.zoho_execute_candidate_administration(uuid,jsonb,text,uuid)','public.zoho_find_candidate_administration(uuid,uuid)',
  'public.zoho_list_candidate_erased_operations(uuid,uuid,uuid)'] LOOP
  function_oid:=to_regprocedure(signature);
  IF function_oid IS NULL OR NOT has_function_privilege('service_role',function_oid,'EXECUTE')
    OR has_function_privilege('anon',function_oid,'EXECUTE') OR has_function_privilege('authenticated',function_oid,'EXECUTE') THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION public.zoho_candidate_runtime_ready_before_administration(),public.zoho_candidate_runtime_ready() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.zoho_candidate_runtime_ready() TO service_role;

COMMIT;
