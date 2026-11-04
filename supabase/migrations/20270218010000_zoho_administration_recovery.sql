BEGIN;
-- Canonical privacy completion and application delivery are separate commits.
-- One source-scoped pending confirmation prevents a later opposite action from
-- overtaking an unfinished page/artifact cleanup. Approval actor is immutable;
-- any currently active platform super-admin may recover an existing commit.
ALTER TABLE public.zoho_candidate_administration_operations
 ADD COLUMN administration_version bigint NOT NULL DEFAULT 0 CHECK(administration_version BETWEEN 0 AND 9007199254740991),
 ADD COLUMN application_acknowledged_at timestamptz,
 ADD COLUMN application_acknowledged_by uuid;
CREATE TABLE public.zoho_candidate_administration_fences (
 source_org_id text NOT NULL CHECK(source_org_id ~ '^[0-9]{1,40}$'), external_id text NOT NULL CHECK(external_id ~ '^[0-9]{1,40}$'),
 administration_version bigint NOT NULL DEFAULT 0 CHECK(administration_version BETWEEN 0 AND 9007199254740991),
 latest_request_id uuid, pending_request_id uuid, updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(source_org_id,external_id)
);
REVOKE ALL ON public.zoho_candidate_administration_fences FROM PUBLIC,anon,authenticated,service_role;
CREATE INDEX zoho_administration_pending_source ON public.zoho_candidate_administration_operations
 ((context->>'sourceOrgId'),created_at DESC,request_id DESC) WHERE application_acknowledged_at IS NULL;

CREATE FUNCTION public.zoho_current_administration_receipt(p_request uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT o.receipt||jsonb_build_object('administrationVersion',o.administration_version,'approvalActorId',o.actor_id,
  'currentAdministration',f.latest_request_id=o.request_id AND f.administration_version=o.administration_version,
  'applicationAcknowledged',o.application_acknowledged_at IS NOT NULL)
 FROM public.zoho_candidate_administration_operations o JOIN public.zoho_candidate_administration_fences f
 ON f.source_org_id=o.context->>'sourceOrgId' AND f.external_id=o.context->>'externalId'
 WHERE o.request_id=p_request AND o.administration_version>0;
$$;
REVOKE ALL ON FUNCTION public.zoho_current_administration_receipt(uuid) FROM PUBLIC,anon,authenticated,service_role;

ALTER FUNCTION public.zoho_preview_candidate_administration(uuid,jsonb) RENAME TO zoho_preview_candidate_administration_before_recovery;
CREATE FUNCTION public.zoho_preview_candidate_administration(p_actor uuid,p_context jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT public.zoho_is_active_import_approver(p_actor) THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM public.zoho_candidate_administration_operations WHERE administration_version=0
  AND context->>'sourceOrgId'=p_context->>'sourceOrgId' AND context->>'externalId'=p_context->>'externalId') THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM public.zoho_candidate_administration_fences WHERE source_org_id=p_context->>'sourceOrgId'
  AND external_id=p_context->>'externalId' AND pending_request_id IS NOT NULL) THEN RETURN NULL; END IF;
 RETURN public.zoho_preview_candidate_administration_before_recovery(p_actor,p_context);
END $$;
ALTER FUNCTION public.zoho_execute_candidate_administration(uuid,jsonb,text,uuid) RENAME TO zoho_execute_candidate_administration_before_recovery;
CREATE FUNCTION public.zoho_execute_candidate_administration(p_actor uuid,p_context jsonb,p_review_hash text,p_request uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE prior public.zoho_candidate_administration_operations; fence public.zoho_candidate_administration_fences; result jsonb;
BEGIN
 IF p_request IS NULL OR NOT public.zoho_is_active_import_approver(p_actor) THEN RAISE EXCEPTION 'Administration authority unavailable' USING ERRCODE='22023'; END IF;
 PERFORM 1 FROM public.users a JOIN public.memberships m ON m.user_id=a.id JOIN public.membership_roles mr ON mr.membership_id=m.id JOIN public.roles r ON r.id=mr.role_id
 WHERE a.id=p_actor AND a.is_blocked IS FALSE AND m.status='active' AND m.org_id='00000000-0000-0000-0000-000000000001' AND r.name='super_admin' FOR SHARE OF a,m,mr,r;
 IF NOT FOUND THEN RAISE EXCEPTION 'Administration authority unavailable' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zoho-administration:'||p_request::text,0));
 SELECT * INTO prior FROM public.zoho_candidate_administration_operations WHERE request_id=p_request;
 IF FOUND THEN
  IF prior.actor_id<>p_actor OR prior.context IS DISTINCT FROM p_context OR prior.review_hash IS DISTINCT FROM p_review_hash THEN RAISE EXCEPTION 'Administration request conflict' USING ERRCODE='40001'; END IF;
  RETURN public.zoho_current_administration_receipt(p_request);
 END IF;
 IF coalesce(p_context->>'sourceOrgId','') !~ '^[0-9]{1,40}$' OR coalesce(p_context->>'externalId','') !~ '^[0-9]{1,40}$' THEN RAISE EXCEPTION 'Invalid administration source' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zoho-source:'||(p_context->>'sourceOrgId')||':'||(p_context->>'externalId'),0));
 IF EXISTS(SELECT 1 FROM public.zoho_candidate_administration_operations WHERE administration_version=0
  AND context->>'sourceOrgId'=p_context->>'sourceOrgId' AND context->>'externalId'=p_context->>'externalId') THEN
  RAISE EXCEPTION 'Administration upgrade required' USING ERRCODE='40001'; END IF;
 INSERT INTO public.zoho_candidate_administration_fences(source_org_id,external_id) VALUES(p_context->>'sourceOrgId',p_context->>'externalId') ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT fence FROM public.zoho_candidate_administration_fences WHERE source_org_id=p_context->>'sourceOrgId' AND external_id=p_context->>'externalId' FOR UPDATE;
 IF fence.pending_request_id IS NOT NULL THEN RAISE EXCEPTION 'Previous administration requires application confirmation' USING ERRCODE='40001'; END IF;
 IF fence.administration_version>=9007199254740991 THEN RAISE EXCEPTION 'Administration version budget exhausted' USING ERRCODE='22003'; END IF;
 result:=public.zoho_execute_candidate_administration_before_recovery(p_actor,p_context,p_review_hash,p_request);
 UPDATE public.zoho_candidate_administration_operations SET administration_version=fence.administration_version+1 WHERE request_id=p_request;
 UPDATE public.zoho_candidate_administration_fences SET administration_version=fence.administration_version+1,latest_request_id=p_request,pending_request_id=p_request,updated_at=clock_timestamp()
  WHERE source_org_id=fence.source_org_id AND external_id=fence.external_id;
 RETURN public.zoho_current_administration_receipt(p_request);
END $$;
REVOKE ALL ON FUNCTION public.zoho_preview_candidate_administration_before_recovery(uuid,jsonb),public.zoho_execute_candidate_administration_before_recovery(uuid,jsonb,text,uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.zoho_preview_candidate_administration(uuid,jsonb),public.zoho_execute_candidate_administration(uuid,jsonb,text,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_preview_candidate_administration(uuid,jsonb),public.zoho_execute_candidate_administration(uuid,jsonb,text,uuid) TO service_role;

CREATE OR REPLACE FUNCTION public.zoho_find_candidate_administration(p_actor uuid,p_request uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT public.zoho_current_administration_receipt(p_request) WHERE public.zoho_is_active_import_approver(p_actor);
$$;
CREATE FUNCTION public.zoho_list_pending_candidate_administrations(p_actor uuid,p_source_org text,p_before_at timestamptz DEFAULT NULL,p_before_request uuid DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE items jsonb; next_cursor jsonb;
BEGIN
 IF NOT public.zoho_is_active_import_approver(p_actor) OR p_source_org IS NULL OR p_source_org !~ '^[0-9]{1,40}$'
  OR (p_before_at IS NULL)<>(p_before_request IS NULL) THEN RETURN NULL; END IF;
 WITH page AS(SELECT o.* FROM public.zoho_candidate_administration_operations o JOIN public.zoho_candidate_administration_fences f
   ON f.pending_request_id=o.request_id WHERE f.source_org_id=p_source_org AND o.application_acknowledged_at IS NULL
   AND (p_before_at IS NULL OR (o.created_at,o.request_id)<(p_before_at,p_before_request)) ORDER BY o.created_at DESC,o.request_id DESC LIMIT 51),
 shown AS(SELECT * FROM page ORDER BY created_at DESC,request_id DESC LIMIT 50)
 SELECT coalesce((SELECT jsonb_agg(jsonb_build_object('requestId',request_id,'actorId',actor_id,'action',context->>'action','sourceOrgId',context->>'sourceOrgId',
  'externalId',context->>'externalId','targetId',context->>'targetId','administrationVersion',administration_version,'createdAt',created_at) ORDER BY created_at DESC,request_id DESC) FROM shown),'[]'),
 CASE WHEN (SELECT count(*) FROM page)>50 THEN (SELECT jsonb_build_object('createdAt',created_at,'requestId',request_id) FROM shown ORDER BY created_at,request_id LIMIT 1) END INTO items,next_cursor;
 RETURN jsonb_build_object('version',1,'sourceOrgId',p_source_org,'items',items,'nextCursor',next_cursor,'emailPolicy','forbidden');
END $$;
CREATE FUNCTION public.zoho_acknowledge_candidate_administration(p_actor uuid,p_request uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE operation public.zoho_candidate_administration_operations; fence public.zoho_candidate_administration_fences;
BEGIN
 IF NOT public.zoho_is_active_import_approver(p_actor) THEN RAISE EXCEPTION 'Administration authority unavailable' USING ERRCODE='22023'; END IF;
 PERFORM 1 FROM public.users a JOIN public.memberships m ON m.user_id=a.id JOIN public.membership_roles mr ON mr.membership_id=m.id JOIN public.roles r ON r.id=mr.role_id
 WHERE a.id=p_actor AND a.is_blocked IS FALSE AND m.status='active' AND m.org_id='00000000-0000-0000-0000-000000000001' AND r.name='super_admin' FOR SHARE OF a,m,mr,r;
 IF NOT FOUND THEN RAISE EXCEPTION 'Administration authority unavailable' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zoho-administration:'||p_request::text,0));
 SELECT * INTO operation FROM public.zoho_candidate_administration_operations WHERE request_id=p_request;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zoho-source:'||(operation.context->>'sourceOrgId')||':'||(operation.context->>'externalId'),0));
 SELECT * INTO STRICT fence FROM public.zoho_candidate_administration_fences WHERE source_org_id=operation.context->>'sourceOrgId' AND external_id=operation.context->>'externalId' FOR UPDATE;
 IF fence.latest_request_id IS DISTINCT FROM p_request OR fence.administration_version<>operation.administration_version THEN RAISE EXCEPTION 'Administration is no longer current' USING ERRCODE='40001'; END IF;
 UPDATE public.zoho_candidate_administration_operations SET application_acknowledged_at=coalesce(application_acknowledged_at,clock_timestamp()),application_acknowledged_by=coalesce(application_acknowledged_by,p_actor) WHERE request_id=p_request;
 UPDATE public.zoho_candidate_administration_fences SET pending_request_id=NULL,updated_at=clock_timestamp() WHERE source_org_id=fence.source_org_id AND external_id=fence.external_id AND pending_request_id=p_request;
 RETURN jsonb_build_object('version',1,'requestId',p_request,'administrationVersion',operation.administration_version,'acknowledged',true,'emailPolicy','forbidden');
END $$;
REVOKE ALL ON FUNCTION public.zoho_list_pending_candidate_administrations(uuid,text,timestamptz,uuid),public.zoho_acknowledge_candidate_administration(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_list_pending_candidate_administrations(uuid,text,timestamptz,uuid),public.zoho_acknowledge_candidate_administration(uuid,uuid) TO service_role;

-- Erasure-page enumeration recovers a committed operation, rather than granting
-- a new erase. A live administrator can finish a revoked original actor's work.
ALTER FUNCTION public.zoho_list_candidate_erased_operations(uuid,uuid,uuid) RENAME TO zoho_list_candidate_erased_operations_before_recovery;
CREATE FUNCTION public.zoho_list_candidate_erased_operations(p_actor uuid,p_request uuid,p_after uuid DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE operation public.zoho_candidate_administration_operations; result jsonb;
BEGIN
 IF NOT public.zoho_is_active_import_approver(p_actor) THEN RETURN NULL; END IF;
 SELECT * INTO operation FROM public.zoho_candidate_administration_operations WHERE request_id=p_request AND context->>'action'='erase_connector';
 IF NOT FOUND THEN RETURN NULL; END IF;
 -- The private legacy enumerator binds the original immutable approval actor;
 -- current recovery authority was verified above. No new canonical effect.
 result:=public.zoho_list_candidate_erased_operations_before_recovery(operation.actor_id,p_request,p_after);
 -- Its live-original-actor check cannot be used after that actor is revoked.
 IF result IS NULL THEN
  WITH refs AS(SELECT r.operation_id FROM public.zoho_candidate_receipts r JOIN public.zoho_candidate_erased_operations e ON e.operation_id=r.operation_id
   WHERE r.approved_context->>'sourceOrgId'=operation.context->>'sourceOrgId' AND r.approved_context->>'externalId'=operation.context->>'externalId'
   AND (p_after IS NULL OR r.operation_id>p_after) ORDER BY r.operation_id LIMIT 501)
  SELECT operation.receipt||jsonb_build_object('erasedOperationIds',coalesce((SELECT jsonb_agg(operation_id ORDER BY operation_id) FROM(SELECT operation_id FROM refs ORDER BY operation_id LIMIT 500) shown),'[]'),
   'moreErasedOperations',(SELECT count(*)>500 FROM refs)) INTO result;
 END IF;
 RETURN result||jsonb_build_object('administrationVersion',operation.administration_version,'approvalActorId',operation.actor_id,
  'currentAdministration',(public.zoho_current_administration_receipt(p_request)->>'currentAdministration')::boolean,
  'applicationAcknowledged',operation.application_acknowledged_at IS NOT NULL);
END $$;
REVOKE ALL ON FUNCTION public.zoho_list_candidate_erased_operations_before_recovery(uuid,uuid,uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.zoho_list_candidate_erased_operations(uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_list_candidate_erased_operations(uuid,uuid,uuid) TO service_role;
ALTER FUNCTION public.zoho_assert_private_identity_boundary() RENAME TO zoho_assert_private_identity_boundary_before_recovery;
CREATE FUNCTION public.zoho_assert_private_identity_boundary() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM public.zoho_assert_private_identity_boundary_before_recovery();
 IF EXISTS(WITH RECURSIVE protected(oid) AS(
  SELECT 'public.zoho_candidate_administration_fences'::regclass::oid
  UNION SELECT r.ev_class FROM protected p JOIN pg_depend d ON d.refobjid=p.oid AND d.refclassid='pg_class'::regclass
   AND d.classid='pg_rewrite'::regclass JOIN pg_rewrite r ON r.oid=d.objid WHERE r.ev_class<>p.oid)
  SELECT 1 FROM protected p CROSS JOIN(VALUES('anon'),('authenticated')) browser(role)
  WHERE has_table_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE,DELETE') OR has_any_column_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE')) THEN
  RAISE EXCEPTION 'Administration recovery requires private source fences' USING ERRCODE='42501'; END IF;
END $$;
REVOKE ALL ON FUNCTION public.zoho_assert_private_identity_boundary_before_recovery(),public.zoho_assert_private_identity_boundary() FROM PUBLIC,anon,authenticated,service_role;
ALTER FUNCTION public.zoho_candidate_runtime_ready() RENAME TO zoho_candidate_runtime_ready_before_recovery;
CREATE FUNCTION public.zoho_candidate_runtime_ready() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE signature text; function_oid oid;
BEGIN
 IF public.zoho_candidate_runtime_ready_before_recovery() IS DISTINCT FROM true THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM public.zoho_candidate_administration_operations WHERE administration_version=0) THEN RETURN false; END IF;
 PERFORM public.zoho_assert_private_identity_boundary();
 FOREACH signature IN ARRAY ARRAY['public.zoho_list_pending_candidate_administrations(uuid,text,timestamp with time zone,uuid)',
  'public.zoho_acknowledge_candidate_administration(uuid,uuid)'] LOOP
  function_oid:=to_regprocedure(signature);
  IF function_oid IS NULL OR NOT has_function_privilege('service_role',function_oid,'EXECUTE')
   OR has_function_privilege('anon',function_oid,'EXECUTE') OR has_function_privilege('authenticated',function_oid,'EXECUTE') THEN RETURN false; END IF;
 END LOOP;
 function_oid:=to_regprocedure('public.zoho_current_administration_receipt(uuid)');
 RETURN function_oid IS NOT NULL AND NOT has_function_privilege('service_role',function_oid,'EXECUTE')
  AND NOT has_function_privilege('anon',function_oid,'EXECUTE') AND NOT has_function_privilege('authenticated',function_oid,'EXECUTE');
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION public.zoho_candidate_runtime_ready_before_recovery(),public.zoho_candidate_runtime_ready() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.zoho_candidate_runtime_ready() TO service_role;
COMMIT;
