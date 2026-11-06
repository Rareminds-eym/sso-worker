DO $$
DECLARE actor uuid:='10000000-0000-4000-8000-000000000001'; recovery_actor uuid:=gen_random_uuid(); membership uuid:=gen_random_uuid();
 g jsonb; uid uuid; ctx jsonb; release_ctx jsonb; review jsonb; erased jsonb; released jsonb; newest jsonb; page jsonb; listing jsonb;
 request uuid:=gen_random_uuid(); release_request uuid:=gen_random_uuid(); last_request uuid:=gen_random_uuid(); cursor uuid; i integer; fake_request uuid;
BEGIN
 INSERT INTO public.users(id,email,password_hash,is_email_verified,is_blocked,user_metadata) VALUES(recovery_actor,'recovery-admin@fixture.invalid','synthetic',true,false,'{}');
 INSERT INTO public.memberships(id,user_id,org_id,status) VALUES(membership,recovery_actor,'00000000-0000-0000-0000-000000000001','active');
 INSERT INTO public.membership_roles(membership_id,role_id) SELECT membership,id FROM public.roles WHERE name='super_admin';
 g:=fixture.candidate_grant('administration-recovery@fixture.invalid','281001',NULL);
 uid:=(public.zoho_provision_candidate(g)->>'targetId')::uuid;
 -- More than one erasure page; these are synthetic receipt references only.
 INSERT INTO public.zoho_candidate_receipts(operation_id,connection_id,record_id,record_revision,approved_context,source_hash,user_id,identity_outcome,activation_state)
 SELECT gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,r.approved_context,r.source_hash,uid,'existing_access_preserved','existing_sign_in_preserved'
 FROM public.zoho_candidate_receipts r CROSS JOIN generate_series(1,501) WHERE r.operation_id=(g->>'operationId')::uuid;
 ctx:=jsonb_build_object('action','erase_connector','sourceOrgId','1234','externalId','281001','targetId',uid,'reason','Explicit privacy recovery fixture','emailPolicy','forbidden','acknowledgeIndependentDiscover',false);
 review:=public.zoho_preview_candidate_administration(actor,ctx);
 erased:=public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',request);
 ASSERT erased->>'administrationVersion'='1' AND erased->>'currentAdministration'='true' AND erased->>'applicationAcknowledged'='false';
 ASSERT public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',request)=erased;
 release_ctx:=jsonb_set(ctx,'{action}','"release_suppression"');
 ASSERT public.zoho_preview_candidate_administration(actor,release_ctx) IS NULL;
 BEGIN PERFORM public.zoho_execute_candidate_administration(actor,release_ctx,repeat('a',64),release_request); RAISE EXCEPTION 'Unconfirmed erase overtaken'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 -- Commit-before-response-loss and original actor revocation are recoverable by
 -- a different CURRENT administrator, preserving the original approval actor.
 UPDATE public.memberships SET status='inactive' WHERE user_id=actor AND org_id='00000000-0000-0000-0000-000000000001';
 ASSERT public.zoho_find_candidate_administration(actor,request) IS NULL;
 ASSERT public.zoho_find_candidate_administration(recovery_actor,request)->>'approvalActorId'=actor::text;
 listing:=public.zoho_list_pending_candidate_administrations(recovery_actor,'1234',NULL,NULL);
 ASSERT listing->'items' @> jsonb_build_array(jsonb_build_object('requestId',request));
 page:=public.zoho_list_candidate_erased_operations(recovery_actor,request,NULL);
 ASSERT jsonb_array_length(page->'erasedOperationIds')=500 AND page->>'moreErasedOperations'='true' AND page->>'administrationVersion'='1';
 cursor:=(page->'erasedOperationIds'->>499)::uuid;
 page:=public.zoho_list_candidate_erased_operations(recovery_actor,request,cursor);
 ASSERT jsonb_array_length(page->'erasedOperationIds')=2 AND page->>'moreErasedOperations'='false';
 ASSERT public.zoho_acknowledge_candidate_administration(recovery_actor,request)->>'acknowledged'='true';
 ASSERT public.zoho_acknowledge_candidate_administration(recovery_actor,request)->>'acknowledged'='true';
 ASSERT (SELECT actor_id=actor AND application_acknowledged_by=recovery_actor FROM public.zoho_candidate_administration_operations WHERE request_id=request);
 review:=public.zoho_preview_candidate_administration(recovery_actor,release_ctx);
 released:=public.zoho_execute_candidate_administration(recovery_actor,release_ctx,review->>'reviewHash',release_request);
 ASSERT released->>'administrationVersion'='2';
 ASSERT public.zoho_find_candidate_administration(recovery_actor,request)->>'currentAdministration'='false';
 ASSERT public.zoho_list_candidate_erased_operations(recovery_actor,request,NULL)->>'currentAdministration'='false';
 BEGIN PERFORM public.zoho_acknowledge_candidate_administration(recovery_actor,request); RAISE EXCEPTION 'Historical ACK accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 -- Opposite direction: erase cannot overtake a pending release either.
 ASSERT public.zoho_preview_candidate_administration(recovery_actor,ctx) IS NULL;
 BEGIN PERFORM public.zoho_execute_candidate_administration(recovery_actor,ctx,repeat('a',64),last_request); RAISE EXCEPTION 'Unconfirmed release overtaken'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 PERFORM public.zoho_acknowledge_candidate_administration(recovery_actor,release_request);
 review:=public.zoho_preview_candidate_administration(recovery_actor,ctx);
 newest:=public.zoho_execute_candidate_administration(recovery_actor,ctx,review->>'reviewHash',last_request);
 ASSERT newest->>'administrationVersion'='3';
 PERFORM public.zoho_acknowledge_candidate_administration(recovery_actor,last_request);
 ASSERT public.zoho_find_candidate_administration(recovery_actor,release_request)->>'currentAdministration'='false';
 UPDATE public.memberships SET status='inactive' WHERE id=membership;
 ASSERT public.zoho_list_pending_candidate_administrations(recovery_actor,'1234',NULL,NULL) IS NULL;
 BEGIN PERFORM public.zoho_acknowledge_candidate_administration(recovery_actor,last_request); RAISE EXCEPTION 'Revoked recovering actor accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
 UPDATE public.memberships SET status='active' WHERE id=membership;
 -- Minimal bounded keyset discovery cannot truncate older pending sources.
 FOR i IN 1..51 LOOP
  fake_request:=gen_random_uuid();
  INSERT INTO public.zoho_candidate_administration_operations(request_id,actor_id,context,review_hash,receipt,administration_version)
   VALUES(fake_request,actor,jsonb_set(ctx,'{externalId}',to_jsonb((282000+i)::text)),repeat('b',64),'{}',1);
  INSERT INTO public.zoho_candidate_administration_fences(source_org_id,external_id,administration_version,latest_request_id,pending_request_id)
   VALUES('1234',(282000+i)::text,1,fake_request,fake_request);
 END LOOP;
 listing:=public.zoho_list_pending_candidate_administrations(recovery_actor,'1234',NULL,NULL);
 ASSERT jsonb_array_length(listing->'items')=50 AND listing->'nextCursor'<>'null'::jsonb;
 ASSERT listing::text NOT LIKE '%reason%' AND listing::text NOT LIKE '%password%';
 listing:=public.zoho_list_pending_candidate_administrations(recovery_actor,'1234',(listing#>>'{nextCursor,createdAt}')::timestamptz,(listing#>>'{nextCursor,requestId}')::uuid);
 ASSERT jsonb_array_length(listing->'items')=1 AND listing->'nextCursor'='null'::jsonb;
 ASSERT public.zoho_list_pending_candidate_administrations(recovery_actor,'bad',NULL,NULL) IS NULL;
 ASSERT NOT has_table_privilege('anon','public.zoho_candidate_administration_fences','SELECT');
 ASSERT NOT has_function_privilege('service_role','public.zoho_current_administration_receipt(uuid)','EXECUTE');
 ASSERT has_function_privilege('service_role','public.zoho_acknowledge_candidate_administration(uuid,uuid)','EXECUTE');
 GRANT SELECT ON public.zoho_candidate_administration_fences TO anon;
 BEGIN
  PERFORM public.zoho_assert_private_identity_boundary();
  RAISE EXCEPTION 'Browser-readable canonical recovery accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 ASSERT public.zoho_candidate_runtime_ready() IS FALSE;
 REVOKE SELECT ON public.zoho_candidate_administration_fences FROM anon;
END $$;
