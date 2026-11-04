-- Run in a disposable canonical fixture; no application seed or user data.
DO $$
DECLARE actor uuid:='10000000-0000-4000-8000-000000000001'; uid uuid:=gen_random_uuid(); sponsor uuid:=gen_random_uuid();
 teacher uuid:=gen_random_uuid(); membership uuid:=gen_random_uuid(); subscription uuid:=gen_random_uuid();
 ctx jsonb; review jsonb; result jsonb; g jsonb; original jsonb; paid_original jsonb; request uuid; op uuid; unrelated uuid;
 body jsonb; old_g jsonb; ids jsonb; source_review_context jsonb;
BEGIN
 INSERT INTO public.roles(id,name) VALUES(teacher,'teacher');
 INSERT INTO public.users(id,email,password_hash,is_email_verified,is_blocked,user_metadata)
 VALUES(uid,'teacher-context@fixture.example','existing-password',true,false,'{"role":"teacher","first_name":"Teacher","preferences":{"email":false}}');
 INSERT INTO public.memberships(id,user_id,org_id,status) VALUES(membership,uid,'00000000-0000-0000-0000-000000000001','active');
 INSERT INTO public.membership_roles(membership_id,role_id) VALUES(membership,teacher);
 SELECT to_jsonb(u) INTO original FROM public.users u WHERE id=uid;
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 ctx:=jsonb_build_object('action','establish_learner_context','sourceOrgId','1234','externalId','21001','targetId',uid,
   'reason','Explicit additional learner context and Discover baseline','emailPolicy','forbidden','acknowledgeIndependentDiscover',true);
 ASSERT public.zoho_preview_candidate_administration(actor,jsonb_set(ctx,'{acknowledgeIndependentDiscover}','false')) IS NULL;
 ASSERT public.zoho_preview_candidate_administration(actor,jsonb_set(ctx,'{targetId}',to_jsonb(actor))) IS NULL;
 ASSERT public.zoho_preview_candidate_administration(gen_random_uuid(),ctx) IS NULL;
 review:=public.zoho_preview_candidate_administration(actor,ctx);
 ASSERT review->'changes'->>'addIndependentLearnerContext'='true' AND review->'changes'->>'grantDiscover'='true';
 ASSERT review::text NOT LIKE '%existing-password%' AND review::text NOT LIKE '%preferences%';
 -- A live canonical drift invalidates both the source and administration review.
 UPDATE public.users SET user_metadata=user_metadata||'{"extra":false}' WHERE id=uid;
 BEGIN
   PERFORM public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',gen_random_uuid());
   RAISE EXCEPTION 'Stale administration review accepted';
 EXCEPTION WHEN serialization_failure THEN NULL; END;
 ASSERT NOT EXISTS(SELECT 1 FROM public.subscriptions WHERE user_id=uid);
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 review:=public.zoho_preview_candidate_administration(actor,ctx); request:=gen_random_uuid();
 SELECT to_jsonb(u) INTO original FROM public.users u WHERE id=uid;
 result:=public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',request);
 ASSERT result->>'state'='completed' AND result->>'canonicalAccountPreserved'='true';
 ASSERT public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',request)=result;
 ASSERT public.zoho_find_candidate_administration(actor,request)=result;
 ASSERT public.zoho_find_candidate_administration(gen_random_uuid(),request) IS NULL;
 ASSERT (SELECT to_jsonb(u)=original FROM public.users u WHERE id=uid);
 ASSERT (SELECT count(*)=2 FROM public.membership_roles WHERE membership_id=membership);
 ASSERT EXISTS(SELECT 1 FROM public.membership_roles WHERE membership_id=membership AND role_id=teacher);
 ASSERT (SELECT count(*)=1 FROM public.subscriptions WHERE user_id=uid AND plan_code='freemium' AND plan_amount=0 AND auto_renew IS FALSE);
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 result:=public.zoho_provision_candidate(g); op:=(g->>'operationId')::uuid;
 body:=(public.zoho_get_candidate_projection(op,g->>'sourceHash')->>'snapshot')::jsonb;
 ASSERT body->'user'->>'primaryRole'='teacher';
 ASSERT body->'learnerContext'->>'role'='learner' AND body->'learnerContext'->>'membershipId'=membership::text;
 ASSERT body->'learnerContext'->'source'='{"sourceOrgId":"1234","externalId":"21001"}';
 ASSERT body->'learnerContext'->'primaryContext'->>'role'='teacher' AND body->'learnerContext'->'primaryContext'->>'membershipId'=membership::text;
 UPDATE public.users SET user_metadata=jsonb_set(user_metadata,'{role}','"super_admin"') WHERE id=uid;
 ASSERT public.zoho_get_candidate_projection(op,g->>'sourceHash') IS NULL;
 SELECT context INTO source_review_context FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
 ASSERT public.zoho_candidate_review_snapshot(source_review_context)->>'decision'='blocked';
 ASSERT public.zoho_candidate_review_snapshot(source_review_context)->'blockers' @> '["primary_role_assignment_unavailable"]';
 ASSERT NOT public.zoho_verify_candidate_review(actor,source_review_context,g->>'candidateReviewHash');
 BEGIN
  PERFORM public.zoho_provision_candidate(fixture.candidate_grant('teacher-context@fixture.example','21009',uid));
  RAISE EXCEPTION 'Invalid primary metadata committed a stranded operation';
 EXCEPTION WHEN invalid_parameter_value OR serialization_failure THEN NULL; END;
 UPDATE public.users SET user_metadata=jsonb_set(user_metadata,'{role}','"teacher"') WHERE id=uid;
 ASSERT public.zoho_get_candidate_projection(op,g->>'sourceHash') IS NOT NULL;
 BEGIN
   PERFORM public.zoho_execute_candidate_administration(actor,jsonb_set(ctx,'{reason}','"Changed scope"'),review->>'reviewHash',request);
   RAISE EXCEPTION 'Conflicting administration retry accepted';
 EXCEPTION WHEN serialization_failure THEN NULL; END;

 -- Sponsorship is never changed. A separately acknowledged Discover baseline is additive.
 INSERT INTO public.organizations(id,name,slug) VALUES(sponsor,'Sponsor fixture','sponsor-context-fixture');
 INSERT INTO public.subscriptions(id,user_id,plan_id,organization_id,full_name,email,plan_code,plan_type,plan_amount,status,is_organization_subscription,is_bulk_purchase)
 VALUES(subscription,uid,'10000000-0000-4000-8000-000000000006',sponsor,'Teacher','teacher-context@fixture.example','freemium','Sponsored',200,'active',true,false);
 DELETE FROM public.subscriptions WHERE user_id=uid AND is_organization_subscription IS NOT TRUE;
 SELECT to_jsonb(s) INTO paid_original FROM public.subscriptions s WHERE id=subscription;
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 review:=public.zoho_preview_candidate_administration(actor,ctx);
 ASSERT review->'changes'->>'grantDiscover'='true' AND review->'changes'->>'addIndependentLearnerContext'='false';
 result:=public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',gen_random_uuid());
 ASSERT (SELECT to_jsonb(s)=paid_original FROM public.subscriptions s WHERE id=subscription);
 ASSERT (SELECT count(*)=1 FROM public.subscriptions WHERE user_id=uid AND is_organization_subscription IS NOT TRUE);
 -- A new review with current paid/personal access does not invent a second personal subscription.
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 review:=public.zoho_preview_candidate_administration(actor,ctx);
 ASSERT review->'changes'->>'grantDiscover'='false';
 PERFORM public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',gen_random_uuid());
 ASSERT (SELECT count(*)=2 FROM public.subscriptions WHERE user_id=uid);
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 review:=public.zoho_preview_candidate_administration(actor,ctx);
 UPDATE public.zoho_candidate_administration_reviews SET expires_at=clock_timestamp()-interval '1 second'
   WHERE actor_id=actor AND review_hash=review->>'reviewHash';
 BEGIN
  PERFORM public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',gen_random_uuid());
  RAISE EXCEPTION 'Expired administration review accepted';
 EXCEPTION WHEN serialization_failure THEN NULL; END;

 -- Connector-only erasure is source scoped and cannot erase the existing canonical account/access.
 g:=fixture.candidate_grant('teacher-context@fixture.example','21002',uid);
 PERFORM public.zoho_provision_candidate(g); unrelated:=(g->>'operationId')::uuid;
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 PERFORM public.zoho_provision_candidate(g); old_g:=g; op:=(g->>'operationId')::uuid;
 SELECT to_jsonb(u) INTO original FROM public.users u WHERE id=uid;
 ctx:=jsonb_build_object('action','erase_connector','sourceOrgId','1234','externalId','21001','targetId',uid,
   'reason','Explicit connector-only erasure request','emailPolicy','forbidden','acknowledgeIndependentDiscover',false);
 review:=public.zoho_preview_candidate_administration(actor,ctx); request:=gen_random_uuid();
 ASSERT review->'changes'->>'eraseConnectorPayloads'='true' AND review->'changes'->>'restoreOldData'='false';
 result:=public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',request);
 ASSERT result->>'scope'='connector_only' AND result->'erasedOperationIds' @> jsonb_build_array(op);
 ASSERT public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',request)=result;
 ASSERT public.zoho_get_candidate_projection(op,old_g->>'sourceHash') IS NULL;
 ASSERT public.zoho_find_candidate_receipt(op,old_g->>'sourceHash') IS NULL;
 ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_outbox WHERE operation_id=op);
 ASSERT EXISTS(SELECT 1 FROM public.zoho_candidate_outbox WHERE operation_id=unrelated);
 ASSERT (SELECT to_jsonb(u)=original FROM public.users u WHERE id=uid);
 ASSERT (SELECT to_jsonb(s)=paid_original FROM public.subscriptions s WHERE id=subscription);
 ASSERT (SELECT count(*)=2 FROM public.subscriptions WHERE user_id=uid);
 ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_reviews WHERE context->>'externalId'='21001');
 ids:=public.zoho_list_candidate_erased_operations(actor,request,NULL);
 ASSERT ids->'erasedOperationIds' @> jsonb_build_array(op) AND ids->>'moreErasedOperations'='false';
 ASSERT public.zoho_list_candidate_erased_operations(gen_random_uuid(),request,NULL) IS NULL;
 BEGIN
  PERFORM public.zoho_provision_candidate(old_g); RAISE EXCEPTION 'Erased operation replay accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 ASSERT (SELECT public.zoho_candidate_review_snapshot(context)->'blockers' @> '["connector_erasure_suppressed"]' FROM public.zoho_candidate_reviews
  WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash');
 -- Release requires separately reviewed human evidence; it never restores payloads/approvals/old operations.
 ctx:=jsonb_set(ctx,'{action}','"release_suppression"');
 review:=public.zoho_preview_candidate_administration(actor,ctx);
 ASSERT review->'changes'->>'releaseSourceSuppression'='true' AND review->'changes'->>'restoreOldData'='false';
 result:=public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',gen_random_uuid());
 ASSERT public.zoho_get_candidate_projection(op,old_g->>'sourceHash') IS NULL;
 BEGIN
  PERFORM public.zoho_provision_candidate(old_g); RAISE EXCEPTION 'Released suppression restored erased operation';
 EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001',uid);
 result:=public.zoho_provision_candidate(g);
 ASSERT result->>'targetId'=uid::text AND public.zoho_get_candidate_projection((g->>'operationId')::uuid,g->>'sourceHash') IS NOT NULL;
 ASSERT public.zoho_get_candidate_projection(op,old_g->>'sourceHash') IS NULL;
 ASSERT (SELECT bool_and(NOT relrowsecurity) FROM pg_class WHERE oid IN('public.zoho_candidate_suppressions'::regclass,'public.zoho_candidate_administration_operations'::regclass));
 ASSERT NOT has_table_privilege('service_role','public.zoho_candidate_suppressions','SELECT');
 ASSERT NOT has_function_privilege('anon','public.zoho_execute_candidate_administration(uuid,jsonb,text,uuid)','EXECUTE');
 ASSERT NOT has_function_privilege('authenticated','public.zoho_preview_candidate_administration(uuid,jsonb)','EXECUTE');
 ASSERT NOT has_function_privilege('service_role','public.zoho_provision_candidate_before_administration(jsonb)','EXECUTE');
 -- A later whole-account deletion cannot cascade away the connector suppression.
 ctx:=jsonb_set(ctx,'{action}','"erase_connector"');
 review:=public.zoho_preview_candidate_administration(actor,ctx);
 PERFORM public.zoho_execute_candidate_administration(actor,ctx,review->>'reviewHash',gen_random_uuid());
 DELETE FROM public.users WHERE id=uid;
 ASSERT EXISTS(SELECT 1 FROM public.zoho_candidate_suppressions WHERE source_org_id='1234' AND external_id='21001' AND released_at IS NULL);
 g:=fixture.candidate_grant('teacher-context@fixture.example','21001');
 ASSERT (SELECT public.zoho_candidate_review_snapshot(context)->'blockers' @> '["connector_erasure_suppressed"]' FROM public.zoho_candidate_reviews
   WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash');
END $$;
