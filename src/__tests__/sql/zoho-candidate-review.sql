-- Entire fixture is synthetic and rolled back by its disposable-database runner.
DO $$
DECLARE g jsonb; ctx jsonb; reviewed jsonb; changed jsonb; result jsonb; uid uuid;
  actor uuid:='10000000-0000-4000-8000-000000000001'; original jsonb; op uuid; unrelated uuid:=gen_random_uuid();
BEGIN
  g:=pg_temp.candidate_grant('review-candidate@fixture.example','9001');
  SELECT context INTO STRICT ctx FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  reviewed:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT reviewed->>'decision'='create' AND reviewed->'identity'->>'activationState'='activation_pending';
  ASSERT reviewed->'identity'->'targetId'='null'::jsonb AND reviewed->'targetId'='null'::jsonb;
  ASSERT reviewed->'entitlements'->>'action'='grant_discover' AND reviewed->'entitlements'->'planCodes'='["freemium"]';
  ASSERT public.zoho_verify_candidate_review(actor,ctx,reviewed->>'reviewHash');
  ASSERT NOT public.zoho_verify_candidate_review(gen_random_uuid(),ctx,reviewed->>'reviewHash');
  ASSERT NOT public.zoho_verify_candidate_review(actor,jsonb_set(ctx,'{revision}','2'),reviewed->>'reviewHash');
  ASSERT NOT public.zoho_verify_candidate_review(actor,ctx,repeat('a',64));
  ASSERT public.zoho_candidate_review_snapshot(jsonb_set(ctx,'{revision}','null')) IS NULL;
  ASSERT reviewed::text NOT LIKE '%password%' AND reviewed::text NOT LIKE '%user_metadata%';
  -- Review is source/config/target bound and canonical catalog drift invalidates execution.
  PERFORM pg_temp.assert_candidate_denied(g-'candidateReviewHash');
  PERFORM pg_temp.assert_candidate_denied(jsonb_set(g,'{candidateReviewHash}',to_jsonb(repeat('a',64))));
  UPDATE public.plans SET pricing_matrix='{"all":{"monthly":5,"yearly":0}}' WHERE plan_code='freemium';
  ASSERT NOT public.zoho_verify_candidate_review(actor,ctx,reviewed->>'reviewHash');
  PERFORM pg_temp.assert_candidate_denied(g);
  UPDATE public.plans SET pricing_matrix='{"all":{"monthly":0,"yearly":0}}' WHERE plan_code='freemium';
  -- A new human preview observes the current state; the old hash is not silently rebased.
  g:=pg_temp.candidate_grant('review-candidate@fixture.example','9001');
  result:=public.zoho_provision_candidate(g); uid:=(result->>'targetId')::uuid; op:=(g->>'operationId')::uuid;
  ASSERT public.zoho_provision_candidate(g)=result; -- replay after own canonical mutation remains idempotent
  SELECT to_jsonb(u) INTO original FROM public.users u WHERE id=uid;
  -- A null staged target can explicitly review an existing match without claiming a new identity.
  g:=pg_temp.candidate_grant('review-candidate@fixture.example','9002');
  SELECT context INTO STRICT ctx FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  reviewed:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT reviewed->>'decision'='preserve_existing' AND reviewed->'identity'->>'targetId'=uid::text;
  ASSERT reviewed->'targetId'='null'::jsonb;
  ASSERT reviewed->'identity'->>'activationState'='activation_pending';
  ASSERT reviewed->'entitlements'->>'action'='preserve';
  result:=public.zoho_provision_candidate(g);
  ASSERT result->>'identityOutcome'='existing_access_preserved' AND result->>'activationState'='activation_pending';
  ASSERT (SELECT to_jsonb(u)=original FROM public.users u WHERE id=uid);
  -- Existing preferences, paid/org access and credentials never get rewritten; drift requires re-review.
  g:=pg_temp.candidate_grant('review-candidate@fixture.example','9003');
  UPDATE public.users SET user_metadata=user_metadata||'{"preference":false}'::jsonb WHERE id=uid;
  PERFORM pg_temp.assert_candidate_denied(g);
  g:=pg_temp.candidate_grant('review-candidate@fixture.example','9004');
  UPDATE public.subscriptions SET features=features||'["synthetic_feature"]'::jsonb WHERE user_id=uid;
  PERFORM pg_temp.assert_candidate_denied(g);
  -- Changes to an unrelated plan do not invalidate this user's preservation review.
  g:=pg_temp.candidate_grant('review-candidate@fixture.example','9005');
  INSERT INTO public.plans(id,plan_code,name,business_type,applicable_entities,pricing_matrix,base_features,product_id)
    VALUES(unrelated,'unrelated_review_plan','Unrelated','b2c','{all}','{}','[]','10000000-0000-4000-8000-000000000002');
  result:=public.zoho_provision_candidate(g);
  ASSERT result->>'targetId'=uid::text;
  DELETE FROM public.plans WHERE id=unrelated;
  -- Existing organization-only sponsorship and missing product context stay blocked, not overwritten by Discover.
  SELECT context INTO STRICT ctx FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  UPDATE public.subscriptions SET is_organization_subscription=true WHERE user_id=uid;
  reviewed:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT reviewed->>'decision'='blocked' AND reviewed->'blockers' @> '["personal_entitlement_requires_review"]';
  UPDATE public.subscriptions SET is_organization_subscription=false WHERE user_id=uid;
  UPDATE public.users SET is_blocked=true WHERE id=uid;
  reviewed:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT reviewed->>'decision'='blocked' AND reviewed->'blockers' @> '["account_blocked"]';
  DELETE FROM public.users WHERE id=uid;
  -- Expired previews cannot register a new human authorization.
  g:=pg_temp.candidate_grant('review-expired@fixture.example','9006');
  SELECT context INTO STRICT ctx FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  UPDATE public.zoho_candidate_reviews SET expires_at=clock_timestamp()-interval '1 second' WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  ASSERT NOT public.zoho_verify_candidate_review(actor,ctx,g->>'candidateReviewHash');
  ASSERT NOT has_table_privilege('service_role','public.zoho_candidate_reviews','SELECT');
  ASSERT NOT has_function_privilege('anon','public.zoho_preview_candidate_review(uuid,jsonb)','EXECUTE');
  ASSERT NOT has_function_privilege('authenticated','public.zoho_verify_candidate_review(uuid,jsonb,text)','EXECUTE');
  ASSERT NOT has_function_privilege('service_role','public.zoho_candidate_review_snapshot(jsonb)','EXECUTE');
END $$;
