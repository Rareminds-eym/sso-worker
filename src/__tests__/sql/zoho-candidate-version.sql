-- Real baseline timestamp triggers are loaded by the runner. NULL is inserted,
-- never manufactured through UPDATE (the actual update trigger supplies a date).
DO $$
DECLARE saved_plan jsonb; g jsonb; blocked_grant jsonb; ctx jsonb; preview jsonb; result jsonb;
  uid uuid; before_user jsonb; bad_subscription uuid:=gen_random_uuid(); bad_plan uuid:=gen_random_uuid();
  actor uuid:='10000000-0000-4000-8000-000000000001';
BEGIN
  ASSERT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.plans'::regclass AND tgname='trg_plans_updated_at' AND tgenabled='O');
  ASSERT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.subscriptions'::regclass AND tgname='trg_subscriptions_updated_at' AND tgenabled='O');
  -- Hold a valid create intent, then encounter a legitimately inserted NULL-version
  -- Discover catalog row. No users depend on this synthetic catalog yet.
  g:=pg_temp.candidate_grant('version-discover@fixture.example','9101');
  SELECT to_jsonb(p) INTO STRICT saved_plan FROM public.plans p WHERE plan_code='freemium';
  DELETE FROM public.plans WHERE plan_code='freemium';
  INSERT INTO public.plans SELECT * FROM jsonb_populate_record(NULL::public.plans,saved_plan||'{"updated_at":null}'::jsonb);
  ASSERT (SELECT updated_at IS NULL FROM public.plans WHERE plan_code='freemium');
  SELECT context INTO STRICT ctx FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  preview:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT preview->>'decision'='blocked' AND preview->'blockers' @> '["discover_plan_version_unavailable"]';
  ASSERT NOT public.zoho_verify_candidate_review(actor,ctx,g->>'candidateReviewHash');
  PERFORM pg_temp.assert_candidate_denied(g); -- approved proof is stale before creation
  blocked_grant:=pg_temp.candidate_grant('version-discover-blocked@fixture.example','9102');
  PERFORM pg_temp.assert_candidate_denied(blocked_grant); -- cannot approve a new blocked preview
  ASSERT NOT EXISTS(SELECT 1 FROM public.users WHERE email IN ('version-discover@fixture.example','version-discover-blocked@fixture.example'));
  ASSERT (SELECT updated_at IS NULL FROM public.plans WHERE plan_code='freemium'); -- no import repair
  -- Restore only this synthetic catalog fixture, preserving the original real version.
  DELETE FROM public.plans WHERE plan_code='freemium';
  INSERT INTO public.plans SELECT * FROM jsonb_populate_record(NULL::public.plans,saved_plan);

  g:=pg_temp.candidate_grant('version-existing@fixture.example','9103');
  result:=public.zoho_provision_candidate(g); uid:=(result->>'targetId')::uuid;
  SELECT to_jsonb(u) INTO STRICT before_user FROM public.users u WHERE id=uid;
  g:=pg_temp.candidate_grant('version-existing@fixture.example','9104');
  -- A cancelled historical row does not replace the valid active personal plan.
  -- Explicit NULL survives actual BEFORE INSERT guards, unlike a NULL UPDATE.
  INSERT INTO public.subscriptions(id,user_id,plan_id,plan_code,plan_type,plan_amount,billing_cycle,features,status,
    is_organization_subscription,is_bulk_purchase,product_id,updated_at)
  VALUES(bad_subscription,uid,(saved_plan->>'id')::uuid,'freemium','Discover',0,'lifetime','[]','cancelled',
    false,false,(saved_plan->>'product_id')::uuid,NULL);
  ASSERT (SELECT updated_at IS NULL FROM public.subscriptions WHERE id=bad_subscription);
  SELECT context INTO STRICT ctx FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  preview:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT preview->>'decision'='blocked' AND preview->'blockers' @> '["projection_versions_unavailable"]';
  ASSERT NOT public.zoho_verify_candidate_review(actor,ctx,g->>'candidateReviewHash');
  PERFORM pg_temp.assert_candidate_denied(g);
  blocked_grant:=pg_temp.candidate_grant('version-existing@fixture.example','9105');
  PERFORM pg_temp.assert_candidate_denied(blocked_grant);
  ASSERT (SELECT to_jsonb(u)=before_user FROM public.users u WHERE id=uid);
  ASSERT (SELECT updated_at IS NULL FROM public.subscriptions WHERE id=bad_subscription);
  DELETE FROM public.subscriptions WHERE id=bad_subscription;

  -- Valid row versions are not enough if the historical row references a plan
  -- whose own nullable canonical version has never been initialized.
  g:=pg_temp.candidate_grant('version-existing@fixture.example','9106');
  INSERT INTO public.plans(id,plan_code,name,business_type,applicable_entities,pricing_matrix,base_features,product_id,updated_at)
    VALUES(bad_plan,'version_history_fixture','Historical fixture','b2c','{all}','{}','[]',(saved_plan->>'product_id')::uuid,NULL);
  INSERT INTO public.subscriptions(id,user_id,plan_id,plan_code,plan_type,plan_amount,billing_cycle,features,status,
    is_organization_subscription,is_bulk_purchase,product_id)
    VALUES(bad_subscription,uid,bad_plan,'version_history_fixture','Historical fixture',0,'lifetime','[]','cancelled',false,false,(saved_plan->>'product_id')::uuid);
  ASSERT (SELECT updated_at IS NOT NULL FROM public.subscriptions WHERE id=bad_subscription);
  ASSERT (SELECT updated_at IS NULL FROM public.plans WHERE id=bad_plan);
  SELECT context INTO STRICT ctx FROM public.zoho_candidate_reviews WHERE actor_id=actor AND review_hash=g->>'candidateReviewHash';
  preview:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT preview->>'decision'='blocked' AND preview->'blockers' @> '["projection_versions_unavailable"]';
  PERFORM pg_temp.assert_candidate_denied(g);
  ASSERT (SELECT to_jsonb(u)=before_user FROM public.users u WHERE id=uid);
  ASSERT (SELECT updated_at IS NULL FROM public.plans WHERE id=bad_plan);
  DELETE FROM public.subscriptions WHERE id=bad_subscription;
  DELETE FROM public.plans WHERE id=bad_plan;
  -- Removing the invalid history makes a fresh explicit review eligible; old
  -- approved proof is never silently rewritten by the import.
  preview:=public.zoho_preview_candidate_review(actor,ctx);
  ASSERT preview->>'decision'='preserve_existing';
  DELETE FROM public.users WHERE id=uid;
END $$;
