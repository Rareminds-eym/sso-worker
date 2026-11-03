DO $$
DECLARE saved_plan public.plans; g jsonb; committed jsonb; uid uuid; metadata jsonb; result jsonb;
  users_before bigint; operations_before bigint; outbox_before bigint;
BEGIN
  ASSERT public.zoho_candidate_runtime_ready();
  SELECT count(*) INTO users_before FROM public.users;
  SELECT count(*) INTO operations_before FROM public.zoho_candidate_receipts;
  SELECT count(*) INTO outbox_before FROM public.zoho_candidate_outbox;
  ASSERT public.zoho_candidate_runtime_ready();
  ASSERT (SELECT count(*)=users_before FROM public.users);
  ASSERT (SELECT count(*)=operations_before FROM public.zoho_candidate_receipts);
  ASSERT (SELECT count(*)=outbox_before FROM public.zoho_candidate_outbox);

  GRANT SELECT ON public.users TO anon;
  ASSERT NOT public.zoho_candidate_runtime_ready();
  REVOKE SELECT ON public.users FROM anon;
  GRANT SELECT ON public.zoho_candidate_outbox TO authenticated;
  ASSERT NOT public.zoho_candidate_runtime_ready();
  REVOKE SELECT ON public.zoho_candidate_outbox FROM authenticated;
  REVOKE EXECUTE ON FUNCTION public.zoho_confirm_candidate_projection(uuid,text,text,uuid) FROM service_role;
  ASSERT NOT public.zoho_candidate_runtime_ready();
  GRANT EXECUTE ON FUNCTION public.zoho_confirm_candidate_projection(uuid,text,text,uuid) TO service_role;
  SELECT * INTO saved_plan FROM public.plans WHERE plan_code='freemium';
  UPDATE public.plans SET is_active=false WHERE id=saved_plan.id;
  ASSERT NOT public.zoho_candidate_runtime_ready();
  UPDATE public.plans SET is_active=saved_plan.is_active WHERE id=saved_plan.id;
  ASSERT public.zoho_candidate_runtime_ready();
  ASSERT NOT has_function_privilege('anon','public.zoho_candidate_runtime_ready()','EXECUTE');
  ASSERT NOT has_function_privilege('authenticated','public.zoho_activate_candidate_oauth(uuid,text,text)','EXECUTE');
  ASSERT NOT has_function_privilege('anon','public.zoho_cleanup_candidate_reviews()','EXECUTE');
  UPDATE public.zoho_candidate_reviews SET expires_at=clock_timestamp()-interval '1 minute';
  PERFORM public.zoho_cleanup_candidate_reviews();
  ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_reviews WHERE expires_at<=clock_timestamp());

  g:=pg_temp.candidate_grant('oauth-activation@fixture.example','99101');
  committed:=public.zoho_provision_candidate(g); uid:=(committed->>'targetId')::uuid;
  ASSERT public.zoho_candidate_sync_policy(uid)->>'genericSyncAllowed'='false';
  UPDATE public.users SET user_metadata=user_metadata||'{"preferences":{"theme":"dark"},"careerContext":true}' WHERE id=uid;
  SELECT user_metadata INTO metadata FROM public.users WHERE id=uid;
  BEGIN
    PERFORM public.zoho_activate_candidate_oauth(uid,'verified-subject','oauth-activation@fixture.example');
    RAISE EXCEPTION 'Missing link accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
  ASSERT (SELECT NOT is_email_verified AND user_metadata=metadata FROM public.users WHERE id=uid);
  INSERT INTO public.oauth_accounts(user_id,provider,provider_user_id) VALUES(uid,'google','verified-subject');
  BEGIN
    PERFORM public.zoho_activate_candidate_oauth(uid,'verified-subject','different@fixture.example');
    RAISE EXCEPTION 'Wrong email accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
  UPDATE public.users SET is_blocked=true WHERE id=uid;
  BEGIN
    PERFORM public.zoho_activate_candidate_oauth(uid,'verified-subject','oauth-activation@fixture.example');
    RAISE EXCEPTION 'Blocked identity accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
  UPDATE public.users SET is_blocked=false WHERE id=uid;
  result:=public.zoho_activate_candidate_oauth(uid,'verified-subject','oauth-activation@fixture.example');
  ASSERT result->>'activated'='true' AND result->'userMetadata'=metadata-'activation_pending';
  ASSERT (SELECT is_email_verified AND password_hash='!zoho-import-no-password!' AND user_metadata=metadata-'activation_pending' FROM public.users WHERE id=uid);
  ASSERT (SELECT activation_state='existing_sign_in_preserved' AND state='projection_pending' FROM public.zoho_candidate_receipts WHERE operation_id=(g->>'operationId')::uuid);
  ASSERT (SELECT payload->>'activationState'='existing_sign_in_preserved' FROM public.zoho_candidate_outbox WHERE operation_id=(g->>'operationId')::uuid);
  ASSERT (SELECT count(*)=1 FROM public.subscriptions WHERE user_id=uid AND plan_code='freemium');
  ASSERT (SELECT count(*)=1 FROM public.memberships WHERE user_id=uid);
  -- A retry never creates a second grant, membership or identity.
  ASSERT public.zoho_activate_candidate_oauth(uid,'verified-subject','oauth-activation@fixture.example')->>'activated'='true';
  ASSERT public.zoho_candidate_sync_policy(uid)->>'genericSyncAllowed'='false';
  ASSERT NOT has_function_privilege('anon','public.zoho_candidate_sync_policy(uuid)','EXECUTE');
  ASSERT (SELECT count(*)=users_before+1 FROM public.users);
  DELETE FROM public.users WHERE id=uid;
END $$;
