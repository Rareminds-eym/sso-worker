DO $$
DECLARE g jsonb; result jsonb; op uuid; uid uuid; snapshot jsonb; old_snapshot jsonb; body jsonb; publications jsonb;
  lease uuid:=gen_random_uuid(); premium uuid:=gen_random_uuid(); receipt uuid:=gen_random_uuid(); i integer;
BEGIN
  g:=pg_temp.candidate_grant('delivery@fixture.example','801');
  result:=public.zoho_provision_candidate(g); op:=(g->>'operationId')::uuid; uid:=(result->>'targetId')::uuid;
  snapshot:=public.zoho_get_candidate_projection(op,g->>'sourceHash');
  ASSERT snapshot->>'operationId'=op::text AND snapshot->>'targetId'=uid::text;
  ASSERT snapshot->>'projectionHash'=encode(sha256(convert_to(snapshot->>'snapshot','UTF8')),'hex');
  body:=(snapshot->>'snapshot')::jsonb;
  ASSERT body->>'emailPolicy'='forbidden' AND body->'user'->>'primaryRole'='learner';
  ASSERT body->'subscriptions'->0->>'plan_code'='freemium';
  ASSERT snapshot::text NOT LIKE '%password%' AND snapshot::text NOT LIKE '%refresh_token%';
  ASSERT public.zoho_get_candidate_projection(op,repeat('b',64)) IS NULL;
  publications:=public.zoho_reserve_candidate_deliveries(lease);
  ASSERT jsonb_array_length(publications)=1 AND publications->0->>'operationId'=op::text;
  ASSERT NOT publications->0 ? 'payload' AND NOT publications->0 ? 'email';
  ASSERT public.zoho_reserve_candidate_deliveries(gen_random_uuid())='[]'::jsonb;
  ASSERT NOT public.zoho_record_candidate_publication(op,gen_random_uuid(),true);
  ASSERT public.zoho_record_candidate_publication(op,lease,true);
  ASSERT (SELECT state='projection_pending' FROM public.zoho_candidate_receipts WHERE operation_id=op);
  ASSERT (SELECT published_at IS NOT NULL AND delivered_at IS NULL FROM public.zoho_candidate_outbox WHERE operation_id=op);
  FOR i IN 2..8 LOOP
    UPDATE public.zoho_candidate_outbox SET next_attempt_at=now()-interval '1 second' WHERE operation_id=op;
    lease:=gen_random_uuid();
    ASSERT jsonb_array_length(public.zoho_reserve_candidate_deliveries(lease))=1;
    ASSERT public.zoho_record_candidate_publication(op,lease,false);
  END LOOP;
  UPDATE public.zoho_candidate_outbox SET next_attempt_at=now()-interval '1 second' WHERE operation_id=op;
  ASSERT public.zoho_reserve_candidate_deliveries(gen_random_uuid())='[]'::jsonb;
  ASSERT (SELECT publication_attempts=8 AND last_error='PUBLICATION_FAILED' AND delivered_at IS NULL FROM public.zoho_candidate_outbox WHERE operation_id=op);
  old_snapshot:=snapshot;
  -- A delayed reference reads the current paid state, including cancellation of the old free row.
  INSERT INTO public.plans(id,plan_code,name,business_type,applicable_entities,pricing_matrix,base_features,product_id)
    VALUES(premium,'delivery_paid_fixture','Paid fixture','b2c','{all}','{"all":{"monthly":100.50}}','["paid_feature"]','10000000-0000-4000-8000-000000000002');
  UPDATE public.subscriptions SET status='cancelled',updated_at=clock_timestamp() WHERE user_id=uid;
  INSERT INTO public.subscriptions(user_id,plan_id,plan_code,plan_type,plan_amount,billing_cycle,features,status,is_organization_subscription,is_bulk_purchase,product_id)
    VALUES(uid,premium,'delivery_paid_fixture','Paid fixture',100.50,'monthly','["paid_feature"]','active',false,false,'10000000-0000-4000-8000-000000000002');
  UPDATE public.users SET user_metadata=user_metadata||'{"temporary_password":"never-project-me"}' WHERE id=uid;
  snapshot:=public.zoho_get_candidate_projection(op,g->>'sourceHash');
  ASSERT snapshot->>'projectionHash'<>old_snapshot->>'projectionHash';
  ASSERT snapshot::text NOT LIKE '%never-project-me%';
  body:=(snapshot->>'snapshot')::jsonb;
  ASSERT jsonb_array_length(body->'subscriptions')=2;
  ASSERT EXISTS(SELECT 1 FROM jsonb_array_elements(body->'subscriptions') s WHERE s->>'plan_code'='delivery_paid_fixture' AND s->>'status'='active');
  BEGIN
    PERFORM public.zoho_confirm_candidate_projection(op,g->>'sourceHash',old_snapshot->>'projectionHash',receipt);
    RAISE EXCEPTION 'Stale canonical snapshot confirmed';
  EXCEPTION WHEN serialization_failure THEN NULL; END;
  ASSERT (SELECT state='projection_pending' FROM public.zoho_candidate_receipts WHERE operation_id=op);
  -- The private entrypoint separately requires independent application postcondition proof.
  -- This DB-owner fixture checks only the final canonical hash/receipt transition.
  result:=public.zoho_confirm_candidate_projection(op,g->>'sourceHash',snapshot->>'projectionHash',receipt);
  ASSERT result->>'state'='completed' AND result->>'operationId'=op::text;
  ASSERT (SELECT projection_receipt_id=receipt AND confirmed_projection_hash=snapshot->>'projectionHash' FROM public.zoho_candidate_receipts WHERE operation_id=op);
  ASSERT (SELECT delivered_at IS NOT NULL AND last_error IS NULL FROM public.zoho_candidate_outbox WHERE operation_id=op);
  ASSERT public.zoho_reserve_candidate_deliveries(gen_random_uuid())='[]'::jsonb;
  ASSERT NOT has_function_privilege('anon','public.zoho_get_candidate_projection(uuid,text)','EXECUTE');
  ASSERT NOT has_function_privilege('authenticated','public.zoho_confirm_candidate_projection(uuid,text,text,uuid)','EXECUTE');
  ASSERT NOT has_table_privilege('service_role','public.zoho_candidate_outbox','UPDATE');
END $$;
