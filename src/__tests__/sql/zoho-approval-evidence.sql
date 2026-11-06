DO $$
DECLARE actor uuid:=gen_random_uuid(); membership uuid:=gen_random_uuid(); role uuid:=gen_random_uuid();
  connection uuid:=gen_random_uuid(); record uuid:=gen_random_uuid(); request uuid:=gen_random_uuid();
  publisher uuid:=gen_random_uuid(); manifest jsonb; grant_value jsonb; expiry timestamptz; key text;
  data jsonb:='{"email":"fixture@example.com","name":"Fixture"}'; source_hash text;
BEGIN
  INSERT INTO public.users(id,is_blocked) VALUES(actor,false);
  INSERT INTO public.memberships(id,user_id,org_id,status) VALUES(membership,actor,'00000000-0000-0000-0000-000000000001','active');
  INSERT INTO public.roles(id,name) VALUES(role,'super_admin');
  INSERT INTO public.membership_roles(membership_id,role_id) VALUES(membership,role);
  source_hash:=encode(sha256(convert_to(data::text,'UTF8')),'hex');
  manifest:=jsonb_build_object('requestId',request,'connectionId',connection,'sourceOrgId','123','publisherOrganizationId',publisher,
    'configRevision',1,'reason','Reviewed fixture','emailPolicy','forbidden','items',jsonb_build_array(jsonb_build_object(
      'recordId',record,'revision',1,'sourceHash',source_hash,'module','Candidates','externalId','456','targetId',NULL)));
  ASSERT public.zoho_record_import_approval(actor,manifest);
  SELECT expires_at INTO expiry FROM public.zoho_import_approvals WHERE connection_id=connection;
  ASSERT public.zoho_record_import_approval(actor,manifest);
  ASSERT (SELECT count(*)=1 AND min(expires_at)=expiry FROM public.zoho_import_approvals WHERE connection_id=connection);
  ASSERT NOT public.zoho_record_import_approval(actor,jsonb_set(manifest,'{reason}','"Different reason"'));
  ASSERT NOT public.zoho_record_import_approval(actor,jsonb_set(manifest,'{items}',(manifest->'items')||(manifest->'items')));
  grant_value:=jsonb_build_object('claimed',true,'operationId',gen_random_uuid(),'lease',gen_random_uuid(),
    'leaseExpiresAt',now()+interval '5 minutes','actorId',actor,'connectionId',connection,'sourceOrgId','123',
    'publisherOrganizationId',publisher,'recordId',record,'revision',1,'configRevision',1,'sourceHash',source_hash,
    'action','provision_candidate','module','Candidates','externalId','456','targetId',NULL,'emailPolicy','forbidden','data',data);
  ASSERT public.zoho_validate_import_approval(grant_value);
  FOREACH key IN ARRAY ARRAY['operationId','lease','leaseExpiresAt','actorId','connectionId','sourceOrgId','publisherOrganizationId','recordId','revision','configRevision','sourceHash','action','module','externalId','emailPolicy','targetId','claimed','data'] LOOP
    ASSERT NOT public.zoho_validate_import_approval(grant_value-key), 'missing field accepted: '||key;
  END LOOP;
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{data,name}','"Tampered"'));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{targetId}',to_jsonb(publisher)));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{connectionId}',to_jsonb(publisher)));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{sourceOrgId}','"999"'));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{publisherOrganizationId}',to_jsonb(connection)));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{configRevision}','2'));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{revision}','2'));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{action}','"apply_job"'));
  ASSERT NOT public.zoho_validate_import_approval(jsonb_set(grant_value,'{leaseExpiresAt}',to_jsonb(now()-interval '1 second')));
  UPDATE public.users SET is_blocked=true WHERE id=actor;
  ASSERT NOT public.zoho_validate_import_approval(grant_value);
  ASSERT NOT public.zoho_record_import_approval(actor,manifest);
  UPDATE public.users SET is_blocked=false WHERE id=actor;
  UPDATE public.zoho_import_approvals SET revoked_at=now() WHERE connection_id=connection;
  ASSERT NOT public.zoho_validate_import_approval(grant_value);
  ASSERT NOT public.zoho_record_import_approval(actor,manifest);
  UPDATE public.zoho_import_approvals SET revoked_at=NULL,expires_at=now()-interval '1 second' WHERE connection_id=connection;
  ASSERT NOT public.zoho_validate_import_approval(grant_value);
  ASSERT NOT public.zoho_record_import_approval(actor,manifest);
  ASSERT NOT has_table_privilege('service_role','public.zoho_import_approvals','INSERT');
  ASSERT NOT has_table_privilege('service_role','public.zoho_import_approvals','UPDATE');
  ASSERT NOT has_function_privilege('anon','public.zoho_record_import_approval(uuid,jsonb)','EXECUTE');
  ASSERT NOT has_function_privilege('authenticated','public.zoho_validate_import_approval(jsonb)','EXECUTE');
END $$;
