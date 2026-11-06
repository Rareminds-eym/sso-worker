-- Synthetic catalog and canonical actors only; never load application seed data.
INSERT INTO public.users(id,email,password_hash,is_email_verified,is_blocked)
VALUES('10000000-0000-4000-8000-000000000001','admin@fixture.example','!disabled!',true,false);
INSERT INTO public.organizations(id,name,slug) VALUES('00000000-0000-0000-0000-000000000001','Platform fixture','fixture');
INSERT INTO public.products(id,code,name) VALUES('10000000-0000-4000-8000-000000000002','skillpassport','SkillPassport fixture');
INSERT INTO public.roles(id,name) VALUES('10000000-0000-4000-8000-000000000003','super_admin'),('10000000-0000-4000-8000-000000000004','learner');
INSERT INTO public.memberships(id,user_id,org_id,status) VALUES('10000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000001','active');
INSERT INTO public.membership_roles(membership_id,role_id) VALUES('10000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000003');
INSERT INTO public.plans(id,plan_code,name,business_type,applicable_entities,pricing_matrix,base_features,product_id)
VALUES('10000000-0000-4000-8000-000000000006','freemium','Discover','b2c','{all}',
 '{"all":{"monthly":0.00,"yearly":0,"currency":"INR"}}','["learner_profile_creation","basic_opportunity_view"]','10000000-0000-4000-8000-000000000002');

INSERT INTO public.organization_products(org_id,product_id,active) VALUES('00000000-0000-0000-0000-000000000001','10000000-0000-4000-8000-000000000002',true);

CREATE FUNCTION pg_temp.candidate_grant(p_email text,p_external text,p_target uuid DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE connection uuid:=gen_random_uuid(); record uuid:=gen_random_uuid(); data jsonb; h text; manifest jsonb; context jsonb; review jsonb;
BEGIN
  data:=jsonb_build_object('email',p_email,'name','Synthetic Learner'); h:=encode(sha256(convert_to(data::text,'UTF8')),'hex');
  context:=jsonb_build_object('connectionId',connection,'sourceOrgId','1234','recordId',record,'revision',1,'configRevision',1,'sourceHash',h,'externalId',p_external,'data',data,'targetId',p_target,'emailPolicy','forbidden');
  review:=public.zoho_preview_candidate_review('10000000-0000-4000-8000-000000000001',context);
  manifest:=jsonb_build_object('requestId',gen_random_uuid(),'connectionId',connection,'sourceOrgId','1234',
    'publisherOrganizationId','10000000-0000-4000-8000-000000000007','configRevision',1,'reason','Reviewed candidate fixture','emailPolicy','forbidden',
    'items',jsonb_build_array(jsonb_build_object('recordId',record,'revision',1,'sourceHash',h,'module','Candidates','externalId',p_external,'targetId',p_target,'candidateReviewHash',review->>'reviewHash')));
  IF review->>'decision'<>'blocked' THEN
    ASSERT public.zoho_record_import_approval('10000000-0000-4000-8000-000000000001',manifest);
  END IF;
  RETURN jsonb_build_object('claimed',true,'operationId',gen_random_uuid(),'lease',gen_random_uuid(),'leaseExpiresAt',clock_timestamp()+interval '5 minutes',
    'approvalExpiresAt',clock_timestamp()+interval '23 hours','actorId','10000000-0000-4000-8000-000000000001','connectionId',connection,
    'sourceOrgId','1234','publisherOrganizationId','10000000-0000-4000-8000-000000000007','recordId',record,'revision',1,'configRevision',1,
    'sourceHash',h,'candidateReviewHash',review->>'reviewHash','action','provision_candidate','module','Candidates','externalId',p_external,'targetId',p_target,'emailPolicy','forbidden','data',data);
END;
$$;
CREATE FUNCTION pg_temp.assert_candidate_denied(p_grant jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE users_before integer; receipts_before integer; outbox_before integer; memberships_before integer; subscriptions_before integer; links_before integer;
BEGIN
  SELECT count(*) INTO users_before FROM public.users;
  SELECT count(*) INTO receipts_before FROM public.zoho_candidate_receipts;
  SELECT count(*) INTO outbox_before FROM public.zoho_candidate_outbox;
  SELECT count(*) INTO memberships_before FROM public.memberships;
  SELECT count(*) INTO subscriptions_before FROM public.subscriptions;
  SELECT count(*) INTO links_before FROM public.zoho_candidate_links;
  BEGIN
    PERFORM public.zoho_provision_candidate(p_grant);
    RAISE EXCEPTION 'Unexpected successful provisioning';
  EXCEPTION WHEN invalid_parameter_value OR serialization_failure THEN NULL;
  END;
  ASSERT (SELECT count(*)=users_before FROM public.users);
  ASSERT (SELECT count(*)=receipts_before FROM public.zoho_candidate_receipts);
  ASSERT (SELECT count(*)=outbox_before FROM public.zoho_candidate_outbox);
  ASSERT (SELECT count(*)=memberships_before FROM public.memberships);
  ASSERT (SELECT count(*)=subscriptions_before FROM public.subscriptions);
  ASSERT (SELECT count(*)=links_before FROM public.zoho_candidate_links);
END;
$$;
-- Opening a direct browser grant must reject the real canonical transaction,
-- before identity, membership, entitlement, source-link or outbox writes.
GRANT SELECT ON public.users TO anon;
DO $$ DECLARE grant_value jsonb; before_users integer; BEGIN
 SELECT count(*) INTO before_users FROM public.users;
 grant_value:=pg_temp.candidate_grant('private-boundary@fixture.example','700');
 BEGIN
  PERFORM public.zoho_provision_candidate(grant_value);
  RAISE EXCEPTION 'Canonical identity bypassed private boundary';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 ASSERT (SELECT count(*)=before_users FROM public.users);
 ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_receipts);
 ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_links);
 ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_outbox);
 ASSERT NOT EXISTS(SELECT 1 FROM public.subscriptions);
END $$;
REVOKE SELECT ON public.users FROM anon;
DO $$
DECLARE grant_value jsonb; result jsonb; learner uuid; snapshot jsonb; grant2 jsonb; premium uuid:=gen_random_uuid();
BEGIN
  DELETE FROM public.organization_products;
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('missing-product@fixture.example','701'));
  INSERT INTO public.organization_products(org_id,product_id,active) VALUES('00000000-0000-0000-0000-000000000001','10000000-0000-4000-8000-000000000002',false);
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('disabled-product@fixture.example','702'));
  UPDATE public.organization_products SET active=true;
  grant_value:=pg_temp.candidate_grant('candidate+tag@fixture.example','1');
  result:=public.zoho_provision_candidate(grant_value);
  learner:=(result->>'targetId')::uuid;
  ASSERT public.get_jwt_claims(learner,'00000000-0000-0000-0000-000000000001')->'products'='["skillpassport"]'::jsonb;
  ASSERT result->>'state'='projection_pending' AND result->>'identityOutcome'='created' AND result->>'activationState'='activation_pending';
  ASSERT (SELECT email='candidate+tag@fixture.example' AND is_email_verified IS FALSE AND is_blocked IS FALSE AND password_hash='!zoho-import-no-password!' FROM public.users WHERE id=learner);
  ASSERT (SELECT count(*)=1 FROM public.memberships WHERE user_id=learner AND org_id='00000000-0000-0000-0000-000000000001');
  ASSERT (SELECT count(*)=1 FROM public.membership_roles mr JOIN public.memberships m ON m.id=mr.membership_id
    JOIN public.roles r ON r.id=mr.role_id WHERE m.user_id=learner AND r.name='learner');
  ASSERT (SELECT count(*)=1 FROM public.membership_products mp JOIN public.memberships m ON m.id=mp.membership_id WHERE m.user_id=learner);
  ASSERT (SELECT plan_code='freemium' AND plan_amount=0 AND status='active' AND auto_renew IS FALSE AND billing_cycle='lifetime'
    AND features='["learner_profile_creation","basic_opportunity_view"]' FROM public.subscriptions WHERE user_id=learner);
  ASSERT (SELECT count(*)=1 FROM public.organizations); -- no academic organization fabricated
  ASSERT (SELECT count(*)=1 FROM public.zoho_candidate_links WHERE user_id=learner);
  ASSERT (SELECT payload->>'emailPolicy'='forbidden' AND payload->>'activationState'='activation_pending'
    AND payload::text NOT LIKE '%password%' FROM public.zoho_candidate_outbox WHERE operation_id=(grant_value->>'operationId')::uuid);
  ASSERT public.zoho_provision_candidate(grant_value)=result;
  ASSERT (SELECT count(*)=1 FROM public.zoho_candidate_receipts);
  ASSERT (SELECT count(*)=1 FROM public.zoho_candidate_outbox);
  ASSERT public.zoho_find_candidate_receipt((grant_value->>'operationId')::uuid,repeat('b',64)) IS NULL;
  -- Null staged target is resolved only by the separately reviewed canonical hash.
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','2')-'candidateReviewHash');
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','3',gen_random_uuid()));

  -- Preserve a reviewed existing learner's paid access, credentials and explicit preferences.
  INSERT INTO public.plans(id,plan_code,name,business_type,applicable_entities,pricing_matrix,base_features,product_id)
    VALUES(premium,'premium_fixture','Paid fixture','b2c','{all}','{}','["paid_feature"]','10000000-0000-4000-8000-000000000002');
  UPDATE public.subscriptions SET plan_id=premium,plan_code='premium_fixture',plan_amount=999,features='["paid_feature"]' WHERE user_id=learner;
  UPDATE public.users SET password_hash='existing-password-hash',is_email_verified=true,user_metadata='{"role":"learner","preference":false,"temporary_password":"do-not-project"}' WHERE id=learner;
  SELECT to_jsonb(u) INTO snapshot FROM public.users u WHERE id=learner;
  -- Personal paid access alone cannot substitute for a usable learner/product context.
  DELETE FROM public.membership_products WHERE membership_id IN (SELECT id FROM public.memberships WHERE user_id=learner);
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','711',learner));
  ASSERT NOT EXISTS(SELECT 1 FROM public.membership_products mp JOIN public.memberships m ON m.id=mp.membership_id WHERE m.user_id=learner);
  -- Product access on a different non-learner membership cannot satisfy the join.
  INSERT INTO public.organizations(id,name,slug) VALUES('10000000-0000-4000-8000-000000000010','Other fixture','other-fixture');
  INSERT INTO public.organization_products(org_id,product_id,active)
    VALUES('10000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000002',true);
  INSERT INTO public.memberships(id,user_id,org_id,status)
    VALUES('10000000-0000-4000-8000-000000000011',learner,'10000000-0000-4000-8000-000000000010','active');
  INSERT INTO public.membership_roles(membership_id,role_id)
    VALUES('10000000-0000-4000-8000-000000000011','10000000-0000-4000-8000-000000000003');
  INSERT INTO public.membership_products(membership_id,product_id)
    VALUES('10000000-0000-4000-8000-000000000011','10000000-0000-4000-8000-000000000002');
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','712',learner));
  DELETE FROM public.memberships WHERE id='10000000-0000-4000-8000-000000000011';
  DELETE FROM public.organizations WHERE id='10000000-0000-4000-8000-000000000010';
  INSERT INTO public.membership_products(membership_id,product_id)
    SELECT id,'10000000-0000-4000-8000-000000000002'::uuid FROM public.memberships WHERE user_id=learner;
  UPDATE public.organization_products SET active=false;
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','713',learner));
  ASSERT NOT EXISTS(SELECT 1 FROM public.organization_products WHERE active IS TRUE);
  DELETE FROM public.organization_products;
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','714',learner));
  ASSERT NOT EXISTS(SELECT 1 FROM public.organization_products);
  INSERT INTO public.organization_products(org_id,product_id,active)
    VALUES('00000000-0000-0000-0000-000000000001','10000000-0000-4000-8000-000000000002',true);
  UPDATE public.memberships SET status='inactive' WHERE user_id=learner;
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','715',learner));
  UPDATE public.memberships SET status='active' WHERE user_id=learner;
  grant2:=pg_temp.candidate_grant('candidate+tag@fixture.example','4',learner);
  result:=public.zoho_provision_candidate(grant2);
  ASSERT result->>'identityOutcome'='existing_access_preserved' AND result->>'state'='projection_pending';
  ASSERT (SELECT to_jsonb(u)=snapshot FROM public.users u WHERE id=learner);
  ASSERT (SELECT count(*)=1 AND min(plan_code)='premium_fixture' AND min(plan_amount)=999 FROM public.subscriptions WHERE user_id=learner);
  ASSERT (SELECT payload::text NOT LIKE '%do-not-project%' AND payload::text NOT LIKE '%existing-password-hash%' FROM public.zoho_candidate_outbox WHERE operation_id=(grant2->>'operationId')::uuid);
  -- Existing source linkage cannot be reassigned or implicitly recreated.
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('other@fixture.example','1'));
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('admin@fixture.example','5','10000000-0000-4000-8000-000000000001'));
  -- A case-variant legacy duplicate is held instead of merging people.
  INSERT INTO public.users(email,password_hash,is_blocked) VALUES('CANDIDATE+TAG@fixture.example','!disabled!',false);
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('candidate+tag@fixture.example','6',learner));
  DELETE FROM public.users WHERE email='CANDIDATE+TAG@fixture.example';

  UPDATE public.plans SET is_active=false WHERE plan_code='freemium';
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('disabled-plan@fixture.example','7'));
  UPDATE public.plans SET is_active=true,pricing_matrix='{"all":{"monthly":1,"yearly":0}}' WHERE plan_code='freemium';
  PERFORM pg_temp.assert_candidate_denied(pg_temp.candidate_grant('paid-plan@fixture.example','8'));
  UPDATE public.plans SET pricing_matrix='{"all":{"monthly":0,"yearly":0}}' WHERE plan_code='freemium';
  grant2:=pg_temp.candidate_grant('expired@fixture.example','9');
  PERFORM pg_temp.assert_candidate_denied(jsonb_set(grant2,'{leaseExpiresAt}',to_jsonb(now()-interval '1 second')));
  PERFORM pg_temp.assert_candidate_denied(jsonb_set(grant2,'{data,name}','"Tampered"'));
  PERFORM pg_temp.assert_candidate_denied(grant2||'{"sendEmail":true}');
  UPDATE public.zoho_import_approvals SET revoked_at=now() WHERE connection_id=(grant2->>'connectionId')::uuid;
  PERFORM pg_temp.assert_candidate_denied(grant2);
  ASSERT NOT has_table_privilege('service_role','public.zoho_candidate_receipts','UPDATE');
  ASSERT NOT has_table_privilege('service_role','public.zoho_candidate_outbox','INSERT');
  ASSERT NOT has_function_privilege('anon','public.zoho_provision_candidate(jsonb)','EXECUTE');
  ASSERT NOT has_function_privilege('authenticated','public.zoho_find_candidate_receipt(uuid,text)','EXECUTE');
END;
$$;
-- A failure after identity/role/subscription/link writes rolls the whole effect back.
CREATE FUNCTION pg_temp.reject_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic outbox failure' USING ERRCODE='22023'; END $$;
CREATE TRIGGER fixture_reject_outbox BEFORE INSERT ON public.zoho_candidate_outbox FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_outbox();
SELECT pg_temp.assert_candidate_denied(pg_temp.candidate_grant('rollback@fixture.example','10'));
DO $$ BEGIN ASSERT NOT EXISTS(SELECT 1 FROM public.users WHERE email='rollback@fixture.example'); END $$;

-- Target deletion removes retained payload/linkage and leaves an effect tombstone,
-- without blocking the canonical delete path or making the old operation reusable.
DO $$
DECLARE grant_value jsonb; result jsonb; learner uuid;
BEGIN
  DELETE FROM public.users WHERE email='candidate+tag@fixture.example';
  ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_links);
  ASSERT NOT EXISTS(SELECT 1 FROM public.zoho_candidate_outbox);
  ASSERT (SELECT count(*)=2 AND count(user_id)=0 FROM public.zoho_candidate_receipts);
  ASSERT NOT EXISTS(SELECT 1 FROM public.subscriptions);
END $$;

DROP TRIGGER fixture_reject_outbox ON public.zoho_candidate_outbox;
