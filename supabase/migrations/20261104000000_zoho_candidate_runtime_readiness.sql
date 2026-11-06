BEGIN;

-- Preview contexts contain contact data. Expiry removes them; approved manifests
-- retain hashes/IDs and do not depend on keeping expired previews indefinitely.
CREATE FUNCTION public.zoho_cleanup_candidate_reviews() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE removed integer;
BEGIN
  WITH expired AS (SELECT actor_id,review_hash FROM public.zoho_candidate_reviews
    WHERE expires_at<=clock_timestamp() ORDER BY expires_at,actor_id,review_hash LIMIT 500 FOR UPDATE SKIP LOCKED)
  DELETE FROM public.zoho_candidate_reviews r USING expired e WHERE r.actor_id=e.actor_id AND r.review_hash=e.review_hash;
  GET DIAGNOSTICS removed=ROW_COUNT;
  RETURN removed;
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_cleanup_candidate_reviews() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_cleanup_candidate_reviews() TO service_role;

CREATE OR REPLACE FUNCTION public.zoho_assert_private_identity_boundary() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF EXISTS (
    WITH RECURSIVE protected(oid) AS (
      SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname IN ('users','memberships','membership_roles','membership_products','subscriptions','oauth_accounts',
          'zoho_candidate_links','zoho_candidate_receipts','zoho_candidate_outbox','zoho_candidate_reviews','zoho_import_approvals')
      UNION
      SELECT r.ev_class FROM protected p
        JOIN pg_depend d ON d.refobjid=p.oid AND d.refclassid='pg_class'::regclass
          AND d.classid='pg_rewrite'::regclass
        JOIN pg_rewrite r ON r.oid=d.objid WHERE r.ev_class<>p.oid
    )
    SELECT 1 FROM protected p CROSS JOIN (VALUES ('anon'),('authenticated')) AS browser(role)
    WHERE has_table_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE,DELETE')
       OR has_any_column_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE')
  ) OR EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
      AND (has_schema_privilege('anon',n.oid,'USAGE') AND has_function_privilege('anon',p.oid,'EXECUTE')
        OR has_schema_privilege('authenticated',n.oid,'USAGE') AND has_function_privilege('authenticated',p.oid,'EXECUTE'))
  ) THEN
    RAISE EXCEPTION 'Private identity requires a verified server-only data boundary' USING ERRCODE='42501';
  END IF;
END;
$$;

-- Called only after the existing trusted gateway verifies a Google identity.
-- The existing link and exact address are independently rechecked under locks;
-- no operator-selected password or assertion of ownership is accepted.
CREATE FUNCTION public.zoho_activate_candidate_oauth(p_user uuid,p_provider_subject text,p_email text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE u public.users;
BEGIN
  IF p_user IS NULL OR p_provider_subject IS NULL OR length(p_provider_subject) NOT BETWEEN 1 AND 255
    OR p_email IS NULL OR p_email<>lower(trim(p_email)) THEN
    RAISE EXCEPTION 'Candidate activation unavailable' USING ERRCODE='22023';
  END IF;
  SELECT * INTO u FROM public.users WHERE id=p_user FOR UPDATE;
  IF NOT FOUND OR u.is_blocked IS DISTINCT FROM false OR u.email IS DISTINCT FROM p_email
    OR NOT EXISTS(SELECT 1 FROM public.zoho_candidate_links WHERE user_id=p_user) THEN
    RAISE EXCEPTION 'Candidate activation unavailable' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM public.oauth_accounts WHERE user_id=p_user AND provider='google' AND provider_user_id=p_provider_subject FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Candidate activation unavailable' USING ERRCODE='22023'; END IF;
  PERFORM public.zoho_assert_private_identity_boundary();
  UPDATE public.users SET is_email_verified=true,user_metadata=coalesce(user_metadata,'{}'::jsonb)-'activation_pending',
    updated_at=clock_timestamp() WHERE id=p_user RETURNING * INTO u;
  UPDATE public.zoho_candidate_receipts SET activation_state='existing_sign_in_preserved' WHERE user_id=p_user;
  UPDATE public.zoho_candidate_outbox SET payload=jsonb_set(payload,'{activationState}','"existing_sign_in_preserved"'::jsonb)
    WHERE user_id=p_user;
  RETURN jsonb_build_object('activated',true,'userMetadata',u.user_metadata);
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_activate_candidate_oauth(uuid,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_activate_candidate_oauth(uuid,text,text) TO service_role;

-- A read-only deployment probe; no synthetic identities, reviews, outbox entries,
-- queue messages or mail are produced. Per-candidate checks remain transactional.
CREATE FUNCTION public.zoho_candidate_runtime_ready() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE signature text; function_oid oid; product uuid;
BEGIN
  PERFORM public.zoho_assert_private_identity_boundary();
  FOREACH signature IN ARRAY ARRAY[
    'public.zoho_candidate_sync_policy(uuid)',
    'public.zoho_activate_candidate_oauth(uuid,text,text)',
    'public.zoho_provision_candidate(jsonb)',
    'public.zoho_validate_import_approval(jsonb)',
    'public.zoho_preview_candidate_review(uuid,jsonb)',
    'public.zoho_verify_candidate_review(uuid,jsonb,text)',
    'public.zoho_find_candidate_receipt(uuid,text)',
    'public.zoho_reserve_candidate_deliveries(uuid)',
    'public.zoho_record_candidate_publication(uuid,uuid,boolean)',
    'public.zoho_get_candidate_projection(uuid,text)',
    'public.zoho_confirm_candidate_projection(uuid,text,text,uuid)'
  ] LOOP
    function_oid:=to_regprocedure(signature);
    IF function_oid IS NULL OR NOT has_function_privilege('service_role',function_oid,'EXECUTE')
      OR has_function_privilege('anon',function_oid,'EXECUTE')
      OR has_function_privilege('authenticated',function_oid,'EXECUTE') THEN RETURN false; END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN (VALUES ('anon'),('authenticated')) AS browser(role)
    WHERE n.nspname='public' AND c.relname IN
      ('zoho_candidate_links','zoho_candidate_receipts','zoho_candidate_outbox','zoho_candidate_reviews','zoho_import_approvals')
      AND (has_table_privilege(browser.role,c.oid,'SELECT,INSERT,UPDATE,DELETE')
        OR has_any_column_privilege(browser.role,c.oid,'SELECT,INSERT,UPDATE'))
  ) THEN RETURN false; END IF;
  SELECT id INTO STRICT product FROM public.products WHERE code='skillpassport';
  IF NOT EXISTS(SELECT 1 FROM public.roles WHERE name='learner')
    OR NOT EXISTS(SELECT 1 FROM public.organizations WHERE id='00000000-0000-0000-0000-000000000001')
    OR NOT EXISTS(SELECT 1 FROM public.organization_products WHERE org_id='00000000-0000-0000-0000-000000000001'
      AND product_id=product AND active IS TRUE)
    OR NOT EXISTS(SELECT 1 FROM public.plans p WHERE p.plan_code='freemium' AND p.product_id=product
      AND p.is_active IS TRUE AND p.business_type='b2c' AND p.updated_at IS NOT NULL
      AND ('all'=ANY(p.applicable_entities) OR 'learner'=ANY(p.applicable_entities))
      AND p.pricing_matrix->'all'->'monthly'='0'::jsonb AND p.pricing_matrix->'all'->'yearly'='0'::jsonb
      AND jsonb_typeof(p.base_features)='array'
      AND p.base_features @> '["learner_profile_creation","basic_opportunity_view"]'::jsonb)
  THEN RETURN false; END IF;
  RETURN true;
EXCEPTION WHEN OTHERS THEN
  -- Missing/partially upgraded dependencies and private-boundary violations fail
  -- closed without exposing canonical catalog or deployment details over RPC.
  RETURN false;
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_candidate_runtime_ready() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_candidate_runtime_ready() TO service_role;

COMMIT;
