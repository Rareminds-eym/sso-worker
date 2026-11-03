BEGIN;
ALTER TABLE public.zoho_candidate_receipts ADD COLUMN projection_receipt_id uuid, ADD COLUMN confirmed_projection_hash text, ADD COLUMN projection_confirmed_at timestamptz;
ALTER TABLE public.zoho_candidate_outbox
  ADD COLUMN publication_attempts integer NOT NULL DEFAULT 0 CHECK(publication_attempts BETWEEN 0 AND 8),
  ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN publication_lease uuid,
  ADD COLUMN publication_expires_at timestamptz,
  ADD COLUMN published_at timestamptz,
  ADD COLUMN last_error text CHECK(last_error IN ('PUBLICATION_FAILED','CONFIRMATION_PENDING'));
CREATE INDEX zoho_candidate_delivery_due ON public.zoho_candidate_outbox(next_attempt_at,operation_id)
  WHERE delivered_at IS NULL AND publication_attempts<8;

-- Queue messages contain no user data. A canonical snapshot is fetched independently
-- at delivery, so an old queued free grant cannot overwrite a subsequent purchase.
CREATE FUNCTION public.zoho_reserve_candidate_deliveries(p_lease uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE item record; messages jsonb:='[]';
BEGIN
  IF p_lease IS NULL THEN RAISE EXCEPTION 'Lease required' USING ERRCODE='22023'; END IF;
  FOR item IN SELECT o.operation_id,r.source_hash FROM public.zoho_candidate_outbox o
    JOIN public.zoho_candidate_receipts r ON r.operation_id=o.operation_id
    WHERE o.delivered_at IS NULL AND r.state='projection_pending' AND r.user_id IS NOT NULL
      AND o.publication_attempts<8 AND o.next_attempt_at<=clock_timestamp()
      AND (o.publication_lease IS NULL OR o.publication_expires_at<=clock_timestamp())
    ORDER BY o.next_attempt_at,o.operation_id LIMIT 10 FOR UPDATE OF o SKIP LOCKED LOOP
    UPDATE public.zoho_candidate_outbox SET publication_attempts=publication_attempts+1,
      publication_lease=p_lease,publication_expires_at=clock_timestamp()+interval '1 minute',
      next_attempt_at=clock_timestamp()+make_interval(secs=>least(3600,120*power(2,publication_attempts)::integer)),
      last_error='CONFIRMATION_PENDING' WHERE operation_id=item.operation_id;
    messages:=messages||jsonb_build_array(jsonb_build_object('operationId',item.operation_id,'sourceHash',item.source_hash,'lease',p_lease));
  END LOOP;
  RETURN messages;
END;
$$;
CREATE FUNCTION public.zoho_record_candidate_publication(p_operation uuid,p_lease uuid,p_published boolean) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF p_published IS NULL THEN RETURN false; END IF;
  UPDATE public.zoho_candidate_outbox SET publication_lease=NULL,publication_expires_at=NULL,
    published_at=CASE WHEN p_published THEN clock_timestamp() ELSE published_at END,
    last_error=CASE WHEN p_published THEN 'CONFIRMATION_PENDING' ELSE 'PUBLICATION_FAILED' END
    WHERE operation_id=p_operation AND publication_lease=p_lease AND publication_expires_at>clock_timestamp() AND delivered_at IS NULL;
  RETURN FOUND;
END;
$$;

CREATE FUNCTION public.zoho_get_candidate_projection(p_operation uuid,p_source_hash text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r public.zoho_candidate_receipts; u public.users; source_payload jsonb; body jsonb; subs jsonb; plans jsonb;
  product uuid; count_subs integer;
BEGIN
  SELECT * INTO r FROM public.zoho_candidate_receipts WHERE operation_id=p_operation AND source_hash=p_source_hash AND user_id IS NOT NULL;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO u FROM public.users WHERE id=r.user_id;
  IF NOT FOUND OR u.is_blocked IS DISTINCT FROM false THEN RETURN NULL; END IF;
  SELECT id INTO STRICT product FROM public.products WHERE code='skillpassport';
  IF NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.membership_roles mr ON mr.membership_id=m.id
      JOIN public.roles role ON role.id=mr.role_id JOIN public.membership_products mp ON mp.membership_id=m.id AND mp.product_id=product
      JOIN public.organization_products op ON op.org_id=m.org_id AND op.product_id=product AND op.active IS TRUE
      WHERE m.user_id=u.id AND m.status='active' AND role.name='learner') THEN RETURN NULL; END IF;
  SELECT payload INTO source_payload FROM public.zoho_candidate_outbox WHERE operation_id=p_operation;
  SELECT count(*) INTO count_subs FROM public.subscriptions s JOIN public.plans p ON p.id=s.plan_id
    WHERE s.user_id=u.id AND p.product_id=product AND s.is_organization_subscription IS NOT TRUE AND s.is_bulk_purchase IS NOT TRUE;
  IF count_subs=0 OR count_subs>25 THEN RETURN NULL; END IF;
  SELECT jsonb_agg(jsonb_build_object('id',s.id,'user_id',s.user_id,'plan_id',s.plan_id,'plan_code',s.plan_code,
      'plan_type',s.plan_type,'plan_amount',s.plan_amount,'billing_cycle',s.billing_cycle,'features',s.features,'status',s.status,
      'subscription_start_date',s.subscription_start_date,'subscription_end_date',s.subscription_end_date,
      'product_id',product,'updated_at',s.updated_at) ORDER BY s.id)
    INTO subs FROM public.subscriptions s JOIN public.plans p ON p.id=s.plan_id
    WHERE s.user_id=u.id AND p.product_id=product AND s.is_organization_subscription IS NOT TRUE AND s.is_bulk_purchase IS NOT TRUE;
  SELECT jsonb_agg(jsonb_build_object('id',p.id,'plan_code',p.plan_code,'name',p.name,'business_type',p.business_type,
    'applicable_entities',to_jsonb(p.applicable_entities),'pricing_matrix',p.pricing_matrix,'base_features',p.base_features,
    'entity_config',p.entity_config,'display_order',p.display_order,'is_active',p.is_active,'product_id',p.product_id,'updated_at',p.updated_at) ORDER BY p.id)
    INTO plans FROM public.plans p WHERE p.id IN (SELECT (s->>'plan_id')::uuid FROM jsonb_array_elements(subs) s);
  body:=jsonb_build_object('version',1,'operationId',r.operation_id,'sourceHash',r.source_hash,'targetId',u.id,
    'identityOutcome',r.identity_outcome,'emailPolicy','forbidden','user',jsonb_build_object('id',u.id,'email',u.email,
      'isEmailVerified',u.is_email_verified,'updatedAt',u.updated_at,'primaryRole',u.user_metadata->>'role',
      'name',coalesce(nullif(trim(concat_ws(' ',u.user_metadata->>'first_name',u.user_metadata->>'last_name')),''),source_payload->>'name')),
    'subscriptions',subs,'plans',plans);
  -- Preserve PostgreSQL's exact numeric/text encoding through JavaScript hops.
  RETURN jsonb_build_object('operationId',r.operation_id,'sourceHash',r.source_hash,'targetId',u.id,
    'snapshot',body::text,'projectionHash',encode(sha256(convert_to(body::text,'UTF8')),'hex'));
END;
$$;

-- The existing-SSO entrypoint independently checks the application receipt/postconditions
-- before calling this function. Recompare current canonical state before completion.
CREATE FUNCTION public.zoho_confirm_candidate_projection(p_operation uuid,p_source_hash text,p_projection_hash text,p_receipt uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r public.zoho_candidate_receipts; snapshot jsonb;
BEGIN
  SELECT * INTO r FROM public.zoho_candidate_receipts WHERE operation_id=p_operation AND source_hash=p_source_hash AND user_id IS NOT NULL FOR UPDATE;
  IF NOT FOUND OR p_receipt IS NULL THEN RAISE EXCEPTION 'Canonical receipt unavailable' USING ERRCODE='22023'; END IF;
  IF r.state='completed' THEN RETURN public.zoho_find_candidate_receipt(p_operation,p_source_hash); END IF;
  snapshot:=public.zoho_get_candidate_projection(p_operation,p_source_hash);
  IF snapshot IS NULL OR snapshot->>'projectionHash' IS DISTINCT FROM p_projection_hash THEN
    RAISE EXCEPTION 'Canonical projection changed' USING ERRCODE='40001'; END IF;
  UPDATE public.zoho_candidate_receipts SET state='completed',projection_receipt_id=p_receipt,confirmed_projection_hash=p_projection_hash,projection_confirmed_at=clock_timestamp() WHERE operation_id=p_operation;
  UPDATE public.zoho_candidate_outbox SET delivered_at=clock_timestamp(),last_error=NULL,publication_lease=NULL,publication_expires_at=NULL
    WHERE operation_id=p_operation;
  RETURN public.zoho_find_candidate_receipt(p_operation,p_source_hash);
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_reserve_candidate_deliveries(uuid),public.zoho_record_candidate_publication(uuid,uuid,boolean),
  public.zoho_get_candidate_projection(uuid,text),public.zoho_confirm_candidate_projection(uuid,text,text,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_reserve_candidate_deliveries(uuid),public.zoho_record_candidate_publication(uuid,uuid,boolean),
  public.zoho_get_candidate_projection(uuid,text),public.zoho_confirm_candidate_projection(uuid,text,text,uuid) TO service_role;
COMMIT;
