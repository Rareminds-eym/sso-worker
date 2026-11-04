BEGIN;

-- Canonical human evidence lives in SSO, outside the discovery/control-plane database.
-- The entrypoint verifies the signed human session before calling the registration RPC.
CREATE TABLE public.zoho_import_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  connection_id uuid NOT NULL,
  request_id uuid NOT NULL,
  manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now()+interval '24 hours'),
  revoked_at timestamptz,
  UNIQUE(connection_id,request_id)
);
REVOKE ALL ON public.zoho_import_approvals FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.zoho_record_import_approval(p_actor uuid,p_manifest jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE existing public.zoho_import_approvals; normalized jsonb; item jsonb;
BEGIN
  IF NOT public.zoho_is_active_import_approver(p_actor) OR p_manifest IS NULL THEN RETURN false; END IF;
  IF jsonb_typeof(p_manifest) IS DISTINCT FROM 'object' OR
    (SELECT count(*) FROM jsonb_object_keys(p_manifest))<>8 OR
    NOT p_manifest ?& ARRAY['requestId','connectionId','sourceOrgId','publisherOrganizationId','configRevision','items','reason','emailPolicy'] OR
    p_manifest->>'emailPolicy' IS DISTINCT FROM 'forbidden' OR jsonb_typeof(p_manifest->'items') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['requestId','connectionId','sourceOrgId','publisherOrganizationId','configRevision','reason','emailPolicy']) k WHERE p_manifest->>k IS NULL) THEN RETURN false; END IF;
  IF jsonb_array_length(p_manifest->'items') NOT BETWEEN 1 AND 50 OR
    length(trim(p_manifest->>'reason')) NOT BETWEEN 3 AND 500 OR p_manifest->>'reason'<>trim(p_manifest->>'reason') OR
    p_manifest->>'sourceOrgId' !~ '^\d{1,40}$' OR (p_manifest->>'configRevision')::integer<1 OR
    (p_manifest->>'publisherOrganizationId')::uuid IS NULL OR (p_manifest->>'connectionId')::uuid IS NULL OR
    (p_manifest->>'requestId')::uuid IS NULL THEN RETURN false; END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(p_manifest->'items') LOOP
    IF EXISTS(SELECT 1 FROM unnest(ARRAY['recordId','revision','sourceHash','module','externalId']) k WHERE item->>k IS NULL) THEN RETURN false; END IF;
    IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>6 OR
      NOT item ?& ARRAY['recordId','revision','sourceHash','module','externalId','targetId'] OR
      (item->>'recordId')::uuid IS NULL OR (item->>'revision')::integer<1 OR
      item->>'sourceHash' !~ '^[a-f0-9]{64}$' OR item->>'module' NOT IN ('Candidates','Job_Openings') OR
      item->>'externalId' !~ '^\d{1,40}$' OR
      (item->'targetId'<>'null'::jsonb AND (item->>'targetId')::uuid IS NULL) THEN RETURN false; END IF;
  END LOOP;
  IF (SELECT count(DISTINCT value->>'recordId') FROM jsonb_array_elements(p_manifest->'items'))<>jsonb_array_length(p_manifest->'items') THEN RETURN false; END IF;
  SELECT jsonb_set(p_manifest,'{items}',jsonb_agg(value ORDER BY value->>'recordId')) INTO normalized FROM jsonb_array_elements(p_manifest->'items');
  -- Concurrent identical retries converge; the original expiry never extends.
  INSERT INTO public.zoho_import_approvals(actor_id,connection_id,request_id,manifest)
    VALUES(p_actor,(p_manifest->>'connectionId')::uuid,(p_manifest->>'requestId')::uuid,normalized)
    ON CONFLICT(connection_id,request_id) DO NOTHING;
  SELECT * INTO STRICT existing FROM public.zoho_import_approvals
    WHERE connection_id=(p_manifest->>'connectionId')::uuid AND request_id=(p_manifest->>'requestId')::uuid;
  RETURN existing.actor_id=p_actor AND existing.manifest=normalized AND existing.revoked_at IS NULL AND existing.expires_at>clock_timestamp();
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END;
$$;

CREATE FUNCTION public.zoho_validate_import_approval(p_grant jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF p_grant IS NULL OR EXISTS(SELECT 1 FROM unnest(ARRAY['operationId','lease','leaseExpiresAt','actorId','connectionId','sourceOrgId','publisherOrganizationId','recordId','revision','configRevision','sourceHash','action','module','externalId','emailPolicy']) k WHERE p_grant->>k IS NULL) OR NOT p_grant ? 'targetId' THEN RETURN false; END IF;
  IF (p_grant->>'operationId')::uuid IS NULL OR (p_grant->>'lease')::uuid IS NULL THEN RETURN false; END IF;
  IF jsonb_typeof(p_grant) IS DISTINCT FROM 'object' OR p_grant->>'emailPolicy' IS DISTINCT FROM 'forbidden' OR
    p_grant->'claimed' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(p_grant->'data') IS DISTINCT FROM 'object' OR
    (p_grant->>'leaseExpiresAt')::timestamptz<=statement_timestamp() OR
    p_grant->>'sourceHash' IS DISTINCT FROM encode(sha256(convert_to((p_grant->'data')::text,'UTF8')),'hex') OR
    NOT public.zoho_is_active_import_approver((p_grant->>'actorId')::uuid) OR
    NOT ((p_grant->>'module'='Candidates' AND p_grant->>'action'='provision_candidate') OR
         (p_grant->>'module'='Job_Openings' AND p_grant->>'action'='apply_job')) THEN RETURN false; END IF;
  RETURN EXISTS(SELECT 1 FROM public.zoho_import_approvals a CROSS JOIN LATERAL jsonb_array_elements(a.manifest->'items') item
    WHERE a.actor_id=(p_grant->>'actorId')::uuid AND a.connection_id=(p_grant->>'connectionId')::uuid
      AND a.revoked_at IS NULL AND a.expires_at>=greatest((p_grant->>'leaseExpiresAt')::timestamptz,statement_timestamp())
      AND a.manifest->>'sourceOrgId'=p_grant->>'sourceOrgId'
      AND a.manifest->>'publisherOrganizationId'=p_grant->>'publisherOrganizationId'
      AND (a.manifest->>'configRevision')::integer=(p_grant->>'configRevision')::integer
      AND item->>'recordId'=p_grant->>'recordId' AND item->>'revision'=p_grant->>'revision'
      AND item->>'sourceHash'=p_grant->>'sourceHash' AND item->>'module'=p_grant->>'module'
      AND item->>'externalId'=p_grant->>'externalId' AND item->'targetId'=p_grant->'targetId');
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_record_import_approval(uuid,jsonb),public.zoho_validate_import_approval(jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_record_import_approval(uuid,jsonb),public.zoho_validate_import_approval(jsonb) TO service_role;
COMMIT;
