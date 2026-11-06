BEGIN;

-- Network batching only. Each outbox row retains its original lease/expiry fence
-- and publication is never interpreted as application delivery/completion.
CREATE FUNCTION public.zoho_record_candidate_publications(p_operations uuid[],p_lease uuid,p_published boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op uuid; results jsonb:='[]'::jsonb;
BEGIN
 IF p_lease IS NULL OR p_published IS NULL OR p_operations IS NULL OR cardinality(p_operations) NOT BETWEEN 1 AND 10
  OR array_ndims(p_operations)<>1 OR array_position(p_operations,NULL) IS NOT NULL
  OR (SELECT count(DISTINCT value) FROM unnest(p_operations) value)<>cardinality(p_operations)
 THEN RAISE EXCEPTION 'Invalid publication batch' USING ERRCODE='22023'; END IF;
 FOREACH op IN ARRAY p_operations LOOP
  results:=results||jsonb_build_array(jsonb_build_object('operationId',op,
   'recorded',public.zoho_record_candidate_publication(op,p_lease,p_published)));
 END LOOP;
 RETURN results;
END;
$$;
REVOKE ALL ON FUNCTION public.zoho_record_candidate_publications(uuid[],uuid,boolean) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_record_candidate_publications(uuid[],uuid,boolean) TO service_role;

COMMIT;
