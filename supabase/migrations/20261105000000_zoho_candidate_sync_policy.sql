BEGIN;
CREATE INDEX zoho_candidate_links_user ON public.zoho_candidate_links(user_id);
CREATE INDEX zoho_candidate_receipts_user ON public.zoho_candidate_receipts(user_id);
-- Durable provenance outlives activation_pending. No contact data leaves this RPC.
CREATE FUNCTION public.zoho_candidate_sync_policy(p_user uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('version',1,'genericSyncAllowed',p_user IS NOT NULL AND NOT (
   EXISTS(SELECT 1 FROM public.zoho_candidate_links WHERE user_id=p_user)
   OR EXISTS(SELECT 1 FROM public.zoho_candidate_receipts WHERE user_id=p_user)));
$$;
REVOKE ALL ON FUNCTION public.zoho_candidate_sync_policy(uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_candidate_sync_policy(uuid) TO service_role;
COMMIT;
