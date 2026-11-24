-- Apply only as a separately approved local batch. No existing-user backfill.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';

-- Trusted gateway has already validated provider proof. Recheck its durable
-- identity link and exact address here; verification and activation are atomic.
CREATE FUNCTION public.verify_oauth_with_subscription_entry(p_user_id uuid,p_provider_subject text,p_email text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE intent record; ids jsonb:='[]'::jsonb; sub uuid;
BEGIN
  IF p_user_id IS NULL OR p_provider_subject IS NULL OR length(btrim(p_provider_subject)) NOT BETWEEN 1 AND 255
    OR p_provider_subject<>btrim(p_provider_subject) OR p_email IS NULL OR length(btrim(p_email))=0 THEN
    RAISE EXCEPTION 'Verified provider identity required';
  END IF;
  PERFORM 1 FROM public.users u WHERE u.id=p_user_id AND u.email=lower(btrim(p_email)) AND u.is_blocked=false
    AND coalesce(u.user_metadata->>'activation_pending','false')<>'true'
    AND coalesce(u.user_metadata->>'must_change_password','false')<>'true'
    AND EXISTS(SELECT 1 FROM public.oauth_accounts a WHERE a.user_id=u.id AND a.provider='google' AND a.provider_user_id=p_provider_subject)
    FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Live linked provider identity required'; END IF;
  UPDATE public.users SET is_email_verified=true WHERE id=p_user_id;
  FOR intent IN SELECT id FROM public.subscription_free_entry_intents WHERE user_id=p_user_id ORDER BY id LOOP
    sub:=public.activate_published_free_subscription(intent.id);
    ids:=ids||jsonb_build_array(sub);
  END LOOP;
  RETURN jsonb_build_object('verified',true,'userId',p_user_id,'subscriptionIds',ids);
END;
$$;
REVOKE ALL ON FUNCTION public.verify_oauth_with_subscription_entry(uuid,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.verify_oauth_with_subscription_entry(uuid,text,text) TO service_role;
COMMIT;
