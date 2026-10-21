-- Preserve the applied reset migration; replace its function in a new migration.
-- Clear first-login setup in the same transaction as credential/token/session updates.
BEGIN;
CREATE OR REPLACE FUNCTION public.complete_password_reset(
    p_token_hash text,
    p_password_hash text
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    candidate public.password_resets%ROWTYPE;
BEGIN
    SELECT * INTO candidate FROM public.password_resets
    WHERE token_hash = p_token_hash FOR UPDATE;
    IF NOT FOUND THEN RETURN jsonb_build_object('status', 'not_found'); END IF;
    IF candidate.used THEN RETURN jsonb_build_object('status', 'used'); END IF;
    IF candidate.expires_at <= clock_timestamp() THEN
        RETURN jsonb_build_object('status', 'expired');
    END IF;

    UPDATE public.users SET password_hash = p_password_hash,
        user_metadata = CASE WHEN user_metadata->>'must_change_password' = 'true'
            THEN jsonb_set(user_metadata, '{must_change_password}', 'false'::jsonb)
            ELSE user_metadata END
    WHERE id = candidate.user_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Password reset user missing'; END IF;
    UPDATE public.sessions SET revoked = true WHERE user_id = candidate.user_id;
    UPDATE public.password_resets SET used = true WHERE id = candidate.id;
    RETURN jsonb_build_object('status', 'reset');
END;
$$;
REVOKE ALL ON FUNCTION public.complete_password_reset(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.complete_password_reset(text, text) TO service_role;
COMMIT;
