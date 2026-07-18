-- Preserve per-app session metadata when rotating refresh tokens.
CREATE OR REPLACE FUNCTION public.rotate_session(p_old_hash text, p_new_hash text, p_new_user_agent text, p_new_ip text, p_token_ttl_ms bigint, p_absolute_lifetime_ms bigint)
 RETURNS TABLE(claimed boolean, reason text, new_session_id uuid, user_id uuid, org_id uuid, family_id uuid, expires_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
    v_old      sessions%ROWTYPE;
    v_new_id   uuid := gen_random_uuid();
    v_origin   timestamptz;
    v_cap      timestamptz;
    v_expires  timestamptz;
BEGIN
    SELECT * INTO v_old FROM sessions
        WHERE refresh_token_hash = p_old_hash
        FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT false, 'not_found', NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid, NULL::timestamptz;
        RETURN;
    END IF;

    v_origin := COALESCE(v_old.family_created_at, v_old.created_at);

    IF now() >= (v_origin + make_interval(secs => p_absolute_lifetime_ms / 1000.0)) THEN
        UPDATE sessions SET revoked = true WHERE id = v_old.id AND revoked = false;
        RETURN QUERY SELECT false, 'lifetime_exceeded', NULL::uuid, v_old.user_id, NULL::uuid, COALESCE(v_old.family_id, v_old.id), NULL::timestamptz;
        RETURN;
    END IF;

    IF v_old.expires_at < now() THEN
        UPDATE sessions SET revoked = true WHERE id = v_old.id AND revoked = false;
        RETURN QUERY SELECT false, 'expired', NULL::uuid, v_old.user_id, NULL::uuid, COALESCE(v_old.family_id, v_old.id), NULL::timestamptz;
        RETURN;
    END IF;

    UPDATE sessions
        SET revoked = true
        WHERE id = v_old.id AND revoked = false;

    IF NOT FOUND THEN
        RETURN QUERY SELECT false, 'revoked', NULL::uuid, v_old.user_id, NULL::uuid, COALESCE(v_old.family_id, v_old.id), NULL::timestamptz;
        RETURN;
    END IF;

    v_cap := v_origin + make_interval(secs => p_absolute_lifetime_ms / 1000.0);
    v_expires := LEAST(now() + make_interval(secs => p_token_ttl_ms / 1000.0), v_cap);

    INSERT INTO sessions (
        id, user_id, org_id, refresh_token_hash, user_agent, ip_address,
        revoked, expires_at, rotated_from, last_used_at, family_id, family_created_at, device_info
    ) VALUES (
        v_new_id, v_old.user_id, v_old.org_id, p_new_hash, p_new_user_agent, p_new_ip,
        false, v_expires, v_old.id, now(), COALESCE(v_old.family_id, v_old.id), COALESCE(v_old.family_created_at, v_old.created_at), v_old.device_info
    );

    UPDATE sessions SET replaced_by = v_new_id WHERE id = v_old.id;

    RETURN QUERY SELECT true, 'ok', v_new_id, v_old.user_id, v_old.org_id, COALESCE(v_old.family_id, v_old.id), v_expires;
END;
$function$;
