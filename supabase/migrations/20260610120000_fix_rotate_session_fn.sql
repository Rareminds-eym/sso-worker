-- Migration: rotate_session RPC (atomic single-winner refresh-token rotation) FIX
-- Phase: Expand
-- Breaking: No
--
-- This migration updates the public.rotate_session function to make legacy
-- sessions (which have NULL family_id and family_created_at) self-healing.
-- Upon the first rotation of a legacy session, it will automatically "mint"
-- itself as the origin of a new token family by coalescing the NULL fields
-- with its own id and created_at.
--
-- This ensures that legacy sessions can be securely revoked upon theft and
-- their absolute lifetime is properly enforced.

CREATE OR REPLACE FUNCTION "public"."rotate_session"(
    "p_old_hash"             "text",
    "p_new_hash"             "text",
    "p_new_user_agent"       "text",
    "p_new_ip"               "text",
    "p_token_ttl_ms"         bigint,
    "p_absolute_lifetime_ms" bigint
) RETURNS TABLE (
    "claimed"        boolean,
    "reason"         "text",        -- 'ok' | 'revoked' | 'expired' | 'lifetime_exceeded' | 'not_found'
    "new_session_id" "uuid",
    "user_id"        "uuid",
    "org_id"         "uuid",
    "family_id"      "uuid",
    "expires_at"     timestamp with time zone
)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_old      sessions%ROWTYPE;
    v_new_id   uuid := gen_random_uuid();
    v_origin   timestamptz;
    v_cap      timestamptz;
    v_expires  timestamptz;
BEGIN
    -- Lock the candidate row to serialize concurrent claims.
    SELECT * INTO v_old FROM sessions
        WHERE refresh_token_hash = p_old_hash
        FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT false, 'not_found', NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid, NULL::timestamptz;
        RETURN;
    END IF;

    -- Family origin: prefer the propagated family_created_at, but tolerate NULL on
    -- not-yet-backfilled legacy rows by falling back to the session's own created_at.
    v_origin := COALESCE(v_old.family_created_at, v_old.created_at);

    -- Absolute-lifetime gate (Req 5.2): refuse if the family is too old.
    IF now() >= (v_origin + make_interval(secs => p_absolute_lifetime_ms / 1000.0)) THEN
        UPDATE sessions SET revoked = true WHERE id = v_old.id AND revoked = false;
        RETURN QUERY SELECT false, 'lifetime_exceeded', NULL::uuid, v_old.user_id, NULL::uuid, COALESCE(v_old.family_id, v_old.id), NULL::timestamptz;
        RETURN;
    END IF;

    -- Expiry gate.
    IF v_old.expires_at < now() THEN
        UPDATE sessions SET revoked = true WHERE id = v_old.id AND revoked = false;
        RETURN QUERY SELECT false, 'expired', NULL::uuid, v_old.user_id, NULL::uuid, COALESCE(v_old.family_id, v_old.id), NULL::timestamptz;
        RETURN;
    END IF;

    -- Single-winner conditional claim (Req 2.1, 2.2): only the caller that flips
    -- revoked false->true wins; the loser matches zero rows and gets 'revoked'.
    UPDATE sessions
        SET revoked = true, replaced_by = v_new_id
        WHERE id = v_old.id AND revoked = false;

    IF NOT FOUND THEN
        -- Lost the race; caller resolves via grace window (Req 1.2) or theft (Req 3).
        RETURN QUERY SELECT false, 'revoked', NULL::uuid, v_old.user_id, NULL::uuid, COALESCE(v_old.family_id, v_old.id), NULL::timestamptz;
        RETURN;
    END IF;

    -- Rotated expiry = earlier of per-token TTL and the absolute-lifetime boundary (Req 5.3).
    v_cap := v_origin + make_interval(secs => p_absolute_lifetime_ms / 1000.0);
    v_expires := LEAST(now() + make_interval(secs => p_token_ttl_ms / 1000.0), v_cap);

    INSERT INTO sessions (
        id, user_id, org_id, refresh_token_hash, user_agent, ip_address,
        revoked, expires_at, rotated_from, last_used_at, family_id, family_created_at
    ) VALUES (
        v_new_id, v_old.user_id, v_old.org_id, p_new_hash, p_new_user_agent, p_new_ip,
        false, v_expires, v_old.id, now(), COALESCE(v_old.family_id, v_old.id), COALESCE(v_old.family_created_at, v_old.created_at)
    );

    RETURN QUERY SELECT true, 'ok', v_new_id, v_old.user_id, v_old.org_id, COALESCE(v_old.family_id, v_old.id), v_expires;
END;
$$;

-- Grant EXECUTE to service_role (consistent with existing cleanup_expired_sessions grant).
GRANT EXECUTE ON FUNCTION "public"."rotate_session"("text", "text", "text", "text", bigint, bigint) TO "service_role";
