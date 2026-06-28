-- Migration: Add revoke_token_family() RPC function
-- Phase: Migrate (rotation Postgres functions — refresh-token-auth-hardening spec)
-- Breaking: No
--
-- Adds public.revoke_token_family(uuid), the companion to rotate_session used for
-- token-family-scoped theft revocation. When Theft_Detection confirms reuse of a
-- revoked Refresh_Token outside the Reuse_Grace_Interval, the worker calls this
-- function to revoke every still-active session in the affected family in one
-- indexed UPDATE (idx_sessions_family), returning the number of sessions revoked.
--
--   * Revokes only sessions in the given family that are currently unrevoked
--     (WHERE family_id = p_family_id AND revoked = false) — confines the theft
--     response to the affected Token_Family (Requirement 3.2 / Property 3).
--   * Returns the affected row count via GET DIAGNOSTICS ROW_COUNT.
--
-- SECURITY DEFINER with a pinned search_path so the worker (service_role) can
-- revoke families regardless of row-level grants, mirroring cleanup_expired_sessions.
--
-- DDL only — no DML (Supabase migration convention).
-- Idempotent: CREATE OR REPLACE FUNCTION + idempotent GRANT.
--
-- Requirements: 3.2   Property: 3

CREATE OR REPLACE FUNCTION "public"."revoke_token_family"("p_family_id" "uuid") RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  n integer;
BEGIN
  UPDATE sessions
     SET revoked = true
   WHERE family_id = p_family_id
     AND revoked = false;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END;
$$;


ALTER FUNCTION "public"."revoke_token_family"("p_family_id" "uuid") OWNER TO "postgres";


-- Grant EXECUTE to service_role (consistent with cleanup_expired_sessions grant).
GRANT EXECUTE ON FUNCTION "public"."revoke_token_family"("p_family_id" "uuid") TO "service_role";
