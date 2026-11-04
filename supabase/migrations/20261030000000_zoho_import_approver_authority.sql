BEGIN;

-- Read-only authority for an isolated import coordinator. No identity mutation,
-- subscription, session, queue, webhook or email side effect is defined here.
CREATE FUNCTION public.zoho_is_active_import_approver(p_actor uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
  SELECT EXISTS(
    SELECT 1 FROM public.users u
    JOIN public.memberships m ON m.user_id=u.id
    JOIN public.membership_roles mr ON mr.membership_id=m.id
    JOIN public.roles r ON r.id=mr.role_id
    WHERE u.id=p_actor AND u.is_blocked IS FALSE
      AND m.org_id='00000000-0000-0000-0000-000000000001'::uuid
      AND m.status='active' AND r.name='super_admin'
  );
$$;
REVOKE ALL ON FUNCTION public.zoho_is_active_import_approver(uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.zoho_is_active_import_approver(uuid) TO service_role;
COMMIT;
