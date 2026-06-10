CREATE OR REPLACE FUNCTION public.check_membership(p_user_id UUID, p_org_id UUID)
RETURNS TABLE (id UUID, status TEXT)
LANGUAGE sql SECURITY DEFINER AS $$
  SELECT id, status FROM memberships
  WHERE user_id = p_user_id AND org_id = p_org_id
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.get_role_by_name(p_role_name TEXT)
RETURNS TABLE (id UUID, name TEXT)
LANGUAGE sql SECURITY DEFINER AS $$
  SELECT id, name FROM roles WHERE name = p_role_name LIMIT 1;
$$;
