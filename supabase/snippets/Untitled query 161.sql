CREATE OR REPLACE FUNCTION public.get_role_by_name(p_role_name TEXT)
RETURNS TABLE (id UUID, name TEXT)
LANGUAGE sql SECURITY DEFINER AS $$
  SELECT id, name FROM roles WHERE name = p_role_name LIMIT 1;
$$;