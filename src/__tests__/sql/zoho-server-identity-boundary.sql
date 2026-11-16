-- Read and column grants, dependent views and callable definer paths all close.
DO $$ BEGIN
 ASSERT NOT has_table_privilege('anon','public.users','SELECT');
 ASSERT NOT has_any_column_privilege('authenticated','public.users','SELECT,INSERT,UPDATE');
 ASSERT NOT has_table_privilege('anon','public.fixture_candidate_identity_reader','SELECT');
 ASSERT NOT has_function_privilege('anon','public.fixture_candidate_identity_count()','EXECUTE');
 ASSERT has_function_privilege('service_role','public.fixture_candidate_identity_count()','EXECUTE');
 ASSERT has_table_privilege('service_role','public.users','SELECT');
 ASSERT public.zoho_private_boundary_safe_routine('graphql.get_schema_version()'::regprocedure);
 ASSERT public.zoho_private_boundary_safe_routine('graphql.increment_schema_version()'::regprocedure);
 ASSERT NOT public.zoho_private_boundary_safe_routine('public.fixture_candidate_identity_count()'::regprocedure);
 PERFORM public.zoho_assert_private_identity_boundary();
 BEGIN
  SET LOCAL ROLE anon;
  PERFORM email FROM public.users;
  RAISE EXCEPTION 'Browser read unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 -- A future privilege regression must immediately disable readiness again.
 GRANT EXECUTE ON FUNCTION public.fixture_candidate_identity_count() TO anon;
 BEGIN
  PERFORM public.zoho_assert_private_identity_boundary();
  RAISE EXCEPTION 'Callable private reader accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 REVOKE EXECUTE ON FUNCTION public.fixture_candidate_identity_count() FROM anon;
 PERFORM public.zoho_assert_private_identity_boundary();
END $$;
DROP FUNCTION public.fixture_candidate_identity_count();
DROP VIEW public.fixture_candidate_identity_reader;
