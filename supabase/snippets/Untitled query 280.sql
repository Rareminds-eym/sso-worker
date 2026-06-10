SELECT routine_name
FROM information_schema.routines
WHERE routine_schema = 'public'
AND routine_name = 'get_sso_user_by_email';
SELECT
    routine_name,
    specific_name
FROM information_schema.routines
WHERE routine_name = 'get_sso_user_by_email';
SELECT * FROM get_sso_user_by_email('test@test.com');