BEGIN;
SET LOCAL search_path=pg_catalog,public;
-- Canonical identity is owned by SSO. Browser clients use signed application
-- APIs; they must never read passwords, imported contacts or membership writes.
-- Keep all existing service-role table privileges and ordinary public catalogs.
-- Supabase owns two browser-callable pg_graphql metadata helpers. They do
-- not read identities. Attest exact extension-owned definitions, not names or
-- whole schemas; any implementation drift makes the boundary fail closed.
CREATE FUNCTION public.zoho_private_boundary_safe_routine(p_oid oid) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $safe$
 SELECT EXISTS(
  SELECT 1 FROM pg_proc p JOIN pg_depend d ON d.classid='pg_proc'::regclass
   AND d.objid=p.oid AND d.refclassid='pg_extension'::regclass AND d.deptype='e'
   JOIN pg_extension e ON e.oid=d.refobjid
  WHERE p.oid=p_oid AND e.extname='pg_graphql'
   AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex') IN (
    'f61f2f82caf3e62d73892d1767b3419fa1ce354371acca1636afd73f9f3b4840',
    '0e461d6c599638cc70f1e14d4175b3f002709e08b55e27b16b7b17245e9f00b8')
   AND EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='graphql' AND c.relname='seq_schema_version' AND c.relkind='S')
 );
$safe$;
REVOKE ALL ON FUNCTION public.zoho_private_boundary_safe_routine(oid) FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION public.zoho_assert_private_identity_boundary_before_administration() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF EXISTS (
    WITH RECURSIVE protected(oid) AS (
      SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname IN ('users','memberships','membership_roles','membership_products','subscriptions','oauth_accounts',
          'zoho_candidate_links','zoho_candidate_receipts','zoho_candidate_outbox','zoho_candidate_reviews','zoho_import_approvals')
      UNION
      SELECT r.ev_class FROM protected p
        JOIN pg_depend d ON d.refobjid=p.oid AND d.refclassid='pg_class'::regclass
          AND d.classid='pg_rewrite'::regclass
        JOIN pg_rewrite r ON r.oid=d.objid WHERE r.ev_class<>p.oid
    )
    SELECT 1 FROM protected p CROSS JOIN (VALUES ('anon'),('authenticated')) AS browser(role)
    WHERE has_table_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE,DELETE')
       OR has_any_column_privilege(browser.role,p.oid,'SELECT,INSERT,UPDATE')
  ) OR EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
      AND NOT public.zoho_private_boundary_safe_routine(p.oid)
      AND (has_schema_privilege('anon',n.oid,'USAGE') AND has_function_privilege('anon',p.oid,'EXECUTE')
        OR has_schema_privilege('authenticated',n.oid,'USAGE') AND has_function_privilege('authenticated',p.oid,'EXECUTE'))
  ) THEN
    RAISE EXCEPTION 'Private identity requires a verified server-only data boundary' USING ERRCODE='42501';
  END IF;
END;
$$;

DO $boundary$
DECLARE relation record; columns text; routine record;
BEGIN
 FOR relation IN
  WITH RECURSIVE protected(oid) AS (
   SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname IN ('users','memberships','membership_roles','membership_products','subscriptions','oauth_accounts')
   UNION
   SELECT r.ev_class FROM protected p JOIN pg_depend d ON d.refobjid=p.oid
    AND d.refclassid='pg_class'::regclass AND d.classid='pg_rewrite'::regclass
    JOIN pg_rewrite r ON r.oid=d.objid WHERE r.ev_class<>p.oid
  ) SELECT c.oid,n.nspname,c.relname FROM protected p
   JOIN pg_class c ON c.oid=p.oid JOIN pg_namespace n ON n.oid=c.relnamespace
 LOOP
  EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM PUBLIC,anon,authenticated',relation.nspname,relation.relname);
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns
   FROM pg_attribute WHERE attrelid=relation.oid AND attnum>0 AND NOT attisdropped;
  IF columns IS NOT NULL THEN
   EXECUTE format('REVOKE SELECT (%s),INSERT (%s),UPDATE (%s),REFERENCES (%s) ON TABLE %I.%I FROM PUBLIC,anon,authenticated',
    columns,columns,columns,columns,relation.nspname,relation.relname);
  END IF;
  IF EXISTS(SELECT 1 FROM (VALUES('anon'),('authenticated')) browser(role)
   WHERE has_table_privilege(browser.role,relation.oid,'SELECT,INSERT,UPDATE,DELETE')
    OR has_any_column_privilege(browser.role,relation.oid,'SELECT,INSERT,UPDATE')) THEN
   RAISE EXCEPTION 'Browser identity privileges remain on %.%',relation.nspname,relation.relname;
  END IF;
 END LOOP;
 -- SECURITY DEFINER helpers can bypass base-table grants. Preserve effective
 -- server access before removing inherited PUBLIC access, including trigger
 -- helpers: installed triggers continue to execute under their existing owner.
 FOR routine IN
  SELECT p.oid::regprocedure::text AS signature,
   has_function_privilege('service_role',p.oid,'EXECUTE') AS server_access
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE p.prosecdef AND p.prokind='f' AND n.nspname NOT IN ('pg_catalog','information_schema')
   AND NOT public.zoho_private_boundary_safe_routine(p.oid)
   AND (has_schema_privilege('anon',n.oid,'USAGE') AND has_function_privilege('anon',p.oid,'EXECUTE')
    OR has_schema_privilege('authenticated',n.oid,'USAGE') AND has_function_privilege('authenticated',p.oid,'EXECUTE'))
 LOOP
  EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC,anon,authenticated',routine.signature);
  IF routine.server_access THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',routine.signature); END IF;
 END LOOP;
END $boundary$;

-- The default platform must offer SkillPassport before its verified freemium
-- learner plan can be used. This creates no user, membership or subscription.
INSERT INTO public.organization_products(org_id,product_id,active)
 SELECT '00000000-0000-0000-0000-000000000001'::uuid,id,true FROM public.products WHERE code='skillpassport'
 ON CONFLICT(org_id,product_id) DO UPDATE SET active=true;
SELECT public.zoho_assert_private_identity_boundary();
NOTIFY pgrst,'reload schema';
COMMIT;
