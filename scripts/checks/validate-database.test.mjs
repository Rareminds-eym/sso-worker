import {test} from 'node:test';
import assert from 'node:assert/strict';
import {migrationDataCommands} from './validate-database.mjs';
test('allows catalog-driven permission and index DDL in executed blocks',()=>{
 for(const sql of [
  `DO $$ BEGIN EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM anon',object.nspname,object.relname); END $$;`,
  `DO $$ BEGIN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',capability.identity); END $$;`,
  `DO $$ BEGIN SELECT n.nspname INTO STRICT extension_schema FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_trgm'; EXECUTE format('CREATE INDEX test ON public.records USING gin (name %I.gin_trgm_ops)',extension_schema); END $$;`,
 ])assert.deepEqual(migrationDataCommands(sql),[]);
});
test('still rejects real data writes, opaque calls and dynamic SQL',()=>{
 for(const sql of [
  'UPDATE public.records SET name=1;',
  'WITH rows AS (SELECT 1) INSERT INTO public.records SELECT * FROM rows;',
  `DO $$ BEGIN EXECUTE 'DELETE FROM public.records'; END $$;`,
  `DO $$ BEGIN EXECUTE format('%s',command); END $$;`,
  `DO $$ BEGIN EXECUTE format('CREATE INDEX x ON public.records(name); DELETE FROM public.records'); END $$;`,
  `DO $$ BEGIN EXECUTE 'REVOKE ALL ON TABLE public.records FROM anon' || unsafe; END $$;`,
  `DO $$ BEGIN PERFORM public.mutate_data(); END $$;`,
  `DO $$ BEGIN SELECT * INTO snapshot FROM public.records; END $$;`,
 ])assert.ok(migrationDataCommands(sql).length>0,sql);
});
