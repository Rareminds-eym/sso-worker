import { readFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
const root = new URL('../../', import.meta.url);
const container = process.argv[2] || 'supabase_db_sso-auth';
if (!/^[a-zA-Z0-9_-]+$/.test(container)) throw new Error('Invalid local container name');
const database = `zoho_candidate_test_${process.pid}_${Date.now()}`;
const read = path => readFileSync(new URL(path, root), 'utf8');
function docker(args, input) {
  const result = spawnSync('docker', ['exec', ...(input ? ['-i'] : []), container, ...args], { input, encoding: 'utf8', timeout: 120000, maxBuffer: 2_000_000 });
  if (result.error || result.status !== 0) throw new Error(result.error?.message || result.stderr || 'Candidate fixture failed');
  return result.stdout;
}
function concurrentProvision(psql, grant) {
  // Base64 is a bounded SQL literal alphabet; JSON is never shell/SQL quoting.
  const encoded = Buffer.from(JSON.stringify(grant)).toString('base64');
  const sql = `BEGIN; SELECT public.zoho_provision_candidate(convert_from(decode('${encoded}','base64'),'UTF8')::jsonb); SELECT pg_sleep(0.15); COMMIT;`;
  return new Promise((resolve, reject) => {
    const child = spawn('docker', ['exec', container, ...psql, '-At', '-c', sql]);
    let stdout = ''; let stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Concurrent candidate transaction timed out')); }, 15000);
    child.stdout.on('data', part => { stdout += part; });
    child.stderr.on('data', part => { stderr += part; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) { reject(new Error(stderr || 'Concurrent candidate transaction rejected')); return; }
      try { resolve(JSON.parse(stdout.split('\n').find(line => line.startsWith('{')))); }
      catch (error) { reject(error); }
    });
  });
}
function holdProvision(psql, grant) {
  const encoded = Buffer.from(JSON.stringify(grant)).toString('base64');
  const child = spawn('docker', ['exec', '-i', container, ...psql, '-qAt']);
  let output = ''; let errors = ''; let ready;
  const holding = new Promise((resolve, reject) => { ready = { resolve, reject }; });
  const timer = setTimeout(() => { child.kill(); ready.reject(new Error('Context lock fixture timed out')); }, 15000);
  const closed = new Promise((resolve, reject) => {
    child.stdout.on('data', data => { output += data; if (output.includes('CONTEXT_LOCKS_HELD\n')) ready.resolve(); });
    child.stderr.on('data', data => { errors += data; });
    child.on('error', error => { clearTimeout(timer); ready.reject(error); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) { const error = new Error(errors || 'Context lock fixture failed'); ready.reject(error); reject(error); }
      else { ready.reject(new Error('Context lock fixture ended before ready')); resolve(); }
    });
  });
  // Attach a rejection handler before awaiting readiness; always await completion below.
  void closed.catch(() => {});
  child.stdin.write(`BEGIN; SELECT public.zoho_provision_candidate(convert_from(decode('${encoded}','base64'),'UTF8')::jsonb); SELECT 'CONTEXT_LOCKS_HELD';\n`);
  return { holding, finish: async () => { child.stdin.end('ROLLBACK;\n'); await closed; } };
}
function assertRevocationBlocked(psql, sql) {
  const result = spawnSync('docker', ['exec', container, ...psql, '-v', 'VERBOSITY=verbose', '-c', `SET lock_timeout='200ms'; ${sql}`],
    { encoding: 'utf8', timeout: 5000 });
  if (result.error || result.status === 0 || !result.stderr.includes('55P03'))
    throw new Error('Concurrent context revocation was not fenced by the candidate transaction');
}
let created = false;
try {
  docker(['createdb', '-U', 'postgres', '--template=template0', database]); created = true;
  const psql = ['psql', '-U', 'postgres', '-d', database, '-v', 'ON_ERROR_STOP=1'];
  // Use the actual canonical table definitions, constraints, indexes and personal-
  // subscription trigger. Omit unrelated extensions, catalog seed data and RPC grants.
  const baseline = read('supabase/migrations/20260526000000_schema.sql');
  const tables = ['users','organizations','products','roles','memberships','membership_roles','membership_products','plans','subscriptions','organization_products','oauth_accounts'];
  const tableSet = new Set(tables);
  const definitions = tables.map(name => {
    const match = baseline.match(new RegExp(`CREATE TABLE IF NOT EXISTS "public"\\."${name}" \\([\\s\\S]*?\\n\\);`));
    if (!match) throw new Error(`Missing canonical table ${name}`);
    return match[0];
  });
  const claimsFunction = baseline.match(/CREATE OR REPLACE FUNCTION "public"\."get_jwt_claims"[\s\S]*?\$\$;/)?.[0];
  if (!claimsFunction) throw new Error('Missing canonical claim resolver');
  definitions.push(claimsFunction);
  const constraints = [...baseline.matchAll(/ALTER TABLE ONLY "public"\."([^"]+)"\s+ADD CONSTRAINT [\s\S]*?;/g)]
    .filter(match => tableSet.has(match[1])).map(match => match[0]);
  const indexes = [...baseline.matchAll(/CREATE (?:UNIQUE )?INDEX [^\n]+ ON "public"\."([^"]+)"[^\n]+;/g)]
    .filter(match => tableSet.has(match[1])).map(match => match[0]);
  const triggerFunction = baseline.match(/CREATE OR REPLACE FUNCTION "public"\."check_duplicate_active_subscription"\(\)[\s\S]*?\$\$;/)?.[0];
  if (!triggerFunction) throw new Error('Missing canonical subscription trigger');
  const timestampFunction = baseline.match(/CREATE OR REPLACE FUNCTION "public"\."set_updated_at"\(\)[\s\S]*?\$\$;/)?.[0];
  if (!timestampFunction) throw new Error('Missing actual canonical timestamp trigger');
  const timestampTriggers = ['trg_plans_updated_at','trg_subscriptions_updated_at'].map(name => {
    const definition = baseline.match(new RegExp(`CREATE OR REPLACE TRIGGER "${name}"[^\\n]+;`))?.[0];
    if (!definition) throw new Error(`Missing actual canonical timestamp trigger ${name}`);
    return definition;
  });
  docker(psql, [...definitions, ...constraints, ...indexes, triggerFunction, timestampFunction, ...timestampTriggers,
    'CREATE TRIGGER trg_check_duplicate_active BEFORE INSERT ON public.subscriptions FOR EACH ROW EXECUTE FUNCTION public.check_duplicate_active_subscription();',
    read('supabase/migrations/20260618000000_add_user_metadata_column.sql'),
    read('supabase/migrations/20261030000000_zoho_import_approver_authority.sql'),
    read('supabase/migrations/20261031000000_zoho_import_approval_evidence.sql'),
    read('supabase/migrations/20261101000000_zoho_candidate_canonical_transaction.sql'),
    read('supabase/migrations/20261102000000_zoho_candidate_projection_delivery.sql'),
    read('supabase/migrations/20261103000000_zoho_candidate_review.sql'),
    read('supabase/migrations/20261104000000_zoho_candidate_runtime_readiness.sql'),
    read('supabase/migrations/20261105000000_zoho_candidate_sync_policy.sql'),
    read('supabase/migrations/20270226010000_zoho_publication_batch.sql'),
  ].join('\n'));
  // The canonical fixture is explicitly server-only. Baseline application grants
  // are not silently changed by production migrations.
  docker(psql, `DO $$ DECLARE f record; BEGIN
    FOR f IN SELECT p.oid::regprocedure AS signature FROM pg_proc p
      JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prosecdef
    LOOP EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,anon,authenticated',f.signature); END LOOP;
  END $$;
  SELECT public.zoho_assert_private_identity_boundary();
  GRANT SELECT ON public.users TO anon;
  DO $$ BEGIN
    BEGIN PERFORM public.zoho_assert_private_identity_boundary(); RAISE EXCEPTION 'Browser-readable identity accepted';
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  END $$;
  REVOKE SELECT ON public.users FROM anon;`);
  docker(psql, ['BEGIN;', read('src/__tests__/sql/zoho-candidate.sql'), read('src/__tests__/sql/zoho-candidate-review.sql'), read('src/__tests__/sql/zoho-candidate-version.sql'), read('src/__tests__/sql/zoho-candidate-delivery.sql'), read('src/__tests__/sql/zoho-candidate-readiness.sql'), 'ROLLBACK;'].join('\n'));
  // Separate real sessions exercise operation idempotency and competing create intents.
  const fixtures = read('src/__tests__/sql/zoho-candidate.sql').split('DO $$\nDECLARE grant_value')[0].replaceAll('pg_temp.', 'fixture.');
  docker(psql, 'CREATE SCHEMA fixture;\n'+fixtures);
  const grant = (email, external, target) => JSON.parse(docker([...psql, '-At', '-c', `SELECT fixture.candidate_grant('${email}','${external}'${target ? `,'${target}'::uuid` : ''});`]).trim());
  const first = grant('concurrent@fixture.example', '42');
  const same = await Promise.all([concurrentProvision(psql, first), concurrentProvision(psql, first)]);
  if (same[0].receiptId !== same[1].receiptId || same[0].targetId !== same[1].targetId) throw new Error('Concurrent operation produced different effects');
  if (!/^[0-9a-f-]{36}$/.test(same[0].targetId)) throw new Error('Invalid fixture target');
  const context = holdProvision(psql, grant('concurrent@fixture.example', '45', same[0].targetId));
  try {
    await context.holding;
    assertRevocationBlocked(psql, `UPDATE public.organization_products SET active=false WHERE org_id='00000000-0000-0000-0000-000000000001';`);
    assertRevocationBlocked(psql, `DELETE FROM public.membership_products WHERE membership_id IN (SELECT id FROM public.memberships WHERE user_id='${same[0].targetId}');`);
    assertRevocationBlocked(psql, `UPDATE public.memberships SET status='inactive' WHERE user_id='${same[0].targetId}';`);
    assertRevocationBlocked(psql, `DELETE FROM public.membership_roles WHERE membership_id IN (SELECT id FROM public.memberships WHERE user_id='${same[0].targetId}');`);
    assertRevocationBlocked(psql, `INSERT INTO public.membership_roles(membership_id,role_id) SELECT id,'10000000-0000-4000-8000-000000000003'::uuid FROM public.memberships WHERE user_id='${same[0].targetId}';`);
  } finally { await context.finish(); }
  const competing = await Promise.allSettled([
    concurrentProvision(psql, grant('competing@fixture.example','43')),
    concurrentProvision(psql, grant('competing@fixture.example','44')),
  ]);
  if (competing.filter(result => result.status === 'fulfilled').length !== 1) throw new Error('Competing create intents did not fence the unreviewed identity');
  docker(psql, `DO $$ BEGIN
    ASSERT (SELECT count(*)=3 FROM public.users);
    ASSERT (SELECT count(*)=2 FROM public.zoho_candidate_receipts);
    ASSERT (SELECT count(*)=2 FROM public.zoho_candidate_outbox);
    ASSERT (SELECT count(*)=2 FROM public.subscriptions);
    ASSERT (SELECT count(*)=2 FROM public.zoho_candidate_links);
  END $$;`);
  // Upgrade the same actual schema after legacy regressions: fresh contracts add
  // separately approved context grants and irreversible connector replay fences.
  docker(psql, read('supabase/migrations/20270217020000_zoho_candidate_administration.sql'));
  docker(psql, ['BEGIN;', read('src/__tests__/sql/zoho-candidate-administration.sql'), 'ROLLBACK;'].join('\n'));
  docker(psql, read('supabase/migrations/20270218010000_zoho_administration_recovery.sql'));
  docker(psql, read('supabase/seed/dev/20270218010000_seed_zoho_administration_recovery.sql'));
  docker(psql, read('supabase/seed/dev/20270218010000_seed_zoho_administration_recovery.sql'));
  const recoverySeed=read('supabase/seed/dev/20270218010000_seed_zoho_administration_recovery.sql').trim().slice('BEGIN;'.length,-'COMMIT;'.length);
  docker(psql, ['BEGIN;', read('src/__tests__/sql/zoho-administration-recovery.sql'),
    'CREATE TEMP TABLE seed_fences_before AS TABLE public.zoho_candidate_administration_fences;',
    'CREATE TEMP TABLE seed_operations_before AS TABLE public.zoho_candidate_administration_operations;',
    recoverySeed,recoverySeed,
    `DO $$ BEGIN
      ASSERT NOT EXISTS((TABLE seed_fences_before EXCEPT TABLE public.zoho_candidate_administration_fences)
        UNION ALL(TABLE public.zoho_candidate_administration_fences EXCEPT TABLE seed_fences_before));
      ASSERT NOT EXISTS((TABLE seed_operations_before EXCEPT TABLE public.zoho_candidate_administration_operations)
        UNION ALL(TABLE public.zoho_candidate_administration_operations EXCEPT TABLE seed_operations_before));
    END $$;`, 'ROLLBACK;'].join('\n'));
  docker(psql,'CREATE EXTENSION IF NOT EXISTS pg_graphql;\nGRANT SELECT ON public.users TO service_role;\nCREATE VIEW public.fixture_candidate_identity_reader AS SELECT id,email FROM public.users;\nGRANT SELECT ON public.fixture_candidate_identity_reader TO anon;\nGRANT SELECT(email) ON public.users TO authenticated;\nCREATE FUNCTION public.fixture_candidate_identity_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER\n SET search_path=pg_catalog,public AS $$ SELECT count(*) FROM public.users $$;\nGRANT EXECUTE ON FUNCTION public.fixture_candidate_identity_count() TO PUBLIC;\n');
  docker(psql,read('supabase/migrations/20270312000000_zoho_identity_server_boundary.sql'));
  docker(psql,read('src/__tests__/sql/zoho-server-identity-boundary.sql'));
  console.log('Canonical candidate SQL regressions, two-session operation/identity races and context-revocation fencing passed in a disposable database using actual SSO constraints and subscription trigger.');
} finally { if (created) docker(['dropdb', '-U', 'postgres', database]); }
