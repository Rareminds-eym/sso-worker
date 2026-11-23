import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';

// Actual installed local SSO objects only. No migrations, application startup,
// account provisioning, credentials, network clients or committed fixture data.
assert.ok(process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === '--storage-only'),
  'Only read-only preflight or explicit --storage-only is supported; permission-denial execution is blocked');
const container = 'supabase_db_sso-auth';
const cluster = '7699357049590226983';
function sql(input, readOnly = false) {
  const result = spawnSync('docker', ['exec', '-i', ...(readOnly
    ? ['-e', 'PGOPTIONS=-c default_transaction_read_only=on'] : []), container,
    'psql', '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'],
  { input, encoding: 'utf8', timeout: 45000, maxBuffer: 1024 * 1024 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
const fingerprint = table => `(SELECT jsonb_build_object('count',count(*),'digest',
  md5(coalesce(string_agg(md5(to_jsonb(t)::text),'' ORDER BY id),''))) FROM public.${table} t)`;
const baselineSql = `SELECT jsonb_build_object('cluster',(SELECT system_identifier::text FROM pg_control_system()),
  'plans',${fingerprint('plans')},'subscriptions',${fingerprint('subscriptions')},
  'transactions',${fingerprint('transactions')},'drafts',${fingerprint('subscription_plan_drafts')});`;
const before = JSON.parse(sql(baselineSql, true));
assert.equal(before.cluster, cluster, 'Local SSO cluster differs from reviewed target');
if (process.argv.length === 2) {
  console.log(JSON.stringify({ mode: 'read-only-preflight', counts: Object.fromEntries(
    ['plans', 'subscriptions', 'transactions', 'drafts'].map(key => [key, before[key].count])) }));
  console.log('LOCAL_DRAFT_SQL_PREFLIGHT_VERIFIED');
  process.exit(0);
}
// Unprivileged RPC attempts crashed this PostgreSQL build both inside DO and
// as plain SELECT. Do not execute permission-denial probes here. Storage-only
// is an explicit test scope, not a substitute for the blocked privilege gate.

const plan = randomUUID(), draft = randomUUID(), credits = randomUUID();
const code = `pln_${plan.replaceAll('-', '')}`;
let cases = 0;
const blocks = [];
function positive(body, role = 'service_role') {
  cases++;
  blocks.push(`SET LOCAL ROLE ${role}; DO $case$ DECLARE r jsonb; BEGIN ${body} END $case$; RESET ROLE;`);
}
function negative(statement, state, message, role = 'service_role') {
  cases++;
  blocks.push(`SET LOCAL ROLE ${role}; DO $case$ BEGIN
    BEGIN ${statement}; RAISE EXCEPTION 'TEST_EXPECTED_FAILURE_NOT_OBSERVED';
    EXCEPTION WHEN SQLSTATE '${state}' THEN
      IF SQLERRM NOT LIKE '${message}' THEN RAISE EXCEPTION 'Unexpected failure: %', SQLERRM; END IF;
    END; END $case$; RESET ROLE;`);
}
const d = "current_setting('subscription_sql.draft')::jsonb";
const c = "current_setting('subscription_sql.credits')::jsonb";
const a = "current_setting('subscription_sql.actor')::uuid";
const call = (draftValue = d, creditValue = c, actor = a) =>
  `public.stage_subscription_plan_draft(${draftValue},${actor},${creditValue})`;
positive(`r := ${call()};
  IF r->'draft' IS DISTINCT FROM ${d} OR r->'includedCredits' IS DISTINCT FROM ${c}
    OR r->>'stagedBy' IS DISTINCT FROM ${a}::text OR r->>'stagedAt' IS NULL
    THEN RAISE EXCEPTION 'Persisted receipt differs'; END IF;
  PERFORM set_config('subscription_sql.receipt',r::text,true);`);
positive(`r := ${call()}; IF r IS DISTINCT FROM current_setting('subscription_sql.receipt')::jsonb
  THEN RAISE EXCEPTION 'Replay changed content or timestamp'; END IF;
  IF (SELECT count(*) FROM public.subscription_plan_drafts WHERE plan_id='${plan}') <> 1
  THEN RAISE EXCEPTION 'Replay inserted duplicate'; END IF;`);
negative(`PERFORM ${call(`jsonb_set(${d},'{name}','"Changed"')`)}`, 'P0001', 'Subscription plan draft replay conflicts%');
negative(`PERFORM ${call(d, `jsonb_set(${c},'{id}',to_jsonb('${randomUUID()}'::text))`)}`, 'P0001', 'Subscription plan draft replay conflicts%');
negative(`PERFORM ${call(d, c, `'${randomUUID()}'::uuid`)}`, 'P0001', 'Subscription plan draft replay conflicts%');
negative(`PERFORM ${call(`jsonb_set(${d},'{id}',to_jsonb('${randomUUID()}'::text))`,
  `jsonb_set(${c},'{revisionId}',to_jsonb('${randomUUID()}'::text))`)}`, 'P0001', 'Invalid included credit binding');
const nextId = randomUUID();
const next = `jsonb_set(jsonb_set(${d},'{id}',to_jsonb('${nextId}'::text)),'{revisionNumber}','2')`;
const nextCredits = `jsonb_set(${c},'{revisionId}',to_jsonb('${nextId}'::text))`;
negative(`PERFORM ${call(`jsonb_set(${next},'{revisionNumber}','3')`, nextCredits)}`, 'P0001', 'Subscription plan draft must use the next revision number');
negative(`PERFORM ${call(`jsonb_set(${next},'{revisionNumber}','1')`, nextCredits)}`, 'P0001', 'Subscription plan draft must use the next revision number');
negative(`PERFORM ${call(`jsonb_set(${d},'{plan,code}',to_jsonb('pln_${randomUUID().replaceAll('-', '')}'::text))`)}`, 'P0001', 'Subscription plan identity does not match%');
negative(`PERFORM ${call(`jsonb_set(${d},'{plan,productId}',to_jsonb('${randomUUID()}'::text))`)}`, 'P0001', 'Subscription plan identity does not match%');
negative(`PERFORM ${call(d, 'NULL')}`, 'P0001', 'Schema 2 requires included credit terms');
negative(`PERFORM ${call(`(${d} || '{"actor":"untrusted"}'::jsonb)`)}`, 'P0001', 'Invalid subscription plan draft');
// Owner attempts distinguish immutable trigger enforcement from role privileges.
negative(`UPDATE public.subscription_plan_drafts SET staged_at=clock_timestamp() WHERE id='${draft}'`, 'P0001', 'Subscription plan drafts are immutable', 'postgres');
negative(`DELETE FROM public.subscription_plan_drafts WHERE id='${draft}'`, 'P0001', 'Subscription plan drafts are immutable', 'postgres');
// No owner TRUNCATE test: it could lock unrelated referencing tables.
positive(`r := ${call(next, nextCredits)};
  IF r#>>'{draft,revisionNumber}' <> '2' OR (SELECT count(*) FROM public.subscription_plan_drafts WHERE plan_id='${plan}') <> 2
  THEN RAISE EXCEPTION 'Next revision missing'; END IF;`);
const transaction = `BEGIN;
SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='2s';
DO $fixture$ DECLARE actor uuid; BEGIN
  IF (SELECT system_identifier::text FROM pg_control_system()) <> '${cluster}'
    THEN RAISE EXCEPTION 'Wrong local cluster'; END IF;
  SELECT id INTO actor FROM public.users ORDER BY id LIMIT 1;
  IF actor IS NULL THEN RAISE EXCEPTION 'Missing existing FK actor; no account provisioning authorized'; END IF;
  PERFORM set_config('subscription_sql.actor',actor::text,true);
  INSERT INTO public.plans(id,plan_code,name,business_type,product_id,is_active)
    SELECT '${plan}','${code}','Subscription SQL rollback fixture',business_type,product_id,false
    FROM public.plans ORDER BY id LIMIT 1;
  IF NOT FOUND THEN RAISE EXCEPTION 'Missing canonical plan/product prerequisite'; END IF;
  PERFORM set_config('subscription_sql.draft',jsonb_build_object('schemaVersion',2,'id','${draft}',
    'plan',jsonb_build_object('id','${plan}','code','${code}','productId',(SELECT product_id FROM public.plans WHERE id='${plan}')),
    'revisionNumber',1,'name','SQL storage fixture','audiences',jsonb_build_array('learner'),
    'purchaseMode','contact_sales','prices','[]'::jsonb,'features','[]'::jsonb)::text,true);
  PERFORM set_config('subscription_sql.credits',jsonb_build_object('schemaVersion',1,'id','${credits}',
    'revisionId','${draft}','funding','included','rules','[]'::jsonb)::text,true);
END $fixture$;
${blocks.join('\n')}
ROLLBACK;
SELECT 'DRAFT_SQL_TRANSACTION_ROLLED_BACK';`;
// psql exits on the first error. Closing the connection also aborts an unfinished
// transaction, including when an assertion fails before explicit ROLLBACK.
let executionError;
try {
  assert.equal(sql(transaction), 'DRAFT_SQL_TRANSACTION_ROLLED_BACK');
} catch (error) { executionError = error; }
let after;
try { after = JSON.parse(sql(baselineSql, true)); }
catch (error) {
  throw new AggregateError([...(executionError ? [executionError] : []), error],
    'SQL execution or post-test verification failed; do not rerun without inspecting database diagnostics');
}
assert.deepEqual(after, before, 'Persistent rows changed during test; inspect concurrent activity before attributing cause');
if (executionError) throw executionError;
console.log(`${cases} actual local SQL assertions passed; plans, subscriptions, transactions and drafts retain count and aggregate digest.`);
console.log('Storage-only: permission-denial, authenticated backend and concurrent-writer tests remain unverified.');
console.log('LOCAL_DRAFT_STORAGE_SQL_VERIFIED');
