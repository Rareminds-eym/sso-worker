import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// Uses only a disposable synthetic DB in a local Supabase container. No app DB,
// source secrets, account/session/subscription writer or email binding is used.
const root = new URL('../../', import.meta.url);
const container = process.argv[2] || 'supabase_db_sso-auth';
if (!/^[a-zA-Z0-9_-]+$/.test(container)) throw new Error('Invalid local container name');
const database = `zoho_approver_test_${process.pid}_${Date.now()}`;
function docker(args, input) {
  const result = spawnSync('docker', ['exec', ...(input ? ['-i'] : []), container, ...args],
    { input, encoding: 'utf8', timeout: 120000, maxBuffer: 2_000_000 });
  if (result.error || result.status !== 0) throw new Error(result.error?.message || result.stderr || 'Local fixture command failed');
  return result.stdout;
}
const read = path => readFileSync(new URL(path, root), 'utf8');
let created = false;
try {
  docker(['createdb', '-U', 'postgres', '--template=template0', database]);
  created = true;
  const psql = ['psql', '-U', 'postgres', '-d', database, '-v', 'ON_ERROR_STOP=1'];
  docker(psql, `
    CREATE TABLE public.users(id uuid PRIMARY KEY,is_blocked boolean);
    CREATE TABLE public.memberships(id uuid PRIMARY KEY,user_id uuid,org_id uuid,status text);
    CREATE TABLE public.roles(id uuid PRIMARY KEY,name text);
    CREATE TABLE public.membership_roles(membership_id uuid,role_id uuid);
  `);
  docker(psql, read('supabase/migrations/20261030000000_zoho_import_approver_authority.sql'));
  docker(psql, read('supabase/migrations/20261031000000_zoho_import_approval_evidence.sql'));
  docker(psql, ['BEGIN;', read('src/__tests__/sql/zoho-approver.sql'), 'ROLLBACK;'].join('\n'));
  docker(psql, ['BEGIN;', read('src/__tests__/sql/zoho-approval-evidence.sql'), 'ROLLBACK;'].join('\n'));
  console.log('Restricted Zoho approver SQL checks passed in a disposable local database.');
} finally {
  if (created) docker(['dropdb', '-U', 'postgres', database]);
}
