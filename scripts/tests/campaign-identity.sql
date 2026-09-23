\set ON_ERROR_STOP on
-- Run only in an isolated, disposable database.
do $$ begin
  if current_database() <> 'campaign_identity_test' then raise exception 'Disposable test database required'; end if;
end $$;
create table public.users (
 id uuid primary key default gen_random_uuid(), email text unique not null, password_hash text not null,
 is_email_verified boolean default false, is_blocked boolean default false,
 user_metadata jsonb default '{}', created_at timestamptz default now(), updated_at timestamptz default now()
);
create table public.organizations (id uuid primary key);
create table public.roles (id uuid primary key default gen_random_uuid(), name text unique);
create table public.memberships (id uuid primary key default gen_random_uuid(), user_id uuid references users(id), org_id uuid references organizations(id), status text, unique(user_id, org_id));
create table public.membership_roles (id uuid primary key default gen_random_uuid(), membership_id uuid references memberships(id), role_id uuid references roles(id), unique(membership_id, role_id));
create table public.sessions (
 id uuid primary key default gen_random_uuid(), user_id uuid references users(id), org_id uuid,
 refresh_token_hash text unique, revoked boolean default false, expires_at timestamptz,
 family_id uuid, family_created_at timestamptz, created_at timestamptz default now(), device_info jsonb
);
insert into organizations values ('11111111-1111-4111-8111-111111111111');
insert into roles(name) values ('learner'), ('admin');
\i /workspace/supabase/migrations/20260918000000_campaign_identity.sql

do $$
declare a jsonb; b jsonb; legacy uuid; blocked uuid; sess uuid := gen_random_uuid(); n bigint;
begin
 a := ensure_educator_campaign_user('NEW@example.test', 'New User', '9000000001', '11111111-1111-4111-8111-111111111111', 'test-only-hash');
 b := ensure_educator_campaign_user('new@example.test', 'New User', '9000000001', '11111111-1111-4111-8111-111111111111', 'different-hash');
 assert a = b, 'Retry changed identity';
 assert (select count(*) from campaign_memberships) = 1, 'Duplicate membership';
 assert (select count(*) from identity_sync_outbox) = 1, 'Duplicate outbox event';
 assert (select signup_app from users where id = (a->>'user_id')::uuid) = '100keducators', 'Missing signup origin';
 assert (select user_metadata->>'learner_id' from users where id = (a->>'user_id')::uuid) = a->>'educator_id', 'Missing educator ID';
 insert into users(email,password_hash,user_metadata,signup_app) values ('existing@example.test', 'existing-hash', '{"role":"admin","learner_id":"original","source":"original"}', 'skillpassport') returning id into legacy;
 perform ensure_educator_campaign_user('existing@example.test', 'Existing', '9000000002', '11111111-1111-4111-8111-111111111111', 'unused', 'LRN-OLD26-00000001');
 assert (select user_metadata->>'role' from users where id=legacy) = 'admin', 'Role overwritten';
 assert (select user_metadata->>'learner_id' from users where id=legacy) = 'original', 'Existing learner identity overwritten';
 assert (select signup_app from users where id=legacy) = 'skillpassport', 'Signup source overwritten';
 assert not exists(select 1 from memberships where user_id=legacy), 'Existing membership/role changed';
 begin
   perform ensure_educator_campaign_user('other@example.test', 'Other', '9000000003', '11111111-1111-4111-8111-111111111111', 'unused', 'LRN-OLD26-00000001');
   raise exception 'Expected educator collision';
 exception when unique_violation then null;
 end;
 assert not exists(select 1 from users where email='other@example.test'), 'Conflict left an orphan user';
 insert into users(email,password_hash,is_blocked) values ('blocked@example.test','hash',true) returning id into blocked;
 begin
   perform ensure_educator_campaign_user('blocked@example.test','Blocked','9000000004','11111111-1111-4111-8111-111111111111','unused');
   raise exception 'Expected blocked account rejection';
 exception when raise_exception then
   if sqlerrm <> 'Account is blocked' then raise; end if;
 end;
 insert into sessions(id,user_id,refresh_token_hash,expires_at,family_id,family_created_at)
 values(sess,legacy,'test-refresh-hash',now()+interval '1 day',sess,now());
 perform record_application_access('test-refresh-hash','skillpassport','login');
 perform record_application_access('test-refresh-hash','skillpassport','login');
 assert (select count(*) from application_access_events) = 1, 'Duplicate login count';
 perform record_application_access('test-refresh-hash','skillpassport','session_access');
 assert (select first_login_at is not null and last_access_at >= last_login_at from user_application_activity where user_id=legacy), 'Missing activity';
 update sessions set revoked=true where id=sess;
 begin
   perform record_application_access('test-refresh-hash','skillpassport','login');
   raise exception 'Expected revoked rejection';
 exception when raise_exception then
   if sqlerrm <> 'Session is not active' then raise; end if;
 end;
 assert not has_function_privilege('anon','public.ensure_educator_campaign_user(text,text,text,uuid,text,text)','execute'), 'Public provisioning RPC';
 assert not has_table_privilege('authenticated','public.campaign_memberships','select'), 'Public identity table';
end $$;
select 'campaign identity assertions passed' as result;
