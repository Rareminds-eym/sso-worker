-- ═══════════════════════════════════════════════════════════════
-- SSO Database Schema — Enterprise RBAC
-- ═══════════════════════════════════════════════════════════════

create extension if not exists "pgcrypto";

-- ─── Users ─────────────────────────────────────────────────────
create table if not exists users (
  id                uuid primary key default gen_random_uuid(),
  email             text not null unique,
  password_hash     text not null,
  is_email_verified boolean default false,
  is_blocked        boolean default false,
  last_login_at     timestamptz,
  created_at        timestamptz default now(),
  updated_at        timestamptz default now()
);

create index if not exists idx_users_email on users (email);

-- ─── Organizations ─────────────────────────────────────────────
create table if not exists organizations (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  slug       text not null unique,
  created_by uuid references users(id) on delete set null,
  metadata   jsonb default '{}',
  created_at timestamptz default now()
);

-- ─── Roles (lookup) ────────────────────────────────────────────
create table if not exists roles (
  id          uuid primary key default gen_random_uuid(),
  name        text not null unique,
  description text,
  created_at  timestamptz default now()
);

insert into roles (name, description) values
  ('owner', 'Organization owner with full access'),
  ('admin', 'Administrator with management access'),
  ('member', 'Regular organization member')
on conflict (name) do nothing;

-- ─── Products (lookup) ─────────────────────────────────────────
create table if not exists products (
  id          uuid primary key default gen_random_uuid(),
  code        text not null unique,   -- e.g. 'lte', 'erp'
  name        text not null,
  description text,
  created_at  timestamptz default now()
);

-- ─── Memberships ───────────────────────────────────────────────
create table if not exists memberships (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users(id) on delete cascade,
  org_id     uuid not null references organizations(id) on delete cascade,
  status     text not null default 'active'
             check (status in ('active', 'inactive', 'suspended', 'expired')),
  created_at timestamptz default now(),
  unique (user_id, org_id)
);

create index if not exists idx_memberships_user on memberships (user_id);
create index if not exists idx_memberships_org  on memberships (org_id);

-- ─── Membership Roles (many-to-many) ──────────────────────────
create table if not exists membership_roles (
  id            uuid primary key default gen_random_uuid(),
  membership_id uuid not null references memberships(id) on delete cascade,
  role_id       uuid not null references roles(id) on delete cascade,
  created_at    timestamptz default now(),
  unique (membership_id, role_id)
);

create index if not exists idx_membership_roles_mid on membership_roles(membership_id);
create index if not exists idx_membership_roles_rid on membership_roles(role_id);

-- ─── Organization Products (org subscriptions) ────────────────
create table if not exists organization_products (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references organizations(id) on delete cascade,
  product_id uuid not null references products(id) on delete cascade,
  active     boolean default true,
  created_at timestamptz default now(),
  unique (org_id, product_id)
);

create index if not exists idx_org_products_org     on organization_products(org_id);
create index if not exists idx_org_products_product on organization_products(product_id);

-- ─── Membership Products (per-user product access) ────────────
create table if not exists membership_products (
  id            uuid primary key default gen_random_uuid(),
  membership_id uuid not null references memberships(id) on delete cascade,
  product_id    uuid not null references products(id) on delete cascade,
  created_at    timestamptz default now(),
  unique (membership_id, product_id)
);

create index if not exists idx_membership_products_mid on membership_products(membership_id);
create index if not exists idx_membership_products_pid on membership_products(product_id);

-- ─── Sessions ──────────────────────────────────────────────────
create table if not exists sessions (
  id                  uuid primary key default gen_random_uuid(),
  user_id             uuid not null references users(id) on delete cascade,
  org_id              uuid references organizations(id) on delete cascade,
  refresh_token_hash  text not null,
  user_agent          text,
  ip_address          text,
  revoked             boolean default false,
  expires_at          timestamptz not null,
  created_at          timestamptz default now(),
  rotated_from        uuid references sessions(id),
  last_used_at        timestamptz,
  device_info         jsonb
);

create index if not exists idx_sessions_token   on sessions (refresh_token_hash);
create index if not exists idx_sessions_user    on sessions (user_id);
create index if not exists idx_sessions_org     on sessions (org_id);
create index if not exists idx_sessions_revoked on sessions (revoked, expires_at);

-- ─── OAuth Accounts (reserved for future OAuth/SSO provider support) ─
create table if not exists oauth_accounts (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid references users(id) on delete cascade,
  provider         text not null,
  provider_user_id text not null,
  created_at       timestamptz default now(),
  unique (provider, provider_user_id)
);

-- ─── Invites ───────────────────────────────────────────────────
create table if not exists invites (
  id          uuid primary key default gen_random_uuid(),
  email       text not null,
  org_id      uuid not null references organizations(id) on delete cascade,
  role        text[] default '{member}',
  token_hash  text unique,
  invited_by  uuid references users(id) on delete set null,
  expires_at  timestamptz,
  accepted    boolean default false,
  accepted_at timestamptz,
  created_at  timestamptz default now()
);

create index if not exists idx_invites_token_hash on invites (token_hash);
create index if not exists idx_invites_org         on invites (org_id);
create index if not exists idx_invites_email_org_active on invites (email, org_id, accepted) where accepted = false;

-- ─── Email Verifications ───────────────────────────────────────
create table if not exists email_verifications (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users(id) on delete cascade,
  token_hash text not null unique,
  used       boolean default false,
  expires_at timestamptz not null,
  created_at timestamptz default now()
);

create index if not exists idx_email_verifications_token_hash on email_verifications (token_hash);
create index if not exists idx_email_verifications_user        on email_verifications (user_id);

-- ─── Password Resets ───────────────────────────────────────────
create table if not exists password_resets (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users(id) on delete cascade,
  token_hash text not null unique,
  used       boolean default false,
  expires_at timestamptz not null,
  created_at timestamptz default now()
);

create index if not exists idx_password_resets_token_hash on password_resets (token_hash);
create index if not exists idx_password_resets_user       on password_resets (user_id);

-- ─── Audit Logs ───────────────────────────────────────────────
create table if not exists audit_logs (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid references users(id) on delete set null,
  org_id     uuid references organizations(id) on delete set null,
  action     text,
  metadata   jsonb,
  ip_address text,
  user_agent text,
  created_at timestamptz default now()
);

create index if not exists idx_audit_user on audit_logs (user_id);
create index if not exists idx_audit_org  on audit_logs (org_id);

-- ─── RLS ───────────────────────────────────────────────────────
alter table users                enable row level security;
alter table organizations        enable row level security;
alter table roles                enable row level security;
alter table products             enable row level security;
alter table memberships          enable row level security;
alter table membership_roles     enable row level security;
alter table organization_products enable row level security;
alter table membership_products  enable row level security;
alter table sessions             enable row level security;
alter table invites              enable row level security;
alter table audit_logs           enable row level security;
alter table oauth_accounts       enable row level security;
alter table email_verifications  enable row level security;
alter table password_resets      enable row level security;

-- ─── RLS Deny-All Policies ─────────────────────────────────────
-- All access goes through the service_role key (bypasses RLS).
-- These policies ensure the anon key gets zero access if accidentally used.

do $$ 
declare
  tbl text;
begin
  for tbl in 
    select unnest(array[
      'users', 'organizations', 'roles', 'products',
      'memberships', 'membership_roles', 'organization_products', 'membership_products',
      'sessions', 'invites', 'audit_logs', 'oauth_accounts',
      'email_verifications', 'password_resets'
    ])
  loop
    execute format(
      'create policy if not exists "deny_all_%s" on %I for all to anon using (false) with check (false)',
      tbl, tbl
    );
  end loop;
end $$;

-- ─── Triggers ──────────────────────────────────────────────────
create or replace function set_updated_at()
returns trigger as $fn$
begin
  new.updated_at = now();
  return new;
end;
$fn$ language plpgsql;

drop trigger if exists trg_users_updated_at on users;
create trigger trg_users_updated_at
  before update on users
  for each row execute function set_updated_at();

-- ─── Functions ─────────────────────────────────────────────────

create or replace function cleanup_expired_sessions()
returns integer as $fn$
declare
  deleted_count integer;
begin
  delete from sessions
  where revoked = true or expires_at < now();
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$fn$ language plpgsql;

-- Cleanup expired tokens from email_verifications, password_resets, and invites
-- Returns the total number of rows deleted
create or replace function cleanup_expired_tokens()
returns integer as $fn$
declare
  v_deleted integer := 0;
  v_count integer;
begin
  -- Expired email verifications (48h buffer past 24h expiry)
  delete from email_verifications
  where expires_at < now() - interval '48 hours';
  get diagnostics v_count = row_count;
  v_deleted := v_deleted + v_count;

  -- Expired password resets (2h buffer past 1h expiry)
  delete from password_resets
  where expires_at < now() - interval '2 hours';
  get diagnostics v_count = row_count;
  v_deleted := v_deleted + v_count;

  -- Expired invites (14d buffer past 7d expiry)
  delete from invites
  where expires_at < now() - interval '14 days';
  get diagnostics v_count = row_count;
  v_deleted := v_deleted + v_count;

  return v_deleted;
end;
$fn$ language plpgsql security definer;

-- Single-query JWT claims generation
create or replace function get_jwt_claims(
  p_user_id uuid,
  p_org_id  uuid
) returns jsonb
language sql stable
set search_path = public
as $$
  select jsonb_build_object(
    'roles', coalesce(
      (select array_agg(distinct r.name order by r.name)
       from membership_roles mr
       join roles r on r.id = mr.role_id
       where mr.membership_id = m.id),
      '{}'::text[]),
    'products', coalesce(
      (select array_agg(distinct p.code order by p.code)
       from membership_products mp
       join products p on p.id = mp.product_id
       join organization_products op
         on op.product_id = mp.product_id
         and op.org_id = m.org_id
         and op.active = true
       where mp.membership_id = m.id),
      '{}'::text[]),
    'membership_status', m.status
  )
  from memberships m
  where m.user_id = p_user_id
    and m.org_id = p_org_id
  limit 1;
$$;

-- Signup: creates user, org, membership, assigns 'owner' role
create or replace function signup_user(
  p_email         text,
  p_password_hash text,
  p_org_name      text,
  p_org_slug      text
) returns jsonb
language plpgsql
set search_path = public
as $$
declare
  v_user_id       uuid;
  v_org_id        uuid;
  v_membership_id uuid;
  v_owner_role_id uuid;
  v_slug          text := p_org_slug;
begin
  insert into users (email, password_hash, is_email_verified)
  values (p_email, p_password_hash, false)
  returning id into v_user_id;

  begin
    insert into organizations (name, slug, created_by)
    values (p_org_name, v_slug, v_user_id)
    returning id into v_org_id;
  exception when unique_violation then
    v_slug := v_slug || '-' || substr(gen_random_uuid()::text, 1, 6);
    insert into organizations (name, slug, created_by)
    values (p_org_name, v_slug, v_user_id)
    returning id into v_org_id;
  end;

  insert into memberships (user_id, org_id, status)
  values (v_user_id, v_org_id, 'active')
  returning id into v_membership_id;

  select id into v_owner_role_id from roles where name = 'owner';
  insert into membership_roles (membership_id, role_id)
  values (v_membership_id, v_owner_role_id);

  return jsonb_build_object(
    'user_id', v_user_id,
    'org_id', v_org_id,
    'slug', v_slug
  );
end;
$$;
