-- ═══════════════════════════════════════════════════════════════
-- SSO Database Schema — Matches actual Supabase DB
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
  created_by uuid references users(id),
  metadata   jsonb default '{}',
  created_at timestamptz default now()
);

-- ─── Memberships ───────────────────────────────────────────────
create table if not exists memberships (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users(id) on delete cascade,
  org_id     uuid not null references organizations(id) on delete cascade,
  role       text not null check (role in ('owner', 'admin', 'member')),
  status     text default 'active',
  created_at timestamptz default now(),
  unique (user_id, org_id)
);

create index if not exists idx_memberships_user on memberships (user_id);
create index if not exists idx_memberships_org  on memberships (org_id);

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

-- ─── OAuth Accounts ────────────────────────────────────────────
create table if not exists oauth_accounts (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid references users(id),
  provider         text not null,
  provider_user_id text not null,
  created_at       timestamptz default now(),
  unique (provider, provider_user_id)
);

-- ─── Invites ───────────────────────────────────────────────────
create table if not exists invites (
  id          uuid primary key default gen_random_uuid(),
  email       text not null,
  org_id      uuid not null,
  role        text,
  token       text unique,
  invited_by  uuid references users(id),
  expires_at  timestamptz,
  accepted    boolean default false,
  accepted_at timestamptz,
  created_at  timestamptz default now()
);

create index if not exists idx_invites_token on invites (token);

-- ─── Audit Logs (plural) ──────────────────────────────────────
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

-- ─── Functions ─────────────────────────────────────────────────
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

create or replace function signup_user(
  p_email text, p_password_hash text, p_org_name text, p_org_slug text
)
returns jsonb as $fn$
declare
  v_user_id uuid;
  v_org_id  uuid;
  v_slug    text := p_org_slug;
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

  insert into memberships (user_id, org_id, role, status)
  values (v_user_id, v_org_id, 'owner', 'active');

  return jsonb_build_object('user_id', v_user_id, 'org_id', v_org_id, 'slug', v_slug);
end;
$fn$ language plpgsql;

-- ─── RLS ───────────────────────────────────────────────────────
alter table users         enable row level security;
alter table organizations enable row level security;
alter table memberships   enable row level security;
alter table sessions      enable row level security;
alter table invites       enable row level security;
alter table audit_logs    enable row level security;
alter table oauth_accounts enable row level security;
