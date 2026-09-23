-- Existing tables only. No backfill, table creation, or reclassification of existing users.
begin;

create index if not exists users_campaign_learner_id_lookup on public.users ((user_metadata->>'learner_id'));
create unique index users_campaign_educator_identity on public.users
  ((user_metadata #>> '{campaigns,100keducators,educator_id}'))
  where user_metadata #>> '{campaigns,100keducators,educator_id}' is not null;
create sequence public.campaign_educator_number start with 10000000 maxvalue 99999999;
create unique index audit_application_session_event on public.audit_logs
  (user_id, action, (metadata->>'app_id'), (metadata->>'family_id'))
  where action in ('application.login', 'application.session_access');

-- Private service-role RPC. The gateway must authenticate its email proof first.
create function public.ensure_educator_campaign_user(
  p_email text, p_name text, p_mobile text, p_org_id uuid,
  p_password_hash text, p_educator_id text default null
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  u public.users%rowtype;
  membership_id uuid;
  role_id uuid;
  new_user boolean := false;
  new_campaign boolean;
  code text;
  joined_at text;
  campaign jsonb;
begin
  p_email := lower(trim(p_email));
  if p_email is null or p_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     or nullif(trim(p_name), '') is null or p_mobile is null or p_mobile !~ '^[0-9]{10}$'
     or (p_educator_id is not null and p_educator_id !~ '^LRN-[A-Z]{3}[0-9]{2}-[0-9]{8}$') then
    raise exception 'Invalid campaign identity';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_email, 0));
  select * into u from public.users where email = p_email for update;
  if not found then
    insert into public.users(email, password_hash, is_email_verified, user_metadata)
    values (p_email, p_password_hash, true,
      jsonb_build_object('name', p_name, 'first_name', p_name, 'contact_number', p_mobile,
        'role', 'learner', 'signup_app', '100keducators'))
    on conflict (email) do nothing returning * into u;
    new_user := found;
    if not new_user then
      select * into strict u from public.users where email = p_email for update;
    end if;
  end if;
  if coalesce(u.is_blocked, false) then raise exception 'Account is blocked'; end if;

  code := u.user_metadata #>> '{campaigns,100keducators,educator_id}';
  new_campaign := code is null;
  if new_campaign then
    code := p_educator_id;
    if code is null then
      loop
        begin
          code := 'LRN-' || rpad(upper(substr(regexp_replace(p_name, '[^A-Za-z]', '', 'g'), 1, 3)), 3, 'X')
            || to_char(now(), 'YY') || '-' || lpad(nextval('public.campaign_educator_number')::text, 8, '0');
        exception when others then
          raise exception 'Campaign educator ID space exhausted';
        end;
        exit when not exists (select 1 from public.users where user_metadata->>'learner_id' = code
          or user_metadata #>> '{campaigns,100keducators,educator_id}' = code);
      end loop;
    end if;
    if exists (select 1 from public.users where id <> u.id and
        (user_metadata->>'learner_id' = code or user_metadata #>> '{campaigns,100keducators,educator_id}' = code)) then
      raise exception 'Educator identity conflict';
    end if;
    joined_at := now()::text;
  elsif p_educator_id is not null and p_educator_id <> code then
    raise exception 'Educator identity conflict';
  else
    joined_at := u.user_metadata #>> '{campaigns,100keducators,joined_at}';
  end if;

  campaign := jsonb_build_object('educator_id', code, 'joined_at', joined_at);
  -- Existing metadata is base; campaign-specific keys are merged on top so they always win.
  update public.users set is_email_verified = true,
    user_metadata = coalesce(user_metadata, '{}'::jsonb)
      || jsonb_build_object(
        'learner_id', code,
        'source', '100keducators_campaign',
        'campaign_educator_id', code,
        'campaigns', coalesce(user_metadata->'campaigns', '{}'::jsonb)
          || jsonb_build_object('100keducators', campaign))
      || case when coalesce(user_metadata->>'signup_app', '') = ''
        then jsonb_build_object('signup_app', '100keducators') else '{}'::jsonb end,
    updated_at = now()
    where id = u.id;
  if new_user then
    select id into strict role_id from public.roles where name = 'learner';
    insert into public.memberships(user_id, org_id, status) values (u.id, p_org_id, 'active') returning id into membership_id;
    insert into public.membership_roles(membership_id, role_id) values (membership_id, role_id);
  end if;
  if new_user or new_campaign then
    -- Existing event inbox doubles as a durable sync outbox, scoped by event_type.
    insert into public.events(event_id, event_type, status, user_id, payload)
      values ('campaign.identity.sync:' || u.id::text, 'campaign.identity.sync', 'received', u.id,
        jsonb_build_object('org_id', case when new_user then p_org_id else null end))
      on conflict (event_id) do nothing;
  end if;
  return jsonb_build_object('user_id', u.id, 'educator_id', code, 'joined_at', joined_at);
end;
$$;

-- Validates the session, deduplicates audit evidence, and updates activity atomically.
create function public.record_application_access(p_refresh_hash text, p_app_id text, p_event_type text, p_signup boolean default false)
returns void language plpgsql security definer set search_path = '' as $$
declare
  s public.sessions%rowtype;
  u public.users%rowtype;
  t timestamptz := clock_timestamp();
  login_time text;
  activity jsonb;
  app_activity jsonb;
begin
  if p_app_id is null or p_app_id not in ('100keducators', 'skillpassport')
     or p_event_type is null or p_event_type not in ('login', 'session_access') then
    raise exception 'Invalid application event';
  end if;
  select * into s from public.sessions where refresh_token_hash = p_refresh_hash
    and not revoked and expires_at > t for update;
  -- Reject if session row missing, or if family is older than 30 days.
  -- For pre-migration rows without family_created_at, fall back to the family's first
  -- session creation time (looked up by family_id) rather than the current row's created_at.
  if not found then raise exception 'Session is not active'; end if;
  declare
    family_origin timestamptz;
  begin
    if s.family_created_at is not null then
      family_origin := s.family_created_at;
    elsif s.family_id is not null then
      select min(created_at) into family_origin from public.sessions where family_id = s.family_id;
    end if;
    family_origin := coalesce(family_origin, s.created_at);
    if family_origin + interval '30 days' <= t then
      raise exception 'Session is not active';
    end if;
  end;
  select * into u from public.users where id = s.user_id for update;
  if not found or coalesce(u.is_blocked, false) then raise exception 'Session is not active'; end if;

  -- Insert audit row, targeting the specific dedup index.
  insert into public.audit_logs(user_id, org_id, action, metadata, created_at)
    values (s.user_id, s.org_id, 'application.' || p_event_type,
      jsonb_build_object('app_id', p_app_id, 'family_id', coalesce(s.family_id, s.id)::text, 'session_id', s.id::text), t)
    on conflict (user_id, action, (metadata->>'app_id'), (metadata->>'family_id'))
      where action in ('application.login', 'application.session_access')
    do nothing;

  -- Track login timestamp only for fresh (non-duplicate) login events.
  if p_event_type = 'login' and found then login_time := t::text; end if;

  -- Update application activity timestamps in user_metadata.
  -- Uses simple last-write-wins for last_* to avoid ::timestamptz cast on potentially corrupt data.
  activity := coalesce(u.user_metadata->'application_activity', '{}'::jsonb);
  app_activity := coalesce(activity->p_app_id, '{}'::jsonb);
  app_activity := app_activity || jsonb_build_object(
    'first_access_at', coalesce(app_activity->>'first_access_at', t::text),
    'last_access_at', t::text);
  if login_time is not null then
    app_activity := app_activity || jsonb_build_object(
      'first_login_at', coalesce(app_activity->>'first_login_at', login_time),
      'last_login_at', t::text);
  end if;
  update public.users set user_metadata = coalesce(user_metadata, '{}'::jsonb)
    || jsonb_build_object('application_activity', activity || jsonb_build_object(p_app_id, app_activity))
    || case when p_signup and p_event_type = 'login' and user_metadata->>'signup_app' is null
      then jsonb_build_object('signup_app', p_app_id) else '{}'::jsonb end
    where id = s.user_id;
  update public.sessions set device_info = coalesce(device_info, '{}'::jsonb) || jsonb_build_object('app', p_app_id)
    where id = s.id;
end;
$$;

revoke all on function public.ensure_educator_campaign_user(text,text,text,uuid,text,text) from public, anon, authenticated;
revoke all on function public.record_application_access(text,text,text,boolean) from public, anon, authenticated;
grant execute on function public.ensure_educator_campaign_user(text,text,text,uuid,text,text) to service_role;
grant execute on function public.record_application_access(text,text,text,boolean) to service_role;
commit;
