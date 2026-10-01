"""Test reset migration locking and rollback in an isolated, disposable Postgres container."""
import json
from pathlib import Path
import subprocess
import time
import uuid

name = 'password-reset-test-' + uuid.uuid4().hex[:8]
image = 'public.ecr.aws/supabase/postgres:17.6.1.143'

def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, text=True, capture_output=True, **kwargs)

def sql(statement):
    return docker('exec', '-i', name, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-At', input=statement).stdout.strip()

try:
    docker('run', '--rm', '-d', '--name', name, '--network', 'none', '--user', 'postgres',
           '--entrypoint', '/bin/sh', image, '-c',
           'initdb -D /tmp/reset-db -A trust >/tmp/reset-init.log && exec postgres -D /tmp/reset-db -c listen_addresses=""')
    for _ in range(60):
        try:
            sql('SELECT 1;')
            break
        except subprocess.CalledProcessError:
            time.sleep(0.25)
    else:
        raise RuntimeError(docker('logs', name).stdout)
    sql('''CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role;
      CREATE TABLE public.users (id uuid PRIMARY KEY, password_hash text NOT NULL);
      CREATE TABLE public.password_resets (id uuid PRIMARY KEY, user_id uuid REFERENCES public.users(id),
        token_hash text UNIQUE NOT NULL, used boolean NOT NULL DEFAULT false, expires_at timestamptz NOT NULL);
      CREATE TABLE public.sessions (id uuid PRIMARY KEY, user_id uuid REFERENCES public.users(id), revoked boolean NOT NULL DEFAULT false);
      GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;''')
    migration = Path(__file__).resolve().parents[1] / 'supabase/migrations/20260930000000_complete_password_reset.sql'
    sql(migration.read_text())
    user, token, session = [str(uuid.uuid4()) for _ in range(3)]
    sql(f"INSERT INTO users VALUES ('{user}', 'old'); INSERT INTO password_resets VALUES ('{token}', '{user}', 'token', false, now()+interval '1 hour'); INSERT INTO sessions VALUES ('{session}', '{user}', false);")
    first = subprocess.Popen(['docker', 'exec', '-i', name, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-At'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    first.stdin.write("BEGIN; SET ROLE service_role; SELECT public.complete_password_reset('token','first'); SELECT pg_sleep(1); COMMIT;\n")
    first.stdin.flush()
    time.sleep(0.2)
    second = json.loads(sql("SET ROLE service_role; SELECT public.complete_password_reset('token','second');").splitlines()[-1])
    out, err = first.communicate(timeout=10)
    assert first.returncode == 0, err
    statuses = [json.loads(line)['status'] for line in out.splitlines() if line.startswith('{')]
    assert sorted([statuses[0], second['status']]) == ['reset', 'used']
    assert sql('SELECT revoked FROM sessions;') == 't'
    print('PASS: concurrent claims have exactly one winner and revoke sessions')

    sql("UPDATE users SET password_hash='old'; UPDATE password_resets SET used=false; UPDATE sessions SET revoked=false;")
    sql("""CREATE FUNCTION public.fail_session_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write failure'; END $$;
      CREATE TRIGGER fail_session BEFORE UPDATE ON public.sessions FOR EACH ROW EXECUTE FUNCTION public.fail_session_write();""")
    try:
        sql("SELECT public.complete_password_reset('token','new');")
        raise AssertionError('Expected injected failure')
    except subprocess.CalledProcessError as error:
        assert 'injected write failure' in error.stderr
    assert sql('SELECT password_hash FROM users;') == 'old'
    assert sql('SELECT used FROM password_resets;') == 'f'
    assert sql('SELECT revoked FROM sessions;') == 'f'
    sql('DROP TRIGGER fail_session ON public.sessions;')
    assert json.loads(sql("SELECT public.complete_password_reset('token','retry');"))['status'] == 'reset'
    print('PASS: write failure rolls back password, token, and sessions; retry succeeds')
    for role in ['anon', 'authenticated']:
        assert sql(f"SELECT has_function_privilege('{role}', 'public.complete_password_reset(text,text)', 'EXECUTE');") == 'f'
    print('PASS: public browser roles cannot execute the reset function')
finally:
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
