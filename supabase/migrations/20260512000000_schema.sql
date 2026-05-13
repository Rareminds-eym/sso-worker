


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE OR REPLACE FUNCTION "public"."cleanup_expired_sessions"() RETURNS integer
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM sessions
  WHERE revoked = true OR expires_at < now();
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$;


ALTER FUNCTION "public"."cleanup_expired_sessions"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_expired_tokens"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_deleted integer := 0;
  v_count integer;
BEGIN
  DELETE FROM email_verifications WHERE expires_at < now() - interval '48 hours';
  GET DIAGNOSTICS v_count = row_count;
  v_deleted := v_deleted + v_count;

  DELETE FROM password_resets WHERE expires_at < now() - interval '2 hours';
  GET DIAGNOSTICS v_count = row_count;
  v_deleted := v_deleted + v_count;

  DELETE FROM invites WHERE expires_at < now() - interval '14 days';
  GET DIAGNOSTICS v_count = row_count;
  v_deleted := v_deleted + v_count;

  RETURN v_deleted;
END;
$$;


ALTER FUNCTION "public"."cleanup_expired_tokens"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_jwt_claims"("p_user_id" "uuid", "p_org_id" "uuid") RETURNS "jsonb"
    LANGUAGE "sql" STABLE
    SET "search_path" TO 'public'
    AS $$
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


ALTER FUNCTION "public"."get_jwt_claims"("p_user_id" "uuid", "p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."rls_auto_enable"() RETURNS "event_trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog'
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN
    SELECT *
    FROM pg_event_trigger_ddl_commands()
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
      AND object_type IN ('table','partitioned table')
  LOOP
     IF cmd.schema_name IS NOT NULL AND cmd.schema_name IN ('public') AND cmd.schema_name NOT IN ('pg_catalog','information_schema') AND cmd.schema_name NOT LIKE 'pg_toast%' AND cmd.schema_name NOT LIKE 'pg_temp%' THEN
      BEGIN
        EXECUTE format('alter table if exists %s enable row level security', cmd.object_identity);
        RAISE LOG 'rls_auto_enable: enabled RLS on %', cmd.object_identity;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE LOG 'rls_auto_enable: failed to enable RLS on %', cmd.object_identity;
      END;
     ELSE
        RAISE LOG 'rls_auto_enable: skip % (either system schema or not in enforced list: %.)', cmd.object_identity, cmd.schema_name;
     END IF;
  END LOOP;
END;
$$;


ALTER FUNCTION "public"."rls_auto_enable"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  new.updated_at = now();
  RETURN new;
END;
$$;


ALTER FUNCTION "public"."set_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."signup_member"("p_email" "text", "p_password_hash" "text", "p_role" "text", "p_org_id" "uuid" DEFAULT NULL::"uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_user_id       uuid;
  v_membership_id uuid;
  v_role_id       uuid;
  v_org_id        uuid;
  v_platform_org  uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
  -- Validate role exists
  SELECT id INTO v_role_id FROM roles WHERE name = p_role;
  IF v_role_id IS NULL THEN
    RAISE EXCEPTION 'Invalid role: %', p_role;
  END IF;

  -- Determine target org: use provided org_id, or fall back to platform org
  IF p_org_id IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = p_org_id) THEN
      RAISE EXCEPTION 'Organization not found';
    END IF;
    v_org_id := p_org_id;
  ELSE
    v_org_id := v_platform_org;
  END IF;

  -- Create user
  INSERT INTO users (email, password_hash, is_email_verified)
  VALUES (p_email, p_password_hash, false)
  RETURNING id INTO v_user_id;

  -- Always create membership and assign role
  INSERT INTO memberships (user_id, org_id, status)
  VALUES (v_user_id, v_org_id, 'active')
  RETURNING id INTO v_membership_id;

  INSERT INTO membership_roles (membership_id, role_id)
  VALUES (v_membership_id, v_role_id);

  RETURN jsonb_build_object(
    'user_id', v_user_id,
    'org_id', v_org_id,
    'membership_id', v_membership_id
  );
END;
$$;


ALTER FUNCTION "public"."signup_member"("p_email" "text", "p_password_hash" "text", "p_role" "text", "p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."signup_user"("p_email" "text", "p_password_hash" "text", "p_org_name" "text", "p_org_slug" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
declare
  v_user_id       uuid;
  v_org_id        uuid;
  v_membership_id uuid;
  v_owner_role_id uuid;
  v_slug          text := p_org_slug;
begin
  -- Create user
  insert into users (email, password_hash, is_email_verified)
  values (p_email, p_password_hash, false)
  returning id into v_user_id;

  -- Create org (handle slug collision)
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

  -- Create membership
  insert into memberships (user_id, org_id, status)
  values (v_user_id, v_org_id, 'active')
  returning id into v_membership_id;

  -- Assign 'owner' role via join table
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


ALTER FUNCTION "public"."signup_user"("p_email" "text", "p_password_hash" "text", "p_org_name" "text", "p_org_slug" "text") OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."audit_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "action" "text",
    "metadata" "jsonb",
    "ip_address" "text",
    "user_agent" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "org_id" "uuid"
);


ALTER TABLE "public"."audit_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."email_verifications" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "token_hash" "text" NOT NULL,
    "used" boolean DEFAULT false,
    "expires_at" timestamp with time zone NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."email_verifications" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."invites" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "email" "text" NOT NULL,
    "org_id" "uuid" NOT NULL,
    "role" "text"[] DEFAULT '{member}'::"text"[],
    "token_hash" "text",
    "expires_at" timestamp with time zone,
    "accepted" boolean DEFAULT false,
    "invited_by" "uuid",
    "accepted_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."invites" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."membership_products" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "membership_id" "uuid" NOT NULL,
    "product_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."membership_products" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."membership_roles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "membership_id" "uuid" NOT NULL,
    "role_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."membership_roles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."memberships" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "org_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "status" "text" DEFAULT 'active'::"text" NOT NULL,
    CONSTRAINT "memberships_status_check" CHECK (("status" = ANY (ARRAY['active'::"text", 'inactive'::"text", 'suspended'::"text", 'expired'::"text"])))
);


ALTER TABLE "public"."memberships" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."oauth_accounts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "provider" "text" NOT NULL,
    "provider_user_id" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."oauth_accounts" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."organization_products" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "org_id" "uuid" NOT NULL,
    "product_id" "uuid" NOT NULL,
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."organization_products" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."organizations" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "slug" "text" NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "metadata" "jsonb" DEFAULT '{}'::"jsonb"
);


ALTER TABLE "public"."organizations" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."password_resets" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "token_hash" "text" NOT NULL,
    "used" boolean DEFAULT false,
    "expires_at" timestamp with time zone NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."password_resets" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."products" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "code" "text" NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."products" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."roles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."roles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."sessions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "refresh_token_hash" "text" NOT NULL,
    "user_agent" "text",
    "ip_address" "text",
    "expires_at" timestamp with time zone NOT NULL,
    "revoked" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "rotated_from" "uuid",
    "last_used_at" timestamp with time zone,
    "device_info" "jsonb",
    "org_id" "uuid"
);


ALTER TABLE "public"."sessions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."users" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "email" "text" NOT NULL,
    "password_hash" "text" NOT NULL,
    "is_email_verified" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "last_login_at" timestamp with time zone,
    "is_blocked" boolean DEFAULT false
);


ALTER TABLE "public"."users" OWNER TO "postgres";


ALTER TABLE ONLY "public"."audit_logs"
    ADD CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."email_verifications"
    ADD CONSTRAINT "email_verifications_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."email_verifications"
    ADD CONSTRAINT "email_verifications_token_key" UNIQUE ("token_hash");



ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_token_key" UNIQUE ("token_hash");



ALTER TABLE ONLY "public"."membership_products"
    ADD CONSTRAINT "membership_products_membership_id_product_id_key" UNIQUE ("membership_id", "product_id");



ALTER TABLE ONLY "public"."membership_products"
    ADD CONSTRAINT "membership_products_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."membership_roles"
    ADD CONSTRAINT "membership_roles_membership_id_role_id_key" UNIQUE ("membership_id", "role_id");



ALTER TABLE ONLY "public"."membership_roles"
    ADD CONSTRAINT "membership_roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."memberships"
    ADD CONSTRAINT "memberships_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."memberships"
    ADD CONSTRAINT "memberships_user_id_org_id_key" UNIQUE ("user_id", "org_id");



ALTER TABLE ONLY "public"."oauth_accounts"
    ADD CONSTRAINT "oauth_accounts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."oauth_accounts"
    ADD CONSTRAINT "oauth_accounts_provider_provider_user_id_key" UNIQUE ("provider", "provider_user_id");



ALTER TABLE ONLY "public"."organization_products"
    ADD CONSTRAINT "organization_products_org_id_product_id_key" UNIQUE ("org_id", "product_id");



ALTER TABLE ONLY "public"."organization_products"
    ADD CONSTRAINT "organization_products_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."organizations"
    ADD CONSTRAINT "organizations_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."organizations"
    ADD CONSTRAINT "organizations_slug_key" UNIQUE ("slug");



ALTER TABLE ONLY "public"."password_resets"
    ADD CONSTRAINT "password_resets_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."password_resets"
    ADD CONSTRAINT "password_resets_token_key" UNIQUE ("token_hash");



ALTER TABLE ONLY "public"."products"
    ADD CONSTRAINT "products_code_key" UNIQUE ("code");



ALTER TABLE ONLY "public"."products"
    ADD CONSTRAINT "products_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."roles"
    ADD CONSTRAINT "roles_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."roles"
    ADD CONSTRAINT "roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_email_key" UNIQUE ("email");



ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_pkey" PRIMARY KEY ("id");



CREATE INDEX "idx_audit_org" ON "public"."audit_logs" USING "btree" ("org_id");



CREATE INDEX "idx_audit_user" ON "public"."audit_logs" USING "btree" ("user_id");



CREATE INDEX "idx_email_verifications_token_hash" ON "public"."email_verifications" USING "btree" ("token_hash");



CREATE INDEX "idx_email_verifications_user" ON "public"."email_verifications" USING "btree" ("user_id");



CREATE INDEX "idx_invites_email_org_active" ON "public"."invites" USING "btree" ("email", "org_id", "accepted") WHERE ("accepted" = false);



CREATE INDEX "idx_invites_invited_by" ON "public"."invites" USING "btree" ("invited_by");



CREATE INDEX "idx_invites_org" ON "public"."invites" USING "btree" ("org_id");



CREATE INDEX "idx_invites_token_hash" ON "public"."invites" USING "btree" ("token_hash");



CREATE INDEX "idx_membership_products_mid" ON "public"."membership_products" USING "btree" ("membership_id");



CREATE INDEX "idx_membership_products_pid" ON "public"."membership_products" USING "btree" ("product_id");



CREATE INDEX "idx_membership_roles_mid" ON "public"."membership_roles" USING "btree" ("membership_id");



CREATE INDEX "idx_membership_roles_rid" ON "public"."membership_roles" USING "btree" ("role_id");



CREATE INDEX "idx_memberships_org" ON "public"."memberships" USING "btree" ("org_id");



CREATE INDEX "idx_memberships_user" ON "public"."memberships" USING "btree" ("user_id");



CREATE INDEX "idx_oauth_accounts_user_id" ON "public"."oauth_accounts" USING "btree" ("user_id");



CREATE INDEX "idx_org_products_org" ON "public"."organization_products" USING "btree" ("org_id");



CREATE INDEX "idx_org_products_product" ON "public"."organization_products" USING "btree" ("product_id");



CREATE INDEX "idx_organizations_created_by" ON "public"."organizations" USING "btree" ("created_by");



CREATE INDEX "idx_password_resets_token_hash" ON "public"."password_resets" USING "btree" ("token_hash");



CREATE INDEX "idx_password_resets_user" ON "public"."password_resets" USING "btree" ("user_id");



CREATE INDEX "idx_sessions_active" ON "public"."sessions" USING "btree" ("user_id") WHERE ("revoked" = false);



CREATE INDEX "idx_sessions_expiry" ON "public"."sessions" USING "btree" ("expires_at");



CREATE INDEX "idx_sessions_last_used" ON "public"."sessions" USING "btree" ("last_used_at");



CREATE INDEX "idx_sessions_org" ON "public"."sessions" USING "btree" ("org_id");



CREATE INDEX "idx_sessions_revoked" ON "public"."sessions" USING "btree" ("revoked");



CREATE INDEX "idx_sessions_rotated_from" ON "public"."sessions" USING "btree" ("rotated_from");



CREATE INDEX "idx_sessions_token" ON "public"."sessions" USING "btree" ("refresh_token_hash");



CREATE INDEX "idx_sessions_user" ON "public"."sessions" USING "btree" ("user_id");



CREATE INDEX "idx_users_email" ON "public"."users" USING "btree" ("email");



CREATE OR REPLACE TRIGGER "trg_users_updated_at" BEFORE UPDATE ON "public"."users" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



ALTER TABLE ONLY "public"."audit_logs"
    ADD CONSTRAINT "audit_logs_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."audit_logs"
    ADD CONSTRAINT "audit_logs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."email_verifications"
    ADD CONSTRAINT "email_verifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_invited_by_fkey" FOREIGN KEY ("invited_by") REFERENCES "public"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."invites"
    ADD CONSTRAINT "invites_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."membership_products"
    ADD CONSTRAINT "membership_products_membership_id_fkey" FOREIGN KEY ("membership_id") REFERENCES "public"."memberships"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."membership_products"
    ADD CONSTRAINT "membership_products_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."membership_roles"
    ADD CONSTRAINT "membership_roles_membership_id_fkey" FOREIGN KEY ("membership_id") REFERENCES "public"."memberships"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."membership_roles"
    ADD CONSTRAINT "membership_roles_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."memberships"
    ADD CONSTRAINT "memberships_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."memberships"
    ADD CONSTRAINT "memberships_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."oauth_accounts"
    ADD CONSTRAINT "oauth_accounts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."organization_products"
    ADD CONSTRAINT "organization_products_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."organization_products"
    ADD CONSTRAINT "organization_products_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."organizations"
    ADD CONSTRAINT "organizations_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."password_resets"
    ADD CONSTRAINT "password_resets_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_rotated_from_fkey" FOREIGN KEY ("rotated_from") REFERENCES "public"."sessions"("id");



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;



ALTER TABLE "public"."audit_logs" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "deny_all_audit_logs" ON "public"."audit_logs" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_email_verifications" ON "public"."email_verifications" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_invites" ON "public"."invites" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_membership_products" ON "public"."membership_products" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_membership_roles" ON "public"."membership_roles" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_memberships" ON "public"."memberships" USING (false);



CREATE POLICY "deny_all_oauth" ON "public"."oauth_accounts" USING (false);



CREATE POLICY "deny_all_oauth_accounts" ON "public"."oauth_accounts" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_organization_products" ON "public"."organization_products" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_organizations" ON "public"."organizations" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_orgs" ON "public"."organizations" USING (false);



CREATE POLICY "deny_all_password_resets" ON "public"."password_resets" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_products" ON "public"."products" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_roles" ON "public"."roles" TO "anon" USING (false) WITH CHECK (false);



CREATE POLICY "deny_all_sessions" ON "public"."sessions" USING (false);



CREATE POLICY "deny_all_users" ON "public"."users" USING (false);



ALTER TABLE "public"."email_verifications" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."invites" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."membership_products" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."membership_roles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."memberships" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."oauth_accounts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."organization_products" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."organizations" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."password_resets" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."products" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."roles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."sessions" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;




ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";


GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";






















































































































































GRANT ALL ON FUNCTION "public"."cleanup_expired_sessions"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_expired_sessions"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_expired_sessions"() TO "service_role";



GRANT ALL ON FUNCTION "public"."cleanup_expired_tokens"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_expired_tokens"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_expired_tokens"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_jwt_claims"("p_user_id" "uuid", "p_org_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_jwt_claims"("p_user_id" "uuid", "p_org_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_jwt_claims"("p_user_id" "uuid", "p_org_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "anon";
GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "service_role";



GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."signup_member"("p_email" "text", "p_password_hash" "text", "p_role" "text", "p_org_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."signup_member"("p_email" "text", "p_password_hash" "text", "p_role" "text", "p_org_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."signup_member"("p_email" "text", "p_password_hash" "text", "p_role" "text", "p_org_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."signup_user"("p_email" "text", "p_password_hash" "text", "p_org_name" "text", "p_org_slug" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."signup_user"("p_email" "text", "p_password_hash" "text", "p_org_name" "text", "p_org_slug" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."signup_user"("p_email" "text", "p_password_hash" "text", "p_org_name" "text", "p_org_slug" "text") TO "service_role";


















GRANT ALL ON TABLE "public"."audit_logs" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs" TO "service_role";



GRANT ALL ON TABLE "public"."email_verifications" TO "anon";
GRANT ALL ON TABLE "public"."email_verifications" TO "authenticated";
GRANT ALL ON TABLE "public"."email_verifications" TO "service_role";



GRANT ALL ON TABLE "public"."invites" TO "anon";
GRANT ALL ON TABLE "public"."invites" TO "authenticated";
GRANT ALL ON TABLE "public"."invites" TO "service_role";



GRANT ALL ON TABLE "public"."membership_products" TO "anon";
GRANT ALL ON TABLE "public"."membership_products" TO "authenticated";
GRANT ALL ON TABLE "public"."membership_products" TO "service_role";



GRANT ALL ON TABLE "public"."membership_roles" TO "anon";
GRANT ALL ON TABLE "public"."membership_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."membership_roles" TO "service_role";



GRANT ALL ON TABLE "public"."memberships" TO "anon";
GRANT ALL ON TABLE "public"."memberships" TO "authenticated";
GRANT ALL ON TABLE "public"."memberships" TO "service_role";



GRANT ALL ON TABLE "public"."oauth_accounts" TO "anon";
GRANT ALL ON TABLE "public"."oauth_accounts" TO "authenticated";
GRANT ALL ON TABLE "public"."oauth_accounts" TO "service_role";



GRANT ALL ON TABLE "public"."organization_products" TO "anon";
GRANT ALL ON TABLE "public"."organization_products" TO "authenticated";
GRANT ALL ON TABLE "public"."organization_products" TO "service_role";



GRANT ALL ON TABLE "public"."organizations" TO "anon";
GRANT ALL ON TABLE "public"."organizations" TO "authenticated";
GRANT ALL ON TABLE "public"."organizations" TO "service_role";



GRANT ALL ON TABLE "public"."password_resets" TO "anon";
GRANT ALL ON TABLE "public"."password_resets" TO "authenticated";
GRANT ALL ON TABLE "public"."password_resets" TO "service_role";



GRANT ALL ON TABLE "public"."products" TO "anon";
GRANT ALL ON TABLE "public"."products" TO "authenticated";
GRANT ALL ON TABLE "public"."products" TO "service_role";



GRANT ALL ON TABLE "public"."roles" TO "anon";
GRANT ALL ON TABLE "public"."roles" TO "authenticated";
GRANT ALL ON TABLE "public"."roles" TO "service_role";



GRANT ALL ON TABLE "public"."sessions" TO "anon";
GRANT ALL ON TABLE "public"."sessions" TO "authenticated";
GRANT ALL ON TABLE "public"."sessions" TO "service_role";



GRANT ALL ON TABLE "public"."users" TO "anon";
GRANT ALL ON TABLE "public"."users" TO "authenticated";
GRANT ALL ON TABLE "public"."users" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";



































