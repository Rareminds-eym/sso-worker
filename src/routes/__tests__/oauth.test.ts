/**
 * Tests for the Google OAuth login route (routes/oauth.ts).
 *
 * Mocks:
 * - Supabase REST API (via global fetch mock) covering users, oauth_accounts,
 *   memberships, sessions, audit_logs and the signup_user/get_jwt_claims RPCs
 * - lib/jwt (RS256 signing not needed for logic tests)
 * - lib/skillpassport-check (re-sync backstop short-circuits when user exists)
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../../types";

vi.mock("../../lib/jwt", () => ({
  signAccessToken: vi.fn(async () => "test-access-token"),
}));

vi.mock("../../lib/skillpassport-check", () => ({
  checkUserExistsInSkillpassport: vi.fn(async () => true),
}));

import { performOAuthLogin } from "../oauth";

// ── KV mock ─────────────────────────────────────────────────────
function createMockKV() {
  const store = new Map<string, string>();
  return {
    get: (key: string) => Promise.resolve(store.get(key) ?? null),
    put: (key: string, value: string, _options?: { expirationTtl?: number }) => {
      store.set(key, value);
      return Promise.resolve();
    },
    delete: (key: string) => {
      store.delete(key);
      return Promise.resolve();
    },
    _store: store,
  };
}

// ── DB state + Supabase REST mock ───────────────────────────────
const dbState = {
  users: [] as Array<{ id: string; email: string; is_blocked: boolean; is_email_verified: boolean; user_metadata: Record<string, unknown>; [key: string]: unknown }>,
  oauth_accounts: [] as Array<Record<string, unknown>>,
  memberships: [] as Array<Record<string, unknown>>,
  sessions: [] as Array<Record<string, unknown>>,
  insertedUsers: [] as Array<{ id: string; email: string; is_email_verified: boolean; user_metadata: Record<string, unknown> }>,
  rpcCalls: [] as Array<{ fn: string; args: Record<string, unknown> }>,
};

function resetDb(): void {
  dbState.users = [];
  dbState.oauth_accounts = [];
  dbState.memberships = [];
  dbState.sessions = [];
  dbState.insertedUsers = [];
  dbState.rpcCalls = [];
}

function seedUser(overrides: Partial<{ email: string; is_blocked: boolean; is_email_verified: boolean }> = {}) {
  const user = {
    id: crypto.randomUUID(),
    email: overrides.email ?? "existing@example.com",
    password_hash: "$2a$12$placeholder",
    is_email_verified: overrides.is_email_verified ?? true,
    is_blocked: overrides.is_blocked ?? false,
    last_login_at: null as string | null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    user_metadata: { role: "learner" } as Record<string, unknown>,
  };
  dbState.users.push(user);
  return user;
}

function createMockSupabaseFetch(): ReturnType<typeof vi.fn> {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    const bodyStr = init?.body ? String(init.body) : null;

    // ── RPCs ──
    if (url.includes("/rest/v1/rpc/signup_user")) {
      const args = JSON.parse(bodyStr ?? "{}") as Record<string, unknown>;
      dbState.rpcCalls.push({ fn: "signup_user", args });
      const newUser = {
        id: crypto.randomUUID(),
        email: String(args.p_email),
        password_hash: args.p_password_hash,
        is_email_verified: false, // signup_user hardcodes false — the gap we patch
        is_blocked: false,
        last_login_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        user_metadata: (args.p_user_metadata ?? {}) as Record<string, unknown>,
      };
      dbState.insertedUsers.push(newUser);
      dbState.users.push(newUser);
      return Response.json({ user_id: newUser.id, org_id: crypto.randomUUID(), slug: "google-x" });
    }
    if (url.includes("/rest/v1/rpc/get_jwt_claims")) {
      dbState.rpcCalls.push({ fn: "get_jwt_claims", args: JSON.parse(bodyStr ?? "{}") });
      return Response.json({ roles: ["learner"], products: [], membership_status: "active" });
    }

    const collection = url.match(/\/rest\/v1\/([^?]+)/)?.[1]?.split("?")[0] ?? "";

    if (collection === "users" && method === "GET") {
      const params = new URLSearchParams(url.split("?")[1] ?? "");
      const idEq = params.get("id")?.replace(/^eq\./, "");
      const emailEq = params.get("email")?.replace(/^eq\./, "");
      const found = dbState.users.find((u) =>
        idEq ? u.id === decodeURIComponent(idEq) : emailEq ? u.email === decodeURIComponent(emailEq) : false,
      );
      return Response.json(found ? [found] : []);
    }

    if (collection === "users" && method === "PATCH") {
      const params = new URLSearchParams(url.split("?")[1] ?? "");
      const idEq = params.get("id")?.replace(/^eq\./, "");
      const target = dbState.users.find((u) => u.id === decodeURIComponent(idEq ?? ""));
      if (target) Object.assign(target, JSON.parse(bodyStr ?? "{}"));
      return new Response(null, { status: 204 });
    }

    if (collection === "users" && method === "POST") {
      const row = JSON.parse(bodyStr ?? "{}") as { email: string; is_email_verified?: boolean; user_metadata?: Record<string, unknown>; password_hash?: string };
      const newUser = {
        id: crypto.randomUUID(),
        email: row.email,
        password_hash: row.password_hash,
        is_email_verified: row.is_email_verified ?? false,
        is_blocked: false,
        last_login_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        user_metadata: row.user_metadata ?? {},
      };
      if (dbState.users.some((u) => u.email === newUser.email)) {
        return Response.json({ code: "23505", message: "duplicate key value violates unique constraint \"users_email_key\"" }, { status: 409 });
      }
      dbState.insertedUsers.push(newUser);
      dbState.users.push(newUser);
      return Response.json([newUser], { status: 201 });
    }

    if (collection === "memberships" && method === "POST") {
      const row = JSON.parse(bodyStr ?? "{}");
      dbState.memberships.push({ ...row, id: crypto.randomUUID(), created_at: new Date().toISOString() });
      return Response.json([dbState.memberships[dbState.memberships.length - 1]], { status: 201 });
    }

    if (collection === "roles" && method === "GET") {
      return Response.json([{ id: "role-learner", name: "learner" }]);
    }

    if (collection === "membership_roles" && method === "POST") {
      return Response.json([JSON.parse(bodyStr ?? "{}")], { status: 201 });
    }

    if (collection === "organizations") {
      return Response.json([{ id: "00000000-0000-0000-0000-000000000001", name: "SkillPassport Platform" }]);
    }

    if (collection === "oauth_accounts" && method === "GET") {
      const params = new URLSearchParams(url.split("?")[1] ?? "");
      const sub = params.get("provider_user_id")?.replace(/^eq\./, "");
      const link = dbState.oauth_accounts.find(
        (l) => l.provider === "google" && l.provider_user_id === decodeURIComponent(sub ?? ""),
      );
      return Response.json(link ? [{ user_id: link.user_id }] : []);
    }

    if (collection === "oauth_accounts" && method === "POST") {
      const row = JSON.parse(bodyStr ?? "{}");
      if (!dbState.oauth_accounts.some((l) => l.provider_user_id === row.provider_user_id)) {
        dbState.oauth_accounts.push(row);
      }
      // ignore-duplicates semantics: empty body either way
      return new Response("[]", { status: 201 });
    }

    if (collection === "memberships") {
      const userId = new URLSearchParams(url.split("?")[1] ?? "").get("user_id")?.replace(/^eq\./, "");
      const rows = dbState.memberships.filter(
        (m) => m.user_id === decodeURIComponent(userId ?? "") && m.status === "active",
      );
      return Response.json(rows);
    }

    if (collection === "sessions" && method === "POST") {
      dbState.sessions.push(JSON.parse(bodyStr ?? "{}"));
      return Response.json([JSON.parse(bodyStr ?? "{}")]);
    }

    if (collection === "subscriptions") {
      return Response.json([]);
    }

    if (collection === "audit_logs" && method === "POST") {
      return Response.json([{}]);
    }

    throw new Error(`Unhandled mock fetch: ${method} ${url}`);
  });
}

// ── Harness ─────────────────────────────────────────────────────
function createMockQueue() {
  return {
    sent: [] as Array<{ type: string; payload: Record<string, unknown> }>,
    send: function (msg: { type: string; payload: Record<string, unknown> }) {
      this.sent.push(msg);
      return Promise.resolve();
    },
  };
}

function createEnv(): Env {
  return {
    SUPABASE_URL: "https://identity.example.com",
    SUPABASE_SERVICE_ROLE_KEY: "service-key",
    RATE_LIMIT_KV: createMockKV(),
    SYNC_QUEUE: createMockQueue(),
    ALLOWED_ORIGINS: "",
    ALLOWED_APP_URLS: "",
    JWT_PRIVATE_KEY: "",
    JWT_PUBLIC_KEY: "",
    JWT_KID: "",
  } as unknown as Env;
}

function createCtx() {
  return {
    waitUntil: (_p: Promise<unknown>) => {},
  } as unknown as ExecutionContext;
}

const GOOGLE_PROFILE = {
  provider: "google",
  provider_user_id: "google-sub-123",
  email: "newperson@example.com",
  email_verified: true,
  name: "New Person",
  picture: "https://lh3.googleusercontent.com/avatar.jpg",
};

beforeEach(() => {
  resetDb();
  vi.stubGlobal("fetch", createMockSupabaseFetch());
});

describe("performOAuthLogin", () => {
  it("rejects unsupported providers", async () => {
    const result = await performOAuthLogin(
      createEnv(),
      createCtx(),
      { ...GOOGLE_PROFILE, provider: "facebook" },
      "1.2.3.4",
      "ua",
    ) as { error?: string; status?: number };

    expect(result.status).toBe(400);
  });

  it("rejects unverified provider emails without touching the DB", async () => {
    const result = await performOAuthLogin(
      createEnv(),
      createCtx(),
      { ...GOOGLE_PROFILE, email_verified: false },
      "1.2.3.4",
      "ua",
    ) as { error?: string; status?: number };

    expect(result.status).toBe(400);
    expect(dbState.users).toHaveLength(0);
  });

  it("logs in an existing linked user", async () => {
    const seeded = seedUser();
    dbState.oauth_accounts.push({ user_id: seeded.id, provider: "google", provider_user_id: "google-sub-123" });

    const result = await performOAuthLogin(createEnv(), createCtx(), GOOGLE_PROFILE, "1.2.3.4", "ua") as {
      error?: string; access_token?: string; refresh_token?: string; user?: { id: string; email: string };
    };

    expect(result.error).toBeUndefined();
    expect(result.access_token).toBe("test-access-token");
    expect(result.refresh_token).toBeTruthy();
    expect(result.user).toEqual({ id: seeded.id, email: seeded.email });
    expect(dbState.sessions).toHaveLength(1);
    expect(dbState.rpcCalls.some((c) => c.fn === "get_jwt_claims")).toBe(true);
  });

  it("links an existing password account by verified email and marks it verified", async () => {
    const seeded = seedUser({ email: GOOGLE_PROFILE.email, is_email_verified: false });

    const result = await performOAuthLogin(createEnv(), createCtx(), GOOGLE_PROFILE, "1.2.3.4", "ua") as {
      error?: string; user?: { id: string };
    };

    expect(result.error).toBeUndefined();
    expect(result.user!.id).toBe(seeded.id);
    expect(dbState.oauth_accounts).toHaveLength(1);
    expect(dbState.oauth_accounts[0]).toMatchObject({
      user_id: seeded.id,
      provider: "google",
      provider_user_id: "google-sub-123",
    });
    expect(seeded.is_email_verified).toBe(true);
  });

  it("creates a verified learner attached to the platform org", async () => {
    const result = await performOAuthLogin(createEnv(), createCtx(), GOOGLE_PROFILE, "1.2.3.4", "ua") as {
      error?: string; user?: { id: string };
    };

    expect(result.error).toBeUndefined();

    const created = dbState.insertedUsers[0];
    expect(created.is_email_verified).toBe(true); // verified at insert time
    expect(created.user_metadata).toMatchObject({ role: "learner", firstName: "New", lastName: "Person" });
    expect(String(created.password_hash)).toMatch(/^\$2[aby]\$/);
    expect(dbState.oauth_accounts).toHaveLength(1);
    expect(result.user!.id).toBe(created.id);

    // Membership lands on the platform org; no temp org is ever created.
    expect(dbState.memberships).toHaveLength(1);
    expect(dbState.memberships[0]).toMatchObject({
      user_id: created.id,
      org_id: "00000000-0000-0000-0000-000000000001",
      status: "active",
    });

    // New-user path publishes user.created + membership.created — never organization.created.
    const envWithQueue = createEnv() as Env & { SYNC_QUEUE: { sent: Array<{ type: string }> } };
    await performOAuthLogin(
      envWithQueue,
      createCtx(),
      { ...GOOGLE_PROFILE, email: "second.new@example.com", provider_user_id: "google-sub-456" },
      "1.2.3.4",
      "ua",
    );
    const eventTypes = envWithQueue.SYNC_QUEUE.sent.map((e) => e.type);
    expect(eventTypes).toContain("membership.created");
    expect(eventTypes).not.toContain("organization.created");
  });

  it("refuses a blocked account found by email", async () => {
    seedUser({ email: GOOGLE_PROFILE.email, is_blocked: true });
    const result = await performOAuthLogin(createEnv(), createCtx(), GOOGLE_PROFILE, "1.2.3.4", "ua") as {
      error?: string; status?: number;
    };

    expect(result.status).toBe(403);
    expect(dbState.sessions).toHaveLength(0);
  });
});
