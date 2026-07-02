/**
 * Comprehensive tests for forgot-password and reset-password endpoints.
 *
 * Tests both route handlers directly with mocked dependencies:
 * - Supabase REST API (via global fetch mock)
 * - KV store (email throttle)
 * - Email service binding
 *
 * Covers: success paths, validation errors, email enumeration prevention,
 * throttle behavior, token lifecycle (create → use → expire), audit logging.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../types";

// ── KV mock ─────────────────────────────────────────────────────
function createMockKV(): {
  get: (key: string) => Promise<string | null>;
  put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
  delete: (key: string) => Promise<void>;
  _store: Map<string, string>;
} {
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

// ── Supabase fetch mock ─────────────────────────────────────────
interface PasswordResetRecord {
  id: string;
  user_id: string;
  token_hash: string;
  used: boolean;
  expires_at: string;
  created_at: string;
}

const dbState: {
  users: Map<string, { id: string; email: string; is_blocked: boolean; password_hash?: string }>;
  password_resets: Map<string, PasswordResetRecord>;
  sessions: Map<string, { id: string; user_id: string; revoked: boolean }>;
  audit_logs: any[];
  userPatches: Array<{ filter: Record<string, string>; body: any }>;
} = {
  users: new Map(),
  password_resets: new Map(),
  sessions: new Map(),
  audit_logs: [],
  userPatches: [],
};

function resetDbState(): void {
  dbState.users.clear();
  dbState.password_resets.clear();
  dbState.sessions.clear();
  dbState.audit_logs = [];
  dbState.userPatches = [];
}

function setupUser(email: string, overrides?: Partial<{ id: string; is_blocked: boolean; password_hash: string }>): { id: string } {
  const id = overrides?.id ?? crypto.randomUUID();
  dbState.users.set(email.toLowerCase(), {
    id,
    email: email.toLowerCase(),
    is_blocked: overrides?.is_blocked ?? false,
    password_hash: overrides?.password_hash ?? "$2a$12$hashedpassword",
  });
  return { id };
}

function createMockSupabaseFetch(): ReturnType<typeof vi.fn> {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    const bodyStr = init?.body ? String(init.body) : null;
    const parsedBody = bodyStr ? JSON.parse(bodyStr) : null;

    // Match the Supabase REST path
    const restPath = url.match(/\/rest\/v1\/([^?]+)/)?.[1] ?? "";
    const queryStr = url.includes("?") ? url.split("?")[1] : "";
    const params = new URLSearchParams(queryStr);

    if (restPath.startsWith("password_resets") && method === "GET") {
      const tokenHashParam = params.get("token_hash")?.replace(/^eq\./, "");
      if (tokenHashParam) {
        const record = dbState.password_resets.get(tokenHashParam);
        return new Response(record ? JSON.stringify([record]) : "[]", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("[]", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (restPath.startsWith("password_resets") && method === "PATCH") {
      const idParam = params.get("id")?.replace(/^eq\./, "");
      if (idParam && parsedBody) {
        for (const [, record] of dbState.password_resets) {
          if (record.id === idParam) {
            Object.assign(record, parsedBody);
          }
        }
      }
      const userIdParam = params.get("user_id")?.replace(/^eq\./, "");
      if (userIdParam) {
        for (const [, record] of dbState.password_resets) {
          if (record.user_id === userIdParam && !record.used) {
            record.used = true;
          }
        }
      }
      return new Response(null, { status: 204 });
    }

    if (restPath.startsWith("password_resets") && method === "POST") {
      const record: PasswordResetRecord = {
        id: parsedBody?.id ?? crypto.randomUUID(),
        user_id: parsedBody?.user_id ?? "",
        token_hash: parsedBody?.token_hash ?? "",
        used: parsedBody?.used ?? false,
        expires_at: parsedBody?.expires_at ?? "",
        created_at: new Date().toISOString(),
      };
      dbState.password_resets.set(record.token_hash, record);
      return new Response(JSON.stringify([record]), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (restPath.startsWith("users") && method === "GET") {
      const emailParam = params.get("email")?.replace(/^eq\./, "");
      if (emailParam) {
        const decodedEmail = decodeURIComponent(emailParam);
        const user = dbState.users.get(decodedEmail);
        if (!user) {
          return new Response("[]", {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify([user]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("[]", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (restPath.startsWith("users") && method === "PATCH") {
      dbState.userPatches.push({ filter: Object.fromEntries(params.entries()), body: parsedBody });
      if (parsedBody?.password_hash) {
        const idParam = params.get("id")?.replace(/^eq\./, "");
        if (idParam) {
          for (const [, user] of dbState.users) {
            if (user.id === idParam) {
              user.password_hash = parsedBody.password_hash;
            }
          }
        }
      }
      return new Response(null, { status: 204 });
    }

    if (restPath.startsWith("sessions") && method === "PATCH") {
      for (const [, session] of dbState.sessions) {
        session.revoked = true;
      }
      return new Response(null, { status: 204 });
    }

    if (restPath.startsWith("audit_logs") && method === "POST") {
      dbState.audit_logs.push(parsedBody);
      return new Response(JSON.stringify([{ id: crypto.randomUUID() }]), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      });
    }

    // console.log(`[mock] unhandled: ${method} ${url}`);
    return new Response("[]", {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
}

// ── Test helpers ────────────────────────────────────────────────
let mockFetch: ReturnType<typeof vi.fn>;
let mailSent: any[] = [];

function createMockEnv(kv?: ReturnType<typeof createMockKV>): Env {
  return {
    SUPABASE_URL: "https://test.supabase.co",
    SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
    JWT_PRIVATE_KEY: "test-private-key",
    JWT_PUBLIC_KEY: "test-public-key",
    JWT_KID: "test-kid-1",
    ALLOWED_ORIGINS: "http://localhost:3000",
    RATE_LIMIT_KV: (kv ?? createMockKV()) as unknown as KVNamespace,
    EMAIL_SERVICE: {
      fetch: vi.fn(async (_req: Request) => {
        mailSent.push({ url: _req.url, body: await _req.json().catch(() => ({})) });
        return new Response("OK", { status: 200 });
      }),
      sendEmail: vi.fn(async () => ({ success: true })),
    } as unknown as Fetcher,
    ALLOWED_APP_URLS: "http://localhost:3000,https://*.rareminds.in",
  } as Env;
}

let _waitUntilPromises: Promise<any>[] = [];

function createMockCtx(): ExecutionContext {
  _waitUntilPromises = [];
  return {
    waitUntil: vi.fn((p: Promise<any>) => { _waitUntilPromises.push(p); }),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

async function flushWaitUntil(): Promise<void> {
  const promises = [..._waitUntilPromises];
  _waitUntilPromises = [];
  await Promise.all(promises);
}

// ── Tests ───────────────────────────────────────────────────────

describe("forgotPassword", () => {
  let env: Env;
  let ctx: ExecutionContext;
  let kv: ReturnType<typeof createMockKV>;

  beforeEach(async () => {
    resetDbState();
    mailSent = [];
    kv = createMockKV();
    env = createMockEnv(kv);
    ctx = createMockCtx();
    mockFetch = createMockSupabaseFetch();
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should send reset email for existing user and return 200", async () => {
    setupUser("user@example.com");

    const { forgotPassword } = await import("../routes/password-reset");
    const body = JSON.stringify({ email: "user@example.com" });
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "203.0.113.42",
        "User-Agent": "TestBrowser/1.0",
      },
      body,
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data).toEqual({ message: "If an account exists, a reset email has been sent." });

    // Flush background email task
    await flushWaitUntil();

    // Email should be sent
    expect(mailSent.length).toBe(1);
    expect(mailSent[0].body.to).toBe("user@example.com");
    expect(mailSent[0].body.subject).toBe("Reset your password");
    expect(mailSent[0].body.html).toContain("/reset-password?token=");
    expect(mailSent[0].body.html).toContain("Reset Password");

    // Token should be stored in DB
    const records = Array.from(dbState.password_resets.values());
    expect(records.length).toBe(1);
    expect(records[0].user_id).toBeDefined();
    expect(records[0].used).toBe(false);
    expect(new Date(records[0].expires_at).getTime()).toBeGreaterThan(Date.now());

    // Audit log should be written with IP and User-Agent
    expect(dbState.audit_logs.length).toBe(1);
    expect(dbState.audit_logs[0].action).toBe("password_reset_requested");
    expect(dbState.audit_logs[0].user_id).toBeDefined();
    expect(dbState.audit_logs[0].ip_address).toBe("203.0.113.42");
    expect(dbState.audit_logs[0].user_agent).toBe("TestBrowser/1.0");
  });

  it("should normalize email to lowercase before lookup", async () => {
    setupUser("user@example.com");

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "USER@EXAMPLE.COM" }),
    });

    const res = await forgotPassword(req, env, ctx);
    expect(res.status).toBe(200);

    await flushWaitUntil();

    // Email should be sent to the normalized (lowercase) email
    expect(mailSent.length).toBe(1);
    expect(mailSent[0].body.to).toBe("user@example.com");
  });

  it("should reject emails with leading/trailing whitespace at validation", async () => {
    setupUser("spaced@example.com");

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "  spaced@example.com  " }),
    });

    const res = await forgotPassword(req, env, ctx);
    expect(res.status).toBe(400);
    const data = (await res.json()) as any;
    expect(data.error).toBe("Invalid email format");

    // No email should be sent (validation failed before throttle/lookup)
    await flushWaitUntil();
    expect(mailSent.length).toBe(0);
  });

  it("should return 400 for missing email field", async () => {
    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: "email is required" });
  });

  it("should return 400 for invalid email format", async () => {
    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "not-an-email" }),
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: "Invalid email format" });
  });

  it("should validate email type (not a string)", async () => {
    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: 123 }),
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: "Invalid email format" });
  });

  it("should return 400 for invalid JSON body", async () => {
    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: "Invalid JSON body" });
  });

  it("should return 400 for invalid redirect_url", async () => {
    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "user@example.com",
        redirect_url: "https://evil.com",
      }),
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: expect.stringContaining("redirect_url is not allowed") });
  });

  it("should return 500 when ALLOWED_APP_URLS is not configured and redirect_url provided", async () => {
    const envNoUrls = {
      ...env,
      ALLOWED_APP_URLS: undefined as unknown as string,
    };

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "user@example.com",
        redirect_url: "http://localhost:3000",
      }),
    });

    const res = await forgotPassword(req, envNoUrls, ctx);
    expect(res.status).toBe(500);
    const data = (await res.json()) as any;
    expect(data.error).toContain("Server misconfiguration");
  });

  it("should throw when ALLOWED_APP_URLS is not configured and no redirect_url given", async () => {
    const envNoUrls = {
      ...env,
      ALLOWED_APP_URLS: undefined as unknown as string,
    };
    setupUser("user@example.com");

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });

    // resolveAppUrl throws Error when ALLOWED_APP_URLS is missing
    // This propagates up as an unhandled exception → 500 in the fetch handler
    await expect(forgotPassword(req, envNoUrls, ctx)).rejects.toThrow("ALLOWED_APP_URLS is required");
  });

  it("should accept valid redirect_url from allowlist", async () => {
    setupUser("user@example.com");

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "user@example.com",
        redirect_url: "https://app.rareminds.in",
      }),
    });

    const res = await forgotPassword(req, env, ctx);
    expect(res.status).toBe(200);

    await flushWaitUntil();

    // Verify the reset URL used the provided redirect_url base
    expect(mailSent[0].body.html).toContain("app.rareminds.in/reset-password?token=");
  });

  it("should return 200 for non-existent user (prevent email enumeration)", async () => {
    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "nonexistent@example.com" }),
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    // Always returns same message
    expect(res.status).toBe(200);
    expect(data).toEqual({ message: "If an account exists, a reset email has been sent." });

    await flushWaitUntil();

    // No email should be sent for non-existent user
    expect(mailSent.length).toBe(0);
  });

  it("should return 200 for blocked user (prevent email enumeration)", async () => {
    setupUser("blocked@example.com", { is_blocked: true });

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "blocked@example.com" }),
    });

    const res = await forgotPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data).toEqual({ message: "If an account exists, a reset email has been sent." });

    await flushWaitUntil();

    // No email for blocked user
    expect(mailSent.length).toBe(0);
  });

  it("should return same response whether user exists or not (timing protection)", async () => {
    const { forgotPassword } = await import("../routes/password-reset");

    // Request for existing user
    setupUser("exists@example.com");
    const req1 = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "exists@example.com" }),
    });
    const res1 = await forgotPassword(req1, env, ctx);

    // Request for non-existing user (different kv to avoid throttle)
    const kv2 = createMockKV();
    const env2 = createMockEnv(kv2);
    const { forgotPassword: forgotPw2 } = await import("../routes/password-reset");
    const req2 = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "noone@example.com" }),
    });
    const res2 = await forgotPassword(req2, env2, { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext);

    const data1 = await res1.json();
    const data2 = await res2.json();

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(data1).toEqual(data2);
  });

  it("should return 429 when email throttle limit is exceeded", async () => {
    setupUser("throttle@example.com");

    // Pre-populate KV throttle slot to simulate 3 prior requests
    const windowSlot = Math.floor(Date.now() / 3600000);
    await kv.put(`et:reset:throttle@example.com:${windowSlot}`, "3");

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "throttle@example.com" }),
    });
    const res = await forgotPassword(req, env, ctx);

    expect(res.status).toBe(429);
    const data = (await res.json()) as any;
    expect(data.error).toContain("Too many");
  });

  it("should invalidate previous unused reset tokens for same user", async () => {
    const user = setupUser("user@example.com");

    // Create an old unused token
    const oldTokenHash = "old_unused_hash_abc123";
    dbState.password_resets.set(oldTokenHash, {
      id: crypto.randomUUID(),
      user_id: user.id,
      token_hash: oldTokenHash,
      used: false,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      created_at: new Date().toISOString(),
    });

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });

    const res = await forgotPassword(req, env, ctx);
    expect(res.status).toBe(200);

    // Old token should now be marked as used
    const oldRecord = dbState.password_resets.get(oldTokenHash);
    expect(oldRecord?.used).toBe(true);

    // New token should be created
    const records = Array.from(dbState.password_resets.values());
    expect(records.length).toBe(2);
  });

  it("should continue even if token invalidation fails (catch handler)", async () => {
    const user = setupUser("user@example.com");

    // Create an old unused token
    const oldTokenHash = "old_token_catch_test";
    dbState.password_resets.set(oldTokenHash, {
      id: crypto.randomUUID(),
      user_id: user.id,
      token_hash: oldTokenHash,
      used: false,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      created_at: new Date().toISOString(),
    });

    // Make PATCH on password_resets with user_id fail (simulate invalidation failure)
    const originalMock = mockFetch;
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const restPath = url.match(/\/rest\/v1\/([^?]+)/)?.[1] ?? "";
      const method = (init?.method ?? "GET").toUpperCase();
      const params = new URLSearchParams(url.includes("?") ? url.split("?")[1] : "");
      if (restPath.startsWith("password_resets") && method === "PATCH") {
        const hasUserId = params.get("user_id");
        const hasId = params.get("id");
        // Fail only the invalidation PATCH (has user_id but no id)
        if (hasUserId && !hasId) {
          return new Response("DB error", { status: 500 });
        }
      }
      return originalMock(input, init);
    });
    vi.restoreAllMocks();
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch);

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });

    // Should NOT throw - the catch handler should swallow the error
    const res = await forgotPassword(req, env, ctx);
    expect(res.status).toBe(200);

    await flushWaitUntil();

    // Email should still be sent
    expect(mailSent.length).toBe(1);

    // Old token should NOT have been marked used (since invalidation failed)
    const oldRecord = dbState.password_resets.get(oldTokenHash);
    expect(oldRecord?.used).toBe(false);

    // New token should still be created
    const records = Array.from(dbState.password_resets.values());
    expect(records.length).toBe(2);
  });

  it("should propagate DB errors (user query failure)", async () => {
    const kv2 = createMockKV();
    const env2 = createMockEnv(kv2);
    mockFetch = vi.fn().mockRejectedValue(new Error("Network error"));
    vi.restoreAllMocks();
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch);

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });

    await expect(forgotPassword(req, env2, ctx)).rejects.toThrow();
  });

  it("should not send email if token storage fails", async () => {
    setupUser("user@example.com");

    // Make POST to password_resets fail
    const originalMock = mockFetch;
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const restPath = url.match(/\/rest\/v1\/([^?]+)/)?.[1] ?? "";
      const method = (init?.method ?? "GET").toUpperCase();
      if (restPath.startsWith("password_resets") && method === "POST") {
        return new Response("DB error", { status: 500 });
      }
      return originalMock(input, init);
    });
    vi.restoreAllMocks();
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch);

    const { forgotPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });

    await expect(forgotPassword(req, env, ctx)).rejects.toThrow();
  });
});

describe("resetPassword", () => {
  let env: Env;
  let ctx: ExecutionContext;
  let kv: ReturnType<typeof createMockKV>;

  beforeEach(async () => {
    resetDbState();
    mailSent = [];
    kv = createMockKV();
    env = createMockEnv(kv);
    ctx = createMockCtx();
    mockFetch = createMockSupabaseFetch();
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should reset password with valid token", async () => {
    const user = setupUser("user@example.com");
    const { hashToken } = await import("../lib/hash");
    const rawToken = crypto.randomUUID();
    const tokenHash = await hashToken(rawToken);

    dbState.password_resets.set(tokenHash, {
      id: crypto.randomUUID(),
      user_id: user.id,
      token_hash: tokenHash,
      used: false,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      created_at: new Date().toISOString(),
    });

    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "198.51.100.7",
        "User-Agent": "ResetClient/2.0",
      },
      body: JSON.stringify({ token: rawToken, password: "NewStr0ng!Pass" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data).toEqual({ reset: true });

    // Token should be marked used
    const records = Array.from(dbState.password_resets.values());
    expect(records.length).toBe(1);
    expect(records[0].used).toBe(true);

    // User password hash should have been updated (PATCH sent to users table)
    const userPatches = dbState.userPatches;
    expect(userPatches.length).toBeGreaterThanOrEqual(1);
    const passwordPatch = userPatches.find(
      (p: any) => p.body && typeof p.body.password_hash === "string",
    );
    expect(passwordPatch).toBeDefined();
    expect(passwordPatch!.body.password_hash).not.toBe("$2a$12$hashedpassword");

    // Audit log written with IP and User-Agent
    expect(dbState.audit_logs.length).toBe(1);
    expect(dbState.audit_logs[0].action).toBe("password_reset_completed");
    expect(dbState.audit_logs[0].ip_address).toBe("198.51.100.7");
    expect(dbState.audit_logs[0].user_agent).toBe("ResetClient/2.0");
  });

  it("should return 400 for missing token", async () => {
    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "NewStr0ng!Pass" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: "token is required" });
  });

  it("should return 400 for missing password", async () => {
    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "some-token" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: "password is required" });
  });

  it("should return 400 for weak password (too short)", async () => {
    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "some-token", password: "Ab1!" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = (await res.json()) as any;

    expect(res.status).toBe(400);
    expect(data.error).toContain("at least 10");
  });

  it("should return 400 for weak password (doesn't meet complexity)", async () => {
    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "some-token", password: "abcdefghijklmnop" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = (await res.json()) as any;

    expect(res.status).toBe(400);
    expect(data.error).toContain("at least 3 of");
  });

  it("should return 400 for password exceeding max length", async () => {
    const { resetPassword } = await import("../routes/password-reset");
    const longPw = "Ab1!" + "x".repeat(72);
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "some-token", password: longPw }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = (await res.json()) as any;

    expect(res.status).toBe(400);
    expect(data.error).toContain("at most 72");
  });

  it("should return 400 for invalid JSON body", async () => {
    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });

    const res = await resetPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data).toEqual({ error: "Invalid JSON body" });
  });

  it("should return 404 for token not found in database", async () => {
    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: crypto.randomUUID(), password: "NewStr0ng!Pass" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(404);
    expect(data).toEqual({ error: "Invalid reset token" });
  });

  it("should return 410 for already-used token", async () => {
    const { hashToken } = await import("../lib/hash");
    const rawToken = "test-raw-token-used";
    const tokenHash = await hashToken(rawToken);

    const user = setupUser("user@example.com");
    dbState.password_resets.set(tokenHash, {
      id: crypto.randomUUID(),
      user_id: user.id,
      token_hash: tokenHash,
      used: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      created_at: new Date().toISOString(),
    });

    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: rawToken, password: "NewStr0ng!Pass" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(410);
    expect(data).toEqual({ error: "Token already used" });
  });

  it("should return 410 for expired token", async () => {
    const { hashToken } = await import("../lib/hash");
    const rawToken = "expired-token-456";
    const tokenHash = await hashToken(rawToken);

    const user = setupUser("user@example.com");
    dbState.password_resets.set(tokenHash, {
      id: crypto.randomUUID(),
      user_id: user.id,
      token_hash: tokenHash,
      used: false,
      expires_at: new Date(Date.now() - 3600_000).toISOString(), // 1 hour ago
      created_at: new Date(Date.now() - 7200_000).toISOString(),
    });

    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: rawToken, password: "NewStr0ng!Pass" }),
    });

    const res = await resetPassword(req, env, ctx);
    const data = await res.json();

    expect(res.status).toBe(410);
    expect(data).toEqual({ error: "Token expired" });
  });

  it("should revoke all sessions for user on password reset", async () => {
    const user = setupUser("user@example.com");
    const { hashToken } = await import("../lib/hash");
    const rawToken = "session-revoke-token";
    const tokenHash = await hashToken(rawToken);

    dbState.password_resets.set(tokenHash, {
      id: crypto.randomUUID(),
      user_id: user.id,
      token_hash: tokenHash,
      used: false,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      created_at: new Date().toISOString(),
    });

    // Add some active sessions
    dbState.sessions.set("sess-1", { id: "sess-1", user_id: user.id, revoked: false });
    dbState.sessions.set("sess-2", { id: "sess-2", user_id: user.id, revoked: false });

    const { resetPassword } = await import("../routes/password-reset");
    const req = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: rawToken, password: "NewStr0ng!Pass" }),
    });

    const res = await resetPassword(req, env, ctx);
    expect(res.status).toBe(200);

    // All sessions should be revoked
    for (const [, session] of dbState.sessions) {
      expect(session.revoked).toBe(true);
    }
  });

  it("should handle concurrent reset attempts - only first succeeds", async () => {
    const user = setupUser("user@example.com");
    const { hashToken } = await import("../lib/hash");
    const rawToken = "concurrent-token-test";
    const tokenHash = await hashToken(rawToken);

    dbState.password_resets.set(tokenHash, {
      id: crypto.randomUUID(),
      user_id: user.id,
      token_hash: tokenHash,
      used: false,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      created_at: new Date().toISOString(),
    });

    const { resetPassword } = await import("../routes/password-reset");

    // First reset should succeed
    const req1 = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: rawToken, password: "NewStr0ng!Pass" }),
    });
    const res1 = await resetPassword(req1, env, ctx);
    expect(res1.status).toBe(200);

    // Second reset with same token should fail (410 - already used)
    const req2 = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: rawToken, password: "AnotherStr0ng!Pass" }),
    });
    const res2 = await resetPassword(req2, env, ctx);
    expect(res2.status).toBe(410);
    const data2 = await res2.json();
    expect(data2).toEqual({ error: "Token already used" });
  });
});

describe("forgotPassword + resetPassword integration", () => {
  let env: Env;
  let ctx: ExecutionContext;
  let kv: ReturnType<typeof createMockKV>;

  beforeEach(async () => {
    resetDbState();
    mailSent = [];
    kv = createMockKV();
    env = createMockEnv(kv);
    ctx = createMockCtx();
    mockFetch = createMockSupabaseFetch();
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should complete the full forgot → reset flow with real token", async () => {
    setupUser("flow@example.com");

    // Step 1: Request password reset
    const { forgotPassword, resetPassword } = await import("../routes/password-reset");
    const forgotReq = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "flow@example.com" }),
    });

    const forgotRes = await forgotPassword(forgotReq, env, ctx);
    expect(forgotRes.status).toBe(200);

    // Flush background tasks to ensure email is sent
    await flushWaitUntil();

    // Extract token from sent email
    expect(mailSent.length).toBe(1);
    const html = mailSent[0].body.html as string;
    const tokenMatch = html.match(/token=([a-f0-9-]+)/);
    expect(tokenMatch).not.toBeNull();
    const resetToken = tokenMatch![1];

    // Step 2: Reset password with the token from email
    const resetReq = new Request("https://sso-api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: resetToken, password: "NewStr0ng!Pass" }),
    });

    const resetRes = await resetPassword(resetReq, env, ctx);
    const resetData = await resetRes.json();

    expect(resetRes.status).toBe(200);
    expect(resetData).toEqual({ reset: true });

    // Verify audit trail
    const auditActions = dbState.audit_logs.map((l: any) => l.action);
    expect(auditActions).toContain("password_reset_requested");
    expect(auditActions).toContain("password_reset_completed");
  });
});

describe("rate limiting middleware for password endpoints", () => {
  beforeEach(async () => {
    resetDbState();
    mailSent = [];
    mockFetch = createMockSupabaseFetch();
    vi.spyOn(globalThis, "fetch").mockImplementation(mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should bypass in-memory rate limit when cf-connecting-ip is missing (internal/service requests)", async () => {
    const kv2 = createMockKV();
    const env2 = createMockEnv(kv2);
    const { default: SsoWorker } = await import("../index");
    const worker = new SsoWorker(
      { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext,
      env2 as any,
    );

    // Request without CF-Connecting-IP should bypass rate limiter
    const req = new Request("https://sso-api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Origin": "http://localhost:3000" },
      body: JSON.stringify({ email: "nobody@example.com" }),
    });

    const res = await worker.fetch(req);
    // Should reach the handler and return 200 (generic message since user doesn't exist)
    expect(res.status).toBe(200);
  });

  it("should apply rate limiting when cf-connecting-ip is present", async () => {
    const kv2 = createMockKV();
    const env2 = createMockEnv(kv2);
    const { default: SsoWorker } = await import("../index");

    // Create multiple requests with the same IP to trigger rate limit
    for (let i = 0; i < 4; i++) {
      const worker = new SsoWorker(
        { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext,
        env2 as any,
      );

      const req = new Request("https://sso-api/auth/forgot-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Origin": "http://localhost:3000",
          "CF-Connecting-IP": "192.168.1.1",
        },
        body: JSON.stringify({ email: `test${i}@example.com` }),
      });

      const res = await worker.fetch(req);
      if (i < 3) {
        expect(res.status).toBe(200);
      } else {
        // 4th request should be rate limited (forgotPassword limit is 3/hr)
        expect(res.status).toBe(429);
      }
    }
  });
});
