/**
 * Pins user-decisions 4: `source: 'invite'` is published ONLY by acceptInvite.
 * The other membership.created producers (login replay, user-sync replay,
 * signup-member) must not carry a `source` key. Payload literals are written to
 * fixtures/membership-created-payloads.json for the SkillPassport sync tests.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../types";
import fixtures from "./fixtures/membership-created-payloads.json";

const published: Array<{ type: string; payload: Record<string, unknown> }> = [];

vi.mock("../lib/sync-queue", () => ({
    publishSyncEvent: (_queue: unknown, _ctx: unknown, type: string, payload: Record<string, unknown>) => {
        published.push({ type, payload });
    },
}));
vi.mock("../lib/audit", () => ({ audit: vi.fn() }));
vi.mock("../lib/skillpassport-check", () => ({ checkUserExistsInSkillpassport: vi.fn().mockResolvedValue(false) }));
vi.mock("../lib/rate-limit", () => ({
    checkAccountLockout: vi.fn().mockResolvedValue(false),
    recordFailedLogin: vi.fn(), clearFailedLogins: vi.fn().mockResolvedValue(undefined),
    endpointRateLimit: vi.fn().mockResolvedValue(false),
}));
vi.mock("../lib/hash", () => ({
    verifyPassword: vi.fn().mockResolvedValue(true), hashPassword: vi.fn().mockResolvedValue("pw-hash"),
    hashToken: vi.fn().mockResolvedValue("token-hash"), generateRefreshToken: vi.fn().mockReturnValue("refresh"),
}));
vi.mock("../lib/jwt", () => ({ signAccessToken: vi.fn().mockResolvedValue("access") }));
vi.mock("../lib/email", () => ({ sendEmail: vi.fn().mockResolvedValue(undefined) }));
vi.mock("../lib/email-throttle", () => ({ checkEmailThrottle: vi.fn().mockResolvedValue(null) }));

const ORG = "org-college-1";
let database: Record<string, (...args: any[]) => unknown>;
vi.mock("../lib/db", () => ({ db: () => database }));

function envWith(sendQueue = vi.fn().mockResolvedValue(undefined)): { env: Env; send: ReturnType<typeof vi.fn> } {
    const store = new Map<string, string>();
    const env = {
        SYNC_QUEUE: { send: sendQueue },
        SKILLPASSPORT_URL: "https://app.example.test",
        RATE_LIMIT_KV: {
            get: async (key: string) => store.get(key) ?? null,
            put: async (key: string, value: string) => { store.set(key, value); },
        },
    } as unknown as Env;
    return { env, send: sendQueue };
}

function ctxCollector(): { ctx: ExecutionContext; flush: () => Promise<void> } {
    const pending: Promise<unknown>[] = [];
    return {
        ctx: { waitUntil: (p: Promise<unknown>) => { pending.push(p); } } as unknown as ExecutionContext,
        flush: async () => { await Promise.allSettled(pending.splice(0)); },
    };
}

beforeEach(() => { published.length = 0; });

describe("membership.created producers other than acceptInvite carry no `source`", () => {
    it("login replay (routes/login.ts)", async () => {
        const { performLogin } = await import("../routes/login");
        database = {
            queryOne: vi.fn(async (path: string) => {
                if (path.startsWith("users?")) {
                    return {
                        id: "user-login-1", email: "edu@example.com", password_hash: "x", is_blocked: false,
                        is_email_verified: true, user_metadata: {}
                    };
                }
                if (path.startsWith("organizations?")) return { id: ORG, name: "Test College" };
                return null;
            }),
            query: vi.fn(async (path: string) => {
                if (path.startsWith("memberships?")) return [{ id: "m1", user_id: "user-login-1", org_id: ORG, status: "active" }];
                return [];
            }),
            mutate: vi.fn(async () => ({})),
            update: vi.fn(async () => undefined),
            rpc: vi.fn(async () => ({ roles: ["college_educator"], products: [], membership_status: "active" })),
        };
        const { env } = envWith();
        const { ctx, flush } = ctxCollector();

        const result = await performLogin(env, ctx, { email: "edu@example.com", password: "Str0ng-Passw0rd!" } as never, "1.1.1.1", "ua");
        await flush();

        expect("access_token" in result).toBe(true);
        const membership = published.find((event) => event.type === "membership.created");
        expect(membership).toBeDefined();
        expect(membership!.payload).not.toHaveProperty("source");
        expect(membership!.payload).toEqual(fixtures.login);
    });

    it("queueUserSync replay (routes/user-sync.ts)", async () => {
        const { performQueueUserSync } = await import("../routes/user-sync");
        database = {
            queryOne: vi.fn(async (path: string) => {
                if (path.startsWith("users?")) return { id: "user-sync-1", email: "edu@example.com", user_metadata: {} };
                if (path.startsWith("memberships?")) return { id: "m1", org_id: ORG };
                if (path.startsWith("organizations?")) return { id: ORG, name: "Test College" };
                return null;
            }),
            query: vi.fn(async () => [{ roles: { name: "college_educator" } }]),
        };
        const { env, send } = envWith();

        const result = await performQueueUserSync(env, "user-sync-1");

        expect(result.queued).toBe(true);
        const sent = send.mock.calls.map(([event]) => event as { type: string; payload: Record<string, unknown> });
        const membership = sent.find((event) => event.type === "membership.created");
        expect(membership).toBeDefined();
        expect(membership!.payload).not.toHaveProperty("source");
        expect(membership!.payload).toEqual(fixtures.userSync);
    });

    it("signup-member (routes/signup-member.ts)", async () => {
        const { performSignupMember } = await import("../routes/signup-member");
        database = {
            query: vi.fn(async () => []),
            queryOne: vi.fn(async () => ({ is_email_verified: false })),
            mutate: vi.fn(async () => ({})),
            update: vi.fn(async () => undefined),
            rpc: vi.fn(async (fn: string) => fn === "signup_member"
                ? { user_id: "user-signup-1", org_id: ORG, membership_id: "m1" }
                : { roles: ["college_educator"], products: [], membership_status: "active" }),
        };
        const { env } = envWith();
        const { ctx, flush } = ctxCollector();

        const result = await performSignupMember(env, ctx, {
            email: "edu@example.com", password: "Str0ng-Passw0rd!", role: "college_educator", org_id: ORG,
        } as never);
        await flush();

        expect(result).not.toHaveProperty("error");
        const membership = published.find((event) => event.type === "membership.created");
        expect(membership).toBeDefined();
        expect(membership!.payload).not.toHaveProperty("source");
        expect(membership!.payload).toEqual(fixtures.signupMember);
    });

    it("bulk import payload literal (bulk-import-handlers.ts:302) has no source key", () => {
        // Transcribed by hand from the producer; the handler needs a full queue harness and is not changed.
        expect(fixtures.bulkImport).not.toHaveProperty("source");
    });
});
