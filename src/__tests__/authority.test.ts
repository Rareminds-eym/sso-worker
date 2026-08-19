import { describe, expect, it } from "vitest";
import type { DbClient } from "../lib/db";
import { createSsoAuthority, type AuthorityDependencies } from "../rpc/authority";
import { SSO_RPC_METHODS, type CorrelationId } from "../rpc/contracts";
import type { Env } from "../types";

const correlationId = "corr_authority_test" as CorrelationId;
const now = Date.parse("2026-08-13T00:00:00.000Z");

interface MemorySession {
    id: string;
    user_id: string;
    org_id: string | null;
    refresh_token_hash: string;
    expires_at: string;
    revoked: boolean;
}

class MemoryAuthorityDb implements DbClient {
    constructor(readonly sessions: MemorySession[]) { }

    async query<T>(path: string, options: RequestInit = {}): Promise<T[]> {
        if (!path.startsWith("sessions?")) return [];
        let rows = this.matchSessions(path);
        if (options.method === "PATCH") {
            rows.forEach((session) => { session.revoked = true; });
        }
        return rows as T[];
    }

    async queryOne<T>(path: string): Promise<T | null> {
        if (path.startsWith("sessions?")) return (this.matchSessions(path)[0] as T | undefined) ?? null;
        if (path.startsWith("users?")) {
            return { id: "user-1", email: "member@example.test", is_email_verified: true, user_metadata: {} } as T;
        }
        return null;
    }

    async rpc<T>(): Promise<T> {
        return { roles: ["member"], products: ["skillpassport"], membership_status: "active" } as T;
    }

    async mutate<T>(): Promise<T> { throw new Error("Unexpected mutate"); }
    async update(): Promise<void> { throw new Error("Unexpected update"); }
    async bulkInsert<T>(): Promise<T[]> { return []; }

    private matchSessions(path: string): MemorySession[] {
        return this.sessions.filter((session) => {
            if (path.includes("revoked=eq.false") && session.revoked) return false;
            const hash = parameter(path, "refresh_token_hash");
            const id = parameter(path, "id");
            const userId = parameter(path, "user_id");
            return (!hash || session.refresh_token_hash === hash)
                && (!id || session.id === id)
                && (!userId || session.user_id === userId);
        });
    }
}
function parameter(path: string, name: string): string | null {
    const match = new RegExp(`(?:^|[?&])${name}=eq\\.([^&]+)`).exec(path);
    return match ? decodeURIComponent(match[1]) : null;
}

function environment(overrides: Partial<Env> = {}): Env {
    return {
        JWT_KID: "active-key",
        JWT_PRIVATE_KEY: "unused-private-key",
        JWT_PUBLIC_KEY: "active-public-key",
        JWKS_FRESHNESS_SECONDS: "300",
        RATE_LIMIT_KV: {} as KVNamespace,
        ...overrides,
    } as Env;
}

function executionContext(): ExecutionContext {
    return {
        waitUntil() { },
        passThroughOnException() { },
        props: {},
    } as unknown as ExecutionContext;
}

function session(id: string, token: string, userId = "user-1"): MemorySession {
    return {
        id,
        user_id: userId,
        org_id: "org-1",
        refresh_token_hash: `hash:${token}`,
        expires_at: new Date(now + 3_600_000).toISOString(),
        revoked: false,
    };
}

function dependencies(database: MemoryAuthorityDb): Partial<AuthorityDependencies> {
    return {
        database: () => database,
        hash: async (value) => `hash:${value}`,
        now: () => now,
        rateLimit: async () => null,
        currentJwk: async () => ({
            kty: "RSA",
            kid: "active-key",
            alg: "RS256",
            use: "sig",
            n: "active-modulus",
            e: "AQAB",
        }),
        exportJwk: async (_pem, kid) => ({
            kty: "RSA",
            kid,
            alg: "RS256",
            use: "sig",
            n: "retiring-modulus",
            e: "AQAB",
        }),
    };
}

describe("SSO authority handlers", () => {
    it("should implement every approved private workflow handler", () => {
        const authority = createSsoAuthority(
            environment(), executionContext(), dependencies(new MemoryAuthorityDb([])),
        );

        expect(SSO_RPC_METHODS.every((method) => typeof authority[method] === "function")).toBe(true);
    });

    it("should publish finite active and retiring JWKS metadata", async () => {
        const env = environment({
            JWT_PUBLIC_KEY_PREVIOUS: "retiring-public-key",
            JWT_KID_PREVIOUS: "retiring-key",
        });
        const authority = createSsoAuthority(env, executionContext(), dependencies(new MemoryAuthorityDb([])));

        const outcome = await authority.getJwks({ correlationId });

        expect(outcome).toEqual({
            kind: "succeeded",
            correlationId,
            freshnessSeconds: 300,
            keys: [
                { kty: "RSA", kid: "active-key", alg: "RS256", use: "sig", status: "active", n: "active-modulus", e: "AQAB" },
                { kty: "RSA", kid: "retiring-key", alg: "RS256", use: "sig", status: "retiring", n: "retiring-modulus", e: "AQAB" },
            ],
        });
    });

    it("should publish key removal by omitting the retired key from the next snapshot", async () => {
        const authority = createSsoAuthority(
            environment(),
            executionContext(),
            dependencies(new MemoryAuthorityDb([])),
        );

        const outcome = await authority.getJwks({ correlationId });

        expect(outcome.kind).toBe("succeeded");
        if (outcome.kind === "succeeded") {
            expect(outcome.keys.map(({ kid, status }) => ({ kid, status }))).toEqual([
                { kid: "active-key", status: "active" },
            ]);
        }
    });

    it("should fail closed when JWKS freshness is not positive and finite", async () => {
        const authority = createSsoAuthority(
            environment({ JWKS_FRESHNESS_SECONDS: "Infinity" }),
            executionContext(),
            dependencies(new MemoryAuthorityDb([])),
        );

        await expect(authority.getJwks({ correlationId })).resolves.toEqual({
            kind: "unavailable",
            correlationId,
        });
    });

    it("should issue an authoritative session after successful credential validation", async () => {
        const database = new MemoryAuthorityDb([session("issued-session", "issued-refresh")]);
        const authority = createSsoAuthority(environment(), executionContext(), {
            ...dependencies(database),
            performLogin: async () => ({
                access_token: "issued-access",
                refresh_token: "issued-refresh",
                user: { id: "user-1", email: "member@example.test" },
                active_org_id: "org-1",
                organizations: [{ org_id: "org-1" }],
            }),
        });

        const outcome = await authority.login({
            correlationId,
            email: "member@example.test",
            password: "not-a-real-password",
        });

        expect(outcome.kind).toBe("issued");
        if (outcome.kind === "issued") {
            expect(outcome.session).toMatchObject({
                accessToken: "issued-access",
                refreshToken: "issued-refresh",
                remainingLifetimeSeconds: 3600,
                identity: { subject: "user-1", organizationId: "org-1" },
            });
        }
    });

    it("should replace a presented prior session before returning login credentials", async () => {
        const database = new MemoryAuthorityDb([
            session("prior-session", "prior-refresh"),
            session("issued-session", "issued-refresh"),
        ]);
        const authority = createSsoAuthority(environment(), executionContext(), {
            ...dependencies(database),
            performLogin: async () => ({
                access_token: "issued-access",
                refresh_token: "issued-refresh",
                user: { id: "user-1", email: "member@example.test" },
                active_org_id: "org-1",
                organizations: [{ org_id: "org-1" }],
            }),
        });

        const outcome = await authority.login({
            correlationId,
            email: "member@example.test",
            password: "not-a-real-password",
            currentRefreshToken: "prior-refresh",
        });

        expect(outcome.kind).toBe("issued");
        expect(database.sessions.map(({ id, revoked }) => ({ id, revoked }))).toEqual([
            { id: "prior-session", revoked: true },
            { id: "issued-session", revoked: false },
        ]);
        if (outcome.kind === "issued") {
            expect(outcome.session.refreshToken).not.toBe("prior-refresh");
        }
    });

    it("should map rotation overlap and replay to distinct safe outcomes", async () => {
        const database = new MemoryAuthorityDb([session("session-1", "replacement")]);
        const base = dependencies(database);
        const overlap = createSsoAuthority(environment(), executionContext(), {
            ...base,
            rotate: async () => ({
                kind: "overlap",
                accessToken: "access-token",
                refreshToken: "replacement",
                userId: "user-1",
                orgId: "org-1",
                familyId: "family-1",
            }),
        });
        const replay = createSsoAuthority(environment(), executionContext(), {
            ...base,
            rotate: async () => ({ kind: "theft", userId: "user-1", familyId: "family-1" }),
        });
        const input = { correlationId, refreshToken: "presented", operation: "refresh_current_session" as const };

        const overlapOutcome = await overlap.refreshCurrentSession(input);
        const replayOutcome = await replay.refreshCurrentSession(input);

        expect(overlapOutcome.kind).toBe("overlap");
        if (overlapOutcome.kind === "overlap") {
            expect(overlapOutcome.session.remainingLifetimeSeconds).toBe(3600);
            expect(overlapOutcome.session.identity.subject).toBe("user-1");
        }
        expect(replayOutcome).toEqual({ kind: "rejected", code: "replay_detected", correlationId });
    });

    it("should exhaustively map authoritative rotation failures", async () => {
        const cases = [
            [{ kind: "invalid" }, "absent"],
            [{ kind: "session_expired" }, "expired"],
            [{ kind: "expired_lifetime", userId: "user-1", familyId: "family-1" }, "expired"],
            [{ kind: "blocked", userId: "user-1", familyId: "family-1" }, "blocked"],
            [{ kind: "theft", userId: "user-1", familyId: "family-1" }, "replay_detected"],
        ] as const;

        for (const [rotationOutcome, code] of cases) {
            const authority = createSsoAuthority(environment(), executionContext(), {
                ...dependencies(new MemoryAuthorityDb([])),
                rotate: async () => rotationOutcome,
            });

            await expect(authority.refreshCurrentSession({
                correlationId,
                refreshToken: "presented",
                operation: "refresh_current_session",
            })).resolves.toEqual({ kind: "rejected", code, correlationId });
        }
    });

    it("should classify bounded rate limiting, timeout, and unavailability safely", async () => {
        const database = new MemoryAuthorityDb([]);
        const input = {
            correlationId,
            refreshToken: "presented",
            operation: "refresh_current_session" as const,
        };
        const rateLimited = createSsoAuthority(environment(), executionContext(), {
            ...dependencies(database),
            rateLimit: async () => new Response(null, { status: 429, headers: { "Retry-After": "1.2" } }),
        });
        const timeout = createSsoAuthority(environment(), executionContext(), {
            ...dependencies(database),
            rotate: async () => {
                const error = new Error("private timeout detail");
                error.name = "TimeoutError";
                throw error;
            },
        });
        const unavailable = createSsoAuthority(environment(), executionContext(), {
            ...dependencies(database),
            rotate: async () => { throw new Error("private infrastructure detail"); },
        });

        await expect(rateLimited.refreshCurrentSession(input)).resolves.toEqual({
            kind: "rate_limited",
            retryAfterSeconds: 2,
            correlationId,
        });
        await expect(timeout.refreshCurrentSession(input)).resolves.toEqual({ kind: "timeout", correlationId });
        await expect(unavailable.refreshCurrentSession(input)).resolves.toEqual({ kind: "unavailable", correlationId });
    });

    it("should omit invalid retry metadata from a rate-limited outcome", async () => {
        const authority = createSsoAuthority(environment(), executionContext(), {
            ...dependencies(new MemoryAuthorityDb([])),
            rateLimit: async () => new Response(null, { status: 429 }),
        });

        await expect(authority.refreshCurrentSession({
            correlationId,
            refreshToken: "presented",
            operation: "refresh_current_session",
        })).resolves.toEqual({ kind: "rate_limited", correlationId });
    });

    it("should keep current-session and all-session revocation scopes distinct", async () => {
        const currentDb = new MemoryAuthorityDb([
            session("current", "current-token"),
            session("other", "other-token"),
        ]);
        const currentAuthority = createSsoAuthority(environment(), executionContext(), dependencies(currentDb));

        const currentOutcome = await currentAuthority.logoutCurrentSession({
            correlationId,
            refreshToken: "current-token",
            scope: "current",
        });

        expect(currentOutcome.kind).toBe("current_revoked");
        expect(currentDb.sessions.map(({ id, revoked }) => ({ id, revoked }))).toEqual([
            { id: "current", revoked: true },
            { id: "other", revoked: false },
        ]);

        const allDb = new MemoryAuthorityDb([
            session("current", "current-token"),
            session("other", "other-token"),
            session("different-user", "different-token", "user-2"),
        ]);
        const allAuthority = createSsoAuthority(environment(), executionContext(), dependencies(allDb));
        const allOutcome = await allAuthority.logoutAllSessions({
            correlationId,
            refreshToken: "current-token",
            scope: "all",
        });

        expect(allOutcome.kind).toBe("all_revoked");
        expect(allDb.sessions.map(({ id, revoked }) => ({ id, revoked }))).toEqual([
            { id: "current", revoked: true },
            { id: "other", revoked: true },
            { id: "different-user", revoked: false },
        ]);
    });

    it("should return already-ended outcomes for authoritative session absence", async () => {
        const authority = createSsoAuthority(
            environment(),
            executionContext(),
            dependencies(new MemoryAuthorityDb([])),
        );

        await expect(authority.logoutCurrentSession({
            correlationId,
            refreshToken: "absent-token",
            scope: "current",
        })).resolves.toEqual({ kind: "current_already_ended", correlationId });
        await expect(authority.logoutAllSessions({
            correlationId,
            refreshToken: "absent-token",
            scope: "all",
        })).resolves.toEqual({ kind: "all_already_ended", correlationId });
    });

    it("should adapt credential rejection without exposing authority details", async () => {
        const authority = createSsoAuthority(environment(), executionContext(), {
            ...dependencies(new MemoryAuthorityDb([])),
            performLogin: async () => ({ error: "sensitive upstream text", status: 401 }),
        });

        await expect(authority.login({
            correlationId,
            email: "member@example.test",
            password: "not-a-real-password",
        })).resolves.toEqual({
            kind: "rejected",
            code: "invalid_credentials",
            correlationId,
        });
    });
});
