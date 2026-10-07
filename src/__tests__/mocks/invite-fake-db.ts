/**
 * In-memory DbClient + environment fakes for the invite workflow tests
 * (accept-invite.test.ts, create-invite-gate.test.ts).
 *
 * The fake THROWS on any write to `users` for an email/id that already exists,
 * so a future change that updates an existing user (for example force-verifying
 * them) fails the suite.
 */
import { vi } from "vitest";
import type { DbClient } from "../../lib/db";
import type { PreservedWorkflowDependencies } from "../../rpc/preserved-workflows";
import type { Env, JwtClaims } from "../../types";

export const NOW = Date.parse("2026-08-13T00:00:00.000Z");
export const ORG_ID = "00000000-0000-4000-8000-0000000000a1";

export interface FakeUser {
    id: string; email: string; is_email_verified: boolean; is_blocked?: boolean;
    user_metadata?: Record<string, unknown> | null; password_hash?: string;
}
export interface FakeInvite {
    id: string; email: string; org_id: string; role: string[] | null; token_hash: string | null;
    invited_by: string | null; expires_at: string | null; accepted: boolean; accepted_at: string | null;
    created_at: string | null;
}

export class FakeInviteDb implements DbClient {
    users: FakeUser[] = [];
    invites: FakeInvite[] = [];
    memberships: Array<{ id: string; user_id: string; org_id: string; status: string }> = [];
    membershipRoles: Array<{ membership_id: string; role_id: string }> = [];
    sessions: Array<Record<string, unknown>> = [];
    roles = ["member", "learner", "admin", "owner", "super_admin", "college_admin", "school_admin",
        "college_educator", "school_educator"].map((name) => ({ id: `role-${name}`, name }));
    claims: JwtClaims | null = { roles: [], products: [], membership_status: "active" } as unknown as JwtClaims;
    claimsError: Error | null = null;
    rpcCalls: Array<{ fn: string; args?: Record<string, unknown> }> = [];
    mutateCalls: Array<{ table: string; body: Record<string, unknown> }> = [];
    /** Every path issued through query()/queryOne(), in order. */
    queryPaths: string[] = [];
    /** Every update() call, in order. */
    updateCalls: Array<{ table: string; filter: Record<string, string>; body: Record<string, unknown> }> = [];
    private seq = 0;

    private id(prefix: string): string { return `${prefix}-${++this.seq}`; }

    private param(path: string, name: string): string | null {
        const match = new RegExp(`(?:^|[?&])${name}=eq\\.([^&]+)`).exec(path);
        return match ? decodeURIComponent(match[1]) : null;
    }

    /** Total number of database interactions of any kind (used for "zero DB calls" assertions). */
    totalCalls(): number {
        return this.queryPaths.length + this.updateCalls.length + this.mutateCalls.length + this.rpcCalls.length;
    }

    async query<T>(path: string, options: RequestInit = {}): Promise<T[]> {
        this.queryPaths.push(path);
        if (path.startsWith("users") && options.method && options.method !== "GET") {
            throw new Error("users write via query()");
        }
        if (path.startsWith("roles?")) {
            const names = /name=in\.\(([^)]*)\)/.exec(path)?.[1]?.split(",").map(decodeURIComponent) ?? [];
            return this.roles.filter((role) => names.includes(role.name)) as T[];
        }
        if (path.startsWith("invites?")) {
            const org = this.param(path, "org_id");
            const pendingOnly = /(?:^|[?&])accepted=not\.is\.true(?:&|$)/.test(path);
            const limitMatch = /(?:^|[?&])limit=(\d+)/.exec(path);
            let rows = this.invites.filter((row) => (org === null || row.org_id === org) &&
                (!pendingOnly || (row.accepted as boolean | null) !== true));
            if (/(?:^|[?&])order=created_at\.desc\.nullslast,id\.desc(?:&|$)/.test(path)) {
                rows = [...rows].sort((a, b) => {
                    if (a.created_at !== b.created_at) {
                        if (a.created_at === null) return 1;
                        if (b.created_at === null) return -1;
                        return a.created_at < b.created_at ? 1 : -1;
                    }
                    return a.id < b.id ? 1 : a.id > b.id ? -1 : 0;
                });
            }
            if (limitMatch) rows = rows.slice(0, Number(limitMatch[1]));
            return rows.map((row) => ({ ...row })) as unknown as T[];
        }
        return [];
    }

    async queryOne<T>(path: string): Promise<T | null> {
        this.queryPaths.push(path);
        const table = path.split("?")[0];
        if (table === "invites") {
            const inviteId = this.param(path, "id");
            if (inviteId) return (this.invites.find((row) => row.id === inviteId) as T | undefined) ?? null;
            const hash = this.param(path, "token_hash");
            if (hash) return (this.invites.find((row) => row.token_hash === hash) as T | undefined) ?? null;
            const email = this.param(path, "email");
            const org = this.param(path, "org_id");
            return (this.invites.find((row) => row.email === email && row.org_id === org && !row.accepted) as T | undefined) ?? null;
        }
        if (table === "users") {
            const email = this.param(path, "email");
            const id = this.param(path, "id");
            return (this.users.find((row) => (email ? row.email === email : row.id === id)) as T | undefined) ?? null;
        }
        if (table === "memberships") {
            const userId = this.param(path, "user_id");
            const orgId = this.param(path, "org_id");
            return (this.memberships.find((row) => row.user_id === userId && row.org_id === orgId) as T | undefined) ?? null;
        }
        if (table === "organizations") return { name: "Test College" } as T;
        return null;
    }

    async mutate<T>(table: string, body: Record<string, unknown>): Promise<T> {
        this.mutateCalls.push({ table, body });
        if (table === "users") {
            if (this.users.some((row) => row.email === body.email)) throw new Error("users write on existing user");
            const row = { id: this.id("user"), is_blocked: false, user_metadata: {}, ...body } as unknown as FakeUser;
            this.users.push(row);
            return row as unknown as T;
        }
        if (table === "invites") {
            const row = { id: this.id("invite"), accepted: false, accepted_at: null, created_at: null, ...body } as unknown as FakeInvite;
            this.invites.push(row);
            return row as unknown as T;
        }
        if (table === "memberships") {
            const row = { id: this.id("membership"), ...body } as { id: string; user_id: string; org_id: string; status: string };
            this.memberships.push(row);
            return row as unknown as T;
        }
        if (table === "membership_roles") {
            const row = body as { membership_id: string; role_id: string };
            if (this.membershipRoles.some((r) => r.membership_id === row.membership_id && r.role_id === row.role_id)) {
                throw new Error("DB mutate failed [409]: 23505 duplicate key");
            }
            this.membershipRoles.push(row);
            return row as unknown as T;
        }
        if (table === "sessions") {
            this.sessions.push(body);
            return body as unknown as T;
        }
        throw new Error(`Unexpected mutate on ${table}`);
    }

    async update(table: string, filter: Record<string, string>, body: Record<string, unknown>): Promise<void> {
        this.updateCalls.push({ table, filter: { ...filter }, body: { ...body } });
        if (table === "users") throw new Error("users write via update()");
        const rows: Array<Record<string, unknown>> | undefined = table === "invites" ? this.invites as unknown as Array<Record<string, unknown>>
            : table === "memberships" ? this.memberships as unknown as Array<Record<string, unknown>>
                : table === "sessions" ? this.sessions : undefined;
        // Honors every filter: `eq.X` compares equal, `not.is.true` keeps null/false rows.
        const matches = (row: Record<string, unknown>) => Object.entries(filter).every(([column, condition]) => {
            if (condition === "not.is.true") return row[column] !== true;
            return row[column] === decodeURIComponent(condition.replace(/^eq\./, ""));
        });
        const row = rows?.find(matches);
        if (row) Object.assign(row, body);
    }

    async rpc<T>(fn: string, args?: Record<string, unknown>): Promise<T> {
        this.rpcCalls.push({ fn, args });
        if (this.claimsError) throw this.claimsError;
        return this.claims as unknown as T;
    }

    async bulkInsert<T>(): Promise<T[]> { return []; }

    usersWrites(): Array<{ table: string; body: Record<string, unknown> }> {
        return this.mutateCalls.filter((call) => call.table === "users");
    }
}

export function makeEnv(): { env: Env; send: ReturnType<typeof vi.fn>; sendEmail: ReturnType<typeof vi.fn> } {
    const store = new Map<string, string>();
    const send = vi.fn().mockResolvedValue(undefined);
    const sendEmail = vi.fn().mockResolvedValue({ success: true });
    const env = {
        SYNC_QUEUE: { send },
        EMAIL_SERVICE: { sendEmail },
        SKILLPASSPORT_URL: "https://app.example.test",
        RATE_LIMIT_KV: {
            get: async (key: string) => store.get(key) ?? null,
            put: async (key: string, value: string) => { store.set(key, value); },
        },
    } as unknown as Env;
    return { env, send, sendEmail };
}

type SendEmailMock = ReturnType<typeof vi.fn>;

/** Provider answers `{ success: false, errorCode }`. */
export function emailProviderRejects(sendEmail: SendEmailMock, errorCode = "PROVIDER_ERROR", error = "provider detail"): void {
    sendEmail.mockResolvedValue({ success: false, errorCode, error });
}
/** The email RPC promise rejects. */
export function emailRejects(sendEmail: SendEmailMock, error: Error = new Error("Worker shared-email-api not found")): void {
    sendEmail.mockRejectedValue(error);
}
/** The email RPC throws synchronously, before returning a promise. */
export function emailThrowsSync(sendEmail: SendEmailMock, error: Error = new Error("sync boom")): void {
    sendEmail.mockImplementation(() => { throw error; });
}
/** The email RPC never settles. */
export function emailHangs(sendEmail: SendEmailMock): void {
    sendEmail.mockImplementation(() => new Promise(() => undefined));
}

export function makeCtx(): { ctx: ExecutionContext; flush: () => Promise<void> } {
    const pending: Promise<unknown>[] = [];
    const ctx = { waitUntil: (promise: Promise<unknown>) => { pending.push(promise); }, passThroughOnException: () => undefined } as unknown as ExecutionContext;
    return { ctx, flush: async () => { await Promise.allSettled(pending.splice(0)); } };
}

export function makeDependencies(overrides: Partial<PreservedWorkflowDependencies> = {}): PreservedWorkflowDependencies {
    let refresh = 0;
    return {
        hash: async (value: string) => `hash:${value}`,
        hashPassword: async (value: string) => `pw:${value}`,
        generateRefreshToken: () => `refresh-${++refresh}`,
        signAccessToken: async () => "access-token",
        verifyAccessToken: async () => { throw new Error("verifyAccessToken not stubbed"); },
        now: () => NOW,
        ...overrides,
    } as PreservedWorkflowDependencies;
}

export function seedInvite(db: FakeInviteDb, overrides: Partial<FakeInvite> = {}, token = "invite-token"): FakeInvite {
    const invite: FakeInvite = {
        id: `invite-seed-${db.invites.length + 1}`, email: "test.educator@example.com", org_id: ORG_ID,
        role: ["college_educator"], token_hash: `hash:${token}`, invited_by: "admin-1",
        expires_at: new Date(NOW + 86_400_000).toISOString(), accepted: false, accepted_at: null,
        created_at: null, ...overrides,
    };
    db.invites.push(invite);
    return invite;
}
