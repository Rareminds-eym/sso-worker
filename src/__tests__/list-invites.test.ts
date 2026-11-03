/**
 * SSO listInvites: read-only, org-scoped, admin-gated, capped, never returns a token or hash.
 */
import { describe, expect, it, vi } from "vitest";
import type { CorrelationId } from "../rpc/contracts";
import { createPreservedWorkflowAuthority } from "../rpc/preserved-workflows";
import type { AccessTokenPayload } from "../types";
import {
    FakeInviteDb, makeCtx, makeDependencies, makeEnv, NOW, ORG_ID, seedInvite,
} from "./mocks/invite-fake-db";

const auditMock = vi.hoisted(() => vi.fn());
vi.mock("../lib/audit", () => ({ audit: auditMock }));

const correlationId = "corr_list_invites" as CorrelationId;
const OTHER_ORG_ID = "00000000-0000-4000-8000-0000000000b2";
const SEEDED_TOKEN = "super-secret-seeded-token";

function setup(tokenRoles: string[] = ["member"], verify?: () => Promise<AccessTokenPayload>) {
    const db = new FakeInviteDb();
    db.claims = { roles: ["college_admin"], products: [], membership_status: "active" } as never;
    const { env } = makeEnv();
    const { ctx } = makeCtx();
    const caller = {
        sub: "caller-1", email: "caller@example.com", org_id: ORG_ID, roles: tokenRoles, products: [],
        membership_status: "active", is_email_verified: true, user_metadata: {},
    } as AccessTokenPayload;
    const authority = createPreservedWorkflowAuthority(env, ctx, db, makeDependencies({
        verifyAccessToken: verify ?? (async () => caller),
    }));
    const list = (...args: [organizationId?: unknown, accessToken?: string]) => {
        const organizationId = args.length > 0 ? args[0] : ORG_ID;
        const accessToken = args[1] ?? "token";
        return authority.listInvites({ correlationId, accessToken, organizationId } as never);
    };
    return { db, list };
}

function dbClaims(db: FakeInviteDb, roles: string[], membership_status: "active" | "suspended" = "active") {
    db.claims = { roles, products: [], membership_status } as never;
}

const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();

describe("listInvites: org isolation", () => {
    it("returns only the caller's org and every query is scoped to it", async () => {
        const { db, list } = setup();
        seedInvite(db, { id: "a-1", email: "a1@example.com" });
        seedInvite(db, { id: "a-2", email: "a2@example.com" });
        seedInvite(db, { id: "b-1", email: "b1@example.com", org_id: OTHER_ORG_ID });

        const outcome = await list() as any;
        expect(outcome.kind).toBe("succeeded");
        expect(outcome.data.invites.map((i: any) => i.email).sort()).toEqual(["a1@example.com", "a2@example.com"]);
        const inviteQueries = db.queryPaths.filter((p) => p.startsWith("invites"));
        expect(inviteQueries.length).toBeGreaterThan(0);
        for (const path of inviteQueries) expect(path).toContain(`org_id=eq.${ORG_ID}`);
        for (const path of db.queryPaths) expect(path).not.toContain(OTHER_ORG_ID);
    });

    it("rejects another organizationId with authorization_denied before any DB query", async () => {
        const { db, list } = setup();
        seedInvite(db, { org_id: OTHER_ORG_ID });
        const outcome = await list(OTHER_ORG_ID);
        expect(outcome).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
        expect(db.totalCalls()).toBe(0);
    });
});

describe("listInvites: admin-only gate", () => {
    for (const role of ["owner", "admin", "super_admin", "college_admin", "school_admin"]) {
        it(`allows ${role}`, async () => {
            const { db, list } = setup();
            dbClaims(db, [role]);
            expect((await list()).kind).toBe("succeeded");
        });
    }

    const denied: Array<[string, string[]]> = [
        ["member", ["member"]], ["learner", ["learner"]], ["college_educator", ["college_educator"]],
        ["university_admin", ["university_admin"]], ["no roles", []],
    ];
    for (const [label, roles] of denied) {
        it(`denies ${label} and reads no invites`, async () => {
            const { db, list } = setup();
            dbClaims(db, roles);
            expect(await list()).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
            expect(db.queryPaths.filter((p) => p.startsWith("invites"))).toHaveLength(0);
        });
    }

    it("denies null claims (fail closed)", async () => {
        const { db, list } = setup();
        db.claims = null;
        expect((await list()).kind).toBe("rejected");
        expect(db.queryPaths).toHaveLength(0);
    });

    it("denies a suspended admin", async () => {
        const { db, list } = setup();
        dbClaims(db, ["admin"], "suspended");
        expect((await list()).kind).toBe("rejected");
    });

    it("database roles win over token roles", async () => {
        const { db, list } = setup(["owner", "admin"]);
        dbClaims(db, ["member"]);
        expect((await list()).kind).toBe("rejected");
        expect(db.rpcCalls[0]).toEqual({ fn: "get_jwt_claims", args: { p_user_id: "caller-1", p_org_id: ORG_ID } });
    });

    it("a get_jwt_claims error yields unavailable", async () => {
        const { db, list } = setup();
        db.claimsError = new Error("DB rpc failed [500]");
        expect(await list()).toEqual({ kind: "unavailable", correlationId });
    });

    it("an invites query failure yields unavailable", async () => {
        const { db, list } = setup();
        db.query = async () => { throw new Error("DB query failed [500]"); };
        expect(await list()).toEqual({ kind: "unavailable", correlationId });
    });
});

describe("listInvites: identity comes from the token only", () => {
    for (const [label, value] of [
        ["undefined", undefined], ["empty", ""], ["number", 42], ["null", null], ["object", {}], ["65 chars", "x".repeat(65)],
    ] as Array<[string, unknown]>) {
        it(`${label} organizationId is invalid_request with zero DB calls`, async () => {
            const { db, list } = setup();
            expect(await list(value)).toEqual({ kind: "rejected", correlationId, code: "invalid_request" });
            expect(db.totalCalls()).toBe(0);
        });
    }

    it("a bad token is authorization_denied with zero DB calls", async () => {
        const { db, list } = setup(["member"], async () => { throw new Error("bad token"); });
        expect(await list(ORG_ID, "bad")).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
        expect(db.totalCalls()).toBe(0);
    });

    it("an empty token is authorization_denied", async () => {
        const { list } = setup();
        expect(await list(ORG_ID, "")).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
    });
});

describe("listInvites: no secrets in the response", () => {
    it("exposes exactly six fields and never a token, hash or seeded value", async () => {
        const { db, list } = setup();
        seedInvite(db, { id: "a-1", created_at: iso(-1000) }, SEEDED_TOKEN);
        const outcome = await list() as any;
        const serialized = JSON.stringify(outcome);
        expect(serialized).not.toContain("token");
        expect(serialized).not.toContain("hash");
        expect(serialized).not.toContain(SEEDED_TOKEN);
        expect(Object.keys(outcome.data.invites[0]).sort()).toEqual(
            ["createdAt", "email", "expiresAt", "inviteId", "roles", "status"],
        );
        for (const path of db.queryPaths) expect(path).not.toContain("token_hash");
        expect(db.queryPaths.find((p) => p.startsWith("invites"))).toContain("select=id,email,role,created_at,expires_at");
    });

    it("maps rows field by field (extra columns never leak)", async () => {
        const { db, list } = setup();
        db.query = async <T>() => [{
            id: "a-1", email: "a@example.com", role: ["x"], created_at: null, expires_at: null,
            token_hash: "leaky", invited_by: "someone",
        }] as unknown as T[];
        const serialized = JSON.stringify(await list());
        expect(serialized).not.toContain("leaky");
        expect(serialized).not.toContain("someone");
    });

    it("is read-only: no writes and no audit entry", async () => {
        const { db, list } = setup();
        auditMock.mockClear();
        seedInvite(db);
        await list();
        expect(db.mutateCalls).toHaveLength(0);
        expect(db.updateCalls).toHaveLength(0);
        expect(auditMock).not.toHaveBeenCalled();
    });
});

describe("listInvites: status, cap and ordering", () => {
    it("derives pending and expired, treats null expiry as pending, expires_at == now as expired", async () => {
        const { db, list } = setup();
        seedInvite(db, { id: "pending", email: "p@example.com", expires_at: iso(1) });
        seedInvite(db, { id: "expired", email: "e@example.com", expires_at: iso(-1) });
        seedInvite(db, { id: "boundary", email: "b@example.com", expires_at: iso(0) });
        seedInvite(db, { id: "noexpiry", email: "n@example.com", expires_at: null });
        const outcome = await list() as any;
        const status = Object.fromEntries(outcome.data.invites.map((i: any) => [i.inviteId, i.status]));
        expect(status).toEqual({ pending: "pending", expired: "expired", boundary: "expired", noexpiry: "pending" });
    });

    it("excludes accepted invites and lists accepted = null", async () => {
        const { db, list } = setup();
        seedInvite(db, { id: "done", email: "done@example.com", accepted: true });
        seedInvite(db, { id: "nullish", email: "null@example.com", accepted: null as unknown as boolean });
        seedInvite(db, { id: "open", email: "open@example.com" });
        const outcome = await list() as any;
        expect(outcome.data.invites.map((i: any) => i.inviteId).sort()).toEqual(["nullish", "open"]);
    });

    it("caps at 100 and reports truncated when 101 rows exist", async () => {
        const { db, list } = setup();
        for (let i = 0; i < 101; i++) {
            seedInvite(db, { id: `inv-${String(i).padStart(3, "0")}`, email: `u${i}@example.com`, created_at: iso(i * 1000) });
        }
        const outcome = await list() as any;
        expect(outcome.data.invites).toHaveLength(100);
        expect(outcome.data.truncated).toBe(true);
        expect(db.queryPaths.find((p) => p.startsWith("invites"))).toContain("limit=101");
        // Newest first: the oldest row (i = 0) is the one dropped.
        expect(outcome.data.invites[0].inviteId).toBe("inv-100");
        expect(outcome.data.invites.some((i: any) => i.inviteId === "inv-000")).toBe(false);
    });

    it("reports truncated: false with exactly 100 rows", async () => {
        const { db, list } = setup();
        for (let i = 0; i < 100; i++) seedInvite(db, { id: `inv-${i}`, email: `u${i}@example.com` });
        const outcome = await list() as any;
        expect(outcome.data.invites).toHaveLength(100);
        expect(outcome.data.truncated).toBe(false);
    });

    it("orders newest first with nulls last and id as the tiebreaker", async () => {
        const { db, list } = setup();
        seedInvite(db, { id: "old", email: "old@example.com", created_at: iso(-5000) });
        seedInvite(db, { id: "nodate", email: "nd@example.com", created_at: null });
        seedInvite(db, { id: "new", email: "new@example.com", created_at: iso(-1000) });
        seedInvite(db, { id: "tie-a", email: "ta@example.com", created_at: iso(-3000) });
        seedInvite(db, { id: "tie-b", email: "tb@example.com", created_at: iso(-3000) });
        const outcome = await list() as any;
        expect(outcome.data.invites.map((i: any) => i.inviteId)).toEqual(["new", "tie-b", "tie-a", "old", "nodate"]);
        expect(db.queryPaths.find((p) => p.startsWith("invites"))).toContain("order=created_at.desc.nullslast,id.desc");
    });

    it("lists a null role as an empty roles array and drops non-string entries", async () => {
        const { db, list } = setup();
        seedInvite(db, { id: "nullrole", email: "nr@example.com", role: null });
        seedInvite(db, { id: "mixed", email: "mx@example.com", role: ["college_educator", 7 as unknown as string] });
        const outcome = await list() as any;
        const byId = Object.fromEntries(outcome.data.invites.map((i: any) => [i.inviteId, i]));
        expect(byId.nullrole.roles).toEqual([]);
        expect(byId.mixed.roles).toEqual(["college_educator"]);
    });

    it("returns the sent date and expiry as stored", async () => {
        const { db, list } = setup();
        seedInvite(db, { id: "x", created_at: iso(-2000), expires_at: iso(5000) });
        const [invite] = ((await list()) as any).data.invites;
        expect(invite).toMatchObject({ createdAt: iso(-2000), expiresAt: iso(5000), roles: ["college_educator"] });
    });
});
