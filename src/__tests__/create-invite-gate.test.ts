/**
 * SSO createInvite educator-role gate (user-decisions 3, design AC24).
 * The caller's roles are read from get_jwt_claims, never from the token.
 */
import { describe, expect, it, vi } from "vitest";
import type { CorrelationId } from "../rpc/contracts";
import { createPreservedWorkflowAuthority } from "../rpc/preserved-workflows";
import type { AccessTokenPayload } from "../types";
import {
    FakeInviteDb, makeCtx, makeDependencies, makeEnv, ORG_ID, seedInvite,
} from "./mocks/invite-fake-db";

vi.mock("../lib/audit", () => ({ audit: vi.fn() }));

const correlationId = "corr_create_invite" as CorrelationId;

function setup(tokenRoles: string[] = ["member"]) {
    const db = new FakeInviteDb();
    const { env, sendEmail } = makeEnv();
    const { ctx, flush } = makeCtx();
    const caller: AccessTokenPayload = {
        sub: "caller-1", email: "caller@example.com", org_id: ORG_ID, roles: tokenRoles, products: [],
        membership_status: "active", is_email_verified: true, user_metadata: {},
    } as AccessTokenPayload;
    const authority = createPreservedWorkflowAuthority(env, ctx, db, makeDependencies({
        verifyAccessToken: async () => caller,
    }));
    const create = async (roles: string[], email = "new.person@example.com") => {
        const outcome = await authority.createInvite({
            correlationId, accessToken: "token", email, organizationId: ORG_ID, roles,
        });
        await flush();
        return outcome;
    };
    return { db, sendEmail, create };
}

function dbClaims(db: FakeInviteDb, roles: string[], membership_status: "active" | "suspended" = "active") {
    db.claims = { roles, products: [], membership_status } as never;
}

describe("createInvite educator gate: allowed inviter roles", () => {
    const INVITER = ["owner", "admin", "super_admin", "college_admin", "school_admin"];
    for (const inviter of INVITER) {
        for (const educator of ["college_educator", "school_educator"]) {
            it(`${inviter} may invite ${educator}`, async () => {
                const { db, sendEmail, create } = setup();
                dbClaims(db, [inviter]);
                const outcome = await create([educator]);

                expect(outcome.kind).toBe("succeeded");
                expect(db.invites).toHaveLength(1);
                expect(db.invites[0].role).toEqual([educator]);
                expect(sendEmail).toHaveBeenCalledTimes(1);
            });
        }
    }
});

describe("createInvite educator gate: denied callers", () => {
    const deniedCases: Array<[string, string[]]> = [
        ["member", ["member"]],
        ["learner", ["learner"]],
        ["college_educator", ["college_educator"]],
        ["school_educator", ["school_educator"]],
        ["no roles", []],
        ["university_admin (excluded on purpose)", ["university_admin"]],
    ];
    for (const [label, roles] of deniedCases) {
        it(`${label} is denied with not_authorized, no invite row, no email`, async () => {
            const { db, sendEmail, create } = setup();
            dbClaims(db, roles);
            const outcome = await create(["college_educator"]);

            expect(outcome).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
            expect(db.invites).toHaveLength(0);
            expect(sendEmail).not.toHaveBeenCalled();
        });
    }

    it("null claims deny (fail closed)", async () => {
        const { db, sendEmail, create } = setup();
        db.claims = null;
        expect((await create(["school_educator"])).kind).toBe("rejected");
        expect(db.invites).toHaveLength(0);
        expect(sendEmail).not.toHaveBeenCalled();
    });

    it("an admin role with a suspended membership is denied", async () => {
        const { db, create } = setup();
        dbClaims(db, ["admin"], "suspended");
        expect((await create(["college_educator"])).kind).toBe("rejected");
        expect(db.invites).toHaveLength(0);
    });

    it("database roles win over token roles", async () => {
        const { db, create } = setup(["admin"]);
        dbClaims(db, ["member"]);
        expect((await create(["college_educator"])).kind).toBe("rejected");
        expect(db.invites).toHaveLength(0);
        expect(db.rpcCalls[0]).toEqual({ fn: "get_jwt_claims", args: { p_user_id: "caller-1", p_org_id: ORG_ID } });
    });

    it("a get_jwt_claims transport error yields the existing unavailable outcome, no invite", async () => {
        const { db, create } = setup();
        db.claimsError = new Error("DB rpc failed [500]");
        const outcome = await create(["college_educator"]);
        expect(outcome).toEqual({ kind: "unavailable", correlationId });
        expect(db.invites).toHaveLength(0);
    });

    it("the gate runs before the duplicate lookup (not_authorized, never conflict)", async () => {
        const { db, create } = setup();
        dbClaims(db, ["member"]);
        seedInvite(db, { email: "new.person@example.com", role: ["college_educator"] });
        const outcome = await create(["college_educator"]);
        expect(outcome).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
    });
});

describe("createInvite: non-educator invites are unchanged", () => {
    for (const roles of [["learner"], ["member"], ["admin"]]) {
        it(`a plain member inviting ${JSON.stringify(roles)} still succeeds with no claims lookup`, async () => {
            const { db, create } = setup();
            dbClaims(db, ["member"]);
            const outcome = await create(roles);

            expect(outcome.kind).toBe("succeeded");
            expect(db.invites).toHaveLength(1);
            expect(db.rpcCalls).toHaveLength(0);
        });
    }

    it("the organization check still applies to every invite", async () => {
        const { env } = makeEnv();
        const { ctx } = makeCtx();
        const authority = createPreservedWorkflowAuthority(env, ctx, new FakeInviteDb(), makeDependencies({
            verifyAccessToken: async () => ({ sub: "c", email: "c@example.com", org_id: "other-org", roles: ["admin"] }) as never,
        }));
        const outcome = await authority.createInvite({
            correlationId, accessToken: "t", email: "x@example.com", organizationId: ORG_ID, roles: ["learner"],
        });
        expect(outcome).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
    });

    it("a duplicate pending non-educator invite still reports conflict", async () => {
        const { db, create } = setup();
        seedInvite(db, { email: "new.person@example.com", role: ["learner"] });
        expect(await create(["learner"])).toEqual({ kind: "rejected", correlationId, code: "conflict" });
    });
});
