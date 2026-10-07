/**
 * SSO resendInvite: DB-claims admin gate, org isolation, fresh token, throttle, audit.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { INVITE_TTL_MS } from "../lib/constants";
import type { CorrelationId } from "../rpc/contracts";
import { createPreservedWorkflowAuthority } from "../rpc/preserved-workflows";
import type { AccessTokenPayload } from "../types";
import {
    FakeInviteDb, makeCtx, makeDependencies, makeEnv, NOW, ORG_ID, seedInvite,
} from "./mocks/invite-fake-db";

const auditMock = vi.hoisted(() => vi.fn());
vi.mock("../lib/audit", () => ({ audit: auditMock }));

const correlationId = "corr_resend_invite" as CorrelationId;
const OTHER_ORG_ID = "00000000-0000-4000-8000-0000000000b2";
const INVITE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const OTHER_INVITE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
const UNKNOWN_ID = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";

beforeEach(() => auditMock.mockClear());

function setup(tokenRoles: string[] = ["member"]) {
    const db = new FakeInviteDb();
    db.claims = { roles: ["college_admin"], products: [], membership_status: "active" } as never;
    const { env, sendEmail } = makeEnv();
    const { ctx, flush } = makeCtx();
    const caller = {
        sub: "caller-1", email: "caller@example.com", org_id: ORG_ID, roles: tokenRoles, products: [],
        membership_status: "active", is_email_verified: true, user_metadata: {},
    } as AccessTokenPayload;
    const authority = createPreservedWorkflowAuthority(env, ctx, db, makeDependencies({
        verifyAccessToken: async () => caller,
    }));
    const resend = async (...args: [inviteId?: unknown, extra?: Record<string, unknown>]) => {
        const inviteId = args.length > 0 ? args[0] : INVITE_ID;
        const outcome = await authority.resendInvite({ correlationId, accessToken: "token", inviteId, ...args[1] } as never);
        await flush();
        return outcome as any;
    };
    const accept = async (token: string) => {
        const outcome = await authority.acceptInvite({ correlationId, invitationToken: token });
        await flush();
        return outcome as any;
    };
    return { db, sendEmail, resend, accept };
}

function dbClaims(db: FakeInviteDb, roles: string[], membership_status: "active" | "suspended" = "active") {
    db.claims = { roles, products: [], membership_status } as never;
}

function sentToken(sendEmail: ReturnType<typeof makeEnv>["sendEmail"]): string {
    const text = sendEmail.mock.calls.at(-1)?.[0].text as string;
    return /token=([0-9a-f-]+)/.exec(text)![1];
}

describe("resendInvite: fresh token and expiry", () => {
    it("replaces the hash, resets expiry to now + 7d (also for an expired invite) and emails the new link", async () => {
        const { db, sendEmail, resend, accept } = setup();
        db.users.push({ id: "user-1", email: "test.educator@example.com", is_email_verified: true });
        const invite = seedInvite(db, { id: INVITE_ID, expires_at: new Date(NOW - 86_400_000).toISOString() }, "old-token");
        const oldHash = invite.token_hash;

        const outcome = await resend();
        expect(outcome.kind).toBe("succeeded");
        const expected = new Date(NOW + INVITE_TTL_MS).toISOString();
        expect(outcome.data).toEqual({ inviteId: INVITE_ID, email: "test.educator@example.com", expiresAt: expected });
        expect(db.invites[0].expires_at).toBe(expected);
        expect(db.invites[0].token_hash).not.toBe(oldHash);
        expect(sendEmail).toHaveBeenCalledTimes(1);

        const newToken = sentToken(sendEmail);
        expect(db.invites[0].token_hash).toBe(`hash:${newToken}`);
        expect((await accept("old-token")).code).toBe("invalid_invitation");
        expect((await accept(newToken)).kind).toBe("issued");
    });

    it("works for educator and non-educator roles", async () => {
        for (const role of [["college_educator"], ["member"], ["admin"]]) {
            const { db, resend } = setup();
            seedInvite(db, { id: INVITE_ID, role });
            expect((await resend()).kind).toBe("succeeded");
        }
    });

    it("never puts the token or hash in the outcome", async () => {
        const { db, sendEmail, resend } = setup();
        seedInvite(db, { id: INVITE_ID });
        const outcome = await resend();
        const serialized = JSON.stringify(outcome);
        expect(serialized).not.toContain(sentToken(sendEmail));
        expect(serialized).not.toContain("hash");
    });

    it("the write carries the accepted and org filters", async () => {
        const { db, resend } = setup();
        seedInvite(db, { id: INVITE_ID });
        await resend();
        expect(db.updateCalls).toHaveLength(1);
        expect(db.updateCalls[0].table).toBe("invites");
        expect(db.updateCalls[0].filter).toEqual({
            id: `eq.${INVITE_ID}`, accepted: "not.is.true", org_id: `eq.${ORG_ID}`,
        });
        expect(Object.keys(db.updateCalls[0].body).sort()).toEqual(["expires_at", "token_hash"]);
    });

    it("resends an invite whose accepted column is null", async () => {
        const { db, resend } = setup();
        seedInvite(db, { id: INVITE_ID, accepted: null as unknown as boolean });
        expect((await resend()).kind).toBe("succeeded");
        expect(db.invites[0].expires_at).toBe(new Date(NOW + INVITE_TTL_MS).toISOString());
    });

    it("reads only non-secret columns of the invite", async () => {
        const { db, resend } = setup();
        seedInvite(db, { id: INVITE_ID });
        await resend();
        const lookup = db.queryPaths.find((p) => p.startsWith("invites"))!;
        expect(lookup).toBe(`invites?id=eq.${INVITE_ID}&select=id,email,org_id,accepted`);
    });
});

describe("resendInvite: org isolation and state", () => {
    it("returns not_found for another org's invite, identical to a missing id, and issues no update", async () => {
        const { db, sendEmail, resend } = setup();
        const foreign = seedInvite(db, { id: OTHER_INVITE_ID, org_id: OTHER_ORG_ID }, "foreign-token");
        const before = { ...foreign };

        const other = await resend(OTHER_INVITE_ID);
        const missing = await resend(UNKNOWN_ID);
        expect(other).toEqual({ kind: "rejected", correlationId, code: "not_found" });
        expect(missing).toEqual(other);
        expect(db.updateCalls).toHaveLength(0);
        expect(sendEmail).not.toHaveBeenCalled();
        expect(db.invites[0]).toEqual(before);
    });

    it("returns already_used for an accepted invite", async () => {
        const { db, sendEmail, resend } = setup();
        seedInvite(db, { id: INVITE_ID, accepted: true });
        expect(await resend()).toEqual({ kind: "rejected", correlationId, code: "already_used" });
        expect(db.updateCalls).toHaveLength(0);
        expect(sendEmail).not.toHaveBeenCalled();
    });

    it("returns not_found for a well-formed unknown id", async () => {
        const { resend } = setup();
        expect(await resend(UNKNOWN_ID)).toEqual({ kind: "rejected", correlationId, code: "not_found" });
    });
});

describe("resendInvite: admin gate (DB claims, token roles ignored)", () => {
    for (const role of ["owner", "admin", "super_admin", "college_admin", "school_admin"]) {
        it(`allows ${role}`, async () => {
            const { db, resend } = setup();
            dbClaims(db, [role]);
            seedInvite(db, { id: INVITE_ID });
            expect((await resend()).kind).toBe("succeeded");
        });
    }

    it("college_admin with no owner/admin token role is allowed (R1 regression)", async () => {
        const { db, resend } = setup(["member"]);
        dbClaims(db, ["college_admin"]);
        seedInvite(db, { id: INVITE_ID });
        expect((await resend()).kind).toBe("succeeded");
    });

    for (const [label, roles] of [
        ["member", ["member"]], ["learner", ["learner"]], ["college_educator", ["college_educator"]],
        ["university_admin", ["university_admin"]], ["no roles", []],
    ] as Array<[string, string[]]>) {
        it(`denies ${label} before any invite lookup`, async () => {
            const { db, sendEmail, resend } = setup(["owner", "admin"]);
            dbClaims(db, roles);
            seedInvite(db, { id: INVITE_ID });
            expect(await resend()).toEqual({ kind: "rejected", correlationId, code: "authorization_denied" });
            expect(db.queryPaths.filter((p) => p.startsWith("invites"))).toHaveLength(0);
            expect(db.updateCalls).toHaveLength(0);
            expect(sendEmail).not.toHaveBeenCalled();
        });
    }

    it("denies null claims and suspended memberships", async () => {
        const first = setup();
        first.db.claims = null;
        seedInvite(first.db, { id: INVITE_ID });
        expect((await first.resend()).code).toBe("authorization_denied");

        const second = setup();
        dbClaims(second.db, ["admin"], "suspended");
        seedInvite(second.db, { id: INVITE_ID });
        expect((await second.resend()).code).toBe("authorization_denied");
    });

    it("a get_jwt_claims error yields unavailable and changes nothing", async () => {
        const { db, resend } = setup();
        db.claimsError = new Error("DB rpc failed [500]");
        const invite = seedInvite(db, { id: INVITE_ID });
        const before = { ...invite };
        expect(await resend()).toEqual({ kind: "unavailable", correlationId });
        expect(db.invites[0]).toEqual(before);
    });
});

describe("resendInvite: inviteId validation", () => {
    for (const [label, value] of [
        ["non-UUID string", "not-a-uuid"], ["empty string", ""], ["number", 42], ["null", null], ["object", {}],
        ["UUID with injected filter", `${INVITE_ID}&org_id=neq.x`],
    ] as Array<[string, unknown]>) {
        it(`${label} gives invalid_request with zero DB, email and throttle calls`, async () => {
            const { db, sendEmail, resend } = setup();
            seedInvite(db, { id: INVITE_ID });
            const outcome = await resend(value);
            expect(outcome).toEqual({ kind: "rejected", correlationId, code: "invalid_request" });
            expect(db.totalCalls()).toBe(0);
            expect(db.rpcCalls).toHaveLength(0);
            expect(sendEmail).not.toHaveBeenCalled();
            expect(auditMock).not.toHaveBeenCalled();
        });
    }

    it("a missing inviteId gives invalid_request", async () => {
        const { db, resend } = setup();
        const outcome = await resend(undefined);
        expect(outcome.code).toBe("invalid_request");
        expect(db.totalCalls()).toBe(0);
    });

    it("the throttle counter is untouched by invalid ids", async () => {
        const { db, resend } = setup();
        seedInvite(db, { id: INVITE_ID });
        for (let i = 0; i < 15; i++) await resend("nope");
        expect((await resend()).kind).toBe("succeeded");
    });
});

describe("resendInvite: throttle", () => {
    it("rate-limits the 11th call in an hour, leaves the row unchanged and sends no email", async () => {
        const { db, sendEmail, resend } = setup();
        seedInvite(db, { id: INVITE_ID });
        for (let i = 0; i < 10; i++) expect((await resend()).kind).toBe("succeeded");
        expect(sendEmail).toHaveBeenCalledTimes(10);
        const snapshot = { ...db.invites[0] };
        const updates = db.updateCalls.length;

        const outcome = await resend();
        expect(outcome).toEqual({ kind: "rate_limited", correlationId });
        expect(db.invites[0]).toEqual(snapshot);
        expect(db.updateCalls).toHaveLength(updates);
        expect(sendEmail).toHaveBeenCalledTimes(10);
    });
});

describe("resendInvite: audit", () => {
    it("emits invite_resent once with only invite_id and email_status", async () => {
        const { db, resend } = setup();
        seedInvite(db, { id: INVITE_ID });
        await resend();
        expect(auditMock).toHaveBeenCalledTimes(1);
        const [, , action, entry] = auditMock.mock.calls[0];
        expect(action).toBe("invite_resent");
        expect(entry).toEqual({
            user_id: "caller-1", org_id: ORG_ID, metadata: { invite_id: INVITE_ID, email_status: "sent" },
        });
        expect(JSON.stringify(entry)).not.toContain("example.com");
    });

    it("emits no audit entry when the request is rejected", async () => {
        const { db, resend } = setup();
        seedInvite(db, { id: INVITE_ID, org_id: OTHER_ORG_ID });
        await resend();
        expect(auditMock).not.toHaveBeenCalled();
    });
});
