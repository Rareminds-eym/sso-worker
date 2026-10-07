/**
 * SSO acceptInvite: verify NEW users only, user.created before membership.created,
 * additive `source: 'invite'` (user-decisions 2, 4, 5; design AC1-AC4, AC29).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CorrelationId } from "../rpc/contracts";
import { createPreservedWorkflowAuthority } from "../rpc/preserved-workflows";
import {
    FakeInviteDb, makeCtx, makeDependencies, makeEnv, NOW, ORG_ID, seedInvite,
} from "./mocks/invite-fake-db";

vi.mock("../lib/audit", () => ({ audit: vi.fn() }));

const correlationId = "corr_accept_invite" as CorrelationId;
const STRONG_PASSWORD = "Str0ng-Passw0rd!";

interface Harness {
    db: FakeInviteDb;
    send: ReturnType<typeof makeEnv>["send"];
    accept: (input?: { password?: string; token?: string }) => Promise<any>;
    sentEvents: () => Array<{ type: string; payload: Record<string, unknown> }>;
}

function harness(): Harness {
    const db = new FakeInviteDb();
    db.claims = { roles: ["college_educator"], products: [], membership_status: "active" } as never;
    const { env, send } = makeEnv();
    const { ctx, flush } = makeCtx();
    const authority = createPreservedWorkflowAuthority(env, ctx, db, makeDependencies());
    return {
        db, send,
        accept: async (input = {}) => {
            const outcome = await authority.acceptInvite({
                correlationId, invitationToken: input.token ?? "invite-token", password: input.password,
            });
            await flush();
            return outcome;
        },
        sentEvents: () => send.mock.calls.map(([event]) => event as { type: string; payload: Record<string, unknown> }),
    };
}

let h: Harness;
beforeEach(() => { h = harness(); });

describe("acceptInvite: new user (AC1)", () => {
    it("creates a verified user, publishes user.created then membership.created with source", async () => {
        const invite = seedInvite(h.db);
        const outcome = await h.accept({ password: STRONG_PASSWORD });

        expect(outcome.kind).toBe("issued");
        const userInsert = h.db.mutateCalls.find((call) => call.table === "users");
        expect(userInsert?.body.is_email_verified).toBe(true);
        expect(userInsert?.body.email).toBe("test.educator@example.com");

        const events = h.sentEvents();
        expect(events.map((event) => event.type)).toEqual(["user.created", "membership.created"]);
        const user = h.db.users[0];
        expect(events[0].payload).toEqual({
            id: user.id, email: user.email, is_email_verified: true, user_metadata: { role: "college_educator" },
        });
        expect(events[1].payload).toEqual({
            user_id: user.id, organization_id: ORG_ID, roles: ["college_educator"], status: "active", source: "invite",
        });
        expect(h.db.invites.find((row) => row.id === invite.id)?.accepted).toBe(true);
        expect(h.db.memberships).toHaveLength(1);
        expect(h.db.membershipRoles).toHaveLength(1);
    });
});

describe("acceptInvite: existing user (AC2)", () => {
    it("issues no users write, no user.created, keeps is_email_verified, still sets source", async () => {
        seedInvite(h.db);
        h.db.users.push({ id: "user-existing", email: "test.educator@example.com", is_email_verified: false, user_metadata: {} });
        const outcome = await h.accept();

        expect(outcome.kind).toBe("issued");
        expect(h.db.usersWrites()).toHaveLength(0);
        expect(h.db.users[0].is_email_verified).toBe(false);
        const events = h.sentEvents();
        expect(events.map((event) => event.type)).toEqual(["membership.created"]);
        expect(events[0].payload.source).toBe("invite");
    });

    it("the fake rejects any users write for an existing user (guards against widening verification)", async () => {
        h.db.users.push({ id: "u1", email: "a@example.com", is_email_verified: false });
        await expect(h.db.update("users", { id: "eq.u1" }, { is_email_verified: true })).rejects.toThrow();
        await expect(h.db.mutate("users", { email: "a@example.com" })).rejects.toThrow();
        await expect(h.db.query("users?id=eq.u1", { method: "PATCH" })).rejects.toThrow();
    });
});

describe("acceptInvite: new user password rules (AC3)", () => {
    it.each([
        ["missing", undefined],
        ["weak", "short"],
        ["low complexity", "alllowercaseletters"],
    ])("%s password is rejected with the unchanged membership_rejected code", async (_label, password) => {
        const invite = seedInvite(h.db);
        const outcome = await h.accept({ password });

        expect(outcome).toEqual({ kind: "rejected", correlationId, code: "membership_rejected" });
        expect(h.db.usersWrites()).toHaveLength(0);
        expect(h.send).not.toHaveBeenCalled();
        expect(h.db.invites.find((row) => row.id === invite.id)?.accepted).toBe(false);
    });
});

describe("acceptInvite: blocked existing user (AC4, characterization)", () => {
    it("is rejected with membership_rejected and no user.created", async () => {
        seedInvite(h.db);
        h.db.users.push({ id: "user-blocked", email: "test.educator@example.com", is_email_verified: true, is_blocked: true });
        const outcome = await h.accept();

        expect(outcome).toEqual({ kind: "rejected", correlationId, code: "membership_rejected" });
        expect(h.sentEvents().map((event) => event.type)).not.toContain("user.created");
        expect(h.sentEvents().map((event) => event.type)).not.toContain("membership.created");
    });
});

describe("acceptInvite: token states", () => {
    it("rejects an empty token", async () => {
        expect((await h.accept({ token: "" })).code).toBe("invalid_invitation");
    });
    it("rejects an unknown token", async () => {
        expect((await h.accept({ token: "nope" })).code).toBe("invalid_invitation");
    });
    it("rejects an expired invite", async () => {
        seedInvite(h.db, { expires_at: new Date(NOW - 1000).toISOString() });
        expect((await h.accept({ password: STRONG_PASSWORD })).code).toBe("invitation_expired");
        expect(h.send).not.toHaveBeenCalled();
    });
    it("rejects an already accepted invite", async () => {
        seedInvite(h.db, { accepted: true });
        expect((await h.accept({ password: STRONG_PASSWORD })).code).toBe("invalid_invitation");
        expect(h.send).not.toHaveBeenCalled();
    });
});

describe("acceptInvite: idempotency and partial failure", () => {
    it("tolerates an existing active membership and duplicate role rows", async () => {
        seedInvite(h.db);
        h.db.users.push({ id: "user-existing", email: "test.educator@example.com", is_email_verified: true });
        h.db.memberships.push({ id: "m-1", user_id: "user-existing", org_id: ORG_ID, status: "active" });
        h.db.membershipRoles.push({ membership_id: "m-1", role_id: "role-college_educator" });

        const outcome = await h.accept();

        expect(outcome.kind).toBe("issued");
        expect(h.db.memberships).toHaveLength(1);
        expect(h.db.membershipRoles).toHaveLength(1);
    });

    it("a retry after a partial failure (user already created) does not republish user.created", async () => {
        seedInvite(h.db);
        const first = vi.spyOn(h.db, "update").mockRejectedValueOnce(new Error("boom"));
        const failed = await h.accept({ password: STRONG_PASSWORD });
        expect(failed.kind).toBe("unavailable");
        first.mockRestore();
        expect(h.sentEvents().map((event) => event.type)).toEqual(["user.created"]);

        h.send.mockClear();
        const retry = await h.accept({ password: STRONG_PASSWORD });
        expect(retry.kind).toBe("issued");
        expect(h.db.users).toHaveLength(1);
        expect(h.sentEvents().map((event) => event.type)).toEqual(["membership.created"]);
    });
});

describe("acceptInvite: auto-verification depends on the invite roles (AC29)", () => {
    it.each([
        [["college_educator"], true],
        [["school_educator"], true],
        [["member"], true],
        [["admin"], false],
        [["owner"], false],
        [["super_admin"], false],
        [["college_admin"], false],
        [["school_admin"], false],
        [["college_educator", "admin"], false],
    ])("roles %j => is_email_verified %s", async (roles, verified) => {
        seedInvite(h.db, { role: roles as string[] });
        const outcome = await h.accept({ password: STRONG_PASSWORD });

        expect(outcome.kind).toBe("issued");
        expect(h.db.users[0].is_email_verified).toBe(verified);
        const [created, membership] = h.sentEvents();
        expect(created.type).toBe("user.created");
        expect(created.payload.is_email_verified).toBe(verified);
        expect(membership.type).toBe("membership.created");
        expect(membership.payload.source).toBe("invite");
    });
});
