/**
 * createInvite / resendInvite emailStatus: bounded awaited delivery, opt-in field,
 * row kept on failure, no provider text, no secrets in logs.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EMAIL_SEND_TIMEOUT_MS } from "../lib/email";
import type { CorrelationId } from "../rpc/contracts";
import { createPreservedWorkflowAuthority } from "../rpc/preserved-workflows";
import type { AccessTokenPayload } from "../types";
import {
    emailHangs, emailProviderRejects, emailRejects, emailThrowsSync,
    FakeInviteDb, makeCtx, makeDependencies, makeEnv, ORG_ID, seedInvite,
} from "./mocks/invite-fake-db";

const auditMock = vi.hoisted(() => vi.fn());
vi.mock("../lib/audit", () => ({ audit: auditMock }));

const correlationId = "corr_email_status" as CorrelationId;
const INVITE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const RECIPIENT = "new.person@example.com";

let errorSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
    auditMock.mockClear();
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

function setup() {
    const db = new FakeInviteDb();
    db.claims = { roles: ["college_admin"], products: [], membership_status: "active" } as never;
    const { env, sendEmail } = makeEnv();
    const { ctx, flush } = makeCtx();
    const caller = {
        sub: "caller-1", email: "caller@example.com", org_id: ORG_ID, roles: ["member"], products: [],
        membership_status: "active", is_email_verified: true, user_metadata: {},
    } as AccessTokenPayload;
    const authority = createPreservedWorkflowAuthority(env, ctx, db, makeDependencies({
        verifyAccessToken: async () => caller,
    }));
    const create = async (extra: Record<string, unknown> = {}) => {
        const outcome = await authority.createInvite({
            correlationId, accessToken: "token", email: RECIPIENT, organizationId: ORG_ID,
            roles: ["college_educator"], ...extra,
        } as never);
        await flush();
        return outcome as any;
    };
    const resend = async (extra: Record<string, unknown> = {}) => {
        const outcome = await authority.resendInvite({
            correlationId, accessToken: "token", inviteId: INVITE_ID, ...extra,
        } as never);
        await flush();
        return outcome as any;
    };
    // Unflushed variants: makeCtx().flush would wait on a never-settling send.
    const createNoFlush = () => authority.createInvite({
        correlationId, accessToken: "token", email: RECIPIENT, organizationId: ORG_ID,
        roles: ["college_educator"], includeEmailStatus: true,
    });
    const resendNoFlush = () => authority.resendInvite({
        correlationId, accessToken: "token", inviteId: INVITE_ID, includeEmailStatus: true,
    });
    return { db, sendEmail, create, resend, createNoFlush, resendNoFlush };
}

const loggedErrors = () => errorSpy.mock.calls.map((call: unknown[]) => call.map(String).join(" ")).join("\n");

type Operation = "create" | "resend";
function run(operation: Operation, extra: Record<string, unknown> = {}) {
    const ctx = setup();
    if (operation === "resend") seedInvite(ctx.db, { id: INVITE_ID });
    const call = operation === "create" ? ctx.create : ctx.resend;
    return { ...ctx, call: () => call(extra) };
}

for (const operation of ["create", "resend"] as const) {
    describe(`${operation}Invite emailStatus`, () => {
        it("is sent when the provider succeeds", async () => {
            const { call } = run(operation, { includeEmailStatus: true });
            const outcome = await call();
            expect(outcome.kind).toBe("succeeded");
            expect(outcome.data.emailStatus).toBe("sent");
        });

        for (const [label, arrange] of [
            ["provider success:false", (fn: any) => emailProviderRejects(fn, "SES_DOWN", "detail text")],
            ["promise rejection", (fn: any) => emailRejects(fn)],
            ["synchronous throw", (fn: any) => emailThrowsSync(fn)],
        ] as Array<[string, (fn: any) => void]>) {
            it(`is failed on ${label}, keeps the invite row and still audits`, async () => {
                const { db, sendEmail, call } = run(operation, { includeEmailStatus: true });
                arrange(sendEmail);
                const outcome = await call();

                expect(outcome.kind).toBe("succeeded");
                expect(outcome.data.emailStatus).toBe("failed");
                expect(db.invites).toHaveLength(1);
                expect(db.invites[0].token_hash).toBeTruthy();
                expect(auditMock).toHaveBeenCalledTimes(1);
                expect(auditMock.mock.calls[0][3].metadata.email_status).toBe("failed");
                const serialized = JSON.stringify(outcome);
                for (const text of ["detail text", "SES_DOWN", "shared-email-api", "sync boom"]) {
                    expect(serialized).not.toContain(text);
                }
            });
        }

        it("is failed after 5s for a never-resolving send and the request resolves", async () => {
            vi.useFakeTimers();
            const { db, sendEmail, createNoFlush, resendNoFlush } = run(operation, { includeEmailStatus: true });
            emailHangs(sendEmail);
            const pending: Promise<any> = operation === "create" ? createNoFlush() : resendNoFlush();
            await vi.advanceTimersByTimeAsync(EMAIL_SEND_TIMEOUT_MS);
            const outcome = await pending;
            expect(outcome.data.emailStatus).toBe("failed");
            expect(db.invites).toHaveLength(1);
            expect(vi.getTimerCount()).toBe(0);
        });

        it("is failed when the organization name lookup throws, and the row is kept", async () => {
            const { db, sendEmail, call } = run(operation, { includeEmailStatus: true });
            const original = db.queryOne.bind(db);
            db.queryOne = async <T>(path: string) => {
                if (path.startsWith("organizations")) throw new Error(`lookup failed for ${RECIPIENT}`);
                return original<T>(path);
            };
            const outcome = await call();
            expect(outcome.kind).toBe("succeeded");
            expect(outcome.data.emailStatus).toBe("failed");
            expect(sendEmail).not.toHaveBeenCalled();
            expect(db.invites).toHaveLength(1);
            expect(JSON.parse(loggedErrors())).toMatchObject({ reason: "lookup_failed", errorName: "Error" });
            expect(loggedErrors()).not.toContain(RECIPIENT);
        });

        it("includes emailStatus only when includeEmailStatus === true", async () => {
            for (const flag of [undefined, false, "true", 1, null]) {
                const { call } = run(operation, flag === undefined ? {} : { includeEmailStatus: flag });
                const outcome = await call();
                expect(outcome.kind).toBe("succeeded");
                expect(Object.keys(outcome.data).sort()).toEqual(["email", "expiresAt", "inviteId"]);
            }
            const withFlag = await run(operation, { includeEmailStatus: true }).call();
            expect(Object.keys(withFlag.data).sort()).toEqual(["email", "emailStatus", "expiresAt", "inviteId"]);
        });

        it("omits emailStatus for the old shape even when the email fails", async () => {
            const { sendEmail, call } = run(operation);
            emailRejects(sendEmail);
            const outcome = await call();
            expect(Object.keys(outcome.data).sort()).toEqual(["email", "expiresAt", "inviteId"]);
        });

        it("records email_status in the audit metadata on success", async () => {
            const { call } = run(operation);
            await call();
            expect(auditMock.mock.calls[0][3].metadata.email_status).toBe("sent");
        });

        it("never logs the token, recipient or accept URL", async () => {
            const { sendEmail, call } = run(operation, { includeEmailStatus: true });
            emailRejects(sendEmail, new Error("boom https://app.example.test/invite/accept?token=leak-me new.person@example.com"));
            // First capture the real token from the attempted send.
            await call();
            const sent = sendEmail.mock.calls[0][0] as { text: string; to: string };
            const token = /token=([0-9a-f-]+)/.exec(sent.text)![1];
            const output = loggedErrors();
            expect(output).not.toContain(token);
            expect(output).not.toContain(sent.to);
            expect(output).not.toContain("/invite/accept");
            expect(output).not.toContain("leak-me");
            expect(output).not.toContain("boom");
            for (const call of errorSpy.mock.calls) {
                const entry = JSON.parse(String(call[0]));
                expect(Object.keys(entry).every((key) =>
                    ["msg", "inviteId", "reason", "errorCode", "errorName"].includes(key))).toBe(true);
            }
        });
    });
}

describe("createInvite: email failure specifics", () => {
    it("keeps the pre-existing conflict and gate behavior untouched by the status work", async () => {
        const { db, create } = setup();
        seedInvite(db, { email: RECIPIENT });
        expect((await create({ includeEmailStatus: true })).code).toBe("conflict");
    });
});
