/**
 * sendEmailWithStatus: bounded, awaited, never throws, redacted failure logging.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../../types";
import { EMAIL_SEND_TIMEOUT_MS, logEmailFailure, sendEmailWithStatus } from "../email";

const TOKEN = "11111111-2222-4333-8444-555555555555";
const RECIPIENT = "secret.person@example.com";
const ACCEPT_URL = `https://app.example.test/invite/accept?token=${TOKEN}`;
const payload = { to: RECIPIENT, subject: "s", html: `<a href="${ACCEPT_URL}">x</a>`, text: ACCEPT_URL };

function setup(sendEmail: ReturnType<typeof vi.fn>) {
    const env = { EMAIL_SERVICE: { sendEmail } } as unknown as Env;
    const waited: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => { waited.push(p); } } as unknown as ExecutionContext;
    return { env, ctx, waited };
}

let errorSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => { errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

const logged = () => errorSpy.mock.calls.map((call: unknown[]) => call.map(String).join(" ")).join("\n");

describe("sendEmailWithStatus", () => {
    it("exports a 5 second timeout", () => {
        expect(EMAIL_SEND_TIMEOUT_MS).toBe(5_000);
    });

    it("returns sent only when success === true and logs nothing", async () => {
        const sendEmail = vi.fn().mockResolvedValue({ success: true });
        const { env, ctx, waited } = setup(sendEmail);
        await expect(sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-1" })).resolves.toBe("sent");
        expect(sendEmail).toHaveBeenCalledTimes(1);
        expect(waited).toHaveLength(1);
        expect(errorSpy).not.toHaveBeenCalled();
    });

    it("returns failed when the provider answers success: false", async () => {
        const sendEmail = vi.fn().mockResolvedValue({ success: false, errorCode: "BOUNCED", error: "x" });
        const { env, ctx } = setup(sendEmail);
        await expect(sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-1" })).resolves.toBe("failed");
        expect(JSON.parse(logged())).toEqual({
            msg: "[SSO] Invite email not delivered", inviteId: "inv-1", reason: "provider_rejected", errorCode: "BOUNCED",
        });
    });

    it("treats a truthy non-true success and an empty result as failed", async () => {
        for (const result of [{ success: "yes" }, {}, undefined, null]) {
            const { env, ctx } = setup(vi.fn().mockResolvedValue(result));
            await expect(sendEmailWithStatus(env, payload, ctx, { inviteId: "i" })).resolves.toBe("failed");
        }
    });

    it("returns failed when the RPC promise rejects", async () => {
        const { env, ctx } = setup(vi.fn().mockRejectedValue(new TypeError("Worker shared-email-api not found")));
        await expect(sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-2" })).resolves.toBe("failed");
        expect(JSON.parse(logged())).toEqual({
            msg: "[SSO] Invite email not delivered", inviteId: "inv-2", reason: "exception", errorName: "TypeError",
        });
    });

    it("returns failed when the RPC throws synchronously (classified as exception)", async () => {
        const { env, ctx } = setup(vi.fn().mockImplementation(() => { throw new RangeError("boom"); }));
        await expect(sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-3" })).resolves.toBe("failed");
        expect(JSON.parse(logged())).toMatchObject({ reason: "exception", errorName: "RangeError" });
    });

    it("returns failed after 5s for a never-resolving send and clears the timer", async () => {
        vi.useFakeTimers();
        const { env, ctx } = setup(vi.fn().mockImplementation(() => new Promise(() => undefined)));
        const pending = sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-4" });
        await vi.advanceTimersByTimeAsync(EMAIL_SEND_TIMEOUT_MS - 1);
        expect(errorSpy).not.toHaveBeenCalled();
        await vi.advanceTimersByTimeAsync(1);
        await expect(pending).resolves.toBe("failed");
        expect(JSON.parse(logged())).toMatchObject({ reason: "timeout", inviteId: "inv-4" });
        expect(vi.getTimerCount()).toBe(0);
    });

    it("clears the timer after a fast send", async () => {
        vi.useFakeTimers();
        const { env, ctx } = setup(vi.fn().mockResolvedValue({ success: true }));
        await expect(sendEmailWithStatus(env, payload, ctx, { inviteId: "i" })).resolves.toBe("sent");
        expect(vi.getTimerCount()).toBe(0);
    });

    it("a rejection after the timeout is not an unhandled rejection", async () => {
        vi.useFakeTimers();
        let rejectLater: (error: Error) => void = () => undefined;
        const { env, ctx, waited } = setup(vi.fn().mockImplementation(
            () => new Promise((_, reject) => { rejectLater = reject; }),
        ));
        const pending = sendEmailWithStatus(env, payload, ctx, { inviteId: "i" });
        await vi.advanceTimersByTimeAsync(EMAIL_SEND_TIMEOUT_MS);
        await expect(pending).resolves.toBe("failed");
        rejectLater(new Error("late"));
        await expect(Promise.all(waited)).resolves.toBeDefined();
    });
});

describe("failure log redaction", () => {
    const leaks = [TOKEN, RECIPIENT, ACCEPT_URL, "accept", "example.test"];
    const expectRedacted = () => {
        const output = logged();
        for (const leak of leaks) expect(output).not.toContain(leak);
        for (const call of errorSpy.mock.calls) {
            const entry = JSON.parse(String(call[0]));
            expect(Object.keys(entry).every((key) => ["msg", "inviteId", "reason", "errorCode", "errorName"].includes(key))).toBe(true);
        }
    };

    it("never logs the message of a thrown error that echoes token, recipient and URL", async () => {
        const error = new Error(`send failed for ${RECIPIENT}: ${ACCEPT_URL} token=${TOKEN}`);
        const { env, ctx } = setup(vi.fn().mockRejectedValue(error));
        await sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-5" });
        expect(errorSpy).toHaveBeenCalledTimes(1);
        expectRedacted();
    });

    it("never logs res.error text that echoes token, recipient and URL", async () => {
        const res = { success: false, errorCode: "SES_FAIL", error: `to ${RECIPIENT} ${ACCEPT_URL} ${TOKEN}` };
        const { env, ctx } = setup(vi.fn().mockResolvedValue(res));
        await sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-6" });
        expectRedacted();
        expect(JSON.parse(logged()).errorCode).toBe("SES_FAIL");
    });

    it("drops an errorCode or errorName that is not a safe identifier", async () => {
        const res = { success: false, errorCode: `bad code ${RECIPIENT}` };
        const { env, ctx } = setup(vi.fn().mockResolvedValue(res));
        await sendEmailWithStatus(env, payload, ctx, { inviteId: "inv-7" });
        expect(JSON.parse(logged())).not.toHaveProperty("errorCode");

        errorSpy.mockClear();
        const named = new Error("m");
        named.name = `Weird Name ${TOKEN}`;
        const second = setup(vi.fn().mockRejectedValue(named));
        await sendEmailWithStatus(second.env, payload, second.ctx, { inviteId: "inv-8" });
        expect(JSON.parse(logged())).not.toHaveProperty("errorName");
        expectRedacted();
    });

    it("logEmailFailure supports the lookup_failed reason", () => {
        logEmailFailure("inv-9", "lookup_failed", { errorName: "Error" });
        expect(JSON.parse(logged())).toEqual({
            msg: "[SSO] Invite email not delivered", inviteId: "inv-9", reason: "lookup_failed", errorName: "Error",
        });
    });
});
