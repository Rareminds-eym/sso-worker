import { beforeEach, describe, expect, it, vi } from "vitest";
const { rpc } = vi.hoisted(() => ({ rpc: vi.fn() }));
vi.mock("../lib/db", () => ({ db: () => ({ rpc }) }));
import { ZohoApproverAuthority } from "../rpc/zoho-approver-authority";
import type { Env } from "../types";
const id = "10000000-0000-4000-8000-000000000001";
const authority = () => new ZohoApproverAuthority({} as ExecutionContext, {} as Env);
beforeEach(() => { rpc.mockReset(); });
describe("restricted import approver reader", () => {
  it("returns only the live decision, never a user record", async () => {
    rpc.mockResolvedValue(true);
    expect(await authority().checkApprover(id)).toEqual({ allowed: true });
    expect(rpc).toHaveBeenCalledExactlyOnceWith("zoho_is_active_import_approver", { p_actor: id });
  });
  it.each([false, null, "true", { allowed: true }])("fails closed for malformed or inactive authority (%s)", async value => {
    rpc.mockResolvedValue(value);
    expect(await authority().checkApprover(id)).toEqual({ allowed: false });
  });
  it("does not query storage for an invalid actor or accept caller role overrides", async () => {
    for (const value of [null, undefined, "invalid", {}, { actorId: id, roles: ["super_admin"] }])
      expect(await authority().checkApprover(value)).toEqual({ allowed: false });
    expect(rpc).not.toHaveBeenCalled();
  });
  it("returns a denial if canonical authority storage is unavailable", async () => {
    rpc.mockRejectedValue(new Error("private database detail"));
    expect(await authority().checkApprover(id)).toEqual({ allowed: false });
  });
  it("exposes no HTTP command endpoint or inherited SSO writer", async () => {
    const instance = authority();
    expect((await instance.fetch(new Request("https://sso/check"))).status).toBe(404);
    expect("createLearnerUser" in instance).toBe(false);
    expect("login" in instance).toBe(false);
    expect("sendEmail" in instance).toBe(false);
    expect(rpc).not.toHaveBeenCalled();
  });
});
