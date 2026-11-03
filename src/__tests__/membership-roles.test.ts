import { beforeEach, describe, expect, it, vi } from "vitest";
import { SsoWorker } from "../index";
import type { Env } from "../types";
const query = vi.hoisted(() => vi.fn());
vi.mock("../lib/db", () => ({ db: () => ({ query }) }));

describe("membership role projection", () => {
  beforeEach(() => vi.clearAllMocks());
  it("retains all roles while preserving the legacy primary role", async () => {
    query.mockResolvedValue([
      {
        id: "membership",
        org_id: "college",
        status: "active",
        membership_roles: [
          { roles: { name: "educator" } },
          { roles: { name: "college_admin" } },
          { roles: { name: "educator" } },
        ],
      },
    ]);
    const worker = new SsoWorker({} as ExecutionContext, {} as Env);
    const result = await worker.getUserMemberships("user");
    expect(result.memberships[0]).toMatchObject({
      role: "educator",
      roles: ["educator", "college_admin"],
    });
  });
  it("does not invent administrator authority for an empty role list", async () => {
    query.mockResolvedValue([
      { id: "membership", org_id: "school", status: "active" },
    ]);
    const worker = new SsoWorker({} as ExecutionContext, {} as Env);
    expect(
      (await worker.getUserMemberships("user")).memberships[0],
    ).toMatchObject({ role: "member", roles: [] });
  });
});
