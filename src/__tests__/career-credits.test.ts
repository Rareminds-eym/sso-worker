import { describe, it, expect, vi, beforeEach } from "vitest";
import { SsoWorker } from "../index";
import type { Env } from "../types";

vi.mock("../lib/db", () => ({
  db: vi.fn(),
}));

import { db } from "../lib/db";

const mockCtx = { waitUntil: vi.fn(), passThroughOnException: vi.fn(), props: undefined } as unknown as ExecutionContext;
const mockEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "test-key",
} as Env;

function workerWithRpc(rpcImpl: (fn: string, args?: Record<string, unknown>) => Promise<unknown>) {
  vi.mocked(db).mockReturnValue({ rpc: rpcImpl } as never);
  return new SsoWorker(mockCtx, mockEnv);
}

describe("Career AI credit RPCs", () => {
  it.each([true, false])("syncs decimal snapshots and only records confirmed acknowledgement=%s", async (accepted) => {
    const queries: string[] = [];
    const updates: Array<Record<string, unknown>> = [];
    vi.mocked(db).mockReturnValue({
      rpc: async (name: string) => name === "career_credit_balance_json"
        ? {ok: true, granted_credits: "30.000000000000", spent_credits: "0.123456789012", revision: 8}
        : 0,
      query: async (path: string) => {
        queries.push(path);
        return path.startsWith("ai_credit_sync_outbox") ? [{id: "out-1", account_id: "acct-1", attempts: 2}] : [];
      },
      queryOne: async () => ({id: "acct-1", user_id: "u-1", product_id: "prod-1", scope: "career_ai", spent_credits: 0.123456789012}),
      update: async (table: string, _filter: unknown, values: Record<string, unknown>) => { if(table === "ai_credit_sync_outbox") updates.push(values); },
    } as never);
    const fetchMock = vi.fn(async (url: string, options: RequestInit) => {
      expect(url).toBe("https://app.test/sync/credit-balance");
      expect(JSON.parse(options.body as string).data.account).toMatchObject({spent_credits: "0.123456789012", revision: 8});
      return accepted ? Response.json({success: true}) : new Response("<html>SPA fallback</html>");
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      const worker = new SsoWorker(mockCtx, {...mockEnv, SKILLPASSPORT_URL: "https://app.test", INTERNAL_WEBHOOK_SECRET: "test-secret"} as Env);
      await worker.scheduled({} as ScheduledEvent);
      expect(queries.some(q => q.includes("attempts=lt.10"))).toBe(true);
      expect(updates).toContainEqual(expect.objectContaining({status: accepted ? "sent" : "failed", attempts: 3}));
    } finally { vi.unstubAllGlobals(); }
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("getCareerCredits delegates to the grant-once SQL function", async () => {
    const balance = { ok: true, account_id: "acct-1", product_id: "912d5049-e195-46e9-a319-49e3502bf7e7", granted_credits: "30", spent_credits: "0", remaining_credits: "30", revision: 1 };
    const worker = workerWithRpc(async (fn, args) => {
      expect(fn).toBe("get_career_credits");
      expect(args).toEqual({ p_user_id: "u-1" });
      return balance;
    });
    expect(await worker.getCareerCredits("u-1")).toEqual(balance);
  });

  it("beginCareerOperation maps fields to SQL args and requires all identity", async () => {
    const admitted = { ok: true, duplicate: false, account_id: "a", operation_record_id: "op", policy_id: "p" };
    const worker = workerWithRpc(async (fn, args) => {
      expect(fn).toBe("begin_career_operation");
      expect(args).toMatchObject({
        p_user_id: "u-1", p_operation_id: "turn-1", p_execution_id: "ex-1",
        p_session_id: "sess-1", p_action: "careerTalentStrategist.chat", p_payload_hash: "h",
      });
      return admitted;
    });
    const res = await worker.beginCareerOperation({
      userId: "u-1", operationId: "turn-1", executionId: "ex-1",
      sessionId: "sess-1", action: "careerTalentStrategist.chat", payloadHash: "h",
    });
    expect(res).toEqual(admitted);
    await expect(worker.beginCareerOperation({
      userId: "", operationId: "t", executionId: "e", sessionId: "s", action: "a", payloadHash: "h",
    })).rejects.toThrowError(/required/);
  });

  it("passes denial payloads through untouched for worker-side mapping", async () => {
    const denied = { ok: false, error: "EXHAUSTED", spent_credits: "30", granted_credits: "30" };
    const worker = workerWithRpc(async () => denied);
    expect(await worker.beginCareerOperation({
      userId: "u-1", operationId: "t", executionId: "e", sessionId: "s", action: "a", payloadHash: "h",
    })).toEqual(denied);
  });

  it("settleCareerInvocation defaults cost_state to resolved and validates input", async () => {
    const settled = { ok: true, duplicate: false, credits_used: "1.2" };
    const worker = workerWithRpc(async (fn, args) => {
      expect(fn).toBe("settle_career_invocation");
      expect(args).toMatchObject({ p_invocation_id: "inv-1", p_cost_state: "resolved" });
      return settled;
    });
    const res = await worker.settleCareerInvocation({
      invocationId: "inv-1", logId: "log-1", costUsd: "0.001",
      inputTokens: 10, outputTokens: 5, invocationStatus: "succeeded", durationMs: 100,
    });
    expect(res).toEqual(settled);
    await expect(worker.settleCareerInvocation({
      invocationId: "", logId: null, costUsd: null,
      inputTokens: null, outputTokens: null, invocationStatus: "succeeded", durationMs: null,
    })).rejects.toThrowError(/required/);
  });

  it("finish and waive delegate with strict args", async () => {
    const worker = workerWithRpc(async (fn, args) => {
      if (fn === "finish_career_operation") {
        expect(args).toEqual({ p_operation_record_id: "op-1", p_state: "completed" });
        return { ok: true, state: "completed" };
      }
      expect(fn).toBe("waive_career_invocation");
      expect(args).toEqual({ p_invocation_id: "inv-1", p_operator: "ops", p_reason: "lost log" });
      return { ok: true, cost_state: "waived" };
    });
    expect(await worker.finishCareerOperation({ operationRecordId: "op-1", state: "completed" }))
      .toEqual({ ok: true, state: "completed" });
    expect(await worker.waiveCareerInvocation({ invocationId: "inv-1", operator: "ops", reason: "lost log" }))
      .toEqual({ ok: true, cost_state: "waived" });
    await expect(worker.waiveCareerInvocation({ invocationId: "i", operator: "", reason: "r" }))
      .rejects.toThrowError(/required/);
  });
});
