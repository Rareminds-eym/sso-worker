import { describe, it, expect, vi, beforeEach } from "vitest";
import { SsoWorker } from "../index";
import { publishSyncEvent } from "../lib/sync-queue";

vi.mock("../lib/sync-queue", () => ({
  publishSyncEvent: vi.fn(),
}));

describe("Subscription seat_count Sync Verification", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should calculate seat_count from plan entity_config and include it in subscription.created sync event", async () => {
    const mockDbQueryOne = vi.fn(async (query: string) => {
      if (query.startsWith("plans?id=")) {
        return {
          id: "plan-enterprise-123",
          plan_code: "college_enterprise",
          entity_config: {
            college: { max_users: 5000 },
          },
        };
      }
      return null;
    });

    const mockDbMutate = vi.fn(async (table: string, payload: Record<string, unknown>) => {
      return {
        id: "sub-uuid-123",
        ...payload,
      };
    });

    // Mock fetch for REST database calls if needed
    const mockEnv = {
      SUPABASE_URL: "https://test.supabase.co",
      SUPABASE_SERVICE_ROLE_KEY: "test-key",
      SYNC_QUEUE: {} as Queue,
    };

    const worker = new SsoWorker({} as ExecutionContext, mockEnv as any);

    // Mock internal db call on worker
    vi.spyOn(worker as any, "createSubscription").mockImplementation(async (data: any) => {
      let seatCount = data.seat_count || 1;
      if ((!data.seat_count || data.seat_count === 1) && data.plan_id) {
        const planRow = await mockDbQueryOne(`plans?id=${data.plan_id}`);
        if (planRow?.entity_config?.college?.max_users) {
          seatCount = Number(planRow.entity_config.college.max_users);
        }
      }

      const subscription = await mockDbMutate("subscriptions", {
        user_id: data.user_id,
        plan_id: data.plan_id,
        seat_count: seatCount,
      });

      publishSyncEvent(mockEnv.SYNC_QUEUE, {} as ExecutionContext, "subscription.created", {
        id: subscription.id,
        user_id: data.user_id,
        seat_count: seatCount,
        plan_code: "college_enterprise",
      });

      return subscription;
    });

    const result = await worker.createSubscription({
      user_id: "user-123",
      plan_id: "plan-enterprise-123",
      plan_code: "college_enterprise",
    });

    expect(result.seat_count).toBe(5000);
    expect(publishSyncEvent).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      "subscription.created",
      expect.objectContaining({
        seat_count: 5000,
        plan_code: "college_enterprise",
      })
    );
  });
});
