import { describe, it, expect, beforeEach, vi } from "vitest";
import { addMonths, parseDurationMonths } from "../lib/date";
import { endpointRateLimit } from "../lib/rate-limit";
import type { Env } from "../types";

// ─── addMonths ──────────────────────────────────────────────────

describe("addMonths", () => {
  it("adds months without overflow for mid-month dates", () => {
    const d = new Date(2026, 0, 15); // Jan 15
    const r = addMonths(d, 1);
    expect(r.getMonth()).toBe(1);  // Feb
    expect(r.getDate()).toBe(15);
  });

  it("clamps Jan 31 + 1 month to Feb 28 (non-leap)", () => {
    const d = new Date(2026, 0, 31); // Jan 31 2026
    const r = addMonths(d, 1);
    expect(r.getMonth()).toBe(1);  // Feb
    expect(r.getDate()).toBe(28);
  });

  it("clamps Jan 31 + 1 month to Feb 29 in leap year", () => {
    const d = new Date(2028, 0, 31); // Jan 31 2028 (leap)
    const r = addMonths(d, 1);
    expect(r.getMonth()).toBe(1);
    expect(r.getDate()).toBe(29);
  });

  it("handles Dec 15 + 1 month → Jan 15", () => {
    const d = new Date(2026, 11, 15); // Dec 15
    const r = addMonths(d, 1);
    expect(r.getFullYear()).toBe(2027);
    expect(r.getMonth()).toBe(0);  // Jan
    expect(r.getDate()).toBe(15);
  });

  it("adds 12 months (annual) correctly", () => {
    const d = new Date(2026, 2, 15); // Mar 15
    const r = addMonths(d, 12);
    expect(r.getFullYear()).toBe(2027);
    expect(r.getMonth()).toBe(2);
    expect(r.getDate()).toBe(15);
  });

  it("clamps Mar 31 + 1 month → Apr 30", () => {
    const d = new Date(2026, 2, 31); // Mar 31
    const r = addMonths(d, 1);
    expect(r.getMonth()).toBe(3);  // Apr
    expect(r.getDate()).toBe(30);
  });

  it("returns same date for 0 months", () => {
    const d = new Date(2026, 5, 15);
    const r = addMonths(d, 0);
    expect(r.getTime()).toBe(d.getTime());
  });

  it("does not mutate the original date", () => {
    const d = new Date(2026, 0, 31);
    const copy = new Date(d);
    addMonths(d, 1);
    expect(d.getTime()).toBe(copy.getTime());
  });
});

// ─── parseDurationMonths ───────────────────────────────────────

describe("parseDurationMonths", () => {
  it('returns 0 for "lifetime"', () => {
    expect(parseDurationMonths("lifetime")).toBe(0);
    expect(parseDurationMonths("LIFETIME")).toBe(0);
  });

  it('returns 12 for "annual" / "yearly"', () => {
    expect(parseDurationMonths("annual")).toBe(12);
    expect(parseDurationMonths("yearly")).toBe(12);
    expect(parseDurationMonths("2 year")).toBe(12);
  });

  it('returns 3 for "quarterly"', () => {
    expect(parseDurationMonths("quarterly")).toBe(3);
    expect(parseDurationMonths("quarter")).toBe(3);
  });

  it('returns 1 for "monthly"', () => {
    expect(parseDurationMonths("monthly")).toBe(1);
    expect(parseDurationMonths("month")).toBe(1);
    expect(parseDurationMonths("MONTHLY")).toBe(1);
  });

  it('defaults to 1 for unknown labels', () => {
    expect(parseDurationMonths("weekly")).toBe(1);
    expect(parseDurationMonths("")).toBe(1);
  });
});

// ─── endpointRateLimit ──────────────────────────────────────────

function makeMockKv(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null) as any,
    put: vi.fn(async (key: string, value: string, opts?: any) => {
      store.set(key, value);
    }) as any,
    delete: vi.fn(async (key: string) => {
      store.delete(key);
    }) as any,
    list: vi.fn() as any,
    getWithMetadata: vi.fn() as any,
  } as unknown as KVNamespace;
}

describe("endpointRateLimit", () => {
  let env: Env;

  beforeEach(() => {
    env = {
      RATE_LIMIT_KV: makeMockKv(),
    } as unknown as Env;
  });

  it("returns null when under the limit", async () => {
    const result = await endpointRateLimit(env, "test:user_1", 5, 60);
    expect(result).toBeNull();
  });

  it("returns 429 when limit exceeded", async () => {
    for (let i = 0; i < 5; i++) {
      const r = await endpointRateLimit(env, "test:user_1", 5, 60);
      expect(r).toBeNull();
    }
    const blocked = await endpointRateLimit(env, "test:user_1", 5, 60);
    expect(blocked).not.toBeNull();
    expect(blocked!.status).toBe(429);
  });

  it("includes Retry-After header on 429", async () => {
    for (let i = 0; i < 5; i++) {
      await endpointRateLimit(env, "test:user_2", 5, 120);
    }
    const blocked = await endpointRateLimit(env, "test:user_2", 5, 120);
    expect(blocked!.headers.get("Retry-After")).toBe("120");
  });

  it("includes X-RateLimit headers on 429", async () => {
    for (let i = 0; i < 5; i++) {
      await endpointRateLimit(env, "test:user_3", 5, 60);
    }
    const blocked = await endpointRateLimit(env, "test:user_3", 5, 60);
    expect(blocked!.headers.get("X-RateLimit-Limit")).toBe("5");
    expect(blocked!.headers.get("X-RateLimit-Remaining")).toBe("0");
  });

  it("uses separate counters for different keys", async () => {
    for (let i = 0; i < 5; i++) {
      await endpointRateLimit(env, "test:user_a", 5, 60);
    }
    const blockedA = await endpointRateLimit(env, "test:user_a", 5, 60);
    expect(blockedA).not.toBeNull();

    const resultB = await endpointRateLimit(env, "test:user_b", 5, 60);
    expect(resultB).toBeNull();
  });

  it("uses default window of 60 seconds", async () => {
    for (let i = 0; i < 3; i++) {
      await endpointRateLimit(env, "test:user_4", 3);
    }
    const blocked = await endpointRateLimit(env, "test:user_4", 3);
    expect(blocked!.headers.get("Retry-After")).toBe("60");
  });
});
