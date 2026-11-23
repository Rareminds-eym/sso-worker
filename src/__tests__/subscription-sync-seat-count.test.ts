import { beforeEach, describe, expect, it, vi } from 'vitest';
import { executionContext } from './execution-context';
import type { Env } from '../types';

const mocks = vi.hoisted(() => ({ queryOne: vi.fn(), mutate: vi.fn(), publish: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: mocks.publish }));
import { SsoWorker } from '../index';

const input = {
  user_id: 'user-123', plan_id: 'plan-enterprise-123', plan_code: 'college_enterprise',
  plan_type: 'College Enterprise', plan_amount: 0, billing_cycle: 'lifetime', features: [],
  full_name: 'Test User', email: 'user-123@example.invalid',
  organization_id: 'org-123', organization_type: 'college',
};

beforeEach(() => {
  vi.resetAllMocks();
  mocks.queryOne.mockResolvedValue({
    id: input.plan_id, is_active: true, business_type: 'b2b', product_id: 'product-123',
    entity_config: { college: { max_users: 5000 } },
  });
  mocks.mutate.mockImplementation(async (table: string, payload: Record<string, unknown>) => {
    if (table !== 'subscriptions') throw new Error('Unexpected test write');
    return { id: 'sub-123', ...payload };
  });
});

describe('production subscription seat-count sync', () => {
  it('persists configured capacity and publishes it after the real method completes its write', async () => {
    const context = executionContext(vi.fn());
    const queue = {} as Queue;
    const worker = new SsoWorker(context, { SYNC_QUEUE: queue } as Env);
    // Exercise the real method. Only its IO dependencies are mocked.
    const result = await worker.createSubscription(input);

    expect(mocks.queryOne).toHaveBeenCalledExactlyOnceWith('plans?id=eq.plan-enterprise-123');
    expect(mocks.mutate).toHaveBeenCalledExactlyOnceWith('subscriptions', expect.objectContaining({
      plan_id: input.plan_id, organization_id: input.organization_id,
      seat_count: 5000, product_id: 'product-123',
    }));
    expect(result.seat_count).toBe(5000);
    expect(mocks.publish).toHaveBeenCalledExactlyOnceWith(queue, context, 'subscription.created', expect.objectContaining({
      id: 'sub-123', plan_id: input.plan_id, plan_code: input.plan_code,
      seat_count: 5000, product_id: 'product-123',
    }));
    expect(mocks.mutate.mock.invocationCallOrder[0]).toBeLessThan(mocks.publish.mock.invocationCallOrder[0]);
  });

  it('does not publish an unpersisted seat count when storage rejects creation', async () => {
    const failure = new Error('Synthetic persistence rejection');
    mocks.mutate.mockRejectedValue(failure);
    const worker = new SsoWorker(executionContext(), {} as Env);
    await expect(worker.createSubscription(input)).rejects.toBe(failure);
    expect(mocks.mutate).toHaveBeenCalledTimes(1);
    expect(mocks.publish).not.toHaveBeenCalled();
  });
});
