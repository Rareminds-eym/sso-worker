import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getLteSubscriptionSnapshot } from '../lib/subscription-snapshot';
import { db } from '../lib/db';
import { readSubscriptionLifecycle } from '../lib/subscriptions/lifecycle-persistence';
import type { Env } from '../types';

vi.mock('../lib/db', () => ({ db: vi.fn() }));
vi.mock('../lib/subscriptions/lifecycle-persistence', () => ({ readSubscriptionLifecycle: vi.fn() }));
const user = '10000000-0000-4000-8000-000000000001';
const product = '20000000-0000-4000-8000-000000000001';
const row = { id: '30000000-0000-4000-8000-000000000001', user_id: user, organization_id: null,
  is_organization_subscription: false, product_id: product, plan_id: '40000000-0000-4000-8000-000000000001',
  plan_revision_id: '50000000-0000-4000-8000-000000000001', lifecycle_state: { version: 1 },
  lifecycle_policy: { schemaVersion: 1 }, lifecycle_activated_at: '2026-11-22T00:00:00Z', status: 'active',
  features: [], plan_type: 'synthetic', plan_amount: 0, billing_cycle: 'none', subscription_start_date: null,
  subscription_end_date: null, updated_at: '2026-11-22T00:00:00Z', created_at: '2026-11-22T00:00:00Z', plan_code: 'synthetic' };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(db).mockReturnValue({ queryOne: vi.fn().mockResolvedValue({ id: product }),
    query: vi.fn().mockImplementation(async (query: string) => query.startsWith('subscriptions?') ? [row] : []) } as unknown as ReturnType<typeof db>);
  vi.mocked(readSubscriptionLifecycle).mockResolvedValue({ state: { revisionId: row.plan_revision_id,
    planId: row.plan_id, version: 1, status: 'active' } } as Awaited<ReturnType<typeof readSubscriptionLifecycle>>);
});
describe('LTE subscription snapshot revision transport', () => {
  it('retains the binding only after current owner validation', async () => {
    expect(await getLteSubscriptionSnapshot({} as Env, user)).toMatchObject({ plan_revision_id: row.plan_revision_id,
      lifecycle_state: row.lifecycle_state, lifecycle_policy: row.lifecycle_policy, lifecycle_activated_at: row.lifecycle_activated_at });
    expect(readSubscriptionLifecycle).toHaveBeenCalledWith(expect.anything(), row.id, product, { kind: 'user', id: user });
  });
  it('surfaces a changed owner version', async () => {
    vi.mocked(readSubscriptionLifecycle).mockResolvedValue({ state: { revisionId: row.plan_revision_id,
      planId: row.plan_id, version: 2 } } as Awaited<ReturnType<typeof readSubscriptionLifecycle>>);
    await expect(getLteSubscriptionSnapshot({} as Env, user)).rejects.toThrow('Subscription snapshot revision differs');
  });
  it('surfaces unavailable owner validation', async () => {
    vi.mocked(readSubscriptionLifecycle).mockRejectedValue(new Error('owner unavailable'));
    await expect(getLteSubscriptionSnapshot({} as Env, user)).rejects.toThrow('owner unavailable');
  });
});
