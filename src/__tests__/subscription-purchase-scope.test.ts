import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ queryOne: vi.fn(), mutate: vi.fn(), update: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: vi.fn() }));
import { SsoWorker } from '../index';
import type { Env } from '../types';

const input = { user_id: 'user', plan_id: 'plan', plan_code: 'custom-plan', plan_type: 'Custom plan', plan_amount: 749, billing_cycle: 'yearly', features: [], full_name: 'Test', email: 'test@example.test' };
function worker() { return new SsoWorker({ waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext, {} as Env); }
beforeEach(() => {
  vi.clearAllMocks();
  mocks.mutate.mockImplementation(async (_table, values) => ({ id: 'subscription', ...values }));
});
describe('Subscription creation audience', () => {
  it('persists retiring a default subscription before its replacement is created', async () => {
    mocks.queryOne.mockResolvedValue({ id: 'old', status: 'expired' });
    await worker().updateSubscriptionField('old', { status: 'expired' });
    expect(mocks.update).toHaveBeenCalledWith('subscriptions', { id: 'eq.old' }, expect.objectContaining({ status: 'expired' }));
  });
  it('rejects unsupported subscription statuses before writing', async () => {
    await expect(worker().updateSubscriptionField('old', { status: 'unknown' })).rejects.toThrow('Invalid subscription status');
    expect(mocks.update).not.toHaveBeenCalled();
  });
  it('does not turn an individual plan into an organization plan for an org creator', async () => {
    mocks.queryOne.mockResolvedValue({ business_type: 'b2c', is_active: true, product_id: 'sp', entity_config: {} });
    const result = await worker().createSubscription(input);
    expect(result).toMatchObject({ is_organization_subscription: false, organization_id: null });
    expect(mocks.queryOne).toHaveBeenCalledTimes(1);
  });
  it('preserves an explicit bulk purchase of learner seats', async () => {
    mocks.queryOne.mockResolvedValue({ business_type: 'b2c', is_active: true, product_id: 'sp', entity_config: { all: { max_users: 1 } } });
    const result = await worker().createSubscription({ ...input, organization_id: 'org', is_bulk_purchase: true, is_organization_subscription: true, seat_count: 50 });
    expect(result).toMatchObject({ is_organization_subscription: true, organization_id: 'org', seat_count: 50 });
  });
  it('keeps institution purchases linked to the organization', async () => {
    mocks.queryOne.mockImplementation(async path => path.startsWith('plans?')
      ? { business_type: 'b2b', is_active: true, product_id: 'sp', entity_config: { college: { max_users: 500 } } }
      : { id: 'org', metadata: { organization_type: 'college' } });
    expect(await worker().createSubscription(input)).toMatchObject({ is_organization_subscription: true, organization_id: 'org', seat_count: 500 });
  });
  it('does not create a subscription if catalogue verification fails', async () => {
    mocks.queryOne.mockRejectedValue(new Error('Database unavailable'));
    await expect(worker().createSubscription(input)).rejects.toThrow();
    expect(mocks.mutate).not.toHaveBeenCalled();
  });
});
