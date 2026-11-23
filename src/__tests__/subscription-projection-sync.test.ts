import { beforeEach, describe, expect, it, vi } from 'vitest';
const io = vi.hoisted(() => ({ lifecycle: vi.fn(), publish: vi.fn() }));
vi.mock('../lib/subscriptions/lifecycle-persistence', () => ({ readSubscriptionLifecycle: io.lifecycle }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: io.publish }));
import { publishCommittedSubscriptions, readPlanSyncInventory } from '../lib/subscriptions/projection-sync';
import { executionContext } from './execution-context';
import type { DbClient } from '../lib/db';
import type { SyncEvent } from '../lib/sync-queue';

const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const user = id(1), subscription = id(2), plan = id(3), revision = id(4), product = id(5), organization = id(6);
const row = () => ({ id: subscription, user_id: user, plan_id: plan, plan_revision_id: revision,
  product_id: product, status: 'active', is_organization_subscription: false, lifecycle_state: { version: 1 } });
const database = () => ({ query: vi.fn(), queryOne: vi.fn(), rpc: vi.fn() }) satisfies Pick<DbClient, 'query' | 'queryOne' | 'rpc'>;
const queue = {} as Queue<SyncEvent>, ctx = executionContext();
beforeEach(() => {
  vi.resetAllMocks();
  io.lifecycle.mockResolvedValue({ state: { planId: plan, revisionId: revision, status: 'active', version: 1 } });
});

describe('authoritative projection synchronization', () => {
  it('delivers retired plans and pages the complete inventory', async () => {
    const db = database();
    const first = Array.from({ length: 100 }, (_, n) => ({ id: id(n + 1), is_active: n !== 0 }));
    const last = { id: id(101), is_active: false };
    db.query.mockResolvedValueOnce(first).mockResolvedValueOnce([last]);
    expect(await readPlanSyncInventory(db)).toEqual([...first, last]);
    expect(db.query).toHaveBeenNthCalledWith(1, 'plans?order=id.asc&limit=100', undefined, 'json-array');
    expect(db.query).toHaveBeenNthCalledWith(2, `plans?order=id.asc&limit=100&id=gt.${id(100)}`, undefined, 'json-array');
  });
  it.each([null, [{ id: id(1) }], [{ id: id(2), is_active: true }, { id: id(1), is_active: false }]].map(page => ({ page })))(
    'rejects malformed or non-progressing inventory %#', async ({ page }) => {
      const db = database(); db.query.mockResolvedValue(page);
      await expect(readPlanSyncInventory(db)).rejects.toThrow();
    },
  );
  it.each([false, true])('publishes only committed owner-validated subscription rows (organization=%s)', async isOrganization => {
    const db = database(), source = { ...row(), is_organization_subscription: isOrganization, organization_id: isOrganization ? organization : null };
    db.query.mockResolvedValue([source]);
    await publishCommittedSubscriptions(db, queue, ctx, user, [subscription]);
    expect(db.query).toHaveBeenCalledWith(`subscriptions?id=in.(${subscription})&user_id=eq.${user}&order=id.asc`, undefined, 'json-array');
    expect(io.lifecycle).toHaveBeenCalledWith(db, subscription, product,
      { kind: isOrganization ? 'organization' : 'user', id: isOrganization ? organization : user });
    expect(io.publish).toHaveBeenCalledExactlyOnceWith(queue, ctx, 'subscription.created', source);
  });
  it.each([[], [{ ...row(), user_id: id(9) }], [row(), row()]].map(rows => ({ rows })))('rejects missing, foreign or duplicated owner rows %#', async ({ rows }) => {
    const db = database(); db.query.mockResolvedValue(rows);
    await expect(publishCommittedSubscriptions(db, queue, ctx, user, [subscription])).rejects.toThrow();
    expect(io.publish).not.toHaveBeenCalled();
  });
  it('does not publish stale revision data or data whose lifecycle owner fails', async () => {
    const db = database(); db.query.mockResolvedValue([{ ...row(), plan_revision_id: id(9) }]);
    await expect(publishCommittedSubscriptions(db, queue, ctx, user, [subscription])).rejects.toThrow();
    io.lifecycle.mockRejectedValue(new Error('Synthetic owner failure'));
    db.query.mockResolvedValue([row()]);
    await expect(publishCommittedSubscriptions(db, queue, ctx, user, [subscription])).rejects.toThrow();
    expect(io.publish).not.toHaveBeenCalled();
  });
  it('performs no subscription lookup for a verification without activation', async () => {
    const db = database();
    await publishCommittedSubscriptions(db, queue, ctx, user, []);
    expect(db.query).not.toHaveBeenCalled(); expect(io.publish).not.toHaveBeenCalled();
  });
});
