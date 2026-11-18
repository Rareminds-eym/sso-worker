import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ query: vi.fn(), queryOne: vi.fn(), update: vi.fn(), publish: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: mocks.publish }));
import { performListOrganizationsWithSubscriptions, performUpdateHybridSubscription } from '../routes/hybrid-subscription';

beforeEach(() => vi.resetAllMocks());
describe('Hybrid contract read and update', () => {
  it('returns complete saved terms and the registered owner email, never the institution contact', async () => {
    mocks.query.mockImplementation(async (path: string) => {
      if (path.startsWith('organizations?')) return [{ id: 'org', name: 'College', created_by: 'owner', metadata: { organization_type: 'college', email: 'contact@example.test' } }];
      if (path.startsWith('users?')) return [{ id: 'owner', email: 'admin@example.test' }];
      return [{ id: 'sub', organization_id: 'org', plan_code: 'hybrid', status: 'active', plan_amount: 4300, seat_count: 100, billing_cycle: 'monthly', features: ['admissions_data'], metadata: { notes: 'Saved terms' } }];
    });
    const result = await performListOrganizationsWithSubscriptions({} as never, {});
    expect(result.data[0]).toMatchObject({ admin_email: 'admin@example.test', plan_amount: 4300, seat_count: 100, billing_cycle: 'monthly', features: ['admissions_data'], notes: 'Saved terms' });
  });
  it('returns no email when the owner identity is unavailable', async () => {
    mocks.query.mockImplementation(async (path: string) => path.startsWith('organizations?') ? [{ id: 'org', name: 'College', created_by: null, metadata: { email: 'contact@example.test' } }] : []);
    expect((await performListOrganizationsWithSubscriptions({} as never, {})).data[0].admin_email).toBeNull();
  });
  it.each(['active', 'pending'])('publishes persisted expiry and %s status and permits explicit note clearing', async status => {
    mocks.queryOne.mockImplementation(async (path: string) => path.startsWith('organizations?')
      ? { id: 'org', name: 'College', metadata: { organization_type: 'college' } }
      : { id: 'sub', user_id: 'owner', plan_id: 'plan', plan_code: 'hybrid', plan_type: 'Hybrid', status, seat_count: 30, subscription_end_date: null, metadata: { notes: 'Old' } });
    await performUpdateHybridSubscription({} as never, {} as never, { organization_id: 'org', admin_user_id: 'admin', plan_amount: 4300, seat_count: 100, billing_cycle: 'lifetime', features: [], notes: '' });
    expect(mocks.update.mock.calls[0][2]).toMatchObject({ metadata: { notes: '' } });
    expect(mocks.update.mock.calls[0][2]).not.toHaveProperty('subscription_end_date');
    expect(mocks.publish.mock.calls[0][3]).toMatchObject({ status, seat_count: 100, subscription_end_date: null, auto_renew: false });
  });
  it.each(['monthly', 'annual', 'lifetime'])('preserves the existing expiry when editing %s terms', async billing_cycle => {
    const expiry = '2027-02-03T04:05:06.000Z';
    mocks.queryOne.mockImplementation(async (path: string) => path.startsWith('organizations?')
      ? { id: 'org', name: 'College', metadata: { organization_type: 'college' } }
      : { id: 'sub', user_id: 'owner', plan_id: 'plan', plan_code: 'hybrid', plan_type: 'Hybrid', status: 'active', seat_count: 30, subscription_end_date: expiry, metadata: { notes: 'Old' } });
    const result = await performUpdateHybridSubscription({} as never, {} as never, { organization_id: 'org', admin_user_id: 'admin', plan_amount: 4300, seat_count: 100, billing_cycle, features: [], notes: 'Edited' });
    expect(mocks.update.mock.calls[0][2]).not.toHaveProperty('subscription_end_date');
    expect(mocks.publish.mock.calls[0][3]).toMatchObject({ subscription_end_date: expiry, status: 'active' });
    expect(result.subscription_end_date).toBe(expiry);
  });
});


it('summary covers the complete filtered result, is invariant across pages, and counts only active Hybrid plans', async () => {
  mocks.query.mockImplementation(async (path: string) => {
    if (path.startsWith('organizations?')) return [1,2,3].map(n => ({ id: 'org'+n, name: 'Organization '+n }));
    if (path.startsWith('users?')) return [];
    return [
      { id: 's1', organization_id: 'org1', plan_code: 'hybrid', status: 'active', seat_count: 30, plan_amount: 100 },
      { id: 's2', organization_id: 'org2', plan_code: 'hybrid', status: 'pending', seat_count: 20, plan_amount: 200 },
      { id: 's3', organization_id: 'org3', plan_code: 'other', status: 'active', seat_count: 10, plan_amount: 300 },
    ];
  });
  const one=await performListOrganizationsWithSubscriptions({} as never,{ page: 1, limit: 1 });
  const two=await performListOrganizationsWithSubscriptions({} as never,{ page: 2, limit: 1 });
  expect(one.data).toHaveLength(1); expect(two.data).toHaveLength(1);
  expect(one.summary).toEqual({ total: 3, hybridCount: 1, totalSeats: 60, totalDealValue: 600 });
  expect(two.summary).toEqual(one.summary);
  expect((await performListOrganizationsWithSubscriptions({} as never,{ status: 'active' })).summary).toEqual({ total: 2, hybridCount: 1, totalSeats: 40, totalDealValue: 400 });
});
it('exhausts organization REST pages rather than treating the row cap as the global total', async () => {
  mocks.query.mockImplementation(async (path: string) => {
    if (!path.startsWith('organizations?')) return [];
    return path.includes('offset=0') ? Array.from({ length: 500 },(_,n)=>({id:'org'+n,name:'Organization '+n})) : [{id:'last',name:'Last'}];
  });
  const result=await performListOrganizationsWithSubscriptions({} as never,{});
  expect(result.pagination.total).toBe(501); expect(result.summary.total).toBe(501);
});

it('rejects a seat reduction before changing source terms or publishing', async () => {
 mocks.queryOne.mockImplementation(async (path: string) => path.startsWith('organizations?') ? { id: 'org', name: 'College' } : { id: 'sub', seat_count: 30 });
 await expect(performUpdateHybridSubscription({} as never,{} as never,{organization_id:'org',admin_user_id:'admin',seat_count:1,plan_amount:100})).rejects.toThrow('Seat reductions require a coordinated contract change');
 expect(mocks.update).not.toHaveBeenCalled();expect(mocks.publish).not.toHaveBeenCalled();
});
