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
      : { id: 'sub', user_id: 'owner', plan_id: 'plan', plan_code: 'hybrid', plan_type: 'Hybrid', status, subscription_end_date: null, metadata: { notes: 'Old' } });
    await performUpdateHybridSubscription({} as never, {} as never, { organization_id: 'org', admin_user_id: 'admin', plan_amount: 4300, seat_count: 100, billing_cycle: 'lifetime', features: [], notes: '' });
    expect(mocks.update.mock.calls[0][2]).toMatchObject({ metadata: { notes: '' } });
    expect(mocks.update.mock.calls[0][2]).not.toHaveProperty('subscription_end_date');
    expect(mocks.publish.mock.calls[0][3]).toMatchObject({ status, subscription_end_date: null, auto_renew: false });
  });
  it.each(['monthly', 'annual', 'lifetime'])('preserves the existing expiry when editing %s terms', async billing_cycle => {
    const expiry = '2027-02-03T04:05:06.000Z';
    mocks.queryOne.mockImplementation(async (path: string) => path.startsWith('organizations?')
      ? { id: 'org', name: 'College', metadata: { organization_type: 'college' } }
      : { id: 'sub', user_id: 'owner', plan_id: 'plan', plan_code: 'hybrid', plan_type: 'Hybrid', status: 'active', subscription_end_date: expiry, metadata: { notes: 'Old' } });
    const result = await performUpdateHybridSubscription({} as never, {} as never, { organization_id: 'org', admin_user_id: 'admin', plan_amount: 4300, seat_count: 100, billing_cycle, features: [], notes: 'Edited' });
    expect(mocks.update.mock.calls[0][2]).not.toHaveProperty('subscription_end_date');
    expect(mocks.publish.mock.calls[0][3]).toMatchObject({ subscription_end_date: expiry, status: 'active' });
    expect(result.subscription_end_date).toBe(expiry);
  });
});
