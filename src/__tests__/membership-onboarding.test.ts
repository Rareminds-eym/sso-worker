import { describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ rpc: vi.fn(), update: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/hash', () => ({ hashPassword: async () => 'hashed-password' }));
import { performCreateMember } from '../routes/membership';
describe('administrator educator onboarding metadata', () => {
  it('persists the authoritative role/provenance/first-password flag and publishes it to the app sync queue', async () => {
    mocks.rpc.mockResolvedValue({ user_id: 'user-1', org_id: 'platform-1', membership_id: 'membership-1' });
    const send = vi.fn();
    await performCreateMember({ SYNC_QUEUE: { send } } as any, {
      email: 'HARI@example.com', password: 'Temporary123!', role: 'educator', org_id: 'platform-1',
      user_metadata: { role: 'admin', must_change_password: true, portal_mode: 'assigned_trainer', onboarding_request_id: 'request-1' },
    });
    expect(mocks.rpc).toHaveBeenCalledWith('signup_member', expect.objectContaining({
      p_email: 'hari@example.com', p_password_hash: 'hashed-password',
      p_user_metadata: expect.objectContaining({ role: 'educator', must_change_password: true, onboarding_request_id: 'request-1' }),
    }));
    expect(mocks.update).toHaveBeenCalledWith('users', { id: 'eq.user-1' }, { is_email_verified: true });
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ type: 'user.created', payload: expect.objectContaining({
      user_metadata: expect.objectContaining({ must_change_password: true, portal_mode: 'assigned_trainer' }),
    }) }));
  });
});
