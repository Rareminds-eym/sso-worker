import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Env } from '../types';
const mocks = vi.hoisted(() => ({ query: vi.fn(), queryOne: vi.fn(), update: vi.fn(), verify: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/hash', () => ({ hashToken: async (token: string) => `hashed-${token}`, hashPassword: async () => 'new-hash', verifyPassword: mocks.verify }));
vi.mock('../lib/rate-limit', () => ({ endpointRateLimit: async () => null }));
vi.mock('../lib/audit', () => ({ audit: vi.fn() }));
import { performChangePassword } from '../routes/change-password';
const input = { user_id: 'user-1', current_password: 'OldPassword123!', new_password: 'NewPassword123!', current_refresh_token: 'cookie-token' };
const change = (params = input) => performChangePassword({} as Env, {} as ExecutionContext, params);
beforeEach(() => {
  vi.resetAllMocks();
  mocks.query.mockResolvedValue([{ password_hash: 'old-hash' }]);
  mocks.queryOne.mockResolvedValue({ id: 'session-1', family_id: 'family-1', expires_at: '2099-01-01' });
  mocks.verify.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
});
describe('preserve the current session on password change', () => {
  it('scopes the cookie lookup to the authenticated user and revokes only other families', async () => {
    expect((await change()).success).toBe(true);
    expect(mocks.queryOne).toHaveBeenCalledWith(expect.stringContaining('refresh_token_hash=eq.hashed-cookie-token&user_id=eq.user-1&revoked=eq.false'));
    expect(mocks.update).toHaveBeenCalledWith('sessions', {
      user_id: 'eq.user-1', revoked: 'eq.false', id: 'neq.session-1',
      or: '(family_id.is.null,family_id.neq.family-1)',
    }, { revoked: true });
  });
  it('preserves the rotation successor of a legacy session with no family ID', async () => {
    mocks.queryOne.mockResolvedValue({ id: 'session-1', family_id: null, expires_at: '2099-01-01' });
    await change();
    expect(mocks.update).toHaveBeenCalledWith('sessions', expect.objectContaining({ id: 'neq.session-1', or: '(family_id.is.null,family_id.neq.session-1)' }), { revoked: true });
  });
  it.each([null, { id: 'session-1', family_id: 'family-1', expires_at: '2000-01-01' }])('rejects missing, foreign, revoked or expired sessions before changing the password', async session => {
    mocks.queryOne.mockResolvedValue(session);
    expect((await change()).status).toBe(401);
    expect(mocks.update).not.toHaveBeenCalled();
  });
  it('does not change credentials or sessions when the current password is wrong', async () => {
    mocks.verify.mockReset().mockResolvedValue(false);
    expect((await change()).error).toBe('Current password is incorrect');
    expect(mocks.update).not.toHaveBeenCalled();
  });
  it('keeps revoke-all behavior for callers that do not request session preservation', async () => {
    const { current_refresh_token, ...withoutCookie } = input;
    await performChangePassword({} as Env, {} as ExecutionContext, withoutCookie);
    expect(mocks.update).toHaveBeenCalledWith('sessions', { user_id: 'eq.user-1', revoked: 'eq.false' }, { revoked: true });
  });
});
