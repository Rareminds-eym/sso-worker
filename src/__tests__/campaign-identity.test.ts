import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthorizationCodeStore } from '../durable-objects/AuthorizationCodeStore';
import { ensureCampaignUser, exchangeCampaignHandoff, flushCampaignOutbox, recordSkillpassportAccess } from '../lib/campaign-identity';
import type { Env } from '../types';

const mocks = vi.hoisted(() => ({ rpc: vi.fn(), query: vi.fn(), queryOne: vi.fn(), update: vi.fn(), mutate: vi.fn(), mint: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/hash', () => ({ hashPassword: vi.fn(async () => 'random-password-hash'), hashToken: vi.fn(async () => 'hashed-token'), generateRefreshToken: () => 'a'.repeat(43) }));
vi.mock('../lib/session-rotation', () => ({ mintAccessToken: (...args: unknown[]) => mocks.mint(...args) }));

function store() {
  const data = new Map<string, unknown>();
  let tail = Promise.resolve();
  const transaction = { get: async (k: string) => data.get(k), delete: async (k: string) => data.delete(k) };
  return new AuthorizationCodeStore({ storage: {
    put: async (k: string, v: unknown) => data.set(k, v), setAlarm: async () => {},
    transaction: (fn: any) => { const next = tail.then(() => fn(transaction)); tail = next.catch(() => {}); return next; },
  }} as any, {});
}

beforeEach(() => { vi.clearAllMocks(); mocks.rpc.mockResolvedValue(undefined); mocks.update.mockResolvedValue(undefined); });

describe('campaign identity boundary', () => {
  it('rejects malformed identity before database writes', async () => {
    await expect(ensureCampaignUser({} as Env, { email: 'bad', name: 'Test', mobile: '123' })).rejects.toThrow('Invalid');
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('uses the atomic database operation and never submits a role override', async () => {
    mocks.rpc.mockResolvedValue({ user_id: 'canonical', educator_id: 'LRN-TES26-10000000' });
    const result = await ensureCampaignUser({} as Env, { email: 'TEST@example.test', name: 'Test', mobile: '9000000000' });
    expect(result.user_id).toBe('canonical');
    expect(mocks.rpc).toHaveBeenCalledWith('ensure_educator_campaign_user', expect.objectContaining({ p_email: 'test@example.test', p_educator_id: null }));
    expect(mocks.rpc.mock.calls[0][1]).not.toHaveProperty('role');
  });
  it('does not acknowledge undelivered outbox entries', async () => {
    mocks.query.mockResolvedValue([{ id: 'event', user_id: 'user', payload: { org_id: null } }]);
    mocks.queryOne.mockResolvedValue({ id: 'user', email: 'test@example.test', user_metadata: {} });
    const env = { SYNC_QUEUE: { send: vi.fn().mockRejectedValue(new Error('offline')) } } as any;
    await expect(flushCampaignOutbox(env)).rejects.toThrow('offline');
    expect(mocks.update).not.toHaveBeenCalled();
    env.SYNC_QUEUE.send.mockResolvedValue(undefined);
    await flushCampaignOutbox(env);
    expect(mocks.update).toHaveBeenCalledWith('events', { id: 'eq.event' }, expect.objectContaining({ status: 'completed', processed_at: expect.any(String) }));
  });
  it('fixes the app identity and hashes the session credential', async () => {
    await recordSkillpassportAccess({} as Env, 'opaque-secret', 'login');
    expect(mocks.rpc).toHaveBeenCalledWith('record_application_access', {
      p_refresh_hash: 'hashed-token', p_app_id: 'skillpassport', p_event_type: 'login', p_signup: false,
    });
  });
});

describe('single-use handoff', () => {
  const record = { codeHash: 'hash', stateHash: 'state', userId: 'u', orgId: 'o', targetApp: 'skillpassport' as const, redirectUri: 'https://skillpassport.test/api/campaign/callback', expiresAt: 2000, createdAt: 1 };
  it('allows exactly one concurrent redemption', async () => {
    const codes = store();
    await codes.store(record);
    const consume = () => codes.consume({ codeHash: 'hash', stateHash: 'state', redirectUri: record.redirectUri, now: 1000 });
    const results = await Promise.all([consume(), consume()]);
    expect(results.filter(r => r.success)).toHaveLength(1);
  });
  it('rejects wrong state, wrong callback, and expiration', async () => {
    const codes = store();
    await codes.store(record);
    expect(await codes.consume({ codeHash: 'hash', stateHash: 'wrong', redirectUri: record.redirectUri, now: 1000 })).toEqual({ success: false, reason: 'state_mismatch' });
    expect(await codes.consume({ codeHash: 'hash', stateHash: 'state', redirectUri: 'https://attacker.test', now: 1000 })).toEqual({ success: false, reason: 'redirect_uri_mismatch' });
    expect(await codes.consume({ codeHash: 'hash', stateHash: 'state', redirectUri: record.redirectUri, now: 2000 })).toEqual({ success: false, reason: 'expired' });
  });
  it('rejects target-app confusion before session creation', async () => {
    const env = { SKILLPASSPORT_URL: 'https://skillpassport.test', AUTH_CODE_STORE: { idFromName: () => 'id', get: () => ({ consume: async () => ({ success: true, record: { ...record, targetApp: 'lte' } }) }) } } as any;
    await expect(exchangeCampaignHandoff(env, { code: 'a'.repeat(43), state: 'a'.repeat(64), redirectUri: record.redirectUri })).rejects.toThrow('Invalid or expired');
    expect(mocks.mutate).not.toHaveBeenCalled();
  });
  it('revokes an issued session if authoritative login tracking fails', async () => {
    mocks.mint.mockResolvedValue({ token: 'access' });
    mocks.rpc.mockRejectedValue(new Error('database unavailable'));
    const env = { SKILLPASSPORT_URL: 'https://skillpassport.test', AUTH_CODE_STORE: { idFromName: () => 'id', get: () => ({ consume: async () => ({ success: true, record }) }) } } as any;
    await expect(exchangeCampaignHandoff(env, { code: 'a'.repeat(43), state: 'a'.repeat(64), redirectUri: record.redirectUri })).rejects.toThrow('database unavailable');
    expect(mocks.update).toHaveBeenCalledWith('sessions', expect.anything(), { revoked: true });
  });
});
