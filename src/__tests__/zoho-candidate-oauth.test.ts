import { executionContext } from './execution-context';
import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ query: vi.fn(), queryOne: vi.fn(), mutate: vi.fn(), update: vi.fn(), rpc: vi.fn(),
  sign: vi.fn(), rateLimit: vi.fn(), sync: vi.fn(), audit: vi.fn(), recover: vi.fn() }));
vi.mock('../lib/zoho-candidate-delivery', () => ({ recoverCandidateDeliveries: mocks.recover }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/jwt', () => ({ signAccessToken: mocks.sign }));
vi.mock('../lib/rate-limit', () => ({ endpointRateLimit: mocks.rateLimit }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: mocks.sync }));
vi.mock('../lib/audit', () => ({ audit: mocks.audit }));
vi.mock('../lib/skillpassport-check', () => ({ checkUserExistsInSkillpassport: async () => false }));
import { performOAuthLogin } from '../routes/oauth';
import type { Env } from '../types';
const id = '10000000-0000-4000-8000-000000000001';
const org = '00000000-0000-0000-0000-000000000001';
const metadata = { role: 'learner', activation_pending: true, preferences: { careerSuggestions: true } };
const user = () => ({ id, email: 'imported@example.com', password_hash: '!zoho-import-no-password!',
  is_blocked: false, is_email_verified: false, user_metadata: structuredClone(metadata) });
const body = { provider: 'google', provider_user_id: 'provider-subject', email: 'imported@example.com', email_verified: true };
let pending: Promise<unknown>[];
const ctx = executionContext(task => { pending.push(task); });
const env = { RATE_LIMIT_KV: { get: vi.fn(), put: vi.fn() }, EMAIL_QUEUE: { send: vi.fn() }, EMAIL_SERVICE: { sendEmail: vi.fn() }, SYNC_QUEUE: { send: vi.fn() } } as unknown as Env;
beforeEach(() => {
  vi.resetAllMocks(); pending = [];
  mocks.rateLimit.mockResolvedValue(false); mocks.recover.mockResolvedValue({ published: 0 });
  mocks.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? null : path.startsWith('users?') ? user() : null);
  mocks.query.mockImplementation(async (path, options) => options?.method === 'POST' ? [] : [{ id: 'membership', org_id: org }]);
  mocks.update.mockResolvedValue(undefined); mocks.mutate.mockResolvedValue({ id: 'session' });
  mocks.rpc.mockImplementation(async name => name === 'zoho_activate_candidate_oauth'
    ? { activated: true, userMetadata: { role: 'learner', preferences: metadata.preferences } }
    : name === 'zoho_candidate_sync_policy' ? { version: 1, genericSyncAllowed: false }
    : { roles: ['learner'], products: ['skillpassport'], membership_status: 'active' });
  mocks.sign.mockResolvedValue('signed-token');
});
describe('imported candidate no-email provider activation', () => {
  it('keeps later imported Google sign-in on canonical recovery after activation_pending was removed', async () => {
    mocks.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? { user_id: id }
      : path.startsWith('users?') ? { ...user(), is_email_verified: true, user_metadata: { role: 'learner' } } : null);
    expect(await performOAuthLogin(env, ctx, body, null, null)).toMatchObject({ access_token: 'signed-token' });
    await Promise.all(pending);
    expect(mocks.rpc).toHaveBeenCalledWith('zoho_candidate_sync_policy', { p_user: id });
    expect(mocks.recover).toHaveBeenCalledExactlyOnceWith(env);
    expect(mocks.sync).not.toHaveBeenCalled();
    expect(env.RATE_LIMIT_KV.get).not.toHaveBeenCalled();
  });
  it('does not fall back to generic replay when durable provenance cannot be read', async () => {
    mocks.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? { user_id: id }
      : { ...user(), is_email_verified: true, user_metadata: { role: 'learner' } });
    mocks.rpc.mockImplementation(async name => {
      if (name === 'zoho_candidate_sync_policy') throw new Error('Unavailable');
      return { roles: ['learner'], products: ['skillpassport'], membership_status: 'active' };
    });
    expect(await performOAuthLogin(env, ctx, body, null, null)).toMatchObject({ access_token: 'signed-token' });
    await Promise.all(pending);
    expect(mocks.sync).not.toHaveBeenCalled();
  });
  it('preserves ordinary non-imported Google recovery', async () => {
    mocks.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? { user_id: id }
      : path.startsWith('users?') ? { ...user(), is_email_verified: true, user_metadata: { role: 'learner' } }
      : { id: org, name: 'Synthetic platform' });
    mocks.query.mockImplementation(async path => path.startsWith('memberships?') ? [{ id: 'membership', org_id: org }] : []);
    mocks.rpc.mockImplementation(async name => name === 'zoho_candidate_sync_policy' ? { version: 1, genericSyncAllowed: true }
      : { roles: ['learner'], products: ['skillpassport'], membership_status: 'active' });
    await performOAuthLogin(env, ctx, body, null, null); await Promise.all(pending);
    expect(mocks.sync).toHaveBeenCalledWith(env.SYNC_QUEUE, ctx, 'user.created', expect.objectContaining({ id }));
    expect(mocks.recover).not.toHaveBeenCalled();
  });
  it('activates the same approved identity through verified Google ownership and preserves Discover/context', async () => {
    const result = await performOAuthLogin(env, ctx, body, '127.0.0.1', 'fixture');
    await Promise.all(pending);
    expect(result).toMatchObject({ access_token: 'signed-token', user: { id, email: body.email }, active_org_id: org });
    expect(mocks.rpc).toHaveBeenCalledWith('zoho_activate_candidate_oauth', { p_user: id, p_provider_subject: body.provider_user_id, p_email: body.email });
    expect(mocks.query).toHaveBeenCalledWith('oauth_accounts', expect.objectContaining({ method: 'POST',
      body: JSON.stringify({ user_id: id, provider: 'google', provider_user_id: body.provider_user_id }) }));
    expect(mocks.mutate.mock.calls.map(([table]) => table)).toEqual(['sessions']);
    expect(mocks.update.mock.calls.every(([table, , values]) => table === 'users' && !('is_email_verified' in values))).toBe(true);
    expect(mocks.sign).toHaveBeenCalledWith(expect.objectContaining({ sub: id, is_email_verified: true,
      products: ['skillpassport'], user_metadata: { role: 'learner', preferences: metadata.preferences } }), env);
    expect(env.EMAIL_QUEUE.send).not.toHaveBeenCalled();
    expect(env.EMAIL_SERVICE.sendEmail).not.toHaveBeenCalled();
    expect(mocks.sync).not.toHaveBeenCalled();
    expect(mocks.recover).toHaveBeenCalledExactlyOnceWith(env);
    expect(env.RATE_LIMIT_KV.get).not.toHaveBeenCalled();
  });
  it('repairs a previously linked but activation-pending import before issuing a session', async () => {
    mocks.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? { user_id: id } : user());
    expect(await performOAuthLogin(env, ctx, body, null, null)).toMatchObject({ access_token: 'signed-token' });
    await Promise.all(pending);
    expect(mocks.rpc).toHaveBeenCalledWith('zoho_activate_candidate_oauth', expect.objectContaining({ p_user: id }));
    expect(mocks.query.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  });
  it.each([{ email_verified: false }, { provider: 'other' }])('rejects unverified or unsupported provider %j without identity writes', async patch => {
    expect(await performOAuthLogin(env, ctx, { ...body, ...patch }, null, null)).toMatchObject({ status: 400 });
    expect(mocks.queryOne).not.toHaveBeenCalled(); expect(mocks.rpc).not.toHaveBeenCalled(); expect(mocks.sign).not.toHaveBeenCalled();
  });
  it('blocks imported identities before linking or activating', async () => {
    mocks.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? null : { ...user(), is_blocked: true });
    expect(await performOAuthLogin(env, ctx, body, null, null)).toMatchObject({ status: 403 });
    expect(mocks.rpc).not.toHaveBeenCalled(); expect(mocks.mutate).not.toHaveBeenCalled(); expect(mocks.sign).not.toHaveBeenCalled();
  });
  it('does not issue sessions when canonical activation declines', async () => {
    mocks.rpc.mockResolvedValue({ activated: false });
    expect(await performOAuthLogin(env, ctx, body, null, null)).toMatchObject({ status: 503 });
    expect(mocks.mutate).not.toHaveBeenCalled(); expect(mocks.sign).not.toHaveBeenCalled();
  });
});
