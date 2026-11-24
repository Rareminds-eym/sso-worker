import { beforeEach, describe, expect, it, vi } from 'vitest';
import { executionContext } from './execution-context';
const io = vi.hoisted(() => ({ rpc: vi.fn(), query: vi.fn(), queryOne: vi.fn(), mutate: vi.fn(), update: vi.fn(),
  sign: vi.fn(), sync: vi.fn(), send: vi.fn(), project: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => io }));
vi.mock('../lib/hash', () => ({ hashPassword: async () => 'synthetic-hash', hashToken: async () => 'a'.repeat(64), generateRefreshToken: () => 'synthetic-refresh' }));
vi.mock('../lib/jwt', () => ({ signAccessToken: io.sign }));
vi.mock('../lib/rate-limit', () => ({ endpointRateLimit: async () => null }));
vi.mock('../lib/email-throttle', () => ({ checkEmailThrottle: async () => false }));
vi.mock('../lib/email', () => ({ sendEmail: io.send }));
vi.mock('../lib/audit', () => ({ audit: vi.fn() }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: io.sync }));
vi.mock('../lib/subscriptions/projection-sync', () => ({ publishCommittedSubscriptions: io.project }));
vi.mock('../lib/zoho-candidate-sync-policy', () => ({ isImportedCandidate: async () => false }));
import { performSignup } from '../routes/signup';
import { performSignupMember } from '../routes/signup-member';
import { performVerifyEmail } from '../routes/verify-email';
import { performOAuthLogin } from '../routes/oauth';
import { freeSignupPolicy } from '../lib/subscriptions/free-entry';
import type { Env } from '../types';
import { PLATFORM_ORG_ID } from '../lib/constants';

const id = '10000000-0000-4000-8000-000000000001';
const sub = '10000000-0000-4000-8000-000000000002';
const env = { SYNC_QUEUE: {}, ALLOWED_REDIRECT_ORIGINS: 'https://app.example.invalid', SKILLPASSPORT_URL: 'https://app.example.invalid' } as unknown as Env;
const profile = { provider: 'google', provider_user_id: 'synthetic-provider-subject', email: 'learner@example.invalid', email_verified: true };
let pending: Promise<unknown>[];
const ctx = executionContext(task => pending.push(task));
beforeEach(() => {
  vi.resetAllMocks(); pending = [];
  io.query.mockResolvedValue([]);
  io.queryOne.mockImplementation(async path => path.startsWith('organizations?') ? { id: PLATFORM_ORG_ID }
    : path.startsWith('users?id=') ? { is_email_verified: false } : null);
  io.mutate.mockResolvedValue({ id: 'synthetic-session' }); io.update.mockResolvedValue(undefined);
  io.sign.mockResolvedValue('synthetic-access'); io.send.mockResolvedValue(undefined);
  io.project.mockResolvedValue(undefined);
  io.rpc.mockImplementation(async name => name === 'signup_with_subscription_entry'
    ? { user_id: id, org_id: PLATFORM_ORG_ID, slug: 'synthetic-org' }
    : name === 'get_jwt_claims' ? { roles: ['learner'], products: [], membership_status: 'active' }
    : name === 'verify_email_with_subscription_entry' || name === 'verify_oauth_with_subscription_entry'
      ? { verified: true, userId: id, subscriptionIds: [sub] } : Promise.reject(new Error('Unexpected RPC')));
});

describe('complete signup and verification routes', () => {
  it.each(Object.keys(freeSignupPolicy().signupRoles))('routes %s organization signup to the owner and activates only on verification', async role => {
    const result = await performSignup(env, ctx, { email: 'manager@example.invalid', password: 'SyntheticPassword123!', role, org_name: 'Synthetic Org' });
    await Promise.all(pending);
    expect(result).toMatchObject({ access_token: 'synthetic-access', email_sent: true });
    expect(io.rpc).toHaveBeenCalledWith('signup_with_subscription_entry', expect.objectContaining({ p_kind: 'organization', p_signup: expect.objectContaining({ p_role: role }) }));
    expect(io.rpc.mock.calls.some(([name]) => name.startsWith('verify_') || name.startsWith('activate_'))).toBe(false);
    expect(io.project).not.toHaveBeenCalled();
    expect(await performVerifyEmail(env, ctx, { token: 'synthetic-token' })).toEqual({ verified: true });
    await Promise.all(pending);
    expect(io.rpc).toHaveBeenLastCalledWith('verify_email_with_subscription_entry', { p_token_hash: 'a'.repeat(64) });
    expect(io.project).toHaveBeenCalledExactlyOnceWith(io, env.SYNC_QUEUE, ctx, id, [sub]);
  });
  it('routes personal signup through the same intent owner without a contract, price or premature activation', async () => {
    expect(await performSignupMember(env, ctx, { email: profile.email, password: 'SyntheticPassword123!', role: 'learner' }))
      .toMatchObject({ access_token: 'synthetic-access', email_sent: true });
    await Promise.all(pending);
    expect(io.rpc).toHaveBeenCalledWith('signup_with_subscription_entry', expect.objectContaining({ p_kind: 'member' }));
    expect(io.rpc.mock.calls.filter(([name]) => name === 'verify_email_with_subscription_entry')).toHaveLength(0);
    expect(io.mutate.mock.calls.some(([table]) => table === 'subscriptions')).toBe(false);
  });
  it('new Google signup records the intent and activates with verified provider proof before issuing a session', async () => {
    const result = await performOAuthLogin(env, ctx, profile, null, null);
    await Promise.all(pending);
    expect(result).toMatchObject({ access_token: 'synthetic-access', user: { id } });
    expect(io.rpc).toHaveBeenCalledWith('signup_with_subscription_entry', expect.objectContaining({ p_kind: 'member',
      p_signup: expect.objectContaining({ p_role: 'learner', p_org_id: PLATFORM_ORG_ID }) }));
    expect(io.rpc).toHaveBeenCalledWith('verify_oauth_with_subscription_entry', { p_user_id: id, p_provider_subject: profile.provider_user_id, p_email: profile.email });
    const verificationCall = io.rpc.mock.calls.findIndex(([name]) => name === 'verify_oauth_with_subscription_entry');
    expect(io.rpc.mock.invocationCallOrder[verificationCall]).toBeLessThan(io.sign.mock.invocationCallOrder[0]);
    expect(io.mutate.mock.calls.map(([table]) => table)).toEqual(['sessions']);
    expect(io.send).not.toHaveBeenCalled();
    expect(io.project).toHaveBeenCalledExactlyOnceWith(io, env.SYNC_QUEUE, ctx, id, [sub]);
  });
  it.each([true, false])('Google verifies an existing unverified password signup with an existing link=%s', async linked => {
    io.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? linked ? { user_id: id } : null
      : path.startsWith('users?') ? { id, email: profile.email, is_blocked: false, is_email_verified: false, user_metadata: {} } : null);
    expect(await performOAuthLogin(env, ctx, profile, null, null)).toMatchObject({ access_token: 'synthetic-access' });
    await Promise.all(pending);
    expect(io.rpc).toHaveBeenCalledWith('verify_oauth_with_subscription_entry', expect.objectContaining({ p_user_id: id }));
    expect(io.project).toHaveBeenCalledExactlyOnceWith(io, env.SYNC_QUEUE, ctx, id, [sub]);
    expect(io.update.mock.calls.some(([, , patch]) => 'is_email_verified' in patch)).toBe(false);
    expect(io.rpc.mock.calls.some(([name]) => name === 'signup_with_subscription_entry')).toBe(false);
  });
  it('does not issue a session or verified event when Google activation fails', async () => {
    const original = io.rpc.getMockImplementation()!;
    io.rpc.mockImplementation(async (name, args) => { if (name === 'verify_oauth_with_subscription_entry') throw new Error('Rejected'); return original(name, args); });
    expect(await performOAuthLogin(env, ctx, profile, null, null)).toMatchObject({ status: 503 });
    await Promise.all(pending);
    expect(io.sign).not.toHaveBeenCalled(); expect(io.mutate).not.toHaveBeenCalled();
    expect(io.sync.mock.calls.some(([, , event]) => event === 'user.email_verified')).toBe(false);
    expect(io.project).not.toHaveBeenCalled();
  });
  it('rejects a linked provider address mismatch and unverified provider input', async () => {
    io.queryOne.mockImplementation(async path => path.startsWith('oauth_accounts?') ? { user_id: id }
      : { id, email: 'other@example.invalid', is_blocked: false });
    expect(await performOAuthLogin(env, ctx, profile, null, null)).toMatchObject({ status: 403 });
    expect(await performOAuthLogin(env, ctx, { ...profile, email_verified: false }, null, null)).toMatchObject({ status: 400 });
    expect(io.sign).not.toHaveBeenCalled(); expect(io.mutate).not.toHaveBeenCalled();
  });
});
