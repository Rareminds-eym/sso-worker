import { executionContext } from './execution-context';
import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ query: vi.fn(), queryOne: vi.fn(), mutate: vi.fn(), update: vi.fn(), rpc: vi.fn(),
  sign: vi.fn(), rateLimit: vi.fn(), sync: vi.fn(), audit: vi.fn(), recover: vi.fn() }));
vi.mock('../lib/zoho-candidate-delivery', () => ({ recoverCandidateDeliveries: mocks.recover }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
vi.mock('../lib/jwt', () => ({ signAccessToken: mocks.sign }));
vi.mock('../lib/rate-limit', () => ({ endpointRateLimit: mocks.rateLimit, checkAccountLockout: async () => false, clearFailedLogins: async () => {}, recordFailedLogin: async () => {} }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: mocks.sync }));
vi.mock('../lib/audit', () => ({ audit: mocks.audit }));
vi.mock('../lib/skillpassport-check', () => ({ checkUserExistsInSkillpassport: async () => false }));
import { performLogin } from '../routes/login';
vi.mock('../lib/hash', () => ({ verifyPassword: async () => true, generateRefreshToken: () => 'fixture-refresh', hashToken: async () => 'fixture-hash' }));
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
describe('imported password-login recovery after separately established credentials', () => {
 it('uses durable provenance even after activation and never emits generic snapshots', async () => {
  mocks.queryOne.mockImplementation(async path => path.startsWith('users?') ? { ...user(), password_hash: 'separately-established-hash', is_email_verified: true, user_metadata: { role: 'learner' } } : null);
  expect(await performLogin(env, ctx, { email: body.email, password: 'fixture-verified-password' }, null, null)).toMatchObject({ access_token: 'signed-token' });
  await Promise.all(pending);
  expect(mocks.rpc).toHaveBeenCalledWith('zoho_candidate_sync_policy', { p_user: id });
  expect(mocks.recover).toHaveBeenCalledExactlyOnceWith(env);
  expect(mocks.sync).not.toHaveBeenCalled();
 });
});
