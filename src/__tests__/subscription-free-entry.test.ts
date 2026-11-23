import { describe, expect, it, vi, beforeEach } from 'vitest';
import { freeSignupPolicy, signupWithFreeEntry, verifyEmailWithFreeEntry } from '../lib/subscriptions/free-entry';
import { earlierSubscriptionEnd, subscriptionEntryEnd } from '../lib/subscriptions/entry-validity';
import { readSubscriptionLifecycleAccess, type LifecyclePolicy, type LifecycleState } from '../lib/subscriptions/lifecycle';
import config from '../../config/subscriptions/free-signup.json';
import { performVerifyEmail } from '../routes/verify-email';
import type { Env } from '../types';

const { rpc, sync, audit } = vi.hoisted(() => ({ rpc: vi.fn(), sync: vi.fn(), audit: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc }) }));
vi.mock('../lib/hash', () => ({ hashToken: vi.fn(async () => 'a'.repeat(64)) }));
vi.mock('../lib/sync-queue', () => ({ publishSyncEvent: sync }));
vi.mock('../lib/audit', () => ({ audit }));
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const database = { rpc: async <T>(name: string, args?: Record<string, unknown>) => await rpc(name, args) as T };
const receipt = () => ({ verified: true, userId: id(1), subscriptionIds: [id(2)] });
const context = { waitUntil: vi.fn() } as unknown as ExecutionContext;

beforeEach(() => vi.clearAllMocks());

describe('verified signup free-entry owner transport', () => {
  it('records each organization audience and the personal audience from validated owner configuration', async () => {
    const policy = freeSignupPolicy();
    expect(Object.values(policy.signupRoles).map(b => b.audience).sort()).toEqual(['college', 'recruitment', 'school', 'university']);
    for (const [role, binding] of Object.entries(policy.signupRoles)) {
      rpc.mockResolvedValueOnce({ user_id: id(1), org_id: id(2) });
      const signup = { p_role: role, p_email: 'synthetic@example.invalid', p_password_hash: 'synthetic-hash' };
      await signupWithFreeEntry(database, 'organization', signup);
      expect(rpc).toHaveBeenLastCalledWith('signup_with_subscription_entry', { p_kind: 'organization', p_signup: signup, p_policy: policy });
      expect(binding.organizationType).not.toBeNull();
    }
    await signupWithFreeEntry(database, 'member', { p_role: 'learner' });
    expect(rpc).toHaveBeenLastCalledWith('signup_with_subscription_entry', expect.objectContaining({ p_kind: 'member' }));
  });
  it('retains normal signup for an unrelated role without manufacturing free intent', async () => {
    await signupWithFreeEntry(database, 'member', { p_role: 'school_educator' });
    expect(rpc).toHaveBeenCalledExactlyOnceWith('signup_member', { p_role: 'school_educator' });
  });
  it('never attempts another signup path when the new owner operation fails', async () => {
    rpc.mockRejectedValueOnce(new Error('owner unavailable'));
    await expect(signupWithFreeEntry(database, 'member', { p_role: 'learner' })).rejects.toThrow('owner unavailable');
    expect(rpc).toHaveBeenCalledTimes(1);
  });
  it.each([
    { ...config, productCode: '' },
    { ...config, signupRoles: { learner: { audience: 'recruitment', organizationType: 'company' } } },
    { ...config, signupRoles: { owner: { audience: 'recruitment', organizationType: 'college' } } },
    { ...config, memberRoles: { learner: { audience: 'individual', organizationType: 'company' } } },
  ])('rejects invalid server routing configuration', value => expect(() => freeSignupPolicy(value)).toThrow());
  it('sends only the hashed token and validates the atomic receipt', async () => {
    rpc.mockResolvedValueOnce(receipt());
    expect(await verifyEmailWithFreeEntry(database, 'a'.repeat(64))).toEqual(receipt());
    expect(rpc).toHaveBeenCalledExactlyOnceWith('verify_email_with_subscription_entry', { p_token_hash: 'a'.repeat(64) });
  });
  it.each([{}, { ...receipt(), verified: false }, { ...receipt(), subscriptionIds: [id(2), id(2)] },
    { ...receipt(), subscriptionIds: ['invalid'] }, { ...receipt(), userId: 'invalid' }, { ...receipt(), extra: true }])(
    'rejects malformed owner acknowledgement', async value => {
      rpc.mockResolvedValueOnce(value);
      await expect(verifyEmailWithFreeEntry(database, 'a'.repeat(64))).rejects.toThrow();
    });
  it.each([404, 410])('preserves the owner verification rejection %i', async status => {
    rpc.mockResolvedValueOnce({ error: 'Synthetic verification rejection', status });
    expect(await verifyEmailWithFreeEntry(database, 'a'.repeat(64))).toEqual({ error: 'Synthetic verification rejection', status });
  });
  it('requires a hash and never sends a raw token to persistence', async () => {
    await expect(verifyEmailWithFreeEntry(database, 'raw-token')).rejects.toThrow();
    expect(rpc).not.toHaveBeenCalled();
  });
  it('publishes verified identity only after the atomic owner succeeds', async () => {
    rpc.mockResolvedValueOnce(receipt());
    expect(await performVerifyEmail({} as Env, context, { token: 'synthetic-token' })).toEqual({ verified: true });
    expect(sync).toHaveBeenCalledWith(undefined, context, 'user.email_verified', { user_id: id(1) });
    expect(audit).toHaveBeenCalledTimes(1);
  });
  it('surfaces activation failure without publishing verified success or retrying', async () => {
    rpc.mockRejectedValueOnce(new Error('activation rejected'));
    expect(await performVerifyEmail({} as Env, context, { token: 'synthetic-token' })).toMatchObject({ status: 503 });
    expect(sync).not.toHaveBeenCalled(); expect(audit).not.toHaveBeenCalled(); expect(rpc).toHaveBeenCalledTimes(1);
  });
});

describe('explicit free validity', () => {
  it('uses perpetual terms without a sentinel and derives all trial ends from the published duration', () => {
    expect(subscriptionEntryEnd({ schemaVersion: 1, validity: 'perpetual' }, 1000)).toBeNull();
    for (const durationDays of [1, 17, 30]) {
      expect(subscriptionEntryEnd({ schemaVersion: 1, validity: 'fixed_duration', durationDays }, 1000)).toBe(1000 + durationDays * 86400000);
    }
    expect(earlierSubscriptionEnd(null, null)).toBeNull();
    expect(earlierSubscriptionEnd(null, 20)).toBe(20); expect(earlierSubscriptionEnd(10, null)).toBe(10);
    expect(earlierSubscriptionEnd(10, 20)).toBe(10);
  });
  it.each([{}, { schemaVersion: 1, validity: 'perpetual', durationDays: 30 },
    { schemaVersion: 1, validity: 'fixed_duration' }, { schemaVersion: 1, validity: 'fixed_duration', durationDays: 0 },
    { schemaVersion: 1, validity: 'owner_contract_required' }])('rejects missing or conflicting terms', terms => {
    expect(() => subscriptionEntryEnd(terms, 1000)).toThrow();
  });
  const state = (): LifecycleState => ({ id: id(1), planId: id(2), revisionId: id(3), productId: id(4), subject: { kind: 'user', id: id(5) },
    version: 1, status: 'active', periodStartsAt: 100, periodEndsAt: null, validity: 'perpetual', trialEndsAt: null,
    renewalEnabled: false, cancelledAt: null, paymentFailedAt: null, scheduledChange: null, downgradedAt: null });
  const policy: LifecyclePolicy = { id: id(6), version: 1, productId: id(4), graceDurationMs: 15, graceAccess: 'read_only', expiredAccess: 'read_only',
    readOnlyDurationMs: 90, cancellationAccess: 'read_only', immediateDowngradeAllowed: false, paymentFailureRestrictedMs: 1,
    paymentFailureAfterAccess: 'suspended', paymentRetryOffsetsMs: [1], suspensionApprovalRequired: true, reactivationApprovalRequired: true };
  it('keeps perpetual access active after arbitrary elapsed time while respecting suspension', () => {
    expect(readSubscriptionLifecycleAccess(state(), policy, 9999999999).access).toBe('full');
    expect(readSubscriptionLifecycleAccess({ ...state(), status: 'paused' }, policy, 9999999999).access).toBe('suspended');
    expect(readSubscriptionLifecycleAccess({ ...state(), status: 'cancelled', cancelledAt: 200 }, policy, 300).access).toBe('read_only');
    expect(readSubscriptionLifecycleAccess({ ...state(), downgradedAt: 200 }, policy, 250).access).toBe('read_only');
    expect(readSubscriptionLifecycleAccess({ ...state(), downgradedAt: 200 }, policy, 290).access).toBe('suspended');
  });
  it.each([{ validity: undefined }, { periodEndsAt: 1000 }, { renewalEnabled: true }, { trialEndsAt: 500 },
    { status: 'expired' }, { status: 'grace_period' }, { paymentFailedAt: 200 }])('rejects inconsistent perpetual state', patch => {
    expect(() => readSubscriptionLifecycleAccess({ ...state(), ...patch }, policy, 1000)).toThrow();
  });
});
