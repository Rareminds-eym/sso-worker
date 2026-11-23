import { beforeEach, describe, expect, it, vi } from 'vitest';
import { errors } from 'jose';
const io = vi.hoisted(() => ({ verify: vi.fn(), query: vi.fn(), rpc: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ query: io.query, rpc: io.rpc }) }));
vi.mock('../lib/jwt', () => ({ verifyAccessToken: io.verify }));
import { registerSubscriptionCommerceEntryContract } from '../lib/subscriptions/authoring';
import { PLATFORM_ORG_ID } from '../lib/constants';
import type { Env } from '../types';

const ids = {
  actor: 'a0000000-0000-4000-8000-000000000001',
  product: 'b0000000-0000-4000-8000-000000000001',
  recipient: 'c0000000-0000-4000-8000-000000000001',
  revision: 'd0000000-0000-4000-8000-000000000001',
  contract: 'e0000000-0000-4000-8000-000000000001',
};
const env = {} as Env;
const contract = (kind: 'user' | 'organization' = 'user') => ({
  schemaVersion: 1, id: ids.contract, productId: ids.product, revisionId: ids.revision,
  subject: { kind, id: ids.recipient }, audience: 'synthetic_audience', startsAt: 1000, endsAt: 2000,
  includedLearnerCapacity: kind === 'organization' ? 12 : null, sourceSubscriptionId: null,
  sourceEvidence: { reference: 'synthetic-owner-contract' },
});
let claims: Record<string, unknown>, live: Record<string, unknown>, recipient: Record<string, unknown>;
beforeEach(() => {
  vi.resetAllMocks();
  claims = { sub: ids.actor, org_id: PLATFORM_ORG_ID, exp: Date.now() / 1000 + 60,
    membership_status: 'active', roles: ['super_admin'] };
  live = { membership_status: 'active', roles: ['super_admin'] };
  recipient = { id: ids.recipient, is_blocked: false, is_email_verified: true, deleted_at: null };
  io.verify.mockImplementation(async () => claims);
  io.query.mockImplementation(async (path: string) => {
    if (path.startsWith('users?') && path.includes(ids.actor)) return [{ id: ids.actor, is_blocked: false }];
    if (path.startsWith('products?')) return [{ id: ids.product }];
    if (path.startsWith('users?') || path.startsWith('organizations?')) return [recipient];
    throw new Error('Unexpected owner query');
  });
  io.rpc.mockImplementation(async (name: string) => {
    if (name === 'get_jwt_claims') return live;
    if (name === 'record_subscription_commerce_entry_contract') return ids.contract;
    throw new Error('Unexpected owner RPC');
  });
});
const writes = () => io.rpc.mock.calls.filter(([name]) => name === 'record_subscription_commerce_entry_contract');

describe('signed commerce entry contract administration', () => {
  it.each(['user', 'organization'] as const)('records an exact %s contract using the signed administrator actor', async kind => {
    const input = contract(kind);
    expect(await registerSubscriptionCommerceEntryContract(env, 'signed', ids.product, input)).toEqual({
      kind: 'recorded', contractId: ids.contract, productId: ids.product, revisionId: ids.revision, subject: input.subject,
    });
    expect(writes()).toEqual([['record_subscription_commerce_entry_contract', { p_contract: input, p_actor_id: ids.actor }]]);
  });
  it.each(['anonymous', 'expired', 'wrong_org', 'jwt_role', 'live_role', 'inactive', 'invalid_signature'])('denies %s without writing a contract', async defect => {
    if (defect === 'expired') claims.exp = 0;
    if (defect === 'wrong_org') claims.org_id = ids.recipient;
    if (defect === 'jwt_role') claims.roles = ['learner'];
    if (defect === 'live_role') live.roles = ['learner'];
    if (defect === 'inactive') live.membership_status = 'inactive';
    if (defect === 'invalid_signature') io.verify.mockRejectedValue(new errors.JWTInvalid());
    expect(await registerSubscriptionCommerceEntryContract(env, defect === 'anonymous' ? '' : 'signed', ids.product, contract()))
      .toEqual({ kind: 'forbidden' });
    expect(writes()).toHaveLength(0);
  });
  it.each(['product', 'actor_field', 'blocked_recipient', 'unverified_recipient', 'deleted_org', 'missing_target', 'duplicate_target'])('rejects %s without accepting client authority', async defect => {
    const input: Record<string, unknown> = contract(defect === 'deleted_org' ? 'organization' : 'user');
    if (defect === 'product') input.productId = ids.recipient;
    if (defect === 'actor_field') input.actorId = ids.recipient;
    if (defect === 'blocked_recipient') recipient.is_blocked = true;
    if (defect === 'unverified_recipient') recipient.is_email_verified = false;
    if (defect === 'deleted_org') recipient.deleted_at = '2026-01-01T00:00:00Z';
    if (defect === 'missing_target' || defect === 'duplicate_target') {
      const original = io.query.getMockImplementation()!;
      io.query.mockImplementation(async (path: string) => path.includes(ids.recipient)
        ? defect === 'missing_target' ? [] : [recipient, recipient] : original(path));
    }
    expect(await registerSubscriptionCommerceEntryContract(env, 'signed', ids.product, input)).toEqual({ kind: 'invalid' });
    expect(writes()).toHaveLength(0);
  });
  it('propagates unavailable canonical identity and persistence failures', async () => {
    io.verify.mockRejectedValueOnce(new Error('Identity owner unavailable'));
    await expect(registerSubscriptionCommerceEntryContract(env, 'signed', ids.product, contract())).rejects.toThrow('Identity owner unavailable');
    io.rpc.mockRejectedValueOnce(new Error('Live claims unavailable'));
    await expect(registerSubscriptionCommerceEntryContract(env, 'signed', ids.product, contract())).rejects.toThrow('Live claims unavailable');
    expect(writes()).toHaveLength(0);
  });
  it('rejects an altered persistence acknowledgement', async () => {
    io.rpc.mockImplementation(async (name: string) => name === 'get_jwt_claims' ? live : ids.recipient);
    await expect(registerSubscriptionCommerceEntryContract(env, 'signed', ids.product, contract())).rejects.toThrow('Entry contract acknowledgement differs');
  });
  it('propagates a failed contract write without acknowledging registration', async () => {
    io.rpc.mockImplementation(async (name: string) => {
      if (name === 'get_jwt_claims') return live;
      throw new Error('Contract persistence unavailable');
    });
    await expect(registerSubscriptionCommerceEntryContract(env, 'signed', ids.product, contract()))
      .rejects.toThrow('Contract persistence unavailable');
    expect(writes()).toHaveLength(1);
  });
  it('rejects an unavailable canonical product before recording terms', async () => {
    const original = io.query.getMockImplementation()!;
    io.query.mockImplementation(async (path: string) => path.startsWith('products?') ? [] : original(path));
    expect(await registerSubscriptionCommerceEntryContract(env, 'signed', ids.product, contract())).toEqual({ kind: 'invalid' });
    expect(writes()).toHaveLength(0);
  });
});
