import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SsoWorker } from '../index';
import { db } from '../lib/db';
import { readCreditAuthoringContext, validateCreditAllocationPolicy } from '../lib/subscriptions';
import type { Env } from '../types';

const id = 'a0000000-0000-4000-8000-000000000001', productId = 'b0000000-0000-4000-8000-000000000001';
const timeId = 'c0000000-0000-4000-8000-000000000001';
const env = { SUPABASE_URL: 'https://sso.example.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-key' } as Env;
const pool = () => ({ key: 'learner_ai', featureKey: 'ai_credits', recipient: 'managed_learner', audiences: ['college'] });
const calendar = () => ({ id: timeId, timeZone: 'Asia/Kolkata', monthlyAnchor: 'subscription_anniversary',
  monthDayOverflow: 'clamp', ambiguousTime: 'reject', nonexistentTime: 'reject' });
const settings = () => ({ schemaVersion: 1, pools: [pool()], timePolicies: [calendar()] });
const row = (credit: unknown = settings()) => ({ id, plan_code: `pln_${'a'.repeat(32)}`, product_id: productId, applicable_entities: ['college'],
  entity_config: { college: { max_users: 500 }, subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: 2 }] },
    subscription_credit_authoring: credit } });
let source: unknown, transport = vi.fn<typeof fetch>();
beforeEach(() => {
  source = [row()];
  transport = vi.fn<typeof fetch>().mockImplementation(async input => new Response(JSON.stringify(
    new URL(String(input)).pathname.endsWith('/products') ? [{ id: productId }] : source,
  )));
  vi.stubGlobal('fetch', transport);
});
afterEach(() => vi.unstubAllGlobals());
const read = () => readCreditAuthoringContext(db(env), id);

describe('trusted credit settings through actual worker and database HTTP adapter', () => {
  it('reads commercial and credit settings once from the same canonical plan snapshot', async () => {
    const result = await new SsoWorker({} as ExecutionContext, env).getSubscriptionCreditAuthoringContext(id.toUpperCase());
    expect(result.credit).toEqual(settings()); expect(result.plan.id).toBe(id);
    expect(result).not.toHaveProperty('configuration'); expect(result).not.toHaveProperty('entity_config');
    const urls = transport.mock.calls.map(args => new URL(String(args[0])));
    expect(urls.filter(url => url.pathname.endsWith('/plans'))).toHaveLength(1);
    expect(urls).toHaveLength(2); expect(urls[0].searchParams.get('id')).toBe(`eq.${id}`);
    expect(transport.mock.calls.every(args => args[1]?.method === undefined)).toBe(true);
    expect(Object.isFrozen(result.credit.pools[0].audiences)).toBe(true);
    expect(Object.isFrozen(result.credit.timePolicies[0])).toBe(true); expect(Object.isFrozen(result.credit)).toBe(true);
  });
  it('supplies pool/calendar references accepted by the existing policy validator without fabricating approvals', async () => {
    const context = await read();
    const draft = { schemaVersion: 2, id: crypto.randomUUID(), plan: context.plan, revisionNumber: 1, name: 'Configured plan',
      audiences: ['college'], purchaseMode: 'contact_sales', prices: [],
      features: [{ key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }] };
    const registry = { catalog: { productIds: new Set([productId]), audienceKeys: new Set(context.audiences),
      currencies: new Map(context.currencies.map(value => [value.code, value.minorUnit])), featureTypes: new Map([['ai_credits', 'metered' as const]]) },
      pools: new Map(context.credit.pools.map(value => [value.key, { ...value, audiences: new Set(value.audiences) }])),
      timePolicyIds: new Set(context.credit.timePolicies.map(value => value.id)),
      // Explicit test authority: this fixture grants no commercial exceptions.
      rolloverApprovalIds: new Set<string>(), expiryApprovalIds: new Set<string>() };
    const policy = { schemaVersion: 1, id: crypto.randomUUID(), revisionId: draft.id, funding: 'included', rules: [{ id: crypto.randomUUID(),
      featureKey: 'ai_credits', poolKey: 'learner_ai', recipient: 'managed_learner', audiences: ['college'], quantity: { kind: 'finite', value: 100 },
      cadence: { kind: 'monthly', timePolicyId: timeId }, expiry: { kind: 'allocation_period_end' }, rollover: { kind: 'none' } }] };
    expect(validateCreditAllocationPolicy(policy, draft, registry).rules[0].poolKey).toBe('learner_ai');
    expect(() => validateCreditAllocationPolicy({ ...policy, rules: [{ ...policy.rules[0], rollover: { kind: 'approved', approvalId: timeId } }] }, draft, registry))
      .toThrow('unregistered policy or approval reference');
    expect(context.credit).not.toHaveProperty('rolloverApprovalIds');
  });
  it('allows explicit empty registries without inventing a pool or calendar', async () => {
    source = [row({ schemaVersion: 1, pools: [], timePolicies: [] })];
    expect((await read()).credit).toEqual({ schemaVersion: 1, pools: [], timePolicies: [] });
  });
  it.each([
    { value: undefined, reason: 'settings' }, { value: {}, reason: 'schemaVersion' },
    { value: { ...settings(), schemaVersion: 2 }, reason: 'schemaVersion' },
    { value: { ...settings(), approvals: [timeId] }, reason: 'unsupported field' },
    { value: { schemaVersion: 1, timePolicies: [] }, reason: 'pools' },
    { value: { schemaVersion: 1, pools: [] }, reason: 'timePolicies' },
    { value: { ...settings(), pools: [pool(), pool()] }, reason: 'duplicate pool' },
    { value: { ...settings(), pools: [{ ...pool(), recipient: 'user' }] }, reason: 'recipient' },
    { value: { ...settings(), pools: [{ ...pool(), featureKey: ' ' }] }, reason: 'featureKey' },
    { value: { ...settings(), pools: [{ ...pool(), audiences: ['school'] }] }, reason: 'canonical plan audiences' },
    { value: { ...settings(), pools: [{ ...pool(), audiences: [] }] }, reason: 'canonical plan audiences' },
    { value: { ...settings(), pools: [{ ...pool(), audiences: ['college', 'college'] }] }, reason: 'canonical plan audiences' },
    { value: { ...settings(), pools: [{ ...pool(), max_users: 100 }] }, reason: 'unsupported field' },
    { value: { ...settings(), timePolicies: [calendar(), { ...calendar(), id: timeId.toUpperCase() }] }, reason: 'duplicate time policy' },
    { value: { ...settings(), timePolicies: [{ ...calendar(), id: 'bad' }] }, reason: 'UUID' },
    { value: { ...settings(), timePolicies: [{ ...calendar(), timeZone: 'Invalid/Zone' }] }, reason: 'timeZone' },
    { value: { ...settings(), timePolicies: [{ ...calendar(), timeZone: '+05:30' }] }, reason: 'named time zone' },
    { value: { ...settings(), timePolicies: [{ ...calendar(), monthDayOverflow: undefined }] }, reason: 'monthDayOverflow' },
    { value: { ...settings(), timePolicies: [{ ...calendar(), ambiguousTime: undefined }] }, reason: 'ambiguousTime' },
    { value: { ...settings(), timePolicies: [{ ...calendar(), nonexistentTime: undefined }] }, reason: 'nonexistentTime' },
    { value: { ...settings(), timePolicies: [{ ...calendar(), monthlyAnchor: 'default' }] }, reason: 'monthlyAnchor' },
  ])('rejects malformed explicit configuration for its intended reason %j', async ({ value, reason }) => {
    const record = row(value); if (value === undefined) delete (record.entity_config as Record<string, unknown>).subscription_credit_authoring;
    source = [record]; await expect(read()).rejects.toThrow(reason);
  });
  it.each([200, 204])('rejects empty owner HTTP response %i', async status => {
    transport.mockResolvedValue(new Response(null, { status })); await expect(read()).rejects.toThrow('JSON array');
    expect(transport).toHaveBeenCalledTimes(1);
  });
  it('does not return partial configuration or retry after owner failure', async () => {
    transport.mockRejectedValueOnce(new TypeError('Synthetic owner failure'));
    await expect(read()).rejects.toThrow('Synthetic owner failure'); expect(transport).toHaveBeenCalledTimes(1);
  });
});
