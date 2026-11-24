import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SsoWorker } from '../index';
import { readPlanAuthoringContext, validatePlanRevision } from '../lib/subscriptions';
import { db } from '../lib/db';
import type { Env } from '../types';

const id = 'a0000000-0000-4000-8000-000000000001';
const productId = 'b0000000-0000-4000-8000-000000000001';
const env = { SUPABASE_URL: 'https://sso.example.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-key' } as Env;
const row = () => ({ id, plan_code: `pln_${'a'.repeat(32)}`, product_id: productId, applicable_entities: ['college'],
  entity_config: { college: { max_users: 500 }, subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: 2 }] } } });
let plan: unknown, products: unknown, transport = vi.fn<typeof fetch>();
beforeEach(() => {
  plan = [row()]; products = [{ id: productId }];
  transport = vi.fn<typeof fetch>().mockImplementation(async input => new Response(JSON.stringify(
    new URL(String(input)).pathname.endsWith('/products') ? products : plan,
  )));
  vi.stubGlobal('fetch', transport);
});
afterEach(() => vi.unstubAllGlobals());
const read = () => readPlanAuthoringContext(db(env), id);

describe('trusted plan authoring context through actual HTTP database client', () => {
  it('reaches the real private worker method and reads exact canonical plan/product references', async () => {
    const result = await new SsoWorker({} as ExecutionContext, env).getSubscriptionPlanAuthoringContext(id.toUpperCase());
    expect(result).toEqual({ schemaVersion: 1, plan: { id, code: row().plan_code, productId }, audiences: ['college'], currencies: [{ code: 'INR', minorUnit: 2 }] });
    expect(transport).toHaveBeenCalledTimes(2);
    const urls = transport.mock.calls.map(args => new URL(String(args[0])));
    expect(urls.map(url => url.origin)).toEqual([env.SUPABASE_URL, env.SUPABASE_URL]);
    expect(urls[0].searchParams.get('id')).toBe(`eq.${id}`);
    expect(urls[0].searchParams.get('limit')).toBe('2');
    expect(urls[1].searchParams.get('id')).toBe(`eq.${productId}`);
    expect(transport.mock.calls.every(args => args[1]?.method === undefined)).toBe(true);
  });

  it('supports configured currencies and audiences without hardcoded plan-name or currency branches', async () => {
    const source = row(); source.applicable_entities = ['school', 'college'];
    source.entity_config.subscription_authoring.currencies = [{ code: 'JPY', minorUnit: 0 }, { code: 'KWD', minorUnit: 3 }];
    plan = [source];
    const result = await read();
    const draft = validatePlanRevision({ schemaVersion: 2, id: crypto.randomUUID(), plan: result.plan, revisionNumber: 1,
      name: 'Editable presentation', audiences: result.audiences, purchaseMode: 'self_service',
      prices: [{ id: crypto.randomUUID(), currency: 'JPY', minorUnit: 0, amountMinor: 2500, intervalUnit: 'year', intervalCount: 1,
        quantityBasis: 'subscription', audiences: result.audiences }], features: [] },
    { productIds: new Set([result.plan.productId]), audienceKeys: new Set(result.audiences),
      currencies: new Map(result.currencies.map(item => [item.code, item.minorUnit])), featureTypes: new Map() });
    expect(draft.prices[0].currency).toBe('JPY');
    expect(result.currencies).toHaveLength(2);
  });

  it('returns detached frozen context without raw entity configuration', async () => {
    const result = await read();
    expect(Object.isFrozen(result)).toBe(true); expect(Object.isFrozen(result.plan)).toBe(true);
    expect(Object.isFrozen(result.currencies[0])).toBe(true); expect(Object.isFrozen(result.currencies)).toBe(true);
    expect(Object.isFrozen(result.audiences)).toBe(true); expect(result).not.toHaveProperty('entity_config');
  });

  it('rejects invalid references before HTTP IO', async () => {
    await expect(readPlanAuthoringContext(db(env), 'invalid')).rejects.toThrow('authoring.planId');
    expect(transport).not.toHaveBeenCalled();
  });

  it.each([
    { value: [], reason: 'exactly once' }, { value: [row(), row()], reason: 'exactly once' },
    { value: null, reason: 'JSON array' }, { value: [{ ...row(), id: productId }], reason: 'requested plan' },
    { value: [{ ...row(), product_id: null }], reason: 'plan.productId' },
    { value: [{ ...row(), plan_code: 'hybrid' }], reason: 'opaque plan code' },
    { value: [{ ...row(), applicable_entities: [] }], reason: 'explicit audiences' },
    { value: [{ ...row(), applicable_entities: ['college', 'college'] }], reason: 'explicit audiences' },
    { value: [{ ...row(), entity_config: '{}' }], reason: 'explicit plan configuration' },
    { value: [{ ...row(), entity_config: { college: { max_users: 500 } } }], reason: 'authoring.settings' },
    { value: [{ ...row(), entity_config: { subscription_authoring: { schemaVersion: 2, currencies: [] } } }], reason: 'schemaVersion' },
    { value: [{ ...row(), entity_config: { subscription_authoring: { schemaVersion: 1, currencies: [] } } }], reason: 'explicitly configured currencies' },
    { value: [{ ...row(), entity_config: { subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: 2 }, { code: 'INR', minorUnit: 0 }] } } }], reason: 'unique explicitly' },
    { value: [{ ...row(), entity_config: { subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'inr', minorUnit: 2 }] } } }], reason: 'uppercase currency' },
    { value: [{ ...row(), entity_config: { subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: -1 }] } } }], reason: 'safe integer' },
    { value: [{ ...row(), entity_config: { subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: 2 }], approved: true } } }], reason: 'unsupported field' },
  ])('rejects missing or inconsistent plan/settings evidence for its intended reason %j', async ({ value, reason }) => {
    plan = value;
    await expect(read()).rejects.toThrow(reason);
  });

  it.each([{ value: [], reason: 'exactly once' }, { value: [{ id: productId }, { id: productId }], reason: 'exactly once' },
    { value: [{ id }], reason: 'identity differs' }])('requires a real matching canonical product %j', async ({ value, reason }) => {
    products = value; await expect(read()).rejects.toThrow(reason);
  });

  it.each([200, 204])('rejects a missing HTTP body at status %i without substitution', async status => {
    transport.mockResolvedValue(new Response(null, { status }));
    await expect(read()).rejects.toThrow('JSON array'); expect(transport).toHaveBeenCalledTimes(1);
  });

  it('surfaces a failed product lookup without a partial context or retry', async () => {
    transport.mockResolvedValueOnce(new Response(JSON.stringify([row()])))
      .mockRejectedValueOnce(new TypeError('Synthetic owner failure'));
    await expect(read()).rejects.toThrow('Synthetic owner failure'); expect(transport).toHaveBeenCalledTimes(2);
  });
});
