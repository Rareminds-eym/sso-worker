import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { SignJWT, exportSPKI, generateKeyPair } from 'jose';
import { SsoWorker } from '../index';
import type { Env } from '../types';

const actor = 'd0000000-0000-4000-8000-000000000001', id = 'a0000000-0000-4000-8000-000000000001';
const productId = 'b0000000-0000-4000-8000-000000000001', revision = 'c0000000-0000-4000-8000-000000000001';
const platform = '00000000-0000-0000-0000-000000000001';
let keys: Awaited<ReturnType<typeof generateKeyPair>>, env: Env, live: unknown, users: unknown, plans: unknown;
let transport = vi.fn<typeof fetch>();
const plan = () => ({ id, plan_code: `pln_${'a'.repeat(32)}`, product_id: productId, applicable_entities: ['college'],
  entity_config: { subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: 2 }] },
    subscription_credit_authoring: { schemaVersion: 1, pools: [{ key: 'learner', featureKey: 'ai', recipient: 'managed_learner', audiences: ['college'] }], timePolicies: [] } } });
const bundle = () => ({ schemaVersion: 1, draft: { schemaVersion: 2, id: revision, revisionNumber: 1,
  plan: { id, code: plan().plan_code, productId }, name: 'Draft', audiences: ['college'], purchaseMode: 'contact_sales', prices: [],
  features: [{ key: 'ai', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }] },
  includedCredits: { schemaVersion: 1, id: actor, revisionId: revision, funding: 'included', rules: [{ id: productId,
    featureKey: 'ai', poolKey: 'learner', recipient: 'managed_learner', audiences: ['college'], quantity: { kind: 'finite', value: 100 },
    cadence: { kind: 'activation' }, expiry: { kind: 'subscription_end' }, rollover: { kind: 'none' } }] } });
const features = [{ key: 'ai', type: 'metered' }];
beforeAll(async () => {
  keys = await generateKeyPair('RS256');
  env = { SUPABASE_URL: 'https://sso.example.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-key', JWT_PUBLIC_KEY: await exportSPKI(keys.publicKey) } as Env;
});
beforeEach(() => {
  live = { roles: ['super_admin'], membership_status: 'active' }; users = [{ id: actor, is_blocked: false }]; plans = [plan()];
  transport = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
    const path = new URL(String(input)).pathname;
    if (path.endsWith('/stage_subscription_plan_draft')) {
      const data = JSON.parse(String(init?.body));
      return Response.json({ draft: data.p_draft, includedCredits: data.p_included_credits, stagedBy: data.p_staged_by, stagedAt: '2026-11-18T12:00:00.000000+00:00' });
    }
    return Response.json(path.endsWith('/users') ? users : path.endsWith('/get_jwt_claims') ? live : path.endsWith('/products') ? [{ id: productId }] : plans);
  });
  vi.stubGlobal('fetch', transport);
});
afterEach(() => vi.unstubAllGlobals());
async function credential(patch: Record<string, unknown> = {}, options: { issuer?: string; audience?: string } = {}) {
  return new SignJWT({ sub: actor, org_id: platform, roles: ['super_admin'], membership_status: 'active', exp: Math.floor(Date.now() / 1000) + 300, ...patch })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' }).setIssuer(options.issuer ?? 'sso-api').setAudience(options.audience ?? 'sso-client').sign(keys.privateKey);
}
async function stage(value: unknown = bundle(), types: unknown = features, product = productId, token?: string) {
  return new SsoWorker({} as ExecutionContext, env).stageSubscriptionPlanRevisionBundle(token ?? await credential(), value, product, types);
}
const writes = () => transport.mock.calls.filter(call => new URL(String(call[0])).pathname.endsWith('/stage_subscription_plan_draft'));

describe('actual private authorized staging with real JWT verification and database HTTP adapter', () => {
  it('preserves app-owned enum options and selected terms through the authenticated RPC', async () => {
    const value = bundle();
    const selected = { key: 'synthetic_choice', type: 'enum', enabled: true, value: 'option_b' };
    const input = { ...value, draft: { ...value.draft, features: [...value.draft.features, selected] } };
    const definitions = [...features, { key: selected.key, type: 'enum', options: ['option_a', 'option_b'] }];
    expect(await stage(input, definitions)).toMatchObject({ kind: 'staged', receipt: { bundle: input } });
    expect(writes()).toHaveLength(1);
    expect(await stage(input, [...features, { key: selected.key, type: 'enum', options: ['option_a'] }])).toEqual({ kind: 'invalid' });
    expect(await stage(input, [...features, { key: selected.key, type: 'enum', options: ['option_b', 'option_b'] }])).toEqual({ kind: 'invalid' });
    expect(writes()).toHaveLength(1);
  });
  it('derives actor from signed credentials, checks live canonical scope and stages one complete bundle', async () => {
    const result = await stage();
    expect(result).toEqual({ kind: 'staged', receipt: { bundle: bundle(), stagedBy: actor, stagedAt: '2026-11-18T12:00:00.000000+00:00' } });
    expect(writes()).toHaveLength(1);
    const paths = transport.mock.calls.map(call => new URL(String(call[0])).pathname.split('/').at(-1));
    expect(paths).toEqual(['users', 'get_jwt_claims', 'plans', 'products', 'stage_subscription_plan_draft']);
    expect(JSON.parse(String(writes()[0][1]?.body))).toEqual({ p_draft: bundle().draft, p_staged_by: actor, p_included_credits: bundle().includedCredits });
  });
  it.each(['', 'malformed.jwt', 'eyJhbGciOiJub25lIn0.e30.'])('rejects invalid credentials without owner IO %s', async token => {
    expect(await stage(bundle(), features, productId, token)).toEqual({ kind: 'forbidden' }); expect(transport).not.toHaveBeenCalled();
  });
  it.each([
    { exp: Math.floor(Date.now() / 1000) - 10 }, { exp: undefined }, { roles: ['admin'] },
    { org_id: productId }, { membership_status: 'suspended' }, { sub: 'invalid' }, { roles: 'super_admin' },
  ])('rejects signed credentials with insufficient claims before owner IO %j', async patch => {
    expect(await stage(bundle(), features, productId, await credential(patch))).toEqual({ kind: 'forbidden' });
    expect(transport).not.toHaveBeenCalled();
  });
  it.each([{ issuer: 'other' }, { audience: 'other' }])('enforces cryptographic issuer/audience %j', async options => {
    expect(await stage(bundle(), features, productId, await credential({}, options))).toEqual({ kind: 'forbidden' });
    expect(transport).not.toHaveBeenCalled();
  });
  it('rejects a well-formed token signed by another key before owner IO', async () => {
    const other = await generateKeyPair('RS256');
    const token = await new SignJWT({ sub: actor, org_id: platform, roles: ['super_admin'], membership_status: 'active' })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' }).setIssuer('sso-api').setAudience('sso-client').setExpirationTime('5m').sign(other.privateKey);
    expect(await stage(bundle(), features, productId, token)).toEqual({ kind: 'forbidden' }); expect(transport).not.toHaveBeenCalled();
  });
  it.each([{ roles: [], membership_status: 'active' }, { roles: ['super_admin'], membership_status: 'suspended' }, null])(
    'denies revoked or missing live authority %j', async value => { live = value; expect(await stage()).toEqual({ kind: 'forbidden' }); expect(writes()).toHaveLength(0); });
  it.each([{ id: actor, is_blocked: true }, { id, is_blocked: false }])('denies blocked/mismatched live actor %j', async user => {
    users = [user]; expect(await stage()).toEqual({ kind: 'forbidden' }); expect(writes()).toHaveLength(0);
  });
  it('rejects client actor/registry fields and does not accept otherwise valid exception UUIDs', async () => {
    expect(await stage({ ...bundle(), actorId: id })).toEqual({ kind: 'invalid' });
    expect(await stage({ ...bundle(), registry: {} })).toEqual({ kind: 'invalid' });
    const value = bundle();
    expect(await stage({ ...value, includedCredits: { ...value.includedCredits,
      rules: [{ ...value.includedCredits.rules[0], rollover: { kind: 'approved', approvalId: actor } }] } })).toEqual({ kind: 'invalid' });
    expect(writes()).toHaveLength(0);
  });
  it.each([
    { types: [{ key: 'ai', type: 'boolean' }], product: productId },
    { types: [...features, ...features], product: productId },
    { types: [{ key: 'ai', type: 'metered', approved: true }], product: productId },
    { types: features, product: id },
  ])('rejects disconnected owner feature/product configuration before write %j', async value => {
    expect(await stage(bundle(), value.types, value.product)).toEqual({ kind: 'invalid' }); expect(writes()).toHaveLength(0);
  });
  it('rejects changed canonical code rather than accepting a stale proposal', async () => {
    plans = [{ ...plan(), plan_code: `pln_${'b'.repeat(32)}` }];
    expect(await stage()).toEqual({ kind: 'invalid' }); expect(writes()).toHaveLength(0);
  });
  it('surfaces uncertain storage failure without retrying or writing through another adapter', async () => {
    const original = transport.getMockImplementation()!;
    transport.mockImplementation(async (input, init) => {
      if (new URL(String(input)).pathname.endsWith('/stage_subscription_plan_draft')) throw new TypeError('Synthetic uncertain write');
      return original(input, init);
    });
    await expect(stage()).rejects.toThrow('Synthetic uncertain write'); expect(writes()).toHaveLength(1);
  });
  it('does not acknowledge a stored receipt attributed to a different actor', async () => {
    const original = transport.getMockImplementation()!;
    transport.mockImplementation(async (input, init) => {
      const response = await original(input, init);
      if (!new URL(String(input)).pathname.endsWith('/stage_subscription_plan_draft')) return response;
      const stored: unknown = await response.json();
      if (!stored || typeof stored !== 'object' || Array.isArray(stored)) throw new Error('Invalid fixture receipt');
      return Response.json({ ...stored, stagedBy: id });
    });
    await expect(stage()).rejects.toThrow('does not match'); expect(writes()).toHaveLength(1);
  });
});
