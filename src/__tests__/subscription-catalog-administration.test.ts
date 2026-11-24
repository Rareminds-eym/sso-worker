import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { SignJWT, exportSPKI, generateKeyPair } from 'jose';
import saved from '../../../audit-evidence/local-subscription-db-audit/catalog-rollout.json';
import runtimeContracts from '../../config/subscriptions/runtime-contracts.json';
import { SsoWorker } from '../index';
import type { Env } from '../types';
import { executionContext } from './execution-context';

const actor = 'd0000000-0000-4000-8000-000000000001', platform = '00000000-0000-0000-0000-000000000001';
const product = saved.productId, hybrid = saved.transition.hybridPlanId;
const roles = ['admin', 'college_admin', 'college_educator', 'company_admin', 'educator', 'hr', 'learner', 'member', 'owner',
  'recruiter', 'rm_admin', 'rm_manager', 'school_admin', 'school_educator', 'super_admin', 'university_admin'];
type Profile = { reference: string; bundle: { draft: { plan: { id: string }; features: { key: string; type: string }[] } } };
const profiles = saved.profiles as unknown as Profile[];
// The application owner supplies registered features; ids are synthetic application identities.
const features = [...new Map(profiles.flatMap(profile => profile.bundle.draft.features).map(feature => [feature.key, feature.type])).entries()]
  .map(([key, type], index) => ({ id: `e0000000-0000-4000-8000-${String(index).padStart(12, '0')}`, key, type,
    ...(type === 'enum' ? { options: [...new Set(runtimeContracts.features.find(item => item.key === key)!.terms.map(term => term.value))] } : {}) }));
let keys: Awaited<ReturnType<typeof generateKeyPair>>, env: Env, live: unknown, subscriptionPages: Record<string, unknown>[][];
let transport = vi.fn<typeof fetch>();
const hybridRow = { id: hybrid, plan_code: 'hybrid', product_id: product, is_active: true };
beforeAll(async () => {
  keys = await generateKeyPair('RS256');
  env = { SUPABASE_URL: 'https://sso.example.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-key', JWT_PUBLIC_KEY: await exportSPKI(keys.publicKey),
    SYNC_QUEUE: { send: vi.fn().mockResolvedValue(undefined), sendBatch: vi.fn().mockResolvedValue(undefined) } } as unknown as Env;
});
beforeEach(() => {
  live = { roles: ['super_admin'], membership_status: 'active' }; subscriptionPages = [[]];
  transport = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
    const url = new URL(String(input)), path = url.pathname;
    if (path.endsWith('/install_subscription_catalog_candidates')) {
      const { p_command: command } = JSON.parse(String(init?.body));
      return Response.json({ operationId: command.operationId, actorId: command.actorId, command, planIds: command.entries.map((entry: { plan: { id: string } }) => entry.plan.id) });
    }
    if (path.endsWith('/commit_subscription_catalog_transition')) {
      const { p_command: command } = JSON.parse(String(init?.body));
      return Response.json({ operationId: command.operationId, command, retiredPlanIds: command.replacements.map((row: { legacyPlanId: string }) => row.legacyPlanId),
        preservedSubscriptionIds: command.retainedSubscriptions.map((row: { id: string }) => row.id) });
    }
    if (path.endsWith('/get_jwt_claims')) return Response.json(live);
    if (path.endsWith('/users')) return Response.json([{ id: actor, is_blocked: false }]);
    if (path.endsWith('/roles')) return Response.json(roles.map(name => ({ name })));
    if (path.endsWith('/subscription_plan_publications')) return Response.json(url.searchParams.get('select') === 'plan_id' ? [] : publications);
    if (path.endsWith('/subscriptions')) {
      if (url.searchParams.get('select') === 'plan_id') return Response.json([]);
      const after = url.searchParams.get('id');
      return Response.json(subscriptionPages[after === null ? 0 : subscriptionPages.findIndex(page => page.length && `gt.${page[0].id}` > after) ] ?? []);
    }
    if (path.endsWith('/plans')) return Response.json(url.searchParams.get('select') === '*' ? [hybridRow] : transitionPlans);
    throw new Error(`Unexpected owner path ${path}`);
  });
  vi.stubGlobal('fetch', transport);
});
afterEach(() => vi.unstubAllGlobals());
let publications: unknown[] = [], transitionPlans: unknown[] = [];
async function credential(patch: Record<string, unknown> = {}) {
  return new SignJWT({ sub: actor, org_id: platform, roles: ['super_admin'], membership_status: 'active', exp: Math.floor(Date.now() / 1000) + 300, ...patch })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' }).setIssuer('sso-api').setAudience('sso-client').sign(keys.privateKey);
}
const worker = () => new SsoWorker(executionContext(), env);
const installRequest = (overrides: Record<string, unknown> = {}) => ({ schemaVersion: 1, operationId: 'f0000000-0000-4000-8000-000000000001',
  hybridPlanId: hybrid, approvalReference: 'Local B2b approved by owner', profiles: saved.profiles, ...overrides });
const calls = (suffix: string) => transport.mock.calls.filter(call => new URL(String(call[0])).pathname.endsWith(suffix));

describe('signed catalog installation', () => {
  it('installs all 21 BRD profiles as inactive candidates with resolved owner configuration', async () => {
    const result = await worker().installSubscriptionCatalog(await credential(), product, installRequest(), features);
    expect(result.kind).toBe('installed');
    const [call] = calls('/install_subscription_catalog_candidates');
    const command = JSON.parse(String(call[1]?.body)).p_command;
    expect(command.entries).toHaveLength(21);
    expect(command.actorId).toBe(actor);
    for (const entry of command.entries) {
      expect(entry.plan.is_active).toBe(false);
      expect(entry.plan.id).not.toBe(hybrid);
      expect(entry.plan.entity_config.subscription_commerce.quoteValidityMs).toBe(1800000);
      expect(entry.expected).toBeNull();
    }
    expect(command.entries.map((entry: { plan: { business_type: string; applicable_entities: string[] } }) => entry.plan.business_type === 'b2c')
      .filter(Boolean)).toHaveLength(4);
  });
  it('denies non-administrators before any owner write', async () => {
    live = { roles: ['owner'], membership_status: 'active' };
    expect(await worker().installSubscriptionCatalog(await credential(), product, installRequest(), features)).toEqual({ kind: 'forbidden' });
    expect(await worker().installSubscriptionCatalog(await credential({ roles: ['owner'] }), product, installRequest(), features)).toEqual({ kind: 'forbidden' });
    expect(calls('/install_subscription_catalog_candidates')).toHaveLength(0);
  });
  it('rejects incomplete, tampered or unregistered inputs without writing', async () => {
    const token = await credential();
    expect(await worker().installSubscriptionCatalog(token, product, installRequest({ profiles: saved.profiles.slice(1) }), features)).toEqual({ kind: 'invalid' });
    const inflated = JSON.parse(JSON.stringify(saved.profiles));
    inflated[1].bundle.draft.features.find((feature: { type: string }) => feature.type === 'numeric_limit').limit = { kind: 'finite', value: 999999 };
    expect(await worker().installSubscriptionCatalog(token, product, installRequest({ profiles: inflated }), features)).toEqual({ kind: 'invalid' });
    expect(await worker().installSubscriptionCatalog(token, product, installRequest(), features.slice(1))).toEqual({ kind: 'invalid' });
    expect(calls('/install_subscription_catalog_candidates')).toHaveLength(0);
  });
});

describe('signed legacy retirement', () => {
  const legacy = 'a1000000-0000-4000-8000-000000000001', target = profiles[1].bundle.draft.plan.id, revision = 'a2000000-0000-4000-8000-000000000001';
  const subscription = (id: string) => ({ id, plan_id: legacy, plan_code: 'basic', plan_type: 'Skill Starter', plan_amount: 499, billing_cycle: 'yearly',
    features: [], subscription_start_date: '2026-01-01T00:00:00+00:00', subscription_end_date: '2027-01-01T00:00:00+00:00', plan_revision_id: null,
    lifecycle_state: null, lifecycle_policy: null, metadata: {} });
  beforeEach(() => {
    transitionPlans = [hybridRow, { id: legacy, plan_code: 'basic', is_active: true }, { id: target, plan_code: 'pln_target', is_active: true }];
    publications = [{ plan_id: target, revision_id: revision }];
  });
  const request = () => ({ schemaVersion: 1, operationId: 'f0000000-0000-4000-8000-000000000002', hybridPlanId: hybrid,
    approvalReference: 'Local B2c approved by owner', replacements: [{ legacyPlanId: legacy, planId: target, revisionId: revision }] });
  it('retires only mapped legacy plans and carries every paged purchase unchanged for owner comparison', async () => {
    subscriptionPages = [Array.from({ length: 1000 }, (_, index) => subscription(`b1000000-0000-4000-8000-${String(index).padStart(12, '0')}`)),
      [subscription('b2000000-0000-4000-8000-000000000001')]];
    const result = await worker().retireLegacySubscriptionCatalog(await credential(), product, request());
    expect(result.kind).toBe('retired');
    const command = JSON.parse(String(calls('/commit_subscription_catalog_transition')[0][1]?.body)).p_command;
    expect(command.retainedSubscriptions).toHaveLength(1001);
    expect(command.replacements).toEqual(request().replacements);
    expect(command.retainedSubscriptions[0].purchasedTerms).toMatchObject({ planCode: 'basic', amount: 499, endsAt: '2027-01-01T00:00:00+00:00' });
  });
  it('refuses unpublished targets, Hybrid rewrites and non-administrators without writing', async () => {
    const token = await credential();
    publications = [];
    expect(await worker().retireLegacySubscriptionCatalog(token, product, request())).toEqual({ kind: 'invalid' });
    publications = [{ plan_id: target, revision_id: revision }];
    expect(await worker().retireLegacySubscriptionCatalog(token, product, { ...request(), replacements: [{ legacyPlanId: hybrid, planId: target, revisionId: revision }] })).toEqual({ kind: 'invalid' });
    live = { roles: ['owner'], membership_status: 'active' };
    expect(await worker().retireLegacySubscriptionCatalog(token, product, request())).toEqual({ kind: 'forbidden' });
    expect(calls('/commit_subscription_catalog_transition')).toHaveLength(0);
  });
});

describe('signed Hybrid catalog adoption', () => {
  const legacyConfig = { all: { display_name: 'Hybrid', purchase_mode: 'contact_sales' } };
  const identities = { targetCode: `pln_${'c'.repeat(32)}`, revisionId: 'c0000000-0000-4000-8000-000000000001',
    includedCreditsId: 'c0000000-0000-4000-8000-000000000002', ruleId: 'c0000000-0000-4000-8000-000000000003' };
  const request = (overrides: Record<string, unknown> = {}) => ({ schemaVersion: 1, operationId: 'f0000000-0000-4000-8000-000000000003',
    identityOperationId: 'f0000000-0000-4000-8000-000000000004', hybridPlanId: hybrid, approvalReference: 'Local Hybrid adoption approved by owner', identities, ...overrides });
  let hybridPlan: Record<string, unknown>;
  beforeEach(() => {
    hybridPlan = { id: hybrid, plan_code: 'hybrid', product_id: product, is_active: true, applicable_entities: ['school', 'college', 'university'], entity_config: legacyConfig };
    transitionPlans = [hybridRow]; publications = [];
    subscriptionPages = [[{ id: 'b3000000-0000-4000-8000-000000000001', plan_id: hybrid, plan_code: 'hybrid', plan_type: 'b2b', plan_amount: 0,
      billing_cycle: 'custom', features: [], subscription_start_date: '2026-10-01T00:00:00+00:00', subscription_end_date: '2027-10-01T00:00:00+00:00',
      plan_revision_id: null, lifecycle_state: null, lifecycle_policy: null, metadata: {} }]];
    const base = transport.getMockImplementation()!;
    transport.mockImplementation(async (input, init) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/plans') && url.searchParams.get('select')?.startsWith('id,plan_code,product_id')) return Response.json([hybridPlan]);
      if (url.pathname.endsWith('/adopt_subscription_hybrid_catalog_offer')) {
        const { p_command: command } = JSON.parse(String(init?.body));
        return Response.json({ operationId: command.operationId, identity: { operationId: command.identity.operationId, command: command.identity,
          plan: { id: hybrid, code: command.identity.targetCode, productId: product }, preservedSubscriptionIds: command.identity.retainedSubscriptions.map((row: { id: string }) => row.id) },
        plan: { id: hybrid, code: command.identity.targetCode, productId: product }, configurationKeys: Object.keys(command.configuration).sort() });
      }
      return base(input, init);
    });
  });
  it('adopts Hybrid atomically: opaque code, owner configuration, retained purchases and legacy keys preserved', async () => {
    const result = await worker().adoptHybridCatalogOffer(await credential(), product, request(), features);
    expect(result).toMatchObject({ kind: 'adopted', receipt: { plan: { id: hybrid, code: identities.targetCode } } });
    const [call] = calls('/adopt_subscription_hybrid_catalog_offer');
    const command = JSON.parse(String(call[1]?.body)).p_command;
    expect(command.expectedConfiguration).toEqual(legacyConfig);
    expect(command.identity).toMatchObject({ expectedCode: 'hybrid', targetCode: identities.targetCode, actorId: actor, hybridPlanId: hybrid });
    expect(command.identity.retainedSubscriptions).toHaveLength(1);
    expect(Object.keys(command.configuration).every((key: string) => key.startsWith('subscription_'))).toBe(true);
    expect(command.configuration.subscription_presentation.copy.highlights).toHaveLength(6);
    expect(command.configuration.subscription_commerce_eligibility.bindings.map((row: { audience: string }) => row.audience)).toEqual(['school', 'college', 'university']);
  });
  it('refuses an adopted plan, differing audiences, reused identities and non-administrators without writing', async () => {
    const token = await credential();
    hybridPlan.entity_config = { ...legacyConfig, subscription_presentation: {} };
    expect(await worker().adoptHybridCatalogOffer(token, product, request(), features)).toEqual({ kind: 'invalid' });
    hybridPlan.entity_config = legacyConfig; hybridPlan.applicable_entities = ['school'];
    expect(await worker().adoptHybridCatalogOffer(token, product, request(), features)).toEqual({ kind: 'invalid' });
    hybridPlan.applicable_entities = ['school', 'college', 'university'];
    expect(await worker().adoptHybridCatalogOffer(token, product, request({ identityOperationId: request().operationId }), features)).toEqual({ kind: 'invalid' });
    expect(await worker().adoptHybridCatalogOffer(token, product, request({ identities: { ...identities, targetCode: 'hybrid2' } }), features)).toEqual({ kind: 'invalid' });
    live = { roles: ['owner'], membership_status: 'active' };
    expect(await worker().adoptHybridCatalogOffer(token, product, request(), features)).toEqual({ kind: 'forbidden' });
    expect(calls('/adopt_subscription_hybrid_catalog_offer')).toHaveLength(0);
  });
});
