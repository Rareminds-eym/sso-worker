import { beforeEach, describe, expect, it, vi } from 'vitest';
import { listPublishedSubscriptionPlans, listSubscriptionExecutions } from '../lib/subscriptions/consumers';
import { SubscriptionExecutionDenied } from '../lib/subscriptions/credit-execution';
import type { Env } from '../types';
const io = vi.hoisted(() => ({ token: vi.fn(), query: vi.fn(), rpc: vi.fn() }));
vi.mock('../lib/jwt', () => ({ verifyAccessToken: io.token }));
vi.mock('../lib/db', () => ({ db: () => ({ query: io.query, rpc: io.rpc }) }));

const actor = 'a0000000-0000-4000-8000-000000000001', organization = 'a0000000-0000-4000-8000-000000000002';
const subscription = 'b0000000-0000-4000-8000-000000000001', plan = 'c0000000-0000-4000-8000-000000000001';
const revision = 'd0000000-0000-4000-8000-000000000001', product = 'e0000000-0000-4000-8000-000000000001';
const now = 1800000000000, env = {} as Env;
const definitions = [{ key: 'synthetic_seats', type: 'numeric_limit' }];
const policy = () => ({
  id: product, version: 1, productId: product, graceDurationMs: 1000, graceAccess: 'restricted',
  expiredAccess: 'read_only', cancellationAccess: 'until_period_end', immediateDowngradeAllowed: false,
  paymentFailureRestrictedMs: 1000, paymentFailureAfterAccess: 'read_only', paymentRetryOffsetsMs: [500],
  suspensionApprovalRequired: true, reactivationApprovalRequired: true
});
const state = () => ({
  id: subscription, subject: { kind: 'user', id: actor }, planId: plan, revisionId: revision, productId: product,
  version: 1, status: 'active', periodStartsAt: now - 1000, periodEndsAt: now + 1000, trialEndsAt: null,
  renewalEnabled: true, cancelledAt: null, paymentFailedAt: null, scheduledChange: null
});
const canonical = () => ({
  id: plan, code: `pln_${'a'.repeat(32)}`, productId: product, audiences: ['school'], configuration: {
    subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'TST', minorUnit: 2 }] },
    subscription_credit_authoring: { schemaVersion: 1, pools: [], timePolicies: [] },
    subscription_publication: { schemaVersion: 2, requiredFeatureKeys: ['synthetic_seats'], requiredCreditAllocations: [] },
    subscription_lifecycle: policy(), subscription_revision_changes: [],
    subscription_execution: { schemaVersion: 1, operationRoles: { read: ['owner_role'], cancel: ['owner_role'], suspend: ['another_role'] }, recipientRoles: {}, consumptionTariffs: [] },
    subscription_presentation: { schemaVersion: 1, priceLabel: 'starting_at' as string, taxInclusive: false as boolean, badge: 'Synthetic badge' as string | null },
  }
});
const bundle = () => ({
  schemaVersion: 1, draft: {
    schemaVersion: 2, id: revision, revisionNumber: 1,
    plan: { id: plan, code: canonical().code, productId: product }, name: 'Synthetic published plan', audiences: ['school'],
    purchaseMode: 'self_service', prices: [{
      id: actor, currency: 'TST', minorUnit: 2, amountMinor: 1234,
      intervalUnit: 'month', intervalCount: 1, quantityBasis: 'subscription', audiences: ['school']
    }],
    features: [{ key: 'synthetic_seats', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 7 } }]
  },
  includedCredits: { schemaVersion: 1, id: organization, revisionId: revision, funding: 'included', rules: [] }
});
let row: Record<string, unknown>, listed: Record<string, unknown>[], pointers: unknown[], event: ReturnType<typeof canonical>, staged: ReturnType<typeof bundle>;
let blocked: boolean, roles: string[], organizationRows: Record<string, unknown>[];
function selected(path: string, rows: Record<string, unknown>[]) {
  const columns = new URL('https://isolated.invalid/' + path).searchParams.get('select')?.split(',');
  if (!columns) throw new Error('Expected explicit selected owner columns');
  return rows.map(value => Object.fromEntries(columns.map(key => [key, value[key]])));
}
beforeEach(() => {
  vi.resetAllMocks(); vi.spyOn(Date, 'now').mockReturnValue(now); blocked = false; roles = ['owner_role', 'school_admin'];
  organizationRows = [{ id: organization, metadata: { organization_type: 'school' } }];
  io.token.mockResolvedValue({ sub: actor, org_id: organization, exp: now / 1000 + 60, membership_status: 'active', is_email_verified: true });
  event = canonical(); staged = bundle();
  row = {
    id: subscription, user_id: actor, organization_id: null, is_organization_subscription: false,
    product_id: product, plan_id: plan, plan_revision_id: revision, status: 'active', auto_renew: true,
    metadata: { subscription_execution: { audience: 'school', subscriptionEndsAt: now + 2000 } },
    subscription_start_date: new Date(now - 1000).toISOString(), subscription_end_date: new Date(now + 1000).toISOString(),
    cancelled_at: null, lifecycle_state: state(), lifecycle_policy: policy(), lifecycle_activated_at: new Date(now - 1000).toISOString()
  };
  listed = [row]; pointers = [{ plan_id: plan, revision_id: revision, plans: { id: plan, product_id: product, is_active: true } }];
  io.rpc.mockImplementation(async (name: string) => {
    if (name !== 'get_jwt_claims') throw new Error('Unexpected write');
    return { membership_status: 'active', roles };
  });
  io.query.mockImplementation(async (path: string) => {
    if (path.startsWith('users?')) return [{ id: actor, is_blocked: blocked, is_email_verified: true, user_metadata: null }];
    if (path.startsWith('subscriptions?')) return selected(path, path.includes('&or=') ? listed : [row]);
    if (path.startsWith('organizations?')) return organizationRows;
    if (path.startsWith('subscription_plan_publications?')) return pointers;
    if (path.startsWith('subscription_plan_publication_events?')) return [{ plan_id: plan, revision_id: revision, canonical_plan: event }];
    if (path.startsWith('subscription_plan_drafts?')) return [{ snapshot: staged.draft, included_credits: staged.includedCredits, staged_by: actor, staged_at: new Date(now - 1000).toISOString() }];
    // No processed refund or pending refund freeze exists for this synthetic subscription.
    if (path.startsWith('subscription_commerce_refunds?') || path.startsWith('subscription_commerce_refund_freezes?')) return [];
    throw new Error('Unexpected isolated owner path: ' + path);
  });
});

describe('subscription consumer discovery using production owner readers and isolated verified-token IO', () => {
  it('discovers exact initialized state and only explicitly configured live-role permissions', async () => {
    const result = await listSubscriptionExecutions(env, 'verified-token', product);
    expect(result).toEqual({
      schemaVersion: 1, actorId: actor, productId: product, items: [{
        id: subscription, planId: plan,
        productId: product, subject: state().subject, status: 'active', kind: 'initialized', revisionId: revision, version: 1,
        lifecycleOperations: ['cancel']
      }], nextCursor: subscription
    });
    expect(io.rpc).toHaveBeenCalledWith('get_jwt_claims', { p_user_id: actor, p_org_id: organization });
    expect(io.query.mock.calls.some(([path]) => path.includes(`product_id=eq.${product}`) && path.includes(`organization_id.eq.${organization}`)
      && path.includes(`user_id.eq.${actor}`) && path.includes('limit=50'))).toBe(true);
  });
  it('reports uninitialized own subscriptions without loading or fabricating lifecycle terms', async () => {
    row.lifecycle_state = null; row.plan_revision_id = null;
    expect((await listSubscriptionExecutions(env, 'verified-token', product)).items[0]).toMatchObject({ kind: 'uninitialized', revisionId: null, version: null, lifecycleOperations: [] });
    expect(io.query.mock.calls.some(([path]) => path.startsWith('subscription_plan_publication_events?'))).toBe(false);
  });
  it('does not substitute a denied initialized row for a legacy subscription', async () => {
    roles = ['revoked_role'];
    expect(await listSubscriptionExecutions(env, 'verified-token', product)).toMatchObject({ items: [], nextCursor: subscription });
  });
  it('keeps outages visible instead of returning an empty list', async () => {
    event.configuration.subscription_lifecycle.version = 2;
    await expect(listSubscriptionExecutions(env, 'verified-token', product)).rejects.toThrow('policy differs');
  });
  it.each(['product', 'user', 'organization'])('rejects returned foreign %s scope', async defect => {
    if (defect === 'product') row.product_id = actor;
    if (defect === 'user') row.user_id = product;
    if (defect === 'organization') { row.is_organization_subscription = true; row.organization_id = product; }
    await expect(listSubscriptionExecutions(env, 'verified-token', product)).rejects.toThrow('scope or cursor');
  });
  it('denies blocked canonical identity before discovery IO', async () => {
    blocked = true;
    await expect(listSubscriptionExecutions(env, 'verified-token', product)).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.query.mock.calls.some(([path]) => path.startsWith('subscriptions?'))).toBe(false);
  });
  it('rejects duplicate or backwards cursor data, but continues a short valid page', async () => {
    listed = [row, row];
    await expect(listSubscriptionExecutions(env, 'verified-token', product)).rejects.toThrow('scope or cursor');
    listed = [row];
    await expect(listSubscriptionExecutions(env, 'verified-token', product, subscription)).rejects.toThrow('scope or cursor');
    listed = [];
    expect(await listSubscriptionExecutions(env, 'verified-token', product, subscription)).toMatchObject({ items: [], nextCursor: null });
  });
  it('rejects partial initialization and invalid cursor rather than defaulting them', async () => {
    row.lifecycle_state = null;
    await expect(listSubscriptionExecutions(env, 'verified-token', product)).rejects.toThrow('Incomplete');
    await expect(listSubscriptionExecutions(env, 'verified-token', product, 'bad')).rejects.toThrow();
  });
  it('validates a published immutable bundle against owner feature and coverage registries', async () => {
    const result = await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions);
    expect(result.plans[0]).toMatchObject({
      plan: staged.draft.plan, revisionId: revision, name: staged.draft.name,
      prices: staged.draft.prices, features: staged.draft.features
    });
    expect(result.plans[0]).not.toHaveProperty('configuration');
    // Display terms come from the immutable published configuration and the owner tax policy.
    expect(result.plans[0].presentation).toEqual({ priceLabel: 'starting_at', taxInclusive: false, badge: 'Synthetic badge', copy: null });
    expect(result.tax).toEqual({ kind: 'gst', rateBasisPoints: 1800, priceDisplay: 'exclusive' });
    expect(io.query.mock.calls.some(([path]) => path.startsWith('plans?'))).toBe(false);
  });
  it.each(['inactive', 'foreign_product', 'revision', 'registry', 'coverage', 'presentation', 'tax_display', 'price_label'])('rejects published %s drift', async defect => {
    if (defect === 'presentation') delete (event.configuration as Partial<ReturnType<typeof canonical>['configuration']>).subscription_presentation;
    if (defect === 'tax_display') event.configuration.subscription_presentation.taxInclusive = true;
    if (defect === 'price_label') event.configuration.subscription_presentation.priceLabel = 'discounted';
    if (defect === 'inactive') pointers = [{ plan_id: plan, revision_id: revision, plans: { id: plan, product_id: product, is_active: false } }];
    if (defect === 'foreign_product') event.productId = actor;
    if (defect === 'revision') staged.draft.id = actor;
    if (defect === 'coverage') event.configuration.subscription_publication.requiredFeatureKeys = ['missing'];
    await expect(listPublishedSubscriptionPlans(env, 'verified-token', product,
      defect === 'registry' ? [{ key: 'synthetic_seats', type: 'boolean' }] : definitions)).rejects.toThrow();
  });
  it('serves individual learners in the seeded, non-RFC-versioned platform organization', async () => {
    const platform = '00000000-0000-0000-0000-000000000001';
    io.token.mockResolvedValue({ sub: actor, org_id: platform, exp: Date.now() / 1000 + 60, membership_status: 'active', is_email_verified: true });
    organizationRows = [{ id: platform, metadata: { is_platform_org: true } }]; roles = ['learner'];
    const individual = await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions);
    // The learner resolves to the individual audience, so the school plan is not offered.
    expect(individual.audience).toBe('individual'); expect(individual.plans).toEqual([]);
    expect(io.rpc).toHaveBeenCalledWith('get_jwt_claims', { p_user_id: actor, p_org_id: platform });
    io.token.mockResolvedValue({ sub: actor, org_id: 'not-a-uuid', exp: Date.now() / 1000 + 60, membership_status: 'active', is_email_verified: true });
    await expect(listPublishedSubscriptionPlans(env, 'verified-token', product, definitions)).rejects.toThrow('actor.organization');
  });
  it('offers each buyer only its own audience: organization type plus a live role of that audience', async () => {
    expect((await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions))).toMatchObject({ audience: 'school', plans: [{ revisionId: revision }] });
    organizationRows = [{ id: organization, metadata: { organization_type: 'company' } }];
    expect((await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions)).plans).toEqual([]);
    for (const metadata of [{}, { organization_type: 'unmapped' }]) {
      organizationRows = [{ id: organization, metadata }];
      const result = await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions);
      expect(result.audience).toBeNull(); expect(result.plans).toEqual([]);
    }
    organizationRows = [{ id: organization, metadata: { organization_type: 'school' } }]; roles = ['learner'];
    expect((await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions)).audience).toBeNull();
    organizationRows = [];
    expect((await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions)).plans).toEqual([]);
  });
  it('returns an explicit empty published catalog without loading legacy plans', async () => {
    pointers = [];
    expect(await listPublishedSubscriptionPlans(env, 'verified-token', product, definitions)).toMatchObject({ plans: [], nextCursor: null });
    // users, actor organization and publication pointers only.
    expect(io.query).toHaveBeenCalledTimes(3);
  });
});
