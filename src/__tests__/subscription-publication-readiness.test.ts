import { describe, expect, it, vi } from 'vitest';
import {
  readPlanPublicationCompleteness, validatePlanPublicationCompleteness, validatePlanRevisionBundle,
  type CreditPolicyRegistry, type PlanAuthoringContext,
} from '../lib/subscriptions';

const plan = { id: '10000000-0000-4000-8000-000000000001', code: 'pln_1234567890abcdef1234567890abcdef',
  productId: '20000000-0000-4000-8000-000000000001' };
const revisionId = '30000000-0000-4000-8000-000000000001';
const otherId = '40000000-0000-4000-8000-000000000001';
const context: PlanAuthoringContext = { schemaVersion: 1, plan, audiences: ['organization', 'individual'],
  currencies: [{ code: 'USD', minorUnit: 2 }] };
const registry: CreditPolicyRegistry = {
  catalog: { productIds: new Set([plan.productId, otherId]), audienceKeys: new Set(context.audiences),
    currencies: new Map([['USD', 2]]), featureTypes: new Map([['support', 'boolean'], ['seats', 'numeric_limit']]) },
  pools: new Map(), timePolicyIds: new Set(), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set(),
};
function configuration() {
  return { unrelated: { preserved: true }, subscription_authoring: { schemaVersion: 1, currencies: context.currencies },
    subscription_publication: { schemaVersion: 1, requiredFeatureKeys: ['support', 'seats'] } };
}
function bundle() {
  return { schemaVersion: 1, draft: { schemaVersion: 2, id: revisionId, plan: { ...plan }, revisionNumber: 1,
    name: 'Synthetic offer', audiences: [...context.audiences], purchaseMode: 'self_service',
    prices: [{ id: otherId, currency: 'USD', minorUnit: 2, amountMinor: 0,
      intervalUnit: 'month', intervalCount: 1, quantityBasis: 'subscription', audiences: [...context.audiences] }],
    features: [{ key: 'support', type: 'boolean', enabled: false },
      { key: 'seats', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 0 } }] },
    includedCredits: { schemaVersion: 1, id: otherId, revisionId, funding: 'included', rules: [] } };
}
function client() {
  const value = bundle();
  return { query: vi.fn().mockResolvedValueOnce([{ id: plan.id, plan_code: plan.code, product_id: plan.productId,
    applicable_entities: context.audiences, entity_config: configuration() }]).mockResolvedValueOnce([{ id: plan.productId }])
    .mockResolvedValueOnce([{ snapshot: value.draft, included_credits: value.includedCredits,
      staged_by: otherId, staged_at: '2026-11-18T12:00:00.123456Z' }]) };
}

describe('publication completeness preparation', () => {
  const freeBundle = () => {
    const input = bundle();
    return { ...input, draft: { ...input.draft, purchaseMode: 'free', prices: [] } };
  };
  // Isolated policy fixture; never a source for real catalog/business settings.
  const lifecycle = () => ({ id: otherId, version: 1, productId: plan.productId,
    graceDurationMs: 1000, graceAccess: 'read_only', expiredAccess: 'read_only', readOnlyDurationMs: 9000,
    billing: 'not_applicable', cancellationAccess: 'read_only', immediateDowngradeAllowed: false, paymentFailureRestrictedMs: null,
    paymentFailureAfterAccess: null, paymentRetryOffsetsMs: [],
    suspensionApprovalRequired: true, reactivationApprovalRequired: true });

  it('rejects missing lifecycle terms for otherwise complete free offers before publication', () => {
    const input = freeBundle();
    expect(() => validatePlanRevisionBundle(input, registry)).not.toThrow();
    expect(() => validatePlanPublicationCompleteness(input, context, configuration(), registry)).toThrow('policy');
  });

  it('accepts explicit validated free-offer lifecycle terms for the same canonical product', () => {
    const input = freeBundle();
    expect(validatePlanPublicationCompleteness(input, context,
      { ...configuration(), subscription_lifecycle: lifecycle() }, registry)).toEqual(input);
  });

  it.each([{}, null, { ...lifecycle(), paymentRetryOffsetsMs: [1000] },
    { ...lifecycle(), graceDurationMs: -1 }, { ...lifecycle(), unexpected: true }])(
    'rejects malformed free-offer lifecycle terms %j', policy => {
      expect(() => validatePlanPublicationCompleteness(freeBundle(), context,
        { ...configuration(), subscription_lifecycle: policy }, registry)).toThrow('policy');
    });

  it('rejects lifecycle terms from a different product', () => {
    expect(() => validatePlanPublicationCompleteness(freeBundle(), context,
      { ...configuration(), subscription_lifecycle: { ...lifecycle(), productId: otherId } }, registry))
      .toThrow('publication.lifecycle');
  });

  it('requires explicit terms but accepts disabled features, zero allowances and a zero price', () => {
    const input = bundle();
    const result = validatePlanPublicationCompleteness(input, context, configuration(), registry);
    expect(result).toEqual(input);
    expect(Object.isFrozen(result.draft.features)).toBe(true);
    expect(result).not.toHaveProperty('publishedRevisionId');
    input.draft.name = 'Changed after validation';
    expect(result.draft.name).toBe('Synthetic offer');
  });

  it('accepts audience ordering and dynamic required feature subsets without deriving terms from names', () => {
    const input = bundle(); input.draft.audiences.reverse(); input.draft.name = 'Arbitrary display name';
    const config = configuration(); config.subscription_publication.requiredFeatureKeys = ['seats'];
    expect(validatePlanPublicationCompleteness(input, context, config, registry).draft.name).toBe(input.draft.name);
  });

  it.each([undefined, null, {}, { schemaVersion: 2, requiredFeatureKeys: ['seats'] },
    { schemaVersion: 1, requiredFeatureKeys: [] }, { schemaVersion: 1, requiredFeatureKeys: ['seats', 'seats'] },
    { schemaVersion: 1, requiredFeatureKeys: [' seats'] }, { schemaVersion: 1, requiredFeatureKeys: ['unknown'] },
    { schemaVersion: 1, requiredFeatureKeys: ['seats'], eligible: true },
    { schemaVersion: 1, requiredFeatureKeys: new Array(1) },
  ])('rejects absent, malformed or unregistered authoritative coverage %j', coverage => {
    expect(() => validatePlanPublicationCompleteness(bundle(), context,
      { subscription_publication: coverage }, registry)).toThrow('publication.coverage');
  });

  it('distinguishes a valid incomplete draft from complete configured terms', () => {
    const input = bundle(); input.draft.features = input.draft.features.filter(feature => feature.key !== 'support');
    expect(() => validatePlanRevisionBundle(input, registry)).not.toThrow();
    expect(() => validatePlanPublicationCompleteness(input, context, configuration(), registry)).toThrow('publication.features');
  });

  it.each(['id', 'code', 'productId'] as const)('rejects a shape-valid different canonical %s', key => {
    const input = bundle(); input.draft.plan[key] = key === 'code' ? 'pln_ffffffffffffffffffffffffffffffff' : otherId;
    validatePlanRevisionBundle(input, registry);
    expect(() => validatePlanPublicationCompleteness(input, context, configuration(), registry)).toThrow('publication.plan');
  });

  it('rejects otherwise valid partial audience coverage', () => {
    const input = bundle(); input.draft.audiences = ['individual']; input.draft.prices[0].audiences = ['individual'];
    validatePlanRevisionBundle(input, registry);
    expect(() => validatePlanPublicationCompleteness(input, context, configuration(), registry)).toThrow('publication.audiences');
  });

  it('reuses complete bundle validation rather than accepting coverage as proof of valid prices or credits', () => {
    const input = bundle(); input.includedCredits.revisionId = otherId;
    expect(() => validatePlanPublicationCompleteness(input, context, configuration(), registry)).toThrow('revisionId');
    const noPrices = bundle(); noPrices.draft.prices = [];
    expect(() => validatePlanPublicationCompleteness(noPrices, context, configuration(), registry)).toThrow('prices');
  });
});

describe('canonical persisted completeness reader', () => {
  it('loads actual owner configuration and one immutable bundle using queries only', async () => {
    const database = client();
    const result = await readPlanPublicationCompleteness(database, plan.id, revisionId, registry);
    expect(result.bundle).toEqual(bundle());
    expect(database.query).toHaveBeenCalledTimes(3);
    expect(database.query.mock.calls[2][0]).toBe(`subscription_plan_drafts?select=snapshot,included_credits,staged_by,staged_at&id=eq.${revisionId}&limit=2`);
    expect(result).not.toHaveProperty('eligible');
  });

  it('rejects missing coverage before reading terms instead of fabricating a policy', async () => {
    const database = client(); database.query.mockReset().mockResolvedValueOnce([{ id: plan.id,
      plan_code: plan.code, product_id: plan.productId, applicable_entities: context.audiences,
      entity_config: { subscription_authoring: configuration().subscription_authoring } }])
      .mockResolvedValueOnce([{ id: plan.productId }]);
    await expect(readPlanPublicationCompleteness(database, plan.id, revisionId, registry)).rejects.toThrow('publication.coverage');
    expect(database.query).toHaveBeenCalledTimes(2);
  });

  it('surfaces owner failures without retry or a caller-supplied bundle', async () => {
    const failure = new Error('Owner unavailable');
    const database = { query: vi.fn().mockRejectedValue(failure) };
    await expect(readPlanPublicationCompleteness(database, plan.id, revisionId, registry)).rejects.toBe(failure);
    expect(database.query).toHaveBeenCalledTimes(1);
  });
});

describe('configured publication allocation coverage', () => {
  const creditRegistry: CreditPolicyRegistry = {
    ...registry,
    catalog: { ...registry.catalog, featureTypes: new Map([...registry.catalog.featureTypes, ['credits', 'metered']]) },
    pools: new Map([
      ['admin_pool', { featureKey: 'credits', recipient: 'organization', audiences: new Set(context.audiences) }],
      ['learner_pool', { featureKey: 'credits', recipient: 'managed_learner', audiences: new Set(['organization']) }],
    ]),
  };
  function creditBundle() {
    const input = bundle();
    return { ...input, draft: { ...input.draft, features: [...input.draft.features,
      { key: 'credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }] },
      includedCredits: { ...input.includedCredits, rules: [
        { id: '50000000-0000-4000-8000-000000000001', featureKey: 'credits', poolKey: 'admin_pool',
          recipient: 'organization', audiences: [...context.audiences], quantity: { kind: 'finite', value: 0 },
          cadence: { kind: 'subscription_period' }, expiry: { kind: 'subscription_end' }, rollover: { kind: 'none' } },
        { id: '50000000-0000-4000-8000-000000000002', featureKey: 'credits', poolKey: 'learner_pool',
          recipient: 'managed_learner', audiences: ['organization'], quantity: { kind: 'finite', value: 1 },
          cadence: { kind: 'subscription_period' }, expiry: { kind: 'subscription_end' }, rollover: { kind: 'none' } },
      ] } };
  }
  function creditConfiguration() {
    return { subscription_publication: { schemaVersion: 2, requiredFeatureKeys: ['support', 'seats', 'credits'],
      requiredCreditAllocations: [
        { poolKey: 'admin_pool', audiences: [...context.audiences] },
        { poolKey: 'learner_pool', audiences: ['organization'] },
      ] } };
  }

  it('requires separate configured pools for the same feature and accepts explicit zero allocations', () => {
    const input = creditBundle();
    expect(validatePlanPublicationCompleteness(input, context, creditConfiguration(), creditRegistry)).toEqual(input);
    input.includedCredits.rules.pop();
    // The existing generic policy is valid: the first pool still covers every audience.
    expect(() => validatePlanRevisionBundle(input, creditRegistry)).not.toThrow();
    expect(() => validatePlanPublicationCompleteness(input, context, creditConfiguration(), creditRegistry))
      .toThrow('publication.creditAllocations');
  });

  it('requires each configured pool audience rather than accepting any rule with the same pool', () => {
    const input = creditBundle(); input.includedCredits.rules[0].audiences = ['organization'];
    input.includedCredits.rules.push({ ...input.includedCredits.rules[1],
      id: '50000000-0000-4000-8000-000000000003', poolKey: 'learner_pool', audiences: ['individual'] });
    // Expand the synthetic registry to make both existing rules otherwise valid.
    const expanded = { ...creditRegistry, pools: new Map(creditRegistry.pools) };
    expanded.pools.set('learner_pool', { featureKey: 'credits', recipient: 'managed_learner', audiences: new Set(context.audiences) });
    validatePlanRevisionBundle(input, expanded);
    expect(() => validatePlanPublicationCompleteness(input, context, creditConfiguration(), expanded))
      .toThrow('publication.creditAllocations');
  });

  it('keeps schema-1 feature-only coverage distinct from schema-2 allocation completeness', () => {
    const input = creditBundle(); input.includedCredits.rules.pop();
    expect(() => validatePlanPublicationCompleteness(input, context, configuration(), creditRegistry)).not.toThrow();
    expect(() => validatePlanPublicationCompleteness(input, context, creditConfiguration(), creditRegistry)).toThrow();
    const mixed = { subscription_publication: { ...creditConfiguration().subscription_publication, schemaVersion: 1 } };
    expect(() => validatePlanPublicationCompleteness(input, context, mixed, creditRegistry)).toThrow('publication.coverage');
  });

  it.each([
    undefined, null, new Array(1), [{}], [{ poolKey: 'unknown', audiences: ['organization'] }],
    [{ poolKey: 'learner_pool', audiences: [] }], [{ poolKey: 'learner_pool', audiences: ['individual'] }],
    [{ poolKey: 'learner_pool', audiences: ['organization', 'organization'] }],
    [{ poolKey: 'learner_pool', audiences: ['unregistered'] }],
    [{ poolKey: 'learner_pool', audiences: ['organization'], quantity: 1 }],
    [{ poolKey: 'learner_pool', audiences: ['organization'] }, { poolKey: 'learner_pool', audiences: ['organization'] }],
  ].map(required => ({ required })))('rejects malformed or ambiguous required allocation coverage %j', ({ required }) => {
    const config = creditConfiguration();
    (config.subscription_publication as Record<string, unknown>).requiredCreditAllocations = required;
    expect(() => validatePlanPublicationCompleteness(creditBundle(), context, config, creditRegistry))
      .toThrow('publication.coverage');
  });

  it('rejects required pools without a required registered metered feature', () => {
    const config = creditConfiguration(); config.subscription_publication.requiredFeatureKeys = ['support', 'seats'];
    expect(() => validatePlanPublicationCompleteness(creditBundle(), context, config, creditRegistry))
      .toThrow('publication.coverage');
    const invalid = { ...creditRegistry, pools: new Map(creditRegistry.pools) };
    invalid.pools.set('learner_pool', { featureKey: 'support', recipient: 'managed_learner', audiences: new Set(['organization']) });
    expect(() => validatePlanPublicationCompleteness(creditBundle(), context, creditConfiguration(), invalid))
      .toThrow('publication.coverage');
  });

  it('allows explicit empty pool coverage when no allocation scopes are required', () => {
    const config = creditConfiguration(); config.subscription_publication.requiredCreditAllocations = [];
    expect(() => validatePlanPublicationCompleteness(creditBundle(), context, config, creditRegistry)).not.toThrow();
  });

  it('does not accept a registry audience outside this canonical plan', () => {
    const expanded = { ...creditRegistry, pools: new Map(creditRegistry.pools) };
    expanded.pools.set('learner_pool', { featureKey: 'credits', recipient: 'managed_learner',
      audiences: new Set([...context.audiences, 'different_audience']) });
    const config = creditConfiguration();
    config.subscription_publication.requiredCreditAllocations[1].audiences = ['different_audience'];
    expect(() => validatePlanPublicationCompleteness(creditBundle(), context, config, expanded))
      .toThrow('publication.coverage.allocation.audiences');
  });

  it('loads schema-2 requirements from the canonical plan rather than the submitted bundle', async () => {
    const input = creditBundle(); input.includedCredits.rules.pop();
    validatePlanRevisionBundle(input, creditRegistry);
    const database = { query: vi.fn()
      .mockResolvedValueOnce([{ id: plan.id, plan_code: plan.code, product_id: plan.productId,
        applicable_entities: context.audiences, entity_config: { ...configuration(), ...creditConfiguration() } }])
      .mockResolvedValueOnce([{ id: plan.productId }])
      .mockResolvedValueOnce([{ snapshot: input.draft, included_credits: input.includedCredits,
        staged_by: otherId, staged_at: '2026-11-18T12:00:00.123456Z' }]) };
    await expect(readPlanPublicationCompleteness(database, plan.id, revisionId, creditRegistry))
      .rejects.toThrow('publication.creditAllocations');
    expect(database.query).toHaveBeenCalledTimes(3);
  });
});
