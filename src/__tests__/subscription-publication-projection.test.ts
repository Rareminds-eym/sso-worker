import { describe, expect, it } from 'vitest';
import {
  createPlanPublicationProjection,
  validatePlanRevisionBundle,
  verifyPlanPublicationProjection,
  type CreditPolicyRegistry, type PlanAuthoringContext,
  type PublicationFeatureDefinition
} from '../lib/subscriptions';

const id = (n: number) => `a0000000-0000-4000-8000-${n.toString().padStart(12, '0')}`;
type Mutable<T> = { -readonly [K in keyof T]: Mutable<T[K]> };
const copy = <T>(value: T): Mutable<T> => structuredClone(value) as Mutable<T>;
const plan = { id: id(1), code: 'pln_0123456789abcdef0123456789abcdef', productId: id(2) };
const context: PlanAuthoringContext = {
  schemaVersion: 1, plan, audiences: ['organization'],
  currencies: [{ code: 'USD', minorUnit: 2 }]
};
const definitions: PublicationFeatureDefinition[] = [
  { id: id(11), key: 'access', type: 'boolean' },
  { id: id(12), key: 'seats', type: 'numeric_limit' },
  { id: id(13), key: 'storage', type: 'numeric_limit' },
  { id: id(14), key: 'search', type: 'enum' },
  { id: id(15), key: 'support', type: 'enum' },
  { id: id(16), key: 'credits', type: 'metered' },
];
const registry: CreditPolicyRegistry = {
  catalog: {
    productIds: new Set([plan.productId]), audienceKeys: new Set(context.audiences),
    currencies: new Map([['USD', 2]]), featureTypes: new Map(definitions.map(f => [f.key, f.type])),
    featureOptions: new Map([['search', new Set(['basic', 'advanced'])], ['support', new Set(['email'])]])
  },
  pools: new Map([
    ['organization_pool', { featureKey: 'credits', recipient: 'organization', audiences: new Set(context.audiences) }],
    ['learner_pool', { featureKey: 'credits', recipient: 'managed_learner', audiences: new Set(context.audiences) }],
  ]),
  timePolicyIds: new Set(), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set(),
};
const configuration = {
  subscription_publication: {
    schemaVersion: 2,
    requiredFeatureKeys: definitions.map(f => f.key), requiredCreditAllocations: [
      { poolKey: 'organization_pool', audiences: context.audiences },
      { poolKey: 'learner_pool', audiences: context.audiences },
    ]
  }
};
function bundle() {
  return validatePlanRevisionBundle({
    schemaVersion: 1,
    draft: {
      schemaVersion: 2, id: id(3), plan, revisionNumber: 2, name: 'Synthetic offer',
      audiences: context.audiences, purchaseMode: 'self_service',
      prices: [{
        id: id(4), currency: 'USD', minorUnit: 2, amountMinor: 0,
        intervalUnit: 'year', intervalCount: 1, quantityBasis: 'subscription', audiences: context.audiences
      }],
      features: [
        { key: 'access', type: 'boolean', enabled: false },
        { key: 'seats', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 0 } },
        { key: 'storage', type: 'numeric_limit', enabled: true, limit: { kind: 'unlimited' } },
        { key: 'search', type: 'enum', enabled: true, value: 'basic' },
        { key: 'support', type: 'enum', enabled: false, value: null },
        { key: 'credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } },
      ]
    }, includedCredits: {
      schemaVersion: 1, id: id(5), revisionId: id(3), funding: 'included', rules: [
        {
          id: id(6), featureKey: 'credits', poolKey: 'organization_pool', recipient: 'organization',
          audiences: context.audiences, quantity: { kind: 'finite', value: 0 }, cadence: { kind: 'subscription_period' },
          expiry: { kind: 'subscription_end' }, rollover: { kind: 'none' }
        },
        {
          id: id(7), featureKey: 'credits', poolKey: 'learner_pool', recipient: 'managed_learner',
          audiences: context.audiences, quantity: { kind: 'finite', value: 9 }, cadence: { kind: 'activation' },
          expiry: { kind: 'subscription_end' }, rollover: { kind: 'none' }
        },
      ]
    }
  }, registry);
}
const compile = (value: unknown = bundle(), features = definitions) =>
  createPlanPublicationProjection(value, context, configuration, registry, features);
const verify = (value: unknown, expected: unknown = bundle()) =>
  verifyPlanPublicationProjection(value, expected, context, configuration, registry, definitions);

describe('immutable publication projection', () => {
  it('uses owner identities and the existing value columns without flattening credit rules', () => {
    const result = compile();
    expect(result.entitlements).toEqual([
      { plan_id: id(1), feature_id: id(11), is_enabled: false, value_numeric: null, value_text: null },
      { plan_id: id(1), feature_id: id(12), is_enabled: true, value_numeric: 0, value_text: null },
      { plan_id: id(1), feature_id: id(13), is_enabled: true, value_numeric: null, value_text: null },
      { plan_id: id(1), feature_id: id(14), is_enabled: true, value_numeric: null, value_text: 'basic' },
      { plan_id: id(1), feature_id: id(15), is_enabled: false, value_numeric: null, value_text: null },
      { plan_id: id(1), feature_id: id(16), is_enabled: true, value_numeric: null, value_text: null },
    ]);
    expect(result.bundle).toEqual(bundle());
    expect(result.bundle.includedCredits.rules.map(rule => rule.quantity)).toEqual([
      { kind: 'finite', value: 0 }, { kind: 'finite', value: 9 },
    ]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.entitlements)).toBe(true);
    expect(result.entitlements.every(Object.isFrozen)).toBe(true);
    expect(result).not.toHaveProperty('ready');
  });

  it('accepts row order and database UUID case independently of immutable bundle array order', () => {
    const result = copy(compile()); result.entitlements.reverse();
    result.entitlements.forEach(row => { row.feature_id = row.feature_id.toUpperCase(); row.plan_id = row.plan_id.toUpperCase(); });
    expect(verify(result)).toEqual(compile());
  });

  it('requires complete owner coverage rather than treating a valid draft as sufficient', () => {
    const input = copy(bundle()); input.draft.features = input.draft.features.filter(f => f.key !== 'access');
    validatePlanRevisionBundle(input, registry);
    expect(() => compile(input)).toThrow('publication.features');
  });

  it('rejects valid unresolved numeric contracts instead of granting unlimited access', () => {
    const input = copy(bundle()); input.draft.purchaseMode = 'contact_sales';
    const seats = input.draft.features.find(f => f.key === 'seats');
    if (!seats || seats.type !== 'numeric_limit') throw new Error('Fixture feature missing');
    seats.limit = { kind: 'contract_required' };
    validatePlanRevisionBundle(input, registry);
    expect(() => compile(input)).toThrow('unresolved contract');
  });

  it('rejects unresolved credit quantities while preserving valid contact-sales authoring', () => {
    const input = copy(bundle()); input.draft.purchaseMode = 'contact_sales';
    input.includedCredits.rules[0].quantity = { kind: 'contract_required' };
    validatePlanRevisionBundle(input, registry);
    expect(() => compile(input)).toThrow('projection.credits');
  });

  it('publishes sales-led Custom terms display-only: disabled contract seats, retained contract credit rules', () => {
    const input = copy(bundle()); input.draft.purchaseMode = 'contact_sales'; input.draft.prices = [];
    const seats = input.draft.features.find(f => f.key === 'seats');
    if (!seats || seats.type !== 'numeric_limit') throw new Error('Fixture feature missing');
    seats.limit = { kind: 'contract_required' };
    input.includedCredits.rules[0].quantity = { kind: 'contract_required' };
    const result = compile(input);
    // Never NULL+enabled: a NULL numeric value means unlimited to the current consumer.
    expect(result.entitlements.find(row => row.feature_id === id(12))).toEqual({ plan_id: id(1), feature_id: id(12), is_enabled: false, value_numeric: null, value_text: null });
    expect(result.bundle.includedCredits.rules[0].quantity).toEqual({ kind: 'contract_required' });
    expect(verify(copy(result), input)).toEqual(result);
    const tampered = copy(result); tampered.entitlements.find(row => row.feature_id === id(12))!.is_enabled = true;
    expect(() => verify(tampered, input)).toThrow('stored grant differs');
  });

  it('keeps refusing Custom terms on free and self-serve offers', () => {
    for (const mode of ['self_service', 'free'] as const) {
      const input = copy(bundle()); input.draft.purchaseMode = mode;
      if (mode === 'free') input.draft.prices = [];
      input.includedCredits.rules[0].quantity = { kind: 'contract_required' };
      expect(() => compile(input)).toThrow();
    }
  });

  it.each([
    definitions.slice(1), [...definitions, definitions[0]],
    definitions.map((f, i) => i === 1 ? { ...f, id: definitions[0].id } : f),
    definitions.map((f, i) => i === 0 ? { ...f, id: 'invalid' } : f),
    definitions.map((f, i) => i === 0 ? { ...f, type: 'enum' as const } : f),
    [...definitions, { id: id(99), key: 'unregistered', type: 'boolean' as const }],
    new Array<PublicationFeatureDefinition>(1),
  ].map(features => ({ features })))('rejects incomplete, duplicate, malformed or mismatched owner identity definitions %#', ({ features }) => {
    expect(() => compile(bundle(), features)).toThrow('projection.features');
  });

  it.each<(value: Mutable<ReturnType<typeof compile>>) => void>([
    value => { value.entitlements.pop(); },
    value => { value.entitlements.push(value.entitlements[0]); },
    value => { value.entitlements[1] = value.entitlements[0]; },
    value => { value.entitlements[0].plan_id = id(99); },
    value => { value.entitlements[0].feature_id = id(99); },
    value => { value.entitlements[0].is_enabled = true; },
    value => { value.entitlements[1].value_numeric = null; },
    value => { value.entitlements[2].value_numeric = 0; },
    value => { value.entitlements[3].value_text = 'advanced'; },
    value => { value.entitlements[4].value_text = 'email'; },
    value => { value.entitlements[5].value_numeric = 9; },
    value => { delete (value.entitlements[0] as Partial<typeof value.entitlements[0]>).value_numeric; },
  ])('rejects missing, extra, duplicated, cross-plan or altered projected grants %#', mutate => {
    const value = copy(compile()); mutate(value);
    expect(() => verify(value)).toThrow('projection.entitlements');
  });

  it.each(['price', 'credits', 'revision', 'name', 'cadence'] as const)(
    'rejects changed %s even when all entitlement rows are identical', field => {
      const value = copy(compile());
      if (field === 'price') value.bundle.draft.prices[0].amountMinor = 10;
      if (field === 'credits') value.bundle.includedCredits.rules[0].quantity = { kind: 'finite', value: 10 };
      if (field === 'revision') value.bundle.draft.revisionNumber++;
      if (field === 'name') value.bundle.draft.name = 'Another offer';
      if (field === 'cadence') value.bundle.includedCredits.rules[0].cadence = { kind: 'activation' };
      validatePlanRevisionBundle(value.bundle, registry); // Positive control: generic terms remain valid.
      expect(value.entitlements).toEqual(compile().entitlements);
      expect(() => verify(value)).toThrow('projection.bundle');
    });

  it('rejects an old revision UUID even if its grants match', () => {
    const value = copy(compile()); value.bundle.draft.id = id(99);
    value.bundle.includedCredits.revisionId = id(99);
    validatePlanRevisionBundle(value.bundle, registry);
    expect(() => verify(value)).toThrow('projection.bundle');
  });

  it.each([null, {}, { schemaVersion: 2 }, { ...compile(), ready: true },
    { ...compile(), entitlements: new Array(definitions.length) }])('rejects malformed acknowledgements %#', value => {
      expect(() => verify(value)).toThrow();
    });

  it('rejects string numeric values and unsupported row fields without coercion', () => {
    const original = compile();
    const stringNumeric = {
      ...original, entitlements: original.entitlements.map((row, i) =>
        i === 1 ? { ...row, value_numeric: '0' } : row)
    };
    expect(() => verify(stringNumeric)).toThrow('projection.entitlements');
    const unknown = {
      ...original, entitlements: original.entitlements.map((row, i) =>
        i === 0 ? { ...row, ready: true } : row)
    };
    expect(() => verify(unknown)).toThrow('projection.entitlement');
  });
});
