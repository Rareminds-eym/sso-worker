import { describe, expect, it } from 'vitest';
import {
  CatalogValidationError, createPlanIdentity, selectEntryPlan, validatePlanIdentity, validatePlanRevision,
  type CatalogRegistry, type EntryPlanCandidate,
} from '../lib/subscriptions';

const productId = '912d5049-e195-46e9-a319-49e3502bf7e7';
const planId = 'a0000000-0000-4000-8000-000000000040';
const revisionId = 'b0000000-0000-4000-8000-000000000001';
const priceId = 'c0000000-0000-4000-8000-000000000001';
const code = 'pln_8f3d2c6a91b74e50b5a36d02c7e8a419';

function registry(): CatalogRegistry {
  return {
    productIds: new Set([productId]), audienceKeys: new Set(['learner', 'college']),
    currencies: new Map([['INR', 2], ['JPY', 0]]),
    featureTypes: new Map([['course_lte_access', 'boolean'], ['learner_capacity', 'numeric_limit'], ['ai_credits', 'metered']]),
  };
}

function draft() {
  return {
    schemaVersion: 1, id: revisionId, plan: { id: planId, code, productId },
    revisionNumber: 1, name: 'Any editable display name', audiences: ['learner'], purchaseMode: 'self_service',
    prices: [{ id: priceId, currency: 'INR', minorUnit: 2, amountMinor: 250000, intervalUnit: 'year', intervalCount: 1, quantityBasis: 'subscription', audiences: ['learner'] }],
    features: [
      { key: 'course_lte_access', type: 'boolean', enabled: true },
      { key: 'learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 1 } },
      { key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'finite', value: 150 } },
    ],
  };
}

describe('registered enum grants', () => {
  const grant = { key: 'synthetic_choice', type: 'enum', enabled: true, value: 'option_b' };
  const configured = (): CatalogRegistry => ({ ...registry(),
    featureTypes: new Map([...registry().featureTypes, ['synthetic_choice', 'enum']]),
    featureOptions: new Map([['synthetic_choice', new Set(['option_a', 'option_b'])]]) });
  const revision = (feature: unknown = grant) => ({ ...draft(), schemaVersion: 2, features: [feature] });
  it('preserves an explicit selected value without ordering labels or inspecting plan names', () => {
    const result = validatePlanRevision(revision(), configured());
    expect(result.features).toEqual([grant]);
    expect(Object.isFrozen(result.features[0])).toBe(true);
    expect(validatePlanRevision(revision({ ...grant, enabled: false, value: null }), configured()).features[0])
      .toEqual({ ...grant, enabled: false, value: null });
  });
  it.each([undefined, null, '', ' option_b', 'unknown', 1])('rejects an enabled invalid value %j', value => {
    expect(() => validatePlanRevision(revision({ ...grant, value }), configured())).toThrow('value');
  });
  it('requires a domain even for disabled features and rejects silent default values', () => {
    expect(() => validatePlanRevision(revision(), { ...configured(), featureOptions: undefined })).toThrow('domain');
    expect(() => validatePlanRevision(revision({ ...grant, enabled: false }), configured())).toThrow('explicit null');
    expect(() => validatePlanRevision(revision({ ...grant, enabled: false, value: null }),
      { ...configured(), featureOptions: new Map() })).toThrow('domain');
  });
  it('rejects schema 1, numeric terms on enums and values on non-enum grants', () => {
    expect(() => validatePlanRevision({ ...revision(), schemaVersion: 1 }, configured())).toThrow('schema 2');
    expect(() => validatePlanRevision(revision({ ...grant, limit: { kind: 'finite', value: 1 } }), configured())).toThrow('numeric limit');
    expect(() => validatePlanRevision(revision({ key: 'course_lte_access', type: 'boolean', enabled: true, value: 'option_a' }), configured())).toThrow('only enum');
  });
});

describe('opaque plan identity', () => {
  it('generates independent generic identities in the existing UUID model', () => {
    const first = createPlanIdentity(productId), second = createPlanIdentity(productId);
    expect(first).toEqual(validatePlanIdentity(first));
    expect(first.code).toMatch(/^pln_[0-9a-f]{32}$/);
    expect(first.productId).toBe(productId);
    expect(first.id).not.toBe(second.id);
    expect(first.code).not.toBe(second.code);
    expect(Object.isFrozen(first)).toBe(true);
  });

  it.each(['hybrid', 'basic', 'school_starter', 'pln_123', code.toUpperCase(), ` ${code}`])('rejects non-generic authoring code %s', input => {
    expect(() => validatePlanIdentity({ id: planId, code: input, productId })).toThrow(CatalogValidationError);
  });

  it('rejects malformed identity and unexpected authoring fields', () => {
    expect(() => createPlanIdentity('not-a-product')).toThrow('plan.productId');
    expect(() => validatePlanIdentity({ id: planId, code, productId, tier: 'premium' })).toThrow('unsupported field');
    expect(() => validatePlanIdentity(null)).toThrow('plain object');
  });
});

describe('revision validation', () => {
  it.each(['audiences', 'prices', 'features'])('rejects sparse %s arrays through the validation contract', field => {
    expect(() => validatePlanRevision({ ...draft(), [field]: new Array(1) }, registry()))
      .toThrow(CatalogValidationError);
  });

  it('rejects missing audience elements alongside valid registered audiences', () => {
    const audiences = ['learner']; audiences.length = 2;
    expect(() => validatePlanRevision({ ...draft(), audiences }, registry())).toThrow(CatalogValidationError);
  });

  it('rejects missing nested price audience elements', () => {
    const input = draft(); input.prices[0].audiences.length = 2;
    expect(() => validatePlanRevision(input, registry())).toThrow(CatalogValidationError);
  });

  it('validates typed grants and minor-unit prices without interpreting the display name', () => {
    const input = draft(), result = validatePlanRevision(input, registry());
    expect(result.prices[0].amountMinor).toBe(250000);
    expect(result.features).toEqual(input.features);
    input.name = 'Renamed plan';
    expect(validatePlanRevision(input, registry()).features).toEqual(result.features);
  });

  it('returns a deep immutable detached value without freezing the caller', () => {
    const input = draft(), result = validatePlanRevision(input, registry());
    input.prices[0].amountMinor = 1;
    input.prices[0].audiences.push('college');
    input.features[1].limit!.value = 900;
    expect(result.prices[0].amountMinor).toBe(250000);
    expect(result.prices[0].audiences).toEqual(['learner']);
    expect(result.features[1]).toMatchObject({ limit: { value: 1 } });
    expect(Object.isFrozen(input)).toBe(false);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.features)).toBe(true);
    expect(Object.isFrozen(result.features[1])).toBe(true);
    const numeric = result.features[1];
    expect(numeric.type).toBe('numeric_limit');
    if (numeric.type !== 'numeric_limit') throw new Error('Expected numeric fixture');
    expect(Object.isFrozen(numeric.limit)).toBe(true);
    expect(Object.isFrozen(result.prices[0].audiences)).toBe(true);
  });

  it('supports configured audiences and currency precision without adding plan branches', () => {
    const context = registry();
    const input = draft();
    input.audiences = ['college']; input.prices[0].audiences = ['college'];
    input.prices[0].currency = 'JPY'; input.prices[0].minorUnit = 0;
    expect(validatePlanRevision(input, context).audiences).toEqual(['college']);
  });

  it('permits a deliberately configured free price rather than inferring a free plan', () => {
    const input = draft(); input.prices[0].amountMinor = 0;
    expect(validatePlanRevision(input, registry()).prices[0].amountMinor).toBe(0);
  });

  it('expresses free entry without fabricating billing or allowing negotiated limits', () => {
    const input = { ...draft(), purchaseMode: 'free', prices: [] };
    expect(validatePlanRevision(input, registry())).toMatchObject({ purchaseMode: 'free', prices: [] });
    expect(() => validatePlanRevision({ ...input, prices: draft().prices }, registry())).toThrow('free entry');
    expect(() => validatePlanRevision({ ...input, features: [{ key: 'learner_capacity', type: 'numeric_limit', enabled: true,
      limit: { kind: 'contract_required' } }] }, registry())).toThrow('contact sales');
  });

  it('permits explicitly sales-only proposals without inventing a checkout price', () => {
    const input = { ...draft(), purchaseMode: 'contact_sales', prices: [], features: [
      { key: 'learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'contract_required' } },
    ] };
    expect(validatePlanRevision(input, registry()).prices).toEqual([]);
  });

  it.each([NaN, Infinity, -1, 1.1, Number.MAX_SAFE_INTEGER + 1, '250000', null])('rejects invalid money %s', amountMinor => {
    const input = draft();
    expect(() => validatePlanRevision({ ...input, prices: [{ ...input.prices[0], amountMinor }] }, registry())).toThrow(CatalogValidationError);
  });

  it.each([
    { schemaVersion: 3 }, { revisionNumber: 0 }, { revisionNumber: 1.5 }, { name: '' },
    { audiences: [] }, { audiences: ['unknown'] }, { audiences: ['learner', 'learner'] },
    { prices: [] }, { purchaseMode: 'automatic' }, { unsupported: true },
    { plan: { id: planId, code, productId: priceId } },
  ])('rejects incomplete, unsupported or unregistered configuration %j', patch => {
    expect(() => validatePlanRevision({ ...draft(), ...patch }, registry())).toThrow(CatalogValidationError);
  });

  it.each([
    { minorUnit: 0 }, { currency: 'USD' }, { intervalCount: 0 }, { intervalUnit: 'week' },
    { quantityBasis: 'unknown' }, { audiences: ['college'] }, { audiences: [] },
  ])('rejects unsupported price terms %j', patch => {
    const input = draft();
    expect(() => validatePlanRevision({ ...input, prices: [{ ...input.prices[0], ...patch }] }, registry())).toThrow(CatalogValidationError);
  });

  it('rejects duplicate identities, overlapping prices and uncovered self-service audiences', () => {
    const input = draft(), second = { ...input.prices[0] };
    expect(() => validatePlanRevision({ ...input, prices: [...input.prices, second] }, registry())).toThrow('duplicate price identity');
    second.id = revisionId;
    expect(() => validatePlanRevision({ ...input, prices: [...input.prices, second] }, registry())).toThrow('ambiguous price scope');
    expect(() => validatePlanRevision({ ...input, audiences: ['learner', 'college'] }, registry())).toThrow('every self-service audience');
  });

  it.each([
    { key: 'unregistered', type: 'boolean', enabled: true },
    { key: 'ai_credits', type: 'boolean', enabled: true },
    { key: 'course_lte_access', type: 'boolean', enabled: 'yes' },
    { key: 'course_lte_access', type: 'boolean', enabled: true, limit: { kind: 'finite', value: 1 } },
    { key: 'ai_credits', type: 'metered', enabled: true },
    { key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'unlimited' } },
    { key: 'learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: -1 } },
    { key: 'learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'contract_required' } },
    { key: 'learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'unlimited', value: 0 } },
  ])('rejects invalid feature rules %j', rule => {
    expect(() => validatePlanRevision({ ...draft(), features: [rule] }, registry())).toThrow(CatalogValidationError);
  });

  it('distinguishes explicit unlimited numeric limits from omitted limits', () => {
    const rule = { key: 'learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'unlimited' } };
    expect(validatePlanRevision({ ...draft(), features: [rule] }, registry()).features[0]).toEqual(rule);
    expect(() => validatePlanRevision({ ...draft(), features: [{ ...rule, limit: {} }] }, registry())).toThrow();
  });

  it('rejects duplicate feature rules instead of using the last one', () => {
    const input = draft(); input.features.push(input.features[0]);
    expect(() => validatePlanRevision(input, registry())).toThrow('duplicate feature');
  });
});

describe('configured entry-plan selection', () => {
  const binding = { productId, audience: 'learner', planId };
  const candidate: EntryPlanCandidate = { id: planId, productId, audiences: ['learner'], isActive: true, publishedRevisionId: revisionId };

  it('selects the exact configured published reference without a display name or semantic code', () => {
    expect(selectEntryPlan(productId, 'learner', [binding], [candidate])).toEqual({ planId, revisionId });
  });

  it('rejects missing, duplicate or dangling configuration instead of guessing', () => {
    expect(() => selectEntryPlan(productId, 'learner', [], [candidate])).toThrow('exactly one');
    expect(() => selectEntryPlan(productId, 'learner', [binding, binding], [candidate])).toThrow('exactly one');
    expect(() => selectEntryPlan(productId, 'learner', [binding], [])).toThrow('resolve exactly once');
    expect(() => selectEntryPlan(productId, 'learner', [binding], [candidate, candidate])).toThrow('resolve exactly once');
  });

  it.each([
    { isActive: false }, { productId: revisionId }, { audiences: ['college'] }, { publishedRevisionId: '' },
  ])('rejects ineligible or unpublished candidates %j', patch => {
    expect(() => selectEntryPlan(productId, 'learner', [binding], [{ ...candidate, ...patch }])).toThrow(CatalogValidationError);
  });
});
