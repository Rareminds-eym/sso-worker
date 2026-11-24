import { describe, expect, it } from 'vitest';
import { CatalogValidationError, validateCreditAllocationPolicy, type CreditPolicyRegistry } from '../lib/subscriptions';

const productId = '912d5049-e195-46e9-a319-49e3502bf7e7';
const planId = 'a0000000-0000-4000-8000-000000000041';
const revisionId = 'b0000000-0000-4000-8000-000000000001';
const policyId = 'c0000000-0000-4000-8000-000000000001';
const timeId = 'd0000000-0000-4000-8000-000000000001';
const approvalId = 'e0000000-0000-4000-8000-000000000001';
const ruleId = 'f0000000-0000-4000-8000-000000000001';
const secondId = 'f0000000-0000-4000-8000-000000000002';

function revision() {
  return {
    schemaVersion: 1, id: revisionId, revisionNumber: 1,
    plan: { id: planId, code: 'pln_8f3d2c6a91b74e50b5a36d02c7e8a419', productId },
    name: 'Editable institution proposal', audiences: ['college'], purchaseMode: 'contact_sales', prices: [],
    features: [{ key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'contract_required' } }],
  };
}
function registry(): CreditPolicyRegistry {
  return {
    catalog: {
      productIds: new Set([productId]), audienceKeys: new Set(['college', 'school', 'learner']), currencies: new Map(),
      featureTypes: new Map([['ai_credits', 'metered'], ['capacity', 'numeric_limit']]),
    },
    pools: new Map([
      ['admin_ai', { featureKey: 'ai_credits', recipient: 'organization', audiences: new Set(['college', 'school']) }],
      ['learner_ai', { featureKey: 'ai_credits', recipient: 'managed_learner', audiences: new Set(['college']) }],
      ['personal_ai', { featureKey: 'ai_credits', recipient: 'subscriber', audiences: new Set(['learner']) }],
    ]),
    timePolicyIds: new Set([timeId]), rolloverApprovalIds: new Set([approvalId]), expiryApprovalIds: new Set([approvalId]),
  };
}
function rule() {
  return {
    id: ruleId, featureKey: 'ai_credits', poolKey: 'admin_ai', recipient: 'organization', audiences: ['college'],
    quantity: { kind: 'finite', value: 5000 }, cadence: { kind: 'subscription_period' },
    expiry: { kind: 'subscription_end' }, rollover: { kind: 'none' },
  };
}
function policy() { return { schemaVersion: 1, id: policyId, revisionId, funding: 'included', rules: [rule()] }; }
function topUp() {
  return { ...policy(), funding: 'top_up', rules: [{
    ...rule(), cadence: { kind: 'purchase' }, expiry: { kind: 'after_months', months: 6, timePolicyId: timeId },
  }] };
}
function validate(value: unknown) { return validateCreditAllocationPolicy(value, revision(), registry()); }

describe('revision-bound credit allocation authoring', () => {
  it('represents ten monthly learner credits without rollover independently of the billing interval', () => {
    const input = { ...policy(), rules: [{ ...rule(), poolKey: 'personal_ai', recipient: 'subscriber', audiences: ['learner'],
      quantity: { kind: 'finite', value: 10 }, cadence: { kind: 'monthly', timePolicyId: timeId },
      expiry: { kind: 'allocation_period_end' },
    }] };
    const annualRevision = { ...revision(), audiences: ['learner'], purchaseMode: 'self_service',
      features: [{ ...revision().features[0], limit: { kind: 'finite', value: 10 } }],
      prices: [{ id: secondId, currency: 'INR', minorUnit: 2, amountMinor: 250000,
        intervalUnit: 'year', intervalCount: 1, quantityBasis: 'subscription', audiences: ['learner'] }],
    };
    const context = registry();
    const result = validateCreditAllocationPolicy(input, annualRevision, {
      ...context, catalog: { ...context.catalog, currencies: new Map([['INR', 2]]) },
    });
    expect(annualRevision.prices[0]).toMatchObject({ intervalUnit: 'year', intervalCount: 1 });
    expect(result.rules[0]).toMatchObject({ recipient: 'subscriber', quantity: { value: 10 },
      cadence: { kind: 'monthly', timePolicyId: timeId }, expiry: { kind: 'allocation_period_end' }, rollover: { kind: 'none' } });
  });

  it('represents an institution admin pool plus monthly credits per managed learner separately', () => {
    const input = { ...policy(), rules: [rule(), {
      ...rule(), id: secondId, poolKey: 'learner_ai', recipient: 'managed_learner',
      quantity: { kind: 'finite', value: 3 }, cadence: { kind: 'monthly', timePolicyId: timeId },
      expiry: { kind: 'allocation_period_end' },
    }] };
    const result = validate(input);
    expect(result.rules.map(item => [item.recipient, item.quantity, item.cadence.kind]))
      .toEqual([['organization', { kind: 'finite', value: 5000 }, 'subscription_period'],
        ['managed_learner', { kind: 'finite', value: 3 }, 'monthly']]);
    expect(result.rules[1].expiry).toEqual({ kind: 'allocation_period_end' });
  });

  it('returns detached deeply frozen values and does not modify the caller', () => {
    const input = policy(), result = validate(input);
    input.rules[0].quantity.value = 1; input.rules[0].audiences.push('school');
    expect(result.rules[0].quantity).toEqual({ kind: 'finite', value: 5000 });
    expect(result.rules[0].audiences).toEqual(['college']);
    for (const item of [result, result.rules, result.rules[0], result.rules[0].quantity,
      result.rules[0].cadence, result.rules[0].expiry, result.rules[0].rollover, result.rules[0].audiences]) {
      expect(Object.isFrozen(item)).toBe(true);
    }
    expect(Object.isFrozen(input)).toBe(false);
  });

  it('retains explicit zero quantity in included configuration', () => {
    expect(validate({ ...policy(), rules: [{ ...rule(), quantity: { kind: 'finite', value: 0 } }] }).rules[0].quantity)
      .toEqual({ kind: 'finite', value: 0 });
  });

  it('accepts the maximum quantity supported by one existing ledger amount', () => {
    expect(validate({ ...policy(), rules: [{ ...rule(), quantity: { kind: 'finite', value: 2147483647 } }] }).rules[0].quantity)
      .toEqual({ kind: 'finite', value: 2147483647 });
  });

  it('rejects a safe JavaScript integer exceeding existing ledger storage capacity', () => {
    expect(() => validate({ ...policy(), rules: [{ ...rule(), quantity: { kind: 'finite', value: 2147483648 } }] }))
      .toThrow('creditPolicy.rules[0].quantity.value: quantity exceeds existing ledger integer capacity');
  });

  it('permits an explicit empty included policy when there are no enabled metered features', () => {
    expect(validateCreditAllocationPolicy({ ...policy(), rules: [] }, { ...revision(), features: [] }, registry()).rules).toEqual([]);
  });

  it('allows unresolved negotiated quantities only as contact-sales authoring terms', () => {
    const input = { ...policy(), rules: [{ ...rule(), quantity: { kind: 'contract_required' } }] };
    expect(validate(input).rules[0].quantity).toEqual({ kind: 'contract_required' });
    const paid = { ...revision(), purchaseMode: 'self_service', features: [{ ...revision().features[0], limit: { kind: 'finite', value: 1 } }],
      prices: [{ id: secondId, currency: 'INR', minorUnit: 2, amountMinor: 0, intervalUnit: 'year', intervalCount: 1, quantityBasis: 'subscription', audiences: ['college'] }] };
    const context = registry(); const catalog = { ...context.catalog, currencies: new Map([['INR', 2]]) };
    expect(() => validateCreditAllocationPolicy(input, paid, { ...context, catalog }))
      .toThrow('unresolved quantity requires contact sales');
  });

  it.each([
    { schemaVersion: 2 }, { revisionId: secondId }, { id: 'invalid' }, { funding: 'guessed' }, { extra: true },
  ])('rejects invalid policy identity/schema/funding %j', patch => {
    expect(() => validate({ ...policy(), ...patch })).toThrow(CatalogValidationError);
  });

  it.each([
    { featureKey: 'missing' }, { featureKey: 'capacity' }, { poolKey: 'missing' }, { poolKey: 'learner_ai' },
    { recipient: 'subscriber' }, { audiences: [] }, { audiences: ['school'] }, { audiences: ['college', 'college'] },
    { quantity: { kind: 'unlimited' } }, { quantity: { kind: 'finite', value: -1 } },
    { quantity: { kind: 'finite', value: 1.2 } }, { quantity: { kind: 'finite', value: Number.MAX_SAFE_INTEGER + 1 } },
    { quantity: { kind: 'contract_required', value: 1 } },
    { cadence: { kind: 'monthly' } }, { cadence: { kind: 'monthly', timePolicyId: secondId } },
    { cadence: { kind: 'activation', timePolicyId: timeId } }, { cadence: { kind: 'purchase' } },
    { expiry: { kind: 'after_months', months: 6 } }, { expiry: { kind: 'after_months', months: 0, timePolicyId: timeId } },
    { expiry: { kind: 'subscription_end', months: 1 } }, { rollover: { kind: 'approved' } },
    { rollover: { kind: 'approved', approvalId: secondId } }, { rollover: { kind: 'none', approvalId } },
    { expiryApprovalId: approvalId }, { extra: 'unsupported' },
  ])('rejects invalid or incomplete rule configuration %j', patch => {
    expect(() => validate({ ...policy(), rules: [{ ...rule(), ...patch }] })).toThrow(CatalogValidationError);
  });

  it('rejects rules for a feature disabled by the supplied revision', () => {
    expect(() => validateCreditAllocationPolicy(policy(), { ...revision(), features: [{ ...revision().features[0], enabled: false }] }, registry()))
      .toThrow('enabled registered metered feature');
  });

  it('requires pool audience eligibility as well as revision audience eligibility', () => {
    const context = registry();
    const pools = new Map(context.pools); pools.set('admin_ai', { featureKey: 'ai_credits', recipient: 'organization', audiences: new Set(['school']) });
    expect(() => validateCreditAllocationPolicy(policy(), revision(), { ...context, pools })).toThrow('pool eligible audiences');
  });

  it('rejects duplicate rule IDs and overlapping feature/pool/audience scopes', () => {
    expect(() => validate({ ...policy(), rules: [rule(), rule()] })).toThrow('duplicate allocation rule identity');
    expect(() => validate({ ...policy(), rules: [rule(), { ...rule(), id: secondId, cadence: { kind: 'activation' } }] }))
      .toThrow('overlapping allocation scope');
  });

  it('requires explicit included terms for every enabled metered feature and eligible audience', () => {
    expect(() => validate({ ...policy(), rules: [] })).toThrow('requires included terms');
    expect(() => validateCreditAllocationPolicy(policy(), { ...revision(), audiences: ['college', 'school'] }, registry()))
      .toThrow('requires included terms');
  });

  it('rejects sparse rules and nested audience arrays with validation errors', () => {
    expect(() => validate({ ...policy(), rules: new Array(1) })).toThrow(CatalogValidationError);
    const input = policy(); input.rules[0].audiences.length = 2;
    expect(() => validate(input)).toThrow(CatalogValidationError);
  });

  it('requires a recurring period for allocation-period expiry', () => {
    expect(() => validate({ ...policy(), rules: [{ ...rule(), cadence: { kind: 'activation' }, expiry: { kind: 'allocation_period_end' } }] }))
      .toThrow('period expiry requires a recurring');
  });

  it('accepts registered rollover approval without inventing rollover quantities', () => {
    expect(validate({ ...policy(), rules: [{ ...rule(), rollover: { kind: 'approved', approvalId } }] }).rules[0].rollover)
      .toEqual({ kind: 'approved', approvalId });
  });

  it('does not use an expiry approval as registration for rollover approval', () => {
    const input = { ...policy(), rules: [{ ...rule(), rollover: { kind: 'approved', approvalId } }] };
    const context = { ...registry(), rolloverApprovalIds: new Set<string>() };
    expect(() => validateCreditAllocationPolicy(input, revision(), context))
      .toThrow('creditPolicy.rules[0].rollover.approvalId: unregistered policy or approval reference');
  });

  it('does not use a commercial approval as registration for a time policy', () => {
    const input = { ...policy(), rules: [{ ...rule(), cadence: { kind: 'monthly', timePolicyId: approvalId } }] };
    expect(() => validate(input))
      .toThrow('creditPolicy.rules[0].cadence.timePolicyId: unregistered policy or approval reference');
  });
});

describe('top-up configuration', () => {
  it('requires explicit purchase funding, purchase cadence and six-month expiry', () => {
    const result = validate(topUp());
    expect(result.funding).toBe('top_up');
    expect(result.rules[0].expiry).toEqual({ kind: 'after_months', months: 6, timePolicyId: timeId });
  });

  it.each([
    { cadence: { kind: 'activation' } }, { expiry: { kind: 'subscription_end' } },
    { expiry: { kind: 'after_months', months: 3, timePolicyId: timeId } },
    { quantity: { kind: 'finite', value: 0 } }, { expiryApprovalId: secondId },
  ])('rejects incomplete or unapproved purchased terms %j', patch => {
    expect(() => validate({ ...topUp(), rules: [{ ...topUp().rules[0], ...patch }] })).toThrow(CatalogValidationError);
  });

  it('rejects an empty top-up candidate policy', () => {
    expect(() => validate({ ...topUp(), rules: [] })).toThrow('requires an allocation rule');
  });

  it('accepts a changed expiry with a registered expiry approval reference', () => {
    const result = validate({ ...topUp(), rules: [{ ...topUp().rules[0],
      expiry: { kind: 'after_months', months: 9, timePolicyId: timeId }, expiryApprovalId: approvalId,
    }] });
    expect(result.rules[0].expiryApprovalId).toBe(approvalId);
  });

  it('does not use a rollover approval as registration for expiry approval', () => {
    const input = { ...topUp(), rules: [{ ...topUp().rules[0],
      expiry: { kind: 'after_months', months: 9, timePolicyId: timeId }, expiryApprovalId: approvalId,
    }] };
    const context = { ...registry(), expiryApprovalIds: new Set<string>() };
    expect(() => validateCreditAllocationPolicy(input, revision(), context))
      .toThrow('creditPolicy.rules[0].expiryApprovalId: unregistered policy or approval reference');
  });
});
