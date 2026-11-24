import { describe, expect, it } from 'vitest';
import { prepareIncludedCreditOccurrence } from '../lib/subscriptions';
import type { CreditPolicyRegistry } from '../lib/subscriptions/credit-policy';

// Isolated identities, never used against any database or test-account profile.
const productId = 'a1000000-0000-4000-8000-000000000001';
const planId = 'b2000000-0000-4000-8000-000000000001';
const revisionId = 'c3000000-0000-4000-8000-000000000001';
const policyId = 'd4000000-0000-4000-8000-000000000001';
const ruleId = 'e5000000-0000-4000-8000-000000000001';
const timeId = 'f6000000-0000-4000-8000-000000000001';
const subscriptionId = 'a7000000-0000-4000-8000-000000000001';
const recipientId = 'b8000000-0000-4000-8000-000000000001';
const otherId = 'c9000000-0000-4000-8000-000000000001';
const at = (value: string) => Date.parse(value);
const registry: CreditPolicyRegistry = {
  catalog: { productIds: new Set([productId]), audienceKeys: new Set(['learner']), currencies: new Map(),
    featureTypes: new Map([['ai_credits', 'metered']]) },
  pools: new Map([['personal_ai', { featureKey: 'ai_credits', recipient: 'subscriber', audiences: new Set(['learner']) }]]),
  timePolicyIds: new Set([timeId]), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set(),
};
function bundle(rulePatch: Record<string, unknown> = {}) {
  return { schemaVersion: 1, draft: { schemaVersion: 2, id: revisionId, revisionNumber: 1,
    plan: { id: planId, code: 'pln_c54a072e869d49bda36294389352c125', productId },
    name: 'Isolated fixture', audiences: ['learner'], purchaseMode: 'contact_sales', prices: [],
    features: [{ key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }],
  }, includedCredits: { schemaVersion: 1, id: policyId, revisionId, funding: 'included', rules: [{
    id: ruleId, featureKey: 'ai_credits', poolKey: 'personal_ai', recipient: 'subscriber', audiences: ['learner'],
    quantity: { kind: 'finite', value: 10 }, cadence: { kind: 'monthly', timePolicyId: timeId },
    expiry: { kind: 'allocation_period_end' }, rollover: { kind: 'none' }, ...rulePatch,
  }] } };
}
function context(patch: Record<string, unknown> = {}) {
  return { subscriptionId, productId, planId, revisionId, ruleId, audience: 'learner',
    recipient: { kind: 'subscriber', id: recipientId }, activatedAt: at('2026-01-31T12:34:56.789Z'),
    subscriptionEndsAt: at('2027-01-31T12:34:56.789Z'), periodStartsAt: at('2026-01-31T12:34:56.789Z'),
    periodEndsAt: at('2027-01-31T12:34:56.789Z'), occurrenceIndex: 0, ...patch };
}
function time(patch: Record<string, unknown> = {}) {
  return { id: timeId, timeZone: 'UTC', monthlyAnchor: 'subscription_anniversary', monthDayOverflow: 'clamp',
    ambiguousTime: 'reject', nonexistentTime: 'reject', ...patch };
}
function dates(activation: string, end = '2027-12-31T00:00:00Z') {
  return { activatedAt: at(activation), periodStartsAt: at(activation), periodEndsAt: at(end), subscriptionEndsAt: at(end) };
}
function prepare(options: { rule?: Record<string, unknown>; context?: Record<string, unknown>; time?: Record<string, unknown> } = {}) {
  return prepareIncludedCreditOccurrence(bundle(options.rule), registry, context(options.context), [time(options.time)]);
}

describe('included credit occurrence calendar', () => {
  it('uses calendar months independently of annual billing and preserves milliseconds', async () => {
    const result = await prepare();
    expect(result).toMatchObject({ quantity: 10, startsAt: at('2026-01-31T12:34:56.789Z'),
      endsAt: at('2026-02-28T12:34:56.789Z'), expiresAt: at('2026-02-28T12:34:56.789Z') });
    expect(result).not.toHaveProperty('authorized');
    expect(result).not.toHaveProperty('allocated');
  });

  it('anchors March to the original January anniversary rather than the clamped February day', async () => {
    const february = await prepare({ context: { occurrenceIndex: 1 } });
    const march = await prepare({ context: { occurrenceIndex: 2 } });
    expect(february.endsAt).toBe(at('2026-03-31T12:34:56.789Z'));
    expect(march.startsAt).toBe(february.endsAt);
  });

  it('handles leap-year anniversaries', async () => {
    const result = await prepare({ context: dates('2028-01-31T00:00:00Z', '2029-01-31T00:00:00Z') });
    expect(result.endsAt).toBe(at('2028-02-29T00:00:00Z'));
  });

  it('rejects absent anniversary days when the configured overflow policy rejects', async () => {
    await expect(prepare({ time: { monthDayOverflow: 'reject' } })).rejects.toThrow('anniversary day absent');
  });

  it('retains a partial initial calendar month without inventing prorated credits', async () => {
    const result = await prepare({ time: { monthlyAnchor: 'calendar_month_start', monthDayOverflow: 'reject' } });
    expect(result).toMatchObject({ quantity: 10, startsAt: at('2026-01-31T12:34:56.789Z'), endsAt: at('2026-02-01T00:00:00Z') });
    const next = await prepare({ time: { monthlyAnchor: 'calendar_month_start' }, context: { occurrenceIndex: 1 } });
    expect(next).toMatchObject({ startsAt: result.endsAt, endsAt: at('2026-03-01T00:00:00Z') });
  });

  it('resolves calendar month start in the configured zone rather than UTC', async () => {
    const result = await prepare({ time: { timeZone: 'Asia/Kolkata', monthlyAnchor: 'calendar_month_start' } });
    expect(result.endsAt).toBe(at('2026-01-31T18:30:00Z'));
  });

  it('retains local time across an ordinary DST offset change', async () => {
    const result = await prepare({ context: dates('2026-02-15T17:00:00Z'), time: { timeZone: 'America/New_York' } });
    expect(result.endsAt).toBe(at('2026-03-15T16:00:00Z'));
    expect(result.endsAt - result.startsAt).not.toBe(28 * 24 * 60 * 60 * 1000);
  });

  it('rejects a nonexistent local anniversary when explicitly configured', async () => {
    await expect(prepare({ context: dates('2026-02-08T07:30:00Z'), time: { timeZone: 'America/New_York' } }))
      .rejects.toThrow('nonexistent local occurrence');
  });

  it('shifts a spring-gap anniversary forward by the actual gap', async () => {
    const result = await prepare({ context: dates('2026-02-08T07:30:00Z'),
      time: { timeZone: 'America/New_York', nonexistentTime: 'shift_forward' } });
    expect(result.endsAt).toBe(at('2026-03-08T07:30:00Z'));
  });

  it.each([
    ['earlier', '2026-11-01T05:30:00Z'], ['later', '2026-11-01T06:30:00Z'],
  ])('uses the configured %s instant during an autumn overlap', async (ambiguousTime, expected) => {
    const result = await prepare({ context: dates('2026-10-01T05:30:00Z'), time: { timeZone: 'America/New_York', ambiguousTime } });
    expect(result.endsAt).toBe(at(expected));
  });

  it('rejects an ambiguous anniversary with the reject policy', async () => {
    await expect(prepare({ context: dates('2026-10-01T05:30:00Z'), time: { timeZone: 'America/New_York' } }))
      .rejects.toThrow('ambiguous local occurrence');
  });

  it('supports a half-hour transition rather than assuming all DST gaps are one hour', async () => {
    const result = await prepare({ context: dates('2025-09-04T15:45:00Z'),
      time: { timeZone: 'Australia/Lord_Howe', nonexistentTime: 'shift_forward' } });
    expect(result.endsAt).toBe(at('2025-10-04T15:45:00Z'));
  });

  it('handles a full-day date-line gap using the explicit shift policy', async () => {
    const result = await prepare({ context: dates('2011-11-30T22:00:00Z'),
      time: { timeZone: 'Pacific/Apia', nonexistentTime: 'shift_forward' } });
    expect(result.endsAt).toBe(at('2011-12-30T22:00:00Z'));
  });

  it('caps a final recurring allocation period at subscription end', async () => {
    const result = await prepare({ context: { periodEndsAt: at('2026-02-10T00:00:00Z'), subscriptionEndsAt: at('2026-02-10T00:00:00Z') } });
    expect(result.endsAt).toBe(at('2026-02-10T00:00:00Z'));
    expect(result.expiresAt).toBe(result.endsAt);
    await expect(prepare({ context: { occurrenceIndex: 12 } })).rejects.toThrow('outside the subscription');
  });

  it('uses the loaded subscription period for period allocations', async () => {
    const result = await prepare({ rule: { cadence: { kind: 'subscription_period' } }, context: {
      periodStartsAt: at('2026-07-31T00:00:00Z'), periodEndsAt: at('2026-08-31T00:00:00Z'),
    } });
    expect(result).toMatchObject({ startsAt: at('2026-07-31T00:00:00Z'), endsAt: at('2026-08-31T00:00:00Z'), expiresAt: at('2026-08-31T00:00:00Z') });
  });

  it('keeps one activation allocation independent of subsequent billing periods', async () => {
    const options = { rule: { cadence: { kind: 'activation' }, expiry: { kind: 'subscription_end' } } };
    const first = await prepare(options);
    const later = await prepare({ ...options, context: { periodStartsAt: at('2026-07-31T00:00:00Z') } });
    expect(later).toEqual(first);
    expect(first.expiresAt).toBe(context().subscriptionEndsAt);
  });

  it('calculates relative expiry from allocation start without substituting subscription end', async () => {
    const result = await prepare({ rule: { expiry: { kind: 'after_months', months: 6, timePolicyId: timeId } } });
    expect(result.expiresAt).toBe(at('2026-07-31T12:34:56.789Z'));
    expect(result.expiresAt).toBeGreaterThan(result.endsAt);
  });

  it('can bind a separate calendar definition for relative expiry', async () => {
    const input = bundle({ expiry: { kind: 'after_months', months: 1, timePolicyId: otherId } });
    const result = await prepareIncludedCreditOccurrence(input, { ...registry, timePolicyIds: new Set([timeId, otherId]) }, context(),
      [time(), time({ id: otherId, timeZone: 'Asia/Kolkata', monthlyAnchor: 'calendar_month_start' })]);
    expect(result.timePolicies.map(item => item.id)).toEqual([otherId, timeId]);
    expect(result.expiresAt).toBe(at('2026-02-28T12:34:56.789Z'));
  });
});

describe('allocation identity and strict boundary', () => {
  it('returns a deterministic bounded ledger reference and detached frozen values', async () => {
    const input = bundle(), definitions = [time()];
    const first = await prepareIncludedCreditOccurrence(input, registry, context(), definitions);
    const second = await prepare();
    expect(first).toEqual(second);
    expect(first.referenceId).toMatch(/^sc1_[a-f0-9]{64}$/);
    input.includedCredits.rules[0].quantity.value = 999;
    definitions[0].timeZone = 'America/New_York';
    expect(first.quantity).toBe(10);
    expect(first.timePolicies[0].timeZone).toBe('UTC');
    for (const value of [first, first.recipient, first.timePolicies, first.timePolicies[0]]) expect(Object.isFrozen(value)).toBe(true);
  });

  it('keeps zero explicit and does not turn it into unlimited or a positive allocation', async () => {
    expect((await prepare({ rule: { quantity: { kind: 'finite', value: 0 } } })).quantity).toBe(0);
  });

  it.each([
    { occurrenceIndex: 1 }, { subscriptionId: otherId }, { recipient: { kind: 'subscriber', id: otherId } },
  ])('isolates occurrence references for changed ownership or period %j', async patch => {
    expect((await prepare({ context: patch })).referenceId).not.toBe((await prepare()).referenceId);
  });

  it('separates recurring subscription periods in the ledger reference', async () => {
    const first = await prepare({ rule: { cadence: { kind: 'subscription_period' } } });
    const second = await prepare({ rule: { cadence: { kind: 'subscription_period' } }, context: { periodStartsAt: at('2026-04-01T00:00:00Z') } });
    expect(first.referenceId).not.toBe(second.referenceId);
  });

  it.each(['revision', 'policy', 'rule'])('binds the canonical %s identity', async kind => {
    const input = bundle(), scope = context();
    if (kind === 'revision') {
      input.draft.id = otherId; input.includedCredits.revisionId = otherId; scope.revisionId = otherId;
    } else if (kind === 'policy') input.includedCredits.id = otherId;
    else { input.includedCredits.rules[0].id = otherId; scope.ruleId = otherId; }
    const result = await prepareIncludedCreditOccurrence(input, registry, scope, [time()]);
    expect(result.referenceId).not.toBe((await prepare()).referenceId);
  });

  it('normalizes UUID casing before deriving identity', async () => {
    const input = bundle(); input.draft.id = input.draft.id.toUpperCase();
    const first = await prepareIncludedCreditOccurrence(input, registry, context({ revisionId: revisionId.toUpperCase(),
      subscriptionId: subscriptionId.toUpperCase(), recipient: { kind: 'subscriber', id: recipientId.toUpperCase() } }), [time()]);
    expect(first.referenceId).toBe((await prepare()).referenceId);
  });

  it('does not mint a new identity when mutable quantity or calendar content changes', async () => {
    const first = await prepare();
    const quantity = await prepare({ rule: { quantity: { kind: 'finite', value: 20 } } });
    const calendar = await prepare({ time: { monthlyAnchor: 'calendar_month_start' } });
    expect(quantity.referenceId).toBe(first.referenceId);
    expect(quantity.quantity).not.toBe(first.quantity);
    expect(calendar.referenceId).toBe(first.referenceId);
    expect(calendar.endsAt).not.toBe(first.endsAt);
    // The future atomic writer must reject both changed receipts on replay of this identity.
  });

  it.each([
    { subscriptionId: 'invalid' }, { productId: otherId }, { planId: otherId }, { revisionId: otherId },
    { ruleId: otherId }, { audience: 'school' }, { recipient: { kind: 'organization', id: recipientId } },
    { recipient: { kind: 'subscriber', id: 'invalid' } }, { recipient: { kind: 'subscriber', id: recipientId, authorized: true } },
    { occurrenceIndex: -1 }, { occurrenceIndex: 0.5 }, { occurrenceIndex: Number.MAX_SAFE_INTEGER },
    { activatedAt: Number.NaN }, { activatedAt: -1 }, { activatedAt: 0.1 },
    { periodStartsAt: 0 }, { periodEndsAt: 0 }, { subscriptionEndsAt: 0 },
    { subscriptionEndsAt: 8640000000000001 }, { authorized: true }, { ready: true },
  ])('rejects malformed, mismatched or fabricated owner context %j', async patch => {
    await expect(prepare({ context: patch })).rejects.toThrow();
  });

  it.each(['activation', 'subscription_period'])('rejects nonzero occurrence index for %s', async kind => {
    await expect(prepare({ rule: { cadence: { kind }, expiry: { kind: 'subscription_end' } }, context: { occurrenceIndex: 1 } }))
      .rejects.toThrow('only monthly cadence');
  });

  it('rejects unresolved negotiated quantities rather than guessing a usable allocation', async () => {
    await expect(prepare({ rule: { quantity: { kind: 'contract_required' } } })).rejects.toThrow('must be resolved');
  });

  it('retains explicit rollover approval without converting it into an allocation or removing expiry', async () => {
    const input = bundle({ rollover: { kind: 'approved', approvalId: otherId } });
    const result = await prepareIncludedCreditOccurrence(input, { ...registry, rolloverApprovalIds: new Set([otherId]) }, context(), [time()]);
    expect(result.rollover).toEqual({ kind: 'approved', approvalId: otherId });
    expect(Object.isFrozen(result.rollover)).toBe(true);
    expect(result.expiresAt).toBe(result.endsAt);
  });

  it('rejects missing and duplicate calendar definitions', async () => {
    await expect(prepareIncludedCreditOccurrence(bundle(), registry, context(), [])).rejects.toThrow('missing registered');
    await expect(prepareIncludedCreditOccurrence(bundle(), registry, context(), [time(), time()])).rejects.toThrow('duplicate time policy');
  });

  it.each([
    { timeZone: 'Invalid/Zone' }, { timeZone: '+05:30' }, { ambiguousTime: 'guess' },
    { nonexistentTime: 'earlier' }, { monthlyAnchor: 'billing' }, { monthDayOverflow: 'roll' }, { extra: true },
  ])('uses the authoritative calendar validator and rejects invalid configuration %j', async patch => {
    await expect(prepare({ time: patch })).rejects.toThrow();
  });
});
