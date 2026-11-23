import { describe, expect, it } from 'vitest';
import { prepareIncludedCreditRefresh } from '../lib/subscriptions/credit-occurrences';
import type { CreditPolicyRegistry } from '../lib/subscriptions/credit-policy';

const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const at = Date.parse;
const registry: CreditPolicyRegistry = {
  catalog: { productIds: new Set([id(1)]), audienceKeys: new Set(['synthetic']), currencies: new Map(),
    featureTypes: new Map([['synthetic_credits', 'metered']]) },
  pools: new Map([['synthetic_pool', { featureKey: 'synthetic_credits', recipient: 'subscriber', audiences: new Set(['synthetic']) }]]),
  timePolicyIds: new Set([id(6)]), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set(),
};
const bundle = (patch: Record<string, unknown> = {}) => ({ schemaVersion: 1,
  draft: { schemaVersion: 2, id: id(3), revisionNumber: 1, plan: { id: id(2), productId: id(1), code: 'pln_' + 'a'.repeat(32) },
    name: 'Synthetic refresh', audiences: ['synthetic'], purchaseMode: 'contact_sales', prices: [],
    features: [{ key: 'synthetic_credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }] },
  includedCredits: { schemaVersion: 1, id: id(4), revisionId: id(3), funding: 'included', rules: [{
    id: id(5), featureKey: 'synthetic_credits', poolKey: 'synthetic_pool', recipient: 'subscriber', audiences: ['synthetic'],
    quantity: { kind: 'finite', value: 10 }, cadence: { kind: 'monthly', timePolicyId: id(6) },
    expiry: { kind: 'allocation_period_end' }, rollover: { kind: 'none' }, ...patch,
  }] } });
const context = (patch: Record<string, unknown> = {}) => ({ productId: id(1), planId: id(2), revisionId: id(3),
  subscriptionId: id(7), ruleId: id(5), audience: 'synthetic', recipient: { kind: 'subscriber', id: id(8) },
  activatedAt: at('2026-01-31T12:34:56.789Z'), subscriptionEndsAt: at('2027-01-31T12:34:56.789Z'),
  periodStartsAt: at('2026-01-31T12:34:56.789Z'), periodEndsAt: at('2027-01-31T12:34:56.789Z'),
  now: at('2026-03-31T12:34:56.789Z'), cursor: 0, ...patch });
const calendar = (patch: Record<string, unknown> = {}) => [{ id: id(6), timeZone: 'UTC', monthlyAnchor: 'subscription_anniversary',
  monthDayOverflow: 'clamp', ambiguousTime: 'reject', nonexistentTime: 'reject', ...patch }];

describe('bounded included credit refresh preparation, no allocation authority', () => {
  it('skips expired months, includes the exact due instant and stops before future grants', async () => {
    const page = await prepareIncludedCreditRefresh(bundle(), registry, context(), calendar());
    expect(page.occurrences).toHaveLength(1);
    expect(page.occurrences[0]).toMatchObject({ startsAt: context().now, quantity: 10, endsAt: at('2026-04-30T12:34:56.789Z') });
    expect(page.nextCursor).toBeNull();
  });
  it('uses the same deterministic references on exact repeated refresh', async () => {
    const a = await prepareIncludedCreditRefresh(bundle(), registry, context(), calendar());
    expect(await prepareIncludedCreditRefresh(bundle(), registry, context(), calendar())).toEqual(a);
  });
  it('retains multiple still-valid past allocations only when published expiry allows them', async () => {
    const page = await prepareIncludedCreditRefresh(bundle({ expiry: { kind: 'subscription_end' } }), registry, context(), calendar());
    expect(page.occurrences.map(x => x.startsAt)).toEqual([at('2026-01-31T12:34:56.789Z'), at('2026-02-28T12:34:56.789Z'), context().now]);
    expect(new Set(page.occurrences.map(x => x.referenceId)).size).toBe(3);
  });
  it('uses local calendar-month boundaries rather than a fixed duration', async () => {
    const page = await prepareIncludedCreditRefresh(bundle(), registry,
      context({ now: at('2026-03-31T18:30:00Z') }), calendar({ timeZone: 'Asia/Kolkata', monthlyAnchor: 'calendar_month_start' }));
    expect(page.occurrences).toHaveLength(1);
    expect(page.occurrences[0].startsAt).toBe(at('2026-03-31T18:30:00Z'));
  });
  it('returns no newly allocatable credit at exact subscription expiry', async () => {
    expect((await prepareIncludedCreditRefresh(bundle(), registry, context({ now: context().subscriptionEndsAt }), calendar())).occurrences).toEqual([]);
  });
  it('bounds a long catch-up and returns an advancing cursor without duplicate references', async () => {
    const terms = context({ activatedAt: at('2020-01-01T00:00:00Z'), periodStartsAt: at('2020-01-01T00:00:00Z'),
      subscriptionEndsAt: at('2030-01-01T00:00:00Z'), periodEndsAt: at('2030-01-01T00:00:00Z'), now: at('2026-01-01T00:00:00Z') });
    const retained = bundle({ expiry: { kind: 'subscription_end' } });
    const first = await prepareIncludedCreditRefresh(retained, registry, terms, calendar());
    expect(first.occurrences).toHaveLength(50); expect(first.nextCursor).toBe(50);
    const next = await prepareIncludedCreditRefresh(retained, registry, { ...terms, cursor: first.nextCursor }, calendar());
    expect(next.occurrences).toHaveLength(23); expect(next.nextCursor).toBeNull();
    expect(new Set([...first.occurrences, ...next.occurrences].map(x => x.referenceId)).size).toBe(73);
  });
  it.each(['activation', 'subscription_period'])('refreshes %s cadence once and rejects a fabricated continuation', async kind => {
    const source = bundle({ cadence: { kind }, expiry: { kind: 'subscription_end' } });
    const page = await prepareIncludedCreditRefresh(source, registry, context(), calendar());
    expect(page.occurrences).toHaveLength(1); expect(page.nextCursor).toBeNull();
    await expect(prepareIncludedCreditRefresh(source, registry, context({ cursor: 1 }), calendar())).rejects.toThrow('nonrecurring');
  });
  it.each([{ cursor: -1 }, { cursor: 0.5 }, { cursor: Number.MAX_SAFE_INTEGER + 1 }, { now: 0 },
    { productId: id(99) }, { ruleId: id(99) }, { recipient: { kind: 'organization', id: id(8) } }, { amount: 999 }])('rejects malformed or foreign context %j', async patch => {
    await expect(prepareIncludedCreditRefresh(bundle(), registry, context(patch), calendar())).rejects.toThrow();
  });
});
