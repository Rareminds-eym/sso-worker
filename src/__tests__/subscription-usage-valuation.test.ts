import { describe, expect, it } from 'vitest';
import { validateCommerceUsagePolicy, valuePaidServiceUsage } from '../lib/subscriptions/usage-valuation';
import type { CommerceQuote, CommerceSettlement } from '../lib/subscriptions/commerce';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const quote: CommerceQuote = { id: id(1), actorId: id(2), subscriptionId: id(3), productId: id(4),
  subject: { kind: 'user', id: id(2) }, audience: 'synthetic', stateVersion: 0, expectedRevisionId: id(5),
  planId: id(6), revisionId: id(5), purpose: 'purchase', referenceId: null, priceId: id(7),
  amountMinor: 101, currency: 'INR', minorUnit: 2, periodStartsAt: 1000, periodEndsAt: 2000, createdAt: 1000, validUntil: 1500 };
const settled: CommerceSettlement = { id: id(8), quoteId: quote.id, subscriptionId: quote.subscriptionId,
  productId: quote.productId, subject: quote.subject, purpose: 'purchase', referenceId: null,
  providerPaymentId: 'pay_synthetic', amountMinor: 101, currency: 'INR', settledAt: 1000 };

describe('purchase-attributed monetary usage', () => {
  it('requires an explicit single retained basis and rejects inferred credit conversion', () => {
    for (const basis of ['time_proportional_service', 'recorded_usage']) expect(validateCommerceUsagePolicy({ schemaVersion: 1, basis }).basis).toBe(basis);
    for (const policy of [undefined, {}, { schemaVersion: 2, basis: 'recorded_usage' }, { schemaVersion: 1, basis: 'credits' },
      { schemaVersion: 1, basis: 'recorded_usage', unitCost: 1 }]) expect(() => validateCommerceUsagePolicy(policy)).toThrow();
  });
  it('values only elapsed paid coverage, floors once and caps at actual payment', () => {
    expect(valuePaidServiceUsage(quote, settled, 1000)).toBe(0);
    expect(valuePaidServiceUsage(quote, settled, 1500)).toBe(50);
    expect(valuePaidServiceUsage(quote, settled, 1999)).toBe(100);
    expect(valuePaidServiceUsage(quote, settled, 2000)).toBe(101);
    expect(valuePaidServiceUsage(quote, settled, 5000)).toBe(101);
  });
  it('does not retroactively value upgrade service before the paid amendment', () => {
    const q = { ...quote, purpose: 'upgrade' as const };
    const s = { ...settled, purpose: 'upgrade' as const, settledAt: 1500 };
    expect(valuePaidServiceUsage(q, s, 1500)).toBe(0);
    expect(valuePaidServiceUsage(q, s, 1750)).toBe(50);
  });
  it('uses exact integer arithmetic even when the intermediate product exceeds safe numbers', () => {
    const q = { ...quote, amountMinor: Number.MAX_SAFE_INTEGER, periodStartsAt: 0, periodEndsAt: Number.MAX_SAFE_INTEGER };
    const s = { ...settled, amountMinor: q.amountMinor, settledAt: 0 };
    expect(valuePaidServiceUsage(q, s, Number.MAX_SAFE_INTEGER - 1)).toBe(Number.MAX_SAFE_INTEGER - 1);
  });
  it('rejects foreign purchases, currencies, invalid coverage, unsafe money and prepayment cutoffs', () => {
    for (const s of [{ ...settled, quoteId: id(90) }, { ...settled, productId: id(90) }, { ...settled, subject: { kind: 'user' as const, id: id(90) } },
      { ...settled, currency: 'USD' }, { ...settled, amountMinor: 100 }, { ...settled, amountMinor: Number.MAX_SAFE_INTEGER + 1 }, { ...settled, purpose: 'retake' as const }]) {
      expect(() => valuePaidServiceUsage(quote, s, 1500)).toThrow();
    }
    expect(() => valuePaidServiceUsage({ ...quote, periodEndsAt: 1000 }, settled, 1500)).toThrow();
    expect(() => valuePaidServiceUsage(quote, settled, 999)).toThrow();
  });
});
