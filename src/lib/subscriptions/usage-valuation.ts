import { choice, integer, invalid, record } from './validation';
import type { CommerceQuote, CommerceSettlement } from './commerce';

/** These bases are mutually exclusive: bundled credits are never converted to money. */
export interface CommerceUsagePolicy {
  schemaVersion: 1;
  basis: 'time_proportional_service' | 'recorded_usage';
}

export function validateCommerceUsagePolicy(value: unknown): CommerceUsagePolicy {
  const policy = record(value, 'commerce.usagePolicy', ['schemaVersion', 'basis']);
  if (policy.schemaVersion !== 1) invalid('commerce.usagePolicy', 'unsupported version');
  return { schemaVersion: 1, basis: choice(policy.basis, 'commerce.usagePolicy.basis', ['time_proportional_service', 'recorded_usage']) };
}

/** Exact rational arithmetic floors once at the minor currency unit boundary. */
export function valuePaidServiceUsage(quote: CommerceQuote, settlement: CommerceSettlement, throughAt: number): number {
  const paid = integer(settlement.amountMinor, 'commerce.usage.paidMinor', 1);
  const at = integer(throughAt, 'commerce.usage.throughAt');
  if (settlement.purpose === 'retake' || settlement.quoteId !== quote.id || settlement.subscriptionId !== quote.subscriptionId
    || settlement.productId !== quote.productId || settlement.currency !== quote.currency || paid !== quote.amountMinor
    || settlement.purpose !== quote.purpose || settlement.subject.kind !== quote.subject.kind || settlement.subject.id !== quote.subject.id) {
    invalid('commerce.usage', 'purchase attribution differs');
  }
  const paidAt = integer(settlement.settledAt, 'commerce.usage.settledAt');
  const quotedStart = integer(quote.periodStartsAt, 'commerce.usage.startsAt');
  const start = quote.purpose === 'upgrade' ? Math.max(quotedStart, paidAt) : quotedStart;
  const end = integer(quote.periodEndsAt, 'commerce.usage.endsAt', start + 1);
  if (at < paidAt) invalid('commerce.usage.throughAt', 'precedes settlement');
  const elapsed = Math.min(end - start, Math.max(0, at - start));
  return Number(BigInt(paid) * BigInt(elapsed) / BigInt(end - start));
}
