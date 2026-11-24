import type { LifecycleState } from './lifecycle';
import type { PriceOption } from './types';
import { choice, integer, invalid, record, text, uuid } from './validation';

const MILLISECONDS_PER_SECOND = 1000;
/**
 * A generic safety ceiling on any caller-supplied price adjustment (checkout and catalog
 * display), independent of any specific campaign's actual adjustment value — it exists only to
 * bound a bug or malformed request, not to encode a real price. SkillPassport alone decides the
 * actual adjustment for a given promo.
 */
export const MAX_PROMO_ADJUSTMENT_MINOR = 1_000_000;

export type CommercePurpose = 'purchase' | 'renew' | 'upgrade' | 'retake';
export type CommerceSubject = LifecycleState['subject'];
export interface CommercePolicy {
  schemaVersion: 1; quoteValidityMs: number; refundWindowMs: number;
  retake: { currency: string; minorUnit: number; amountMinor: number; everyRetake: true };
}
export interface CommerceQuote {
  id: string; actorId: string; subscriptionId: string; productId: string; subject: CommerceSubject;
  audience: string; stateVersion: number; expectedRevisionId: string; planId: string; revisionId: string;
  purpose: CommercePurpose; referenceId: string | null; priceId: string | null;
  amountMinor: number; currency: string; minorUnit: number;
  periodStartsAt: number; periodEndsAt: number; createdAt: number; validUntil: number;
}
export interface CommerceSettlement {
  id: string; quoteId: string; subscriptionId: string; productId: string; subject: CommerceSubject;
  purpose: CommercePurpose; referenceId: string | null; providerPaymentId: string;
  amountMinor: number; currency: string; settledAt: number;
}
export interface CommerceCapture {
  quoteId: string; paymentId: string; orderId: string; amountMinor: number; currency: string;
  capturedAt: number; paymentCreatedAt: number;
}
export interface CommerceActor { actorId: string; subject: CommerceSubject; audience: string }

/** Stable codes for deterministic commerce rejections. The SkillPassport Pages
 * contract and browser client mirror this list; retrying never changes the outcome. */
export const COMMERCE_REJECTION_REASONS = ['order_unavailable', 'operation_pending', 'existing_subscription',
  'quote_expired', 'state_changed', 'reconciliation_required', 'checkout_released'] as const;
export type CommerceRejectionReason = typeof COMMERCE_REJECTION_REASONS[number];

/** The registered feature key is a domain identifier. Its quantity is retained
 * publication data; absent capacity denotes an offering without learner seats. */
export function includedLearnerCapacity(features: unknown): number | null {
  if (!Array.isArray(features)) invalid('commerce.capacity', 'published feature array required');
  const grants = features.filter(value => value && typeof value === 'object' && (value as { key?: unknown }).key === 'included_learner_capacity');
  if (!grants.length) return null;
  if (grants.length !== 1) invalid('commerce.capacity', 'ambiguous included learner grant');
  const grant = record(grants[0], 'commerce.capacity', ['key', 'type', 'enabled', 'limit']);
  const limit = record(grant.limit, 'commerce.capacity.limit', ['kind', 'value']);
  if (grant.type !== 'numeric_limit' || grant.enabled !== true || limit.kind !== 'finite') invalid('commerce.capacity', 'included learners require an enabled finite owner quantity');
  const capacity = integer(limit.value, 'commerce.capacity.value', 1);
  if (capacity > 2147483647) invalid('commerce.capacity', 'outside persisted seat capacity range');
  return capacity;
}
export interface CommerceOrder { id: string; amount: number; currency: string; receipt: string; status: string; notes: Record<string, string>; key_id?: string; amount_paid?: number; amount_due?: number }
export interface CommercePayment { id: string; order_id: string; amount: number; currency: string; status: string; captured: boolean; amount_refunded?: number; created_at: number }
export interface CommerceRefund { id: string; payment_id: string; amount: number; currency: string; status: string; notes: Record<string, string> }
/** Implemented by the existing payment owner. Mutation timeouts remain uncertain; never retry automatically. */
export interface CommerceProvider {
  createOrder(input: { amount: number; currency: string; receipt: string; notes: Record<string, string> }): Promise<CommerceOrder>;
  getOrder(id: string): Promise<CommerceOrder>;
  /** Read-only lookup used to recover a reserved order whose provider response was never recorded. */
  getOrdersByReceipt(receipt: string): Promise<{ items: CommerceOrder[] }>;
  getPayment(id: string): Promise<CommercePayment>;
  getOrderPayments(id: string): Promise<{ items: CommercePayment[] }>;
  createRefund(paymentId: string, input: { amount: number; receipt: string; notes: Record<string, string> }): Promise<CommerceRefund>;
  getRefund(paymentId: string, refundId: string): Promise<CommerceRefund>;
}

export function validateCommercePolicy(value: unknown): CommercePolicy {
  const p = record(value, 'commerce.policy', ['schemaVersion', 'quoteValidityMs', 'refundWindowMs', 'retake']);
  if (p.schemaVersion !== 1) invalid('commerce.policy', 'unsupported version');
  const r = record(p.retake, 'commerce.retake', ['currency', 'minorUnit', 'amountMinor', 'everyRetake']);
  if (r.everyRetake !== true) invalid('commerce.retake', 'every retake requires payment');
  const currency = text(r.currency, 'commerce.retake.currency');
  if (!/^[A-Z]{3}$/.test(currency)) invalid('commerce.retake.currency', 'expected ISO currency');
  return {
    schemaVersion: 1, quoteValidityMs: integer(p.quoteValidityMs, 'commerce.quoteValidityMs', 1),
    refundWindowMs: integer(p.refundWindowMs, 'commerce.refundWindowMs', 1),
    retake: { currency, minorUnit: integer(r.minorUnit, 'commerce.retake.minorUnit'), amountMinor: integer(r.amountMinor, 'commerce.retake.amountMinor', 1), everyRetake: true }
  };
}

/** Calendar billing preserves the UTC day, clamping month ends instead of overflowing them. */
export function commercePeriodEnd(start: number, price: Pick<PriceOption, 'intervalUnit' | 'intervalCount'>): number {
  integer(start, 'commerce.period.start');
  const count = integer(price.intervalCount, 'commerce.intervalCount', 1), result = new Date(start), day = result.getUTCDate();
  if (!Number.isFinite(result.getTime())) invalid('commerce.period.start', 'outside calendar range');
  result.setUTCDate(1);
  if (price.intervalUnit === 'month') result.setUTCMonth(result.getUTCMonth() + count);
  else if (price.intervalUnit === 'year') result.setUTCFullYear(result.getUTCFullYear() + count);
  else invalid('commerce.intervalUnit', 'unsupported interval');
  const last = new Date(result.getTime()); last.setUTCMonth(last.getUTCMonth() + 1); last.setUTCDate(0);
  result.setUTCDate(Math.min(day, last.getUTCDate()));
  return integer(result.getTime(), 'commerce.period.end', start + 1);
}

export function createCommerceQuote(input: {
  id: string; actor: CommerceActor; subscriptionId: string; productId: string; audience: string;
  purpose: CommercePurpose; state: LifecycleState | null; planId: string; revisionId: string;
  price: PriceOption | null; referenceId: string | null; policy: CommercePolicy; now: number;
  sourcePurchaseMode?: 'free' | 'self_service';
}): CommerceQuote {
  const now = integer(input.now, 'commerce.now'), policy = validateCommercePolicy(input.policy), purpose = choice(input.purpose, 'commerce.purpose', ['purchase', 'renew', 'upgrade', 'retake']);
  const actorId = uuid(input.actor.actorId, 'commerce.actor'), subscriptionId = uuid(input.subscriptionId, 'commerce.subscriptionId'), productId = uuid(input.productId, 'commerce.productId');
  const subject = { kind: choice(input.actor.subject.kind, 'commerce.subject.kind', ['user', 'organization']), id: uuid(input.actor.subject.id, 'commerce.subject.id') };
  const planId = uuid(input.planId, 'commerce.planId'), revisionId = uuid(input.revisionId, 'commerce.revisionId');
  if (input.audience !== input.actor.audience) invalid('commerce.audience', 'owner scope differs');
  const state = input.state;
  if (purpose === 'purchase' ? state !== null : state === null) invalid('commerce.state', 'purchase requires new identity; other operations require initialized state');
  if (state && (state.id !== subscriptionId || state.productId !== productId || state.subject.kind !== subject.kind || state.subject.id !== subject.id)) invalid('commerce.state', 'subject or product differs');
  if (purpose === 'retake' && (!state || state.status !== 'active' || (state.periodEndsAt === null || now >= state.periodEndsAt))) invalid('commerce.retake', 'active subscription required');
  const freeUpgrade = purpose === 'upgrade' && input.sourcePurchaseMode === 'free';
  if (state && state.periodEndsAt === null && !freeUpgrade) invalid('commerce.state', 'paid commerce requires a finite commercial period');
  const price = input.price;
  if (purpose !== 'retake' && (!price || !price.audiences.includes(input.audience) || price.quantityBasis !== 'subscription')) invalid('commerce.price', 'explicit audience subscription price required; negotiated/seat terms need their contract owner');
  if (purpose === 'retake' && price !== null) invalid('commerce.price', 'retake uses retained retake policy');
  const amountMinor = integer(purpose === 'retake' ? policy.retake.amountMinor : price!.amountMinor, 'commerce.amountMinor', 1);
  const periodStartsAt = purpose === 'purchase' || freeUpgrade ? now : purpose === 'renew' ? state!.trialEndsAt ?? integer(state!.periodEndsAt, 'commerce.periodEndsAt') : state!.periodStartsAt;
  const periodEndsAt = purpose === 'purchase' || purpose === 'renew' || freeUpgrade ? commercePeriodEnd(periodStartsAt, price!) : integer(state!.periodEndsAt, 'commerce.periodEndsAt');
  if (purpose === 'renew' && (now < periodStartsAt || revisionId !== (state!.scheduledChange?.revisionId ?? state!.revisionId))) invalid('commerce.renew', 'renewal boundary or scheduled revision differs');
  if (purpose === 'upgrade' && (state!.status !== 'active' || (state!.periodEndsAt !== null && now >= integer(state!.periodEndsAt, 'commerce.periodEndsAt')) || revisionId === state!.revisionId || state!.scheduledChange !== null)) invalid('commerce.upgrade', 'upgrade must change active current period');
  if (purpose === 'retake' && (planId !== state!.planId || revisionId !== state!.revisionId)) invalid('commerce.retake', 'retake must retain purchased revision');
  return {
    id: uuid(input.id, 'commerce.quoteId'), actorId, subscriptionId, productId, subject, audience: input.audience,
    stateVersion: state?.version ?? 0, expectedRevisionId: state?.revisionId ?? revisionId, planId, revisionId, purpose,
    referenceId: purpose === 'retake' ? uuid(input.referenceId, 'commerce.referenceId') : input.referenceId === null ? null : invalid('commerce.referenceId', 'not applicable'),
    priceId: price?.id ?? null, amountMinor, currency: purpose === 'retake' ? policy.retake.currency : price!.currency,
    minorUnit: purpose === 'retake' ? policy.retake.minorUnit : price!.minorUnit, periodStartsAt, periodEndsAt, createdAt: now,
    validUntil: integer(now + policy.quoteValidityMs, 'commerce.validUntil', now + 1)
  };
}

export function verifyCommerceOrder(quote: CommerceQuote, value: CommerceOrder): CommerceOrder {
  if (!/^order_[A-Za-z0-9]+$/.test(value.id) || value.receipt !== quote.id || value.amount !== quote.amountMinor || value.currency !== quote.currency
    || value.notes.subscription_quote_id !== quote.id || value.notes.subscription_id !== quote.subscriptionId) invalid('commerce.order', 'provider order differs from issued quote');
  return value;
}
export function verifyCommercePayment(quote: CommerceQuote, order: CommerceOrder, payment: CommercePayment, settlementId: string, now: number, capture?: CommerceCapture): CommerceSettlement {
  verifyCommerceOrder(quote, order);
  const paymentCreatedAt = integer(payment.created_at * MILLISECONDS_PER_SECOND, 'commerce.payment.createdAt'), confirmedAt = integer(now, 'commerce.confirmedAt');
  let settledAt = confirmedAt;
  if (capture) {
    const capturedAt = integer(capture.capturedAt, 'commerce.capture.at');
    if (capture.quoteId !== quote.id || capture.paymentId !== payment.id || capture.orderId !== order.id || capture.amountMinor !== quote.amountMinor
      || capture.currency !== quote.currency || capture.paymentCreatedAt !== paymentCreatedAt || capturedAt < quote.createdAt || capturedAt > confirmedAt
      || capturedAt + (MILLISECONDS_PER_SECOND - 1) >= quote.validUntil) invalid('commerce.capture', 'exact timely signed capture required');
    settledAt = capturedAt;
  }
  if (!/^pay_[A-Za-z0-9]+$/.test(payment.id) || payment.order_id !== order.id || payment.status !== 'captured' || payment.captured !== true
    || payment.amount !== quote.amountMinor || payment.currency !== quote.currency || (payment.amount_refunded !== undefined && payment.amount_refunded !== 0)
    || paymentCreatedAt < quote.createdAt - (MILLISECONDS_PER_SECOND - 1) || paymentCreatedAt > settledAt || (!capture && confirmedAt >= quote.validUntil) || order.status !== 'paid') invalid('commerce.payment', 'captured unrefunded payment and live quote or exact timely capture required');
  return {
    id: uuid(settlementId, 'commerce.settlementId'), quoteId: quote.id, subscriptionId: quote.subscriptionId, productId: quote.productId,
    subject: quote.subject, purpose: quote.purpose, referenceId: quote.referenceId, providerPaymentId: payment.id, amountMinor: quote.amountMinor, currency: quote.currency, settledAt
  };
}

/** No absent usage substitution: a complete purchase-attributed valuation is required. */
export function calculateCommerceRefund(input: { paidMinor: number; usageMinor: number; refundedMinor: number; settledAt: number; requestedAt: number; usageComplete: boolean }, policyValue: unknown): number {
  const policy = validateCommercePolicy(policyValue), paid = integer(input.paidMinor, 'refund.paidMinor', 1), usage = integer(input.usageMinor, 'refund.usageMinor'), refunded = integer(input.refundedMinor, 'refund.refundedMinor');
  if (input.usageComplete !== true) invalid('refund.usage', 'complete authoritative valuation required');
  if (refunded > paid) invalid('refund.refundedMinor', 'exceeds paid amount');
  const settled = integer(input.settledAt, 'refund.settledAt'), requested = integer(input.requestedAt, 'refund.requestedAt');
  if (requested < settled || requested - settled > policy.refundWindowMs) invalid('refund.window', 'outside retained refund window');
  return Math.max(0, Math.min(paid - refunded, paid - usage - refunded));
}

/** Strict references-only API. Price, roles, actor and policy are never request authority. */
export interface CommerceRequest {
  kind: 'activate' | 'quote' | 'order' | 'checkout' | 'settle' | 'refund' | 'refund_confirm'; subscriptionId: string; subject: CommerceSubject;
  expectedVersion: number; expectedRevisionId: string;
  purpose?: unknown; revisionId?: unknown; priceId?: unknown; referenceId?: unknown; quoteId?: unknown; paymentId?: unknown; reconcile?: unknown; settlementId?: unknown; refundId?: unknown; contractId?: unknown;
  /**
   * A SkillPassport-decided, bounded price adjustment (see MAX_PROMO_ADJUSTMENT_MINOR in
   * ./commerce-persistence) — quote requests only, always optional. SkillPassport remains the
   * sole authority on promo validity/eligibility/quota; this worker never evaluates a promo
   * code itself, it only ever narrows the independently-derived published price by this amount,
   * within a fixed cap, and never below a positive final price.
   */
  priceAdjustmentMinor?: unknown;
}
export function parseCommerceRequest(value: unknown): CommerceRequest {
  const r = record(value, 'commerce.request', ['kind', 'subscriptionId', 'subject', 'expectedVersion', 'expectedRevisionId', 'purpose', 'revisionId', 'priceId', 'referenceId', 'quoteId', 'paymentId', 'reconcile', 'settlementId', 'refundId', 'contractId', 'priceAdjustmentMinor']);
  const kind = choice(r.kind, 'commerce.kind', ['activate', 'quote', 'order', 'checkout', 'settle', 'refund', 'refund_confirm']);
  const s = record(r.subject, 'commerce.subject', ['kind', 'id']);
  const common = { kind, subscriptionId: uuid(r.subscriptionId, 'commerce.subscriptionId'), subject: { kind: choice(s.kind, 'commerce.subject.kind', ['user', 'organization']), id: uuid(s.id, 'commerce.subject.id') }, expectedVersion: integer(r.expectedVersion, 'commerce.expectedVersion'), expectedRevisionId: uuid(r.expectedRevisionId, 'commerce.expectedRevisionId') };
  if (common.expectedVersion === 0 && (kind === 'refund' || kind === 'refund_confirm' || (kind === 'quote' && r.purpose !== 'purchase'))) invalid('commerce.expectedVersion', 'zero version applies only to a new purchase quote/order/settlement');
  if (kind === 'activate' && common.expectedVersion !== 0) invalid('commerce.expectedVersion', 'activation requires uninitialized subscription');
  const allowed = kind === 'activate' ? ['contractId'] : kind === 'quote' ? ['purpose', 'revisionId', 'priceId', 'referenceId', 'priceAdjustmentMinor'] : kind === 'order' || kind === 'checkout' ? ['quoteId'] : kind === 'settle' ? ['quoteId', 'paymentId', 'reconcile'] : kind === 'refund' ? ['settlementId'] : ['settlementId', 'refundId'];
  for (const k of Object.keys(r)) if (!['kind', 'subscriptionId', 'subject', 'expectedVersion', 'expectedRevisionId', ...allowed].includes(k)) invalid('commerce.request', 'field not applicable');
  if (kind === 'settle' && (r.reconcile === true ? Object.hasOwn(r, 'paymentId') : Object.hasOwn(r, 'reconcile') || typeof r.paymentId !== 'string' || !/^pay_[A-Za-z0-9]+$/.test(r.paymentId))) invalid('commerce.settlement', 'explicit payment reference or reconciliation required exclusively');
  if (kind === 'activate') uuid(r.contractId, 'commerce.contractId');
  if (kind === 'quote') {
    const purpose = choice(r.purpose, 'commerce.purpose', ['purchase', 'renew', 'upgrade', 'retake']);
    uuid(r.revisionId, 'commerce.revisionId');
    if (purpose === 'retake') {
      uuid(r.referenceId, 'commerce.referenceId');
      if (Object.hasOwn(r, 'priceId')) invalid('commerce.priceId', 'retake uses retained retake policy');
    } else {
      uuid(r.priceId, 'commerce.priceId');
      if (Object.hasOwn(r, 'referenceId')) invalid('commerce.referenceId', 'not applicable');
    }
    // Additive-only, matching the existing DIDAC promo_codes.price_adjustment convention
    // (CHECK price_adjustment >= 0) — never a caller-chosen negative value. The fixed cap
    // itself is enforced where the adjustment is applied, not here.
    if (Object.hasOwn(r, 'priceAdjustmentMinor')) integer(r.priceAdjustmentMinor, 'commerce.priceAdjustmentMinor', -Number.MAX_SAFE_INTEGER);
  }
  return { ...common, ...Object.fromEntries(allowed.filter(k => Object.hasOwn(r, k)).map(k => [k, r[k]])) };
}

/** Explicit recovery reads the original provider-owned order; it never creates/captures a charge. */
export function reconcileCommercePayment(quote: CommerceQuote, order: CommerceOrder, value: unknown): CommercePayment {
  const payments = commerceOrderPayments(quote, order, value);
  if (payments.some(p => !['captured', 'failed'].includes(p.status) || p.status === 'failed' && p.captured || p.amount_refunded !== undefined && p.amount_refunded !== 0)) invalid('commerce.reconciliation', 'pending or refunded payment requires investigation');
  const captured = payments.filter(p => p.status === 'captured' && p.captured === true);
  if (captured.length !== 1) invalid('commerce.reconciliation', 'exactly one captured payment required');
  return captured[0];
}

function commerceOrderPayments(quote: CommerceQuote, order: CommerceOrder, value: unknown): CommercePayment[] {
  verifyCommerceOrder(quote, order);
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('commerce.reconciliation', 'order payment evidence unavailable');
  const items = (value as { items?: unknown }).items;
  if (!Array.isArray(items)) invalid('commerce.reconciliation', 'order payment collection unavailable');
  const payments = items as CommercePayment[];
  const ids = new Set<string>();
  for (const p of payments) {
    if (!p || typeof p !== 'object' || typeof p.id !== 'string' || !/^pay_[A-Za-z0-9]+$/.test(p.id) || ids.has(p.id)
      || p.order_id !== order.id || p.amount !== quote.amountMinor || p.currency !== quote.currency
      || !['created', 'authorized', 'captured', 'refunded', 'failed'].includes(p.status) || typeof p.captured !== 'boolean'
      || (p.amount_refunded !== undefined && (!Number.isSafeInteger(p.amount_refunded) || p.amount_refunded < 0))) invalid('commerce.reconciliation', 'foreign or malformed payment evidence');
    ids.add(p.id);
  }
  return payments;
}

/** Read-only recovery classification. Never authorizes a replacement order. */
export function inspectCommerceCheckout(quote: CommerceQuote, order: CommerceOrder, value: unknown, now: number): 'unpaid' | 'paid' | 'expired' | 'blocked' {
  const payments = commerceOrderPayments(quote, order, value);
  const paid = integer(order.amount_paid, 'commerce.checkout.amountPaid'), due = integer(order.amount_due, 'commerce.checkout.amountDue');
  if (paid + due !== quote.amountMinor) return 'blocked';
  // Created attempts have no authorization yet. Only the same fully unpaid order
  // may resume; pending authorization and mixed capture evidence remain blocked.
  if (payments.some(p => !['created', 'failed', 'captured'].includes(p.status) || p.captured !== (p.status === 'captured') || (p.amount_refunded ?? 0) !== 0)) return 'blocked';
  const captured = payments.filter(p => p.status === 'captured');
  if (captured.length === 1 && order.status === 'paid' && paid === quote.amountMinor && due === 0 && !payments.some(p => p.status === 'created')) return 'paid';
  if (captured.length !== 0 || paid !== 0 || due !== quote.amountMinor || !['created', 'attempted'].includes(order.status)) return 'blocked';
  return integer(now, 'commerce.checkout.now') >= quote.validUntil ? 'expired' : 'unpaid';
}
