import type { DbClient } from '../db';
import {
  calculateCommerceRefund, createCommerceQuote, includedLearnerCapacity, inspectCommerceCheckout, MAX_PROMO_ADJUSTMENT_MINOR, parseCommerceRequest,
  reconcileCommercePayment,
  validateCommercePolicy, verifyCommerceOrder, verifyCommercePayment,
  type CommerceActor, type CommerceCapture, type CommerceOrder,
  type CommerceProvider, type CommerceQuote, type CommerceRejectionReason, type CommerceSettlement, type CommerceSubject
} from './commerce';
import { publishedRevisionChanges, validateSubscriptionLifecyclePolicy, type LifecycleCapture, type LifecycleQuote, type LifecycleSettlement } from './lifecycle';
import { prepareLifecycleCommit, readSubscriptionLifecycle } from './lifecycle-persistence';
import { CatalogPersistenceError } from './repository';
import type { PriceOption } from './types';
import { validateCommerceUsagePolicy } from './usage-valuation';
import { array, choice, integer, record, text, uuid } from './validation';

type Database = Pick<DbClient, 'query' | 'rpc' | 'queryOne'>;
const fail = (reason: string): never => { throw new CatalogPersistenceError(reason); };
/** Deterministic domain rejection: the same request can never succeed by retrying. */
export class CommerceRejection extends CatalogPersistenceError {
  constructor(readonly code: CommerceRejectionReason, message: string) { super(message); this.name = 'CommerceRejection'; }
}
const reject = (code: CommerceRejectionReason, message: string): never => { throw new CommerceRejection(code, message); };
async function assertInitialPurchaseAvailable(database: Database, actor: CommerceActor, productId: string) {
  const owner = actor.subject.kind === 'organization'
    ? `organization_id=eq.${actor.subject.id}&is_organization_subscription=is.true`
    : `user_id=eq.${actor.subject.id}&is_organization_subscription=not.is.true`;
  const rows = await database.query<Record<string, unknown>>(`subscriptions?select=id&product_id=eq.${productId}&${owner}&status=in.(active,pending,grace_period,paused)&limit=1`, undefined, 'json-array');
  if (!Array.isArray(rows)) fail('Current subscription evidence unavailable');
  if (rows.length) reject('existing_subscription', 'Existing subscription requires explicit lifecycle transition');
}
const same = (a: unknown, b: unknown): boolean => {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => same(v, b[i]));
  const x = a as Record<string, unknown>, y = b as Record<string, unknown>;
  return Object.keys(x).length === Object.keys(y).length && Object.keys(x).every(k => Object.hasOwn(y, k) && same(x[k], y[k]));
};
async function one(database: Database, query: string): Promise<Record<string, unknown>> {
  const rows = await database.query<Record<string, unknown>>(query, undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length !== 1) fail('Commerce evidence must resolve exactly once');
  return rows[0];
}
async function published(database: Database, revisionId: string, productId: string, retake = false, source = false) {
  const row = await one(database, `subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan&revision_id=eq.${uuid(revisionId, 'revisionId')}&limit=2`);
  const canonical = record(row.canonical_plan, 'commerce.publication', ['id', 'code', 'productId', 'audiences', 'configuration']);
  if (row.revision_id !== revisionId || canonical.id !== row.plan_id || canonical.productId !== productId) fail('Commerce publication product differs');
  const configuration = canonical.configuration;
  if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)) fail('Commerce publication configuration unavailable');
  const config = configuration as Record<string, unknown>;
  const policy = validateCommercePolicy(config.subscription_commerce);
  const draft = await one(database, `subscription_plan_drafts?select=snapshot&id=eq.${revisionId}&limit=2`);
  const snapshot = record(draft.snapshot, 'commerce.draft', ['schemaVersion', 'id', 'plan', 'revisionNumber', 'name', 'audiences', 'purchaseMode', 'prices', 'features']);
  const plan = record(snapshot.plan, 'commerce.plan', ['id', 'code', 'productId']);
  if (snapshot.id !== revisionId || plan.id !== canonical.id || plan.productId !== productId
    || (snapshot.purchaseMode !== 'self_service' && !(source && snapshot.purchaseMode === 'free') && !(retake && snapshot.purchaseMode === 'contact_sales'))) fail('Commerce requires published paid terms; negotiated subscription prices retain their contract owner');
  return { planId: uuid(canonical.id, 'commerce.planId'), purchaseMode: snapshot.purchaseMode, policy, configuration: config, features: snapshot.features, prices: array(snapshot.prices, 'commerce.prices'), audiences: array(canonical.audiences, 'commerce.audiences') };
}
function paidLifecyclePolicy(configuration: Record<string, unknown>, productId: string) {
  const policy = validateSubscriptionLifecyclePolicy(configuration.subscription_lifecycle);
  if (policy.productId !== productId || policy.billing === 'not_applicable') fail('Published paid lifecycle policy required for this product');
  return policy;
}
async function paidTransition(database: Database, stored: Awaited<ReturnType<typeof readSubscriptionLifecycle>>, target: Awaited<ReturnType<typeof published>>, revisionId: string, purpose: 'upgrade' | 'renew') {
  const source = await published(database, stored.state.revisionId, stored.state.productId, false, true);
  const policy = paidLifecyclePolicy(target.configuration, stored.state.productId);
  if (source.purchaseMode === 'free' && stored.policy.billing !== 'not_applicable') fail('Free source requires explicit non-billing lifecycle terms');
  const startsPaidPeriod = purpose === 'upgrade' && source.purchaseMode === 'free' && stored.policy.billing === 'not_applicable';
  if (!startsPaidPeriod && !same(policy, stored.policy)) fail('Target lifecycle policy is incompatible with the retained subscription');
  const changes = publishedRevisionChanges(source.configuration, target.configuration);
  if (purpose === 'upgrade' && !changes.some(c => c.fromRevisionId === stored.state.revisionId && c.toRevisionId === revisionId && c.operation === 'upgrade')) fail('Approved upgrade transition unavailable');
  return { policy, changes, sourcePurchaseMode: source.purchaseMode === 'free' ? 'free' as const : 'self_service' as const };
}
function price(value: unknown): PriceOption {
  const p = record(value, 'commerce.price', ['id', 'currency', 'minorUnit', 'amountMinor', 'intervalUnit', 'intervalCount', 'quantityBasis', 'audiences']);
  return {
    id: uuid(p.id, 'commerce.price.id'), currency: text(p.currency, 'commerce.price.currency'), minorUnit: integer(p.minorUnit, 'commerce.price.minorUnit'), amountMinor: integer(p.amountMinor, 'commerce.price.amountMinor', 1),
    intervalUnit: choice(p.intervalUnit, 'commerce.price.intervalUnit', ['month', 'year']), intervalCount: integer(p.intervalCount, 'commerce.price.intervalCount', 1), quantityBasis: choice(p.quantityBasis, 'commerce.price.quantityBasis', ['subscription', 'seat']), audiences: array(p.audiences, 'commerce.price.audiences').map(v => text(v, 'commerce.price.audience'))
  };
}
function scopedQuote(value: unknown, actor: CommerceActor, subscriptionId: string, productId: string): CommerceQuote {
  // Retained rows are protected by SQL and originate only in createCommerceQuote.
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Commerce quote unavailable');
  const q = value as CommerceQuote;
  if (q.actorId !== actor.actorId || q.subscriptionId !== subscriptionId || q.productId !== productId || q.audience !== actor.audience || !same(q.subject, actor.subject)) fail('Commerce quote owner differs');
  uuid(q.id, 'quote.id'); integer(q.amountMinor, 'quote.amountMinor', 1); integer(q.validUntil, 'quote.validUntil');
  return q;
}
async function retainedCapture(database: Database, quote: CommerceQuote): Promise<(CommerceCapture & { eventId: string }) | undefined> {
  const rows = await database.query<Record<string, unknown>>(`subscription_commerce_captures?select=event_id,quote_id,provider_payment_id,provider_order_id,captured_at_ms,payment_created_at_ms,amount_minor,currency&quote_id=eq.${quote.id}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length > 1) fail('Retained capture evidence unavailable');
  if (!rows.length) return undefined;
  const row = rows[0];
  if (row.quote_id !== quote.id) fail('Retained capture quote differs');
  return {
    eventId: text(row.event_id, 'capture.eventId'), quoteId: quote.id, paymentId: text(row.provider_payment_id, 'capture.paymentId'), orderId: text(row.provider_order_id, 'capture.orderId'),
    capturedAt: integer(Number(row.captured_at_ms), 'capture.at', 1), paymentCreatedAt: integer(Number(row.payment_created_at_ms), 'capture.createdAt', 1),
    amountMinor: integer(Number(row.amount_minor), 'capture.amountMinor', 1), currency: text(row.currency, 'capture.currency')
  };
}
export async function readSettledRetake(database: Database, settlementId: string, subscriptionId: string, productId: string, subject: CommerceSubject, referenceId: string): Promise<CommerceSettlement> {
  const row = await one(database, `subscription_commerce_settlements?select=evidence&id=eq.${uuid(settlementId, 'settlementId')}&limit=2`);
  const s = row.evidence as CommerceSettlement;
  if (!s || s.id !== settlementId || s.purpose !== 'retake' || s.subscriptionId !== uuid(subscriptionId, 'subscriptionId') || s.productId !== uuid(productId, 'productId') || !same(s.subject, subject) || s.referenceId !== uuid(referenceId, 'referenceId')) fail('Retake payment owner differs');
  integer(s.amountMinor, 'retake.amountMinor', 1);
  return s;
}
export async function readRefundCancellation(database: Database, subscriptionId: string, productId: string, subject: CommerceSubject): Promise<boolean> {
  const rows = await database.query<Record<string, unknown>>(`subscription_commerce_refunds?select=subscription_id,product_id,subject,amount_minor,status&subscription_id=eq.${uuid(subscriptionId, 'subscriptionId')}&status=eq.processed&limit=1000`, undefined, 'json-array');
  if (!Array.isArray(rows)) fail('Refund cancellation evidence unavailable');
  return rows.some(row => {
    if (row.subscription_id !== subscriptionId || row.product_id !== productId || !same(row.subject, subject) || row.status !== 'processed') fail('Refund cancellation scope differs');
    return integer(Number(row.amount_minor), 'refund.amountMinor', 1) > 0;
  });
}

/** Billing reservations fence new usage before an external refund can become uncertain. */
export async function readSubscriptionCommerceFreeze(database: Database, subscriptionId: string, productId: string, subject: CommerceSubject): Promise<boolean> {
  const rows = await database.query<Record<string, unknown>>(`subscription_commerce_refund_freezes?select=subscription_id,product_id,subject&subscription_id=eq.${uuid(subscriptionId, 'subscriptionId')}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(rows)) fail('Refund usage freeze unavailable');
  for (const row of rows) if (row.subscription_id !== subscriptionId || row.product_id !== productId || !same(row.subject, subject)) fail('Refund usage freeze scope differs');
  return rows.length > 0;
}

/** Trusted payment queue consumer only, never an end-user evidence API. The
 * payment owner has authenticated the exact body before producing this envelope. */
export async function recordSubscriptionCommerceCapture(database: Database, input: unknown) {
  const event = record(input, 'commerce.captureEvent', ['event_id', 'event_type', 'payload', 'verification', 'capture']);
  const verification = record(event.verification, 'commerce.captureVerification', ['kind', 'bodySha256', 'receivedAt']);
  if (event.event_type !== 'payment.captured' || verification.kind !== 'razorpay_hmac_sha256'
    || typeof event.event_id !== 'string' || !/^[a-f0-9]{64}$/.test(event.event_id) || verification.bodySha256 !== event.event_id) fail('Trusted signed capture envelope required');
  const receivedAt = integer(verification.receivedAt, 'commerce.captureReceivedAt');
  const capture = record(event.capture, 'commerce.capture', ['paymentId', 'orderId', 'amountMinor', 'currency', 'capturedAt', 'paymentCreatedAt']);
  const capturedAt = integer(capture.capturedAt, 'commerce.capturedAt', 1);
  const createdAt = integer(capture.paymentCreatedAt, 'commerce.paymentCreatedAt', 1);
  if (createdAt > capturedAt || capturedAt > receivedAt || receivedAt > Date.now()
    || typeof capture.paymentId !== 'string' || !/^pay_[A-Za-z0-9]+$/.test(capture.paymentId)
    || typeof capture.orderId !== 'string' || !/^order_[A-Za-z0-9]+$/.test(capture.orderId)
    || typeof capture.currency !== 'string' || !/^[A-Z]{3}$/.test(capture.currency)) fail('Capture identity or event time differs');
  integer(capture.amountMinor, 'commerce.captureAmount', 1);
  const result = record(await database.rpc('record_subscription_commerce_capture', { p_event: event }), 'commerce.captureReceipt',
    ['eventId', 'quoteId', 'paymentId', 'productId', 'subscriptionId', 'capturedAt']);
  if (result.eventId !== event.event_id || result.paymentId !== capture.paymentId || result.capturedAt !== capturedAt) fail('Capture owner acknowledgement differs');
  uuid(result.quoteId, 'commerce.captureQuote'); uuid(result.productId, 'commerce.captureProduct'); uuid(result.subscriptionId, 'commerce.captureSubscription');
  return result;
}

/** Internal admin owner only. Authorization is resolved by the signed RPC layer. */
export async function recordSubscriptionCommerceEntryContract(database: Database, actorId: string, productId: string, input: unknown): Promise<string> {
  const c = record(input, 'commerce.entryContract', ['schemaVersion', 'id', 'productId', 'revisionId', 'subject', 'audience', 'startsAt', 'endsAt', 'includedLearnerCapacity', 'sourceSubscriptionId', 'sourceEvidence']);
  if (c.schemaVersion !== 1 || uuid(c.productId, 'commerce.entryContract.productId') !== uuid(productId, 'productId')) fail('Entry contract product differs');
  uuid(c.id, 'commerce.entryContract.id'); uuid(c.revisionId, 'commerce.entryContract.revisionId');
  const subject = record(c.subject, 'commerce.entryContract.subject', ['kind', 'id']);
  choice(subject.kind, 'commerce.entryContract.subject.kind', ['user', 'organization']); uuid(subject.id, 'commerce.entryContract.subject.id');
  text(c.audience, 'commerce.entryContract.audience');
  const startsAt = integer(c.startsAt, 'commerce.entryContract.startsAt'); integer(c.endsAt, 'commerce.entryContract.endsAt', startsAt + 1);
  if (subject.kind === 'organization') integer(c.includedLearnerCapacity, 'commerce.entryContract.includedLearnerCapacity', 1);
  else if (c.includedLearnerCapacity !== null) fail('Individual entry has no institution capacity');
  if (c.sourceSubscriptionId !== null) uuid(c.sourceSubscriptionId, 'commerce.entryContract.sourceSubscriptionId');
  if (!c.sourceEvidence || typeof c.sourceEvidence !== 'object' || Array.isArray(c.sourceEvidence) || !Object.keys(c.sourceEvidence).length) fail('Explicit owner contract evidence required');
  const result = await database.rpc('record_subscription_commerce_entry_contract', { p_contract: c, p_actor_id: uuid(actorId, 'actorId') });
  const contractId = uuid(result, 'commerce.entryContract.receipt');
  if (contractId !== c.id) fail('Entry contract acknowledgement differs');
  return contractId;
}

/** User-approved recovery for an order reservation whose provider result was never recorded.
 * The provider is read by receipt and never asked to create anything. Exactly one verified order
 * is recorded under the original identity and inspected as usual. No order with an expired quote
 * is durably voided as not issued; no order with a still-valid quote stays pending because the
 * original request may still be running. A provider failure propagates and never voids. */
async function recoverUnrecordedOrder(database: Database, provider: CommerceProvider, identity: Record<string, unknown>,
  quote: CommerceQuote, row: Record<string, unknown>, operationId: string) {
  if (row.order_operation_id !== operationId || row.provider_order_id !== null) fail('Retained order scope differs');
  const found = await provider.getOrdersByReceipt(quote.id);
  if (!found || !Array.isArray(found.items)) fail('Provider order lookup returned an invalid response');
  if (found.items.length > 1) reject('reconciliation_required', 'Multiple provider orders match this checkout');
  if (found.items.length === 1) {
    let order: CommerceOrder;
    try { order = verifyCommerceOrder(quote, found.items[0]); }
    catch { return reject('reconciliation_required', 'Provider order differs from the issued quote'); }
    const now = Date.now();
    if (now >= quote.validUntil) {
      // The owner cannot bind an order to an expired quote. An unpaid expired order is reported
      // as expired without a write; any payment evidence needs explicit reconciliation.
      const status = inspectCommerceCheckout(quote, order, await provider.getOrderPayments(order.id), now);
      if (status !== 'expired') reject('reconciliation_required', 'Unrecorded provider order has payment evidence');
      return { kind: 'checkout', status, issued: { kind: 'order', operationId, quoteId: quote.id, order } };
    }
    const issued = record(await database.rpc('complete_subscription_commerce_order', { p_identity: identity, p_order: order }),
      'commerce.issued', ['kind', 'operationId', 'quoteId', 'order']);
    if (issued.kind !== 'order' || issued.operationId !== operationId || issued.quoteId !== quote.id) fail('Recovered order acknowledgement differs');
    const status = inspectCommerceCheckout(quote, order, await provider.getOrderPayments(order.id), Date.now());
    return { kind: 'checkout', status, issued: { ...issued, order } };
  }
  if (Date.now() < quote.validUntil) return { kind: 'checkout', status: 'order_pending', operationId, quoteId: quote.id };
  const voided = record(await database.rpc('void_unissued_subscription_commerce_order', { p_identity: identity }),
    'commerce.voided', ['kind', 'operationId', 'quoteId', 'voidedAt']);
  if (voided.kind !== 'not_issued' || voided.operationId !== operationId || voided.quoteId !== quote.id) fail('Void acknowledgement differs');
  return { kind: 'checkout', status: 'not_issued', operationId, quoteId: quote.id };
}

/** Internal owner API: actor is supplied by signed/live membership authorization, never HTTP JSON.
 * Reserve precedes external mutation. An uncertain mutation remains pending and requires explicit
 * reconciliation; retrying the same operation cannot create a second order/refund.
 */
export async function executeSubscriptionCommerce(database: Database, provider: CommerceProvider | undefined, actor: CommerceActor, productIdValue: string, operationIdValue: string, input: unknown) {
  const productId = uuid(productIdValue, 'commerce.productId'), operationId = uuid(operationIdValue, 'commerce.operationId'), request = parseCommerceRequest(input);
  if (!same(request.subject, actor.subject)) fail('Commerce subject differs');
  uuid(actor.actorId, 'commerce.actorId');
  const identity = { operationId, actorId: actor.actorId, subject: actor.subject, audience: actor.audience, productId, request };
  const prior = await database.query<Record<string, unknown>>(`subscription_commerce_operations?select=identity,receipt&operation_id=eq.${operationId}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(prior) || prior.length > 1) fail('Commerce operation unavailable');
  if (request.kind === 'checkout') {
    // Reuse the original order identity and permission. This branch never creates an order;
    // its only write is recording the outcome of a reservation that never reached the provider.
    const original = { ...identity, request: { ...request, kind: 'order' } };
    if (prior.length !== 1 || !same(prior[0].identity, original)) reject('order_unavailable', 'Retained order unavailable');
    if (!provider) throw new CatalogPersistenceError('Subscription payment owner unavailable');
    const quoteId = uuid(request.quoteId, 'commerce.quoteId');
    const row = await one(database, `subscription_commerce_quotes?select=quote,provider_order_id,order_operation_id&id=eq.${quoteId}&limit=2`);
    const quote = scopedQuote(row.quote, actor, request.subscriptionId, productId);
    if (quote.stateVersion !== request.expectedVersion || quote.expectedRevisionId !== request.expectedRevisionId) fail('Checkout quote state differs');
    if (prior[0].receipt === null) return recoverUnrecordedOrder(database, provider, original, quote, row, operationId);
    const voided = prior[0].receipt as { kind?: unknown; operationId?: unknown; quoteId?: unknown };
    if (voided.kind === 'not_issued') {
      if (voided.operationId !== operationId || voided.quoteId !== quoteId) fail('Retained order scope differs');
      return { kind: 'checkout', status: 'not_issued', operationId, quoteId };
    }
    const issued = record(prior[0].receipt, 'commerce.issued', ['kind', 'operationId', 'quoteId', 'order']);
    if (issued.kind !== 'order' || issued.operationId !== operationId || issued.quoteId !== quoteId) fail('Retained order scope differs');
    const retained = issued.order as { id?: unknown };
    const orderId = text(row.provider_order_id, 'commerce.orderId');
    if (retained.id !== orderId) fail('Retained provider order differs');
    if (request.expectedVersion !== 0) {
      const { state } = await readSubscriptionLifecycle(database, request.subscriptionId, productId, actor.subject);
      if (state.version !== request.expectedVersion || state.revisionId !== request.expectedRevisionId) fail('Checkout subscription state changed');
    }
    const order = verifyCommerceOrder(quote, await provider.getOrder(orderId));
    if (order.id !== orderId) fail('Provider returned a different order');
    const status = inspectCommerceCheckout(quote, order, await provider.getOrderPayments(orderId), Date.now());
    return { kind: 'checkout', status, issued: { ...issued, order } };
  }
  if (prior.length) {
    if (!same(prior[0].identity, identity)) fail('Commerce operation replay conflicts');
    if (prior[0].receipt !== null) {
      const receipt = prior[0].receipt as { kind?: unknown; settlement?: { purpose?: string } };
      if (receipt.kind === 'not_issued') reject('checkout_released', 'This checkout was closed without a payment order');
      if (request.kind === 'settle' && ['upgrade', 'renew'].includes(receipt.settlement?.purpose ?? '')) {
        const rows = await database.query<Record<string, unknown>>(`subscription_lifecycle_operations?select=operation_id,transaction_id&operation_id=eq.${operationId}&limit=2`, undefined, 'json-array');
        if (!Array.isArray(rows) || rows.length !== 1 || rows[0].operation_id !== operationId || rows[0].transaction_id !== operationId) fail('Payment activation is incomplete; retain payment references for recovery');
      }
      return prior[0].receipt;
    }
    if (request.kind !== 'settle') reject('operation_pending', 'Commerce operation is pending; reconcile provider evidence before another mutation');
  }
  if (request.kind === 'activate') return database.rpc('activate_subscription_commerce_contract', { p_identity: identity, p_contract_id: uuid(request.contractId, 'commerce.contractId') });
  if (!provider) throw new CatalogPersistenceError('Subscription payment owner unavailable');
  const now = Date.now();
  const stored = request.expectedVersion === 0 ? null : await readSubscriptionLifecycle(database, request.subscriptionId, productId, actor.subject);
  const state = stored?.state ?? null;
  if (state && (state.version !== request.expectedVersion || state.revisionId !== request.expectedRevisionId)) reject('state_changed', 'Commerce state compare-and-set differs');
  if (request.kind === 'quote') {
    const purpose = choice(request.purpose, 'commerce.purpose', ['purchase', 'renew', 'upgrade', 'retake']), revisionId = uuid(request.revisionId, 'commerce.revisionId');
    if (purpose === 'purchase') await assertInitialPurchaseAvailable(database, actor, productId);
    const retained = await published(database, revisionId, productId, purpose === 'retake');
    if (purpose === 'purchase') paidLifecyclePolicy(retained.configuration, productId);
    if (!retained.audiences.includes(actor.audience)) fail('Commerce audience unavailable');
    if (actor.subject.kind === 'organization' && purpose !== 'retake') includedLearnerCapacity(retained.features);
    const transition = stored && (purpose === 'upgrade' || purpose === 'renew') ? await paidTransition(database, stored, retained, revisionId, purpose) : undefined;
    if (stored && !transition && !same(retained.configuration.subscription_lifecycle, stored.policy)) fail('Target lifecycle policy is incompatible with the retained subscription');
    if (purpose === 'retake' && retained.purchaseMode === 'contact_sales') {
      const purchased = await one(database, `subscriptions?select=id,product_id,plan_id,plan_amount&id=eq.${request.subscriptionId}&limit=2`);
      if (purchased.id !== request.subscriptionId || purchased.product_id !== productId || purchased.plan_id !== retained.planId
        || !Number.isFinite(Number(purchased.plan_amount)) || Number(purchased.plan_amount) <= 0) fail('Retakes require an actual paid negotiated subscription');
    }
    if (purpose === 'retake' && retained.purchaseMode === 'self_service' && !retained.prices.some(value => {
      const p = record(value, 'commerce.price', ['id', 'currency', 'minorUnit', 'amountMinor', 'intervalUnit', 'intervalCount', 'quantityBasis', 'audiences']);
      return integer(p.amountMinor, 'commerce.price.amountMinor') > 0 && array(p.audiences, 'commerce.price.audiences').includes(actor.audience);
    })) fail('Retakes require a paid plan; free plan assessment access is excluded');
    const selected = purpose === 'retake' ? null : retained.prices.filter(value => {
      const p = record(value, 'commerce.price', ['id', 'currency', 'minorUnit', 'amountMinor', 'intervalUnit', 'intervalCount', 'quantityBasis', 'audiences']);
      return p.id === uuid(request.priceId, 'commerce.priceId');
    }).map(price);
    if (selected !== null && selected.length !== 1) fail('Commerce price must resolve exactly once');
    if (!state && (purpose !== 'purchase' || request.expectedRevisionId !== revisionId)) fail('Initial purchase revision differs');
    // SkillPassport is the sole authority on whether a promo applies and by how much (see
    // promo_codes/promo_redemptions in SkillPassport's own database — this worker never reads
    // that data). This worker only ever adjusts the independently-derived published price above
    // (additive-only, matching the existing promo_codes.price_adjustment convention), by a
    // bounded amount, and never accepts an adjustment that leaves a non-positive final price.
    // An absent adjustment changes nothing (ordinary checkout is untouched).
    let effectivePrice = selected === null ? null : selected[0];
    if (effectivePrice && request.priceAdjustmentMinor !== undefined) {
      const adjustment = integer(request.priceAdjustmentMinor, 'commerce.priceAdjustmentMinor');
      if (adjustment > MAX_PROMO_ADJUSTMENT_MINOR) fail('Commerce price adjustment exceeds the fixed limit');
      const adjustedAmountMinor = effectivePrice.amountMinor + adjustment;
      if (adjustedAmountMinor < 1) fail('Commerce price adjustment would not leave a positive price');
      effectivePrice = { ...effectivePrice, amountMinor: adjustedAmountMinor };
    }
    const quote = createCommerceQuote({
      id: operationId, actor, subscriptionId: request.subscriptionId, productId, audience: actor.audience, purpose, state,
      planId: retained.planId, revisionId, sourcePurchaseMode: transition?.sourcePurchaseMode, price: effectivePrice, referenceId: request.referenceId === undefined ? null : uuid(request.referenceId, 'commerce.referenceId'), policy: retained.policy, now
    });
    return database.rpc(purpose === 'retake' ? 'issue_subscription_commerce_retake_quote' : 'issue_subscription_commerce_quote', { p_identity: identity, p_quote: quote });
  }
  if (request.kind === 'order' || request.kind === 'settle') {
    const quoteId = uuid(request.quoteId, 'commerce.quoteId'), row = await one(database, `subscription_commerce_quotes?select=quote,provider_order_id&id=eq.${quoteId}&limit=2`);
    const quote = scopedQuote(row.quote, actor, request.subscriptionId, productId);
    const target = quote.purpose !== 'retake' ? await published(database, quote.revisionId, productId) : undefined;
    if (quote.purpose === 'purchase' && target) paidLifecyclePolicy(target.configuration, productId);
    const transition = target && stored && (quote.purpose === 'upgrade' || quote.purpose === 'renew') ? await paidTransition(database, stored, target, quote.revisionId, quote.purpose) : undefined;
    if ((quote.purpose === 'upgrade' || quote.purpose === 'renew') && !transition) fail('Initialized subscription transition required before payment');
    if (quote.stateVersion !== request.expectedVersion || quote.expectedRevisionId !== request.expectedRevisionId) reject('state_changed', 'Commerce quote state differs');
    if (request.kind === 'order' && now >= quote.validUntil) reject('quote_expired', 'Commerce quote expired');
    if (request.kind === 'order' && quote.purpose === 'purchase') await assertInitialPurchaseAvailable(database, actor, productId);
    const capture = request.kind === 'settle' ? await retainedCapture(database, quote) : undefined;
    if (request.kind === 'settle' && now >= quote.validUntil && !capture) fail('Expired quote requires retained timely signed capture');
    if (!prior.length) await database.rpc('reserve_subscription_commerce_operation', { p_identity: identity, p_evidence: { quoteId } }, 'void');
    if (request.kind === 'order') {
      if (row.provider_order_id !== null) fail('Quote already has an order');
      const order = verifyCommerceOrder(quote, await provider.createOrder({ amount: quote.amountMinor, currency: quote.currency, receipt: quote.id, notes: { subscription_quote_id: quote.id, subscription_id: quote.subscriptionId } }));
      return database.rpc('complete_subscription_commerce_order', { p_identity: identity, p_order: order });
    }
    const orderId = text(row.provider_order_id, 'commerce.orderId');
    const order = await provider.getOrder(orderId);
    if (order.id !== orderId) fail('Provider returned a different retained order');
    const payment = request.reconcile === true
      ? reconcileCommercePayment(quote, order, await provider.getOrderPayments(orderId))
      : await provider.getPayment(text(request.paymentId, 'commerce.paymentId'));
    if (request.reconcile !== true && payment.id !== request.paymentId) fail('Provider returned a different payment');
    const settlement = verifyCommercePayment(quote, order, payment, operationId, now, capture);
    if (transition && stored && (quote.purpose === 'upgrade' || quote.purpose === 'renew')) {
      const lifecycleQuote: LifecycleQuote = {
        id: quote.id, planId: quote.planId, revisionId: quote.revisionId, productId, subscriptionId: quote.subscriptionId,
        subject: quote.subject, stateVersion: quote.stateVersion, operation: quote.purpose, amountMinor: quote.amountMinor, currency: quote.currency,
        periodStartsAt: quote.periodStartsAt, periodEndsAt: quote.periodEndsAt, validUntil: quote.validUntil
      };
      const lifecycleSettlement: LifecycleSettlement = {
        id: settlement.id, quoteId: quote.id, subscriptionId: quote.subscriptionId, subject: quote.subject,
        stateVersion: quote.stateVersion, revisionId: quote.revisionId, amountMinor: quote.amountMinor, currency: quote.currency, operation: quote.purpose,
        kind: 'verified_payment', recordedAt: settlement.settledAt, validUntil: null
      };
      const captures = new Map<string, LifecycleCapture>();
      if (capture) captures.set(settlement.id, {
        eventId: capture.eventId, actorId: actor.actorId, quoteId: quote.id, settlementId: settlement.id, productId,
        subscriptionId: quote.subscriptionId, subject: quote.subject, stateVersion: quote.stateVersion, revisionId: quote.revisionId, amountMinor: quote.amountMinor,
        currency: quote.currency, providerPaymentId: capture.paymentId, providerOrderId: capture.orderId, capturedAt: capture.capturedAt,
        paymentCreatedAt: capture.paymentCreatedAt, quoteCreatedAt: quote.createdAt
      });
      const prepared = prepareLifecycleCommit(operationId, stored.state, {
        operation: quote.purpose, subscriptionId: quote.subscriptionId, subject: quote.subject,
        expectedVersion: quote.stateVersion, expectedRevisionId: quote.expectedRevisionId, reason: quote.purpose === 'renew' ? 'Paid subscription renewal' : 'Paid subscription upgrade', quoteId: quote.id, settlementId: settlement.id
      }, stored.policy,
        {
          now, actorId: actor.actorId, subject: actor.subject, allowedOperations: new Set([quote.purpose]), quotes: new Map([[quote.id, lifecycleQuote]]), settlements: new Map([[settlement.id, lifecycleSettlement]]),
          captures, approvals: new Map(), publishedRevisions: new Map([
            [stored.state.revisionId, { planId: stored.state.planId, revisionId: stored.state.revisionId, productId }],
            [quote.revisionId, { planId: quote.planId, revisionId: quote.revisionId, productId }]]),
          targetPolicies: new Map([[quote.revisionId, transition.policy]]), revisionChanges: transition.changes
        });
      return database.rpc('settle_subscription_commerce_payment', {
        p_identity: identity, p_settlement: settlement, p_order: order, p_payment: payment,
        p_lifecycle_identity: prepared.identity, p_lifecycle_decision: prepared.decision
      });
    }
    return database.rpc('settle_subscription_commerce_payment', { p_identity: identity, p_settlement: settlement, p_order: order, p_payment: payment });
  }
  const settlementId = uuid(request.settlementId, 'commerce.settlementId');
  const saved = await one(database, `subscription_commerce_settlements?select=evidence,quote_id&id=eq.${settlementId}&limit=2`);
  const settlement = saved.evidence as CommerceSettlement;
  if (!settlement || settlement.subscriptionId !== request.subscriptionId || settlement.productId !== productId || !same(settlement.subject, actor.subject) || settlement.purpose === 'retake') fail('Refund purchase owner differs');
  const quoteRow = await one(database, `subscription_commerce_quotes?select=quote&id=eq.${uuid(saved.quote_id, 'quoteId')}&limit=2`);
  const quote = scopedQuote(quoteRow.quote, actor, request.subscriptionId, productId), retained = await published(database, quote.revisionId, productId);
  if (request.kind === 'refund_confirm') {
    const refundId = text(request.refundId, 'commerce.refundId');
    const refund = await provider.getRefund(settlement.providerPaymentId, refundId);
    return database.rpc('confirm_subscription_commerce_refund', { p_identity: identity, p_settlement_id: settlementId, p_refund: refund });
  }
  validateCommerceUsagePolicy(retained.configuration.subscription_commerce_usage);
  // Valuation, usage fence and the existing refund operation reservation share one
  // owner transaction. A failed or uncertain provider mutation never repeats it.
  const frozen = record(await database.rpc('freeze_subscription_commerce_refund', { p_identity: identity }), 'commerce.refundFreeze', ['amountMinor', 'usage', 'requestedAt']);
  const requestedAt = integer(frozen.requestedAt, 'commerce.refundFreeze.requestedAt');
  const usage = record(frozen.usage, 'commerce.refundFreeze.usage', ['settlement_id', 'subscription_id', 'product_id', 'subject', 'currency', 'amount_minor', 'complete', 'through_at']);
  const throughAt = Date.parse(String(usage.through_at));
  if (usage.settlement_id !== settlementId || usage.subscription_id !== request.subscriptionId || usage.product_id !== productId || !same(usage.subject, actor.subject) || usage.currency !== settlement.currency || usage.complete !== true || !Number.isFinite(throughAt) || throughAt !== requestedAt || requestedAt > Date.now()) fail('Complete current purchase-attributed usage valuation required');
  const refunds = await database.query<Record<string, unknown>>(`subscription_commerce_refunds?select=amount_minor,status&settlement_id=eq.${settlementId}`, undefined, 'json-array');
  if (refunds.some(r => r.status !== 'processed')) fail('Prior refund result is uncertain');
  const refundedMinor = refunds.reduce((sum, r) => integer(sum + integer(Number(r.amount_minor), 'refund.amountMinor'), 'refund.total'), 0);
  const amount = calculateCommerceRefund({ paidMinor: settlement.amountMinor, usageMinor: integer(Number(usage.amount_minor), 'usage.amountMinor'), refundedMinor, settledAt: settlement.settledAt, requestedAt, usageComplete: true }, retained.policy);
  if (amount === 0 || integer(frozen.amountMinor, 'commerce.refundFreeze.amountMinor', 1) !== amount) fail('Frozen refundable amount differs');
  const refund = await provider.createRefund(settlement.providerPaymentId, { amount, receipt: operationId, notes: { subscription_refund_operation_id: operationId, subscription_settlement_id: settlementId } });
  if (refund.payment_id !== settlement.providerPaymentId || refund.currency !== settlement.currency || refund.amount !== amount || refund.notes.subscription_refund_operation_id !== operationId) fail('Provider refund identity differs');
  return database.rpc('confirm_subscription_commerce_refund', { p_identity: identity, p_settlement_id: settlementId, p_refund: refund });
}
