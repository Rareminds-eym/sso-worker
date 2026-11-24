import { afterEach, describe, expect, it, vi } from 'vitest';
import { RAZORPAY_API_BASE_URL } from '../../../payments-worker/src/constants';
import { PaymentService } from '../../../payments-worker/src/entrypoint';
import { createLogger } from '../../../payments-worker/src/middleware/logger';
import { handleVerifyWebhook } from '../../../payments-worker/src/routes/payments';
import type { Env as PaymentEnvironment, VerifiedPaymentWebhook } from '../../../payments-worker/src/types';
import { db } from '../lib/db';
import { calculateCommerceRefund, commercePeriodEnd, createCommerceQuote, includedLearnerCapacity, parseCommerceRequest, reconcileCommercePayment, validateCommercePolicy, verifyCommerceOrder, verifyCommercePayment, type CommerceActor, type CommercePolicy, type CommerceProvider, type CommerceQuote } from '../lib/subscriptions/commerce';
import { CommerceRejection, executeSubscriptionCommerce, readRefundCancellation, readSettledRetake, recordSubscriptionCommerceCapture } from '../lib/subscriptions/commerce-persistence';
import { decideSubscriptionLifecycle, readSubscriptionLifecycleAccess, type LifecyclePolicy, type LifecycleState } from '../lib/subscriptions/lifecycle';
import * as lifecyclePersistence from '../lib/subscriptions/lifecycle-persistence';

const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const now = Date.UTC(2026, 0, 31, 12);
const policy: CommercePolicy = { schemaVersion: 1, quoteValidityMs: 60000, refundWindowMs: 7 * 24 * 60 * 60 * 1000, retake: { currency: 'INR', minorUnit: 2, amountMinor: 9900, everyRetake: true } };
const actor: CommerceActor = { actorId: id(1), subject: { kind: 'user', id: id(1) }, audience: 'learner' };
const price = { id: id(6), currency: 'INR', minorUnit: 2, amountMinor: 100000, intervalUnit: 'month' as const, intervalCount: 1, quantityBasis: 'subscription' as const, audiences: ['learner'] };
const state: LifecycleState = { id: id(2), subject: actor.subject, planId: id(3), revisionId: id(4), productId: id(5), version: 1, status: 'active', periodStartsAt: now - 10000, periodEndsAt: now + 100000, trialEndsAt: null, renewalEnabled: true, cancelledAt: null, paymentFailedAt: null, scheduledChange: null };
const paidLifecycle: LifecyclePolicy = {
  id: id(60), version: 1, productId: id(5), graceDurationMs: 1000, graceAccess: 'read_only', expiredAccess: 'read_only', readOnlyDurationMs: 10000,
  cancellationAccess: 'until_period_end', immediateDowngradeAllowed: false, paymentFailureRestrictedMs: 1000, paymentFailureAfterAccess: 'read_only', paymentRetryOffsetsMs: [100], suspensionApprovalRequired: true, reactivationApprovalRequired: true
};
const freeLifecycle: LifecyclePolicy = { ...paidLifecycle, id: id(61), billing: 'not_applicable', cancellationAccess: 'read_only', paymentFailureRestrictedMs: null, paymentFailureAfterAccess: null, paymentRetryOffsetsMs: [] };
const freeState: LifecycleState = { ...state, periodEndsAt: null, validity: 'perpetual', renewalEnabled: false, downgradedAt: null };
const purchase = () => createCommerceQuote({ id: id(7), actor, subscriptionId: id(2), productId: id(5), audience: actor.audience, purpose: 'purchase', state: null, planId: id(3), revisionId: id(4), price, referenceId: null, policy, now });
const retake = () => createCommerceQuote({ id: id(7), actor, subscriptionId: id(2), productId: id(5), audience: actor.audience, purpose: 'retake', state, planId: id(3), revisionId: id(4), price: null, referenceId: id(10), policy, now });
const order = (q: CommerceQuote) => ({ id: 'order_test123', amount: q.amountMinor, amount_paid: q.amountMinor, amount_due: 0, currency: q.currency, receipt: q.id, status: 'paid', notes: { subscription_quote_id: q.id, subscription_id: q.subscriptionId } });
const payment = (q: CommerceQuote) => ({ id: 'pay_test123', order_id: 'order_test123', amount: q.amountMinor, currency: q.currency, status: 'captured', captured: true, amount_refunded: 0, created_at: Math.floor(now / 1000) });
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('canonical subscription commerce policy and evidence', () => {
  it('retains the explicit included learner capacity and rejects unlimited or inferred quantities', () => {
    const grant = { key: 'included_learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 500 } };
    expect(includedLearnerCapacity([grant])).toBe(500);
    expect(includedLearnerCapacity([])).toBeNull();
    for (const value of [undefined, [grant, grant], [{ ...grant, enabled: false }], [{ ...grant, limit: { kind: 'unlimited' } }], [{ ...grant, limit: { kind: 'contract_required' } }],
      [{ ...grant, limit: { kind: 'finite', value: 0 } }], [{ ...grant, limit: { kind: 'finite', value: 1.5 } }], [{ ...grant, limit: { kind: 'finite', value: 2147483648 } }]]) expect(() => includedLearnerCapacity(value)).toThrow();
  });
  it('requires explicit configured retake and refund terms', () => {
    expect(validateCommercePolicy(policy)).toEqual(policy);
    expect(() => validateCommercePolicy({ ...policy, quoteValidityMs: null })).toThrow();
    expect(() => validateCommercePolicy({ ...policy, retake: { ...policy.retake, everyRetake: false } })).toThrow();
  });
  it('quotes every retake separately from retained policy, including first retake', () => {
    const q = retake(); expect(q.amountMinor).toBe(9900); expect(q.referenceId).toBe(id(10)); expect(q.priceId).toBeNull();
    expect(() => createCommerceQuote({ id: id(7), actor, subscriptionId: id(2), productId: id(5), audience: actor.audience, purpose: 'retake', state, planId: id(3), revisionId: id(4), price: null, referenceId: null, policy, now })).toThrow();
  });
  it('rejects foreign subject, inactive scope, seat price and caller policy fields', () => {
    expect(() => createCommerceQuote({ id: id(7), actor: { ...actor, subject: { kind: 'user', id: id(12) } }, subscriptionId: id(2), productId: id(5), audience: actor.audience, purpose: 'retake', state, planId: id(3), revisionId: id(4), price: null, referenceId: id(10), policy, now })).toThrow();
    expect(() => createCommerceQuote({ id: id(7), actor, subscriptionId: id(2), productId: id(5), audience: actor.audience, purpose: 'purchase', state: null, planId: id(3), revisionId: id(4), price: { ...price, quantityBasis: 'seat' }, referenceId: null, policy, now })).toThrow();
    expect(() => parseCommerceRequest({ ...baseRequest(), amountMinor: 1 })).toThrow();
    expect(() => parseCommerceRequest({ kind: 'refund', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), settlementId: id(8) })).toThrow('zero version');
  });
  it('clamps month end and leap-day year billing without extending the source anchor', () => {
    expect(commercePeriodEnd(now, price)).toBe(Date.UTC(2026, 1, 28, 12));
    expect(commercePeriodEnd(Date.UTC(2024, 1, 29), { intervalUnit: 'year', intervalCount: 1 })).toBe(Date.UTC(2025, 1, 28));
  });
  it('retains the existing paid period for an ordinary paid upgrade', () => {
    const q = createCommerceQuote({
      id: id(7), actor, subscriptionId: state.id, productId: state.productId, audience: actor.audience, purpose: 'upgrade', state,
      planId: id(30), revisionId: id(40), price, referenceId: null, policy, now
    });
    expect(q.periodStartsAt).toBe(state.periodStartsAt); expect(q.periodEndsAt).toBe(state.periodEndsAt);
    expect(() => createCommerceQuote({
      id: id(7), actor, subscriptionId: state.id, productId: state.productId, audience: actor.audience, purpose: 'upgrade', state: freeState,
      planId: id(30), revisionId: id(40), price, referenceId: null, policy, now
    })).toThrow('finite commercial period');
  });
  it('binds captured payment to owner quote, exact amount, currency, order, expiry and no prior refund', () => {
    const q = purchase(), o = order(q), p = payment(q);
    expect(verifyCommercePayment(q, o, p, id(8), now).providerPaymentId).toBe(p.id);
    for (const altered of [{ ...p, amount: 1 }, { ...p, currency: 'USD' }, { ...p, order_id: 'order_foreign' }, { ...p, captured: false }, { ...p, amount_refunded: 1 }, { ...p, status: 'authorized' }]) expect(() => verifyCommercePayment(q, o, altered, id(8), now)).toThrow();
    expect(() => verifyCommercePayment(q, o, p, id(8), q.validUntil)).toThrow();
    expect(() => verifyCommerceOrder(q, { ...o, notes: { ...o.notes, subscription_id: id(99) } })).toThrow();
  });
  it('requires explicit exclusive settlement mode and one unrefunded captured payment', () => {
    const common = { kind: 'settle', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7) };
    expect(parseCommerceRequest({ ...common, reconcile: true }).reconcile).toBe(true);
    for (const extra of [{}, { reconcile: false }, { reconcile: true, paymentId: 'pay_test123' }, { paymentId: null }]) expect(() => parseCommerceRequest({ ...common, ...extra })).toThrow();
    const q = purchase(), o = order(q), p = payment(q);
    expect(reconcileCommercePayment(q, o, { items: [{ ...p, id: 'pay_failed', status: 'failed', captured: false }, p] })).toEqual(p);
    for (const items of [[], [p, p], [p, { ...p, id: 'pay_second' }], [{ ...p, order_id: 'order_foreign' }], [{ ...p, amount: 1 }], [{ ...p, currency: 'USD' }], [{ ...p, status: 'authorized', captured: false }], [{ ...p, amount_refunded: 1 }], [p, { ...p, id: 'pay_pending', status: 'created', captured: false }], [{ ...p, status: 'failed', captured: true }]]) expect(() => reconcileCommercePayment(q, o, { items })).toThrow();
  });
  it('calculates paid less usage less previous refunds, floor and cap in exact minor units', () => {
    const calculate = (usageMinor: number, refundedMinor = 0) => calculateCommerceRefund({ paidMinor: 100000, usageMinor, refundedMinor, settledAt: now, requestedAt: now, usageComplete: true }, policy);
    expect(calculate(25000)).toBe(75000); expect(calculate(25000, 30000)).toBe(45000); expect(calculate(120000)).toBe(0); expect(calculate(0, 100000)).toBe(0);
  });
  it('includes exactly seven days and rejects missing usage, excess refunds and unsafe money', () => {
    const input = { paidMinor: 100000, usageMinor: 0, refundedMinor: 0, settledAt: now, requestedAt: now + policy.refundWindowMs, usageComplete: true };
    expect(calculateCommerceRefund(input, policy)).toBe(100000);
    for (const value of [{ ...input, requestedAt: input.requestedAt + 1 }, { ...input, usageComplete: false }, { ...input, refundedMinor: 100001 }, { ...input, usageMinor: 0.1 }, { ...input, paidMinor: Number.MAX_SAFE_INTEGER + 1 }]) expect(() => calculateCommerceRefund(value, policy)).toThrow();
  });
});

describe('actual signed capture webhook admission', () => {
  const secret = 'synthetic-webhook-secret';
  const event = () => ({ entity: 'event', event: 'payment.captured', created_at: 1000, payload: { payment: { entity: { entity: 'payment', id: 'pay_synthetic', order_id: 'order_synthetic', amount: 9900, currency: 'INR', status: 'captured', captured: true, amount_refunded: 0, created_at: 900 } } } });
  const signature = async (body: string) => {
    const encoder = new TextEncoder(), key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(body)))).map(n => n.toString(16).padStart(2, '0')).join('');
  };
  const setup = () => {
    vi.useFakeTimers(); vi.setSystemTime(10_000_000);
    vi.spyOn(console, 'log').mockImplementation(() => { }); vi.spyOn(console, 'error').mockImplementation(() => { });
    const send = vi.fn(async (_value: VerifiedPaymentWebhook) => { }), put = vi.fn(), get = vi.fn(async () => 'stale-kv-marker');
    const env = { RAZORPAY_WEBHOOK_SECRET: secret, WEBHOOK_QUEUE: { send }, RATE_LIMIT_KV: { put, get } } as unknown as PaymentEnvironment;
    const run = async (value: unknown, options: { signature?: string; body?: string } = {}) => {
      const body = options.body ?? JSON.stringify(value);
      return handleVerifyWebhook(new Request('https://owner.invalid/verify-webhook', { method: 'POST', headers: { 'x-razorpay-signature': options.signature ?? await signature(body) }, body }), env, createLogger('synthetic-request'), 'synthetic-request');
    };
    return { send, put, get, env, run };
  };
  it('preserves authenticated capture time separately from payment creation and delayed delivery', async () => {
    const f = setup(); expect((await f.run(event())).status).toBe(200);
    const admitted = f.send.mock.calls[0][0];
    expect(admitted.capture).toEqual({ paymentId: 'pay_synthetic', orderId: 'order_synthetic', amountMinor: 9900, currency: 'INR', capturedAt: 1_000_000, paymentCreatedAt: 900_000 });
    expect(admitted.verification).toEqual({ kind: 'razorpay_hmac_sha256', bodySha256: admitted.event_id, receivedAt: 10_000_000 });
    expect(admitted.event_id).toMatch(/^[a-f0-9]{64}$/); expect(admitted.payload).toEqual(event());
    expect(f.get).not.toHaveBeenCalled(); expect(f.put).not.toHaveBeenCalled();
  });
  it('persists admitted capture through the exact private owner contract and validates acknowledgement', async () => {
    const f = setup(); await f.run(event()); const admitted = f.send.mock.calls[0][0];
    const receipt = { eventId: admitted.event_id, quoteId: id(7), paymentId: 'pay_synthetic', productId: id(5), subscriptionId: id(2), capturedAt: 1_000_000 };
    const database = { query: vi.fn(), queryOne: vi.fn(), rpc: vi.fn(async () => receipt) };
    expect(await recordSubscriptionCommerceCapture(database as never, admitted)).toEqual(receipt);
    expect(database.rpc).toHaveBeenCalledExactlyOnceWith('record_subscription_commerce_capture', { p_event: admitted });
    database.rpc.mockResolvedValue({ ...receipt, paymentId: 'pay_foreign' });
    await expect(recordSubscriptionCommerceCapture(database as never, admitted)).rejects.toThrow('acknowledgement');
  });
  it('never sends malformed capture timing or verification authority to the database', async () => {
    const f = setup(); await f.run(event()); const admitted = f.send.mock.calls[0][0];
    const database = { query: vi.fn(), queryOne: vi.fn(), rpc: vi.fn() };
    for (const value of [{ ...admitted, event_id: 'invalid' }, { ...admitted, event_type: 'payment.authorized' },
    { ...admitted, verification: { ...admitted.verification, bodySha256: '0'.repeat(64) } },
    { ...admitted, capture: { ...admitted.capture!, capturedAt: 11_000_000 } },
    { ...admitted, capture: { ...admitted.capture!, paymentCreatedAt: 2_000_000 } }]) {
      await expect(recordSubscriptionCommerceCapture(database as never, value)).rejects.toThrow();
    }
    expect(database.rpc).not.toHaveBeenCalled();
  });
  it('never acknowledges missing queue or failed durable admission and admits the same signed retry', async () => {
    const f = setup(); f.send.mockRejectedValueOnce(new Error('queue unavailable'));
    expect((await f.run(event())).status).toBe(503); expect(f.put).not.toHaveBeenCalled();
    expect((await f.run(event())).status).toBe(200);
    expect(f.send.mock.calls[0][0].event_id).toBe(f.send.mock.calls[1][0].event_id);
    delete f.env.WEBHOOK_QUEUE; expect((await f.run(event())).status).toBe(503);
  });
  it('authenticates exact bytes before admitting capture evidence', async () => {
    const f = setup(), body = JSON.stringify(event());
    expect((await f.run(event(), { signature: 'invalid' })).status).toBe(401);
    expect((await f.run(event(), { body: body + ' ', signature: await signature(body) })).status).toBe(401);
    expect(f.send).not.toHaveBeenCalled();
  });
  it('uses a stable authenticated-body identity for replay and distinct events for the same payment', async () => {
    const f = setup(); await f.run(event()); await f.run(event()); await f.run({ ...event(), event: 'payment.authorized' });
    expect(f.send.mock.calls[0][0].event_id).toBe(f.send.mock.calls[1][0].event_id);
    expect(f.send.mock.calls[2][0].event_id).not.toBe(f.send.mock.calls[0][0].event_id);
    expect(f.send.mock.calls[2][0].capture).toBeNull();
  });
  it('rejects incomplete, un-captured, refunded, unsafe or temporally impossible capture entities', async () => {
    const f = setup(), base = event();
    for (const changed of [{ captured: false }, { status: 'authorized' }, { amount: 0 }, { amount: 1.5 }, { amount: Number.MAX_SAFE_INTEGER + 1 }, { amount_refunded: 1 }, { currency: 'bad' }, { id: 'foreign' }, { order_id: 'foreign' }, { created_at: 1001 }]) {
      expect((await f.run({ ...base, payload: { payment: { entity: { ...base.payload.payment.entity, ...changed } } } })).status).toBe(400);
    }
    for (const value of [null, [], { ...base, created_at: undefined }, { ...base, created_at: 10_001 }, { ...base, payload: {} }]) expect((await f.run(value)).status).toBe(400);
    expect(f.send).not.toHaveBeenCalled();
  });
});

describe('real PaymentService refund adapter with isolated fetch', () => {
  const paymentId = 'pay_Synthetic123456', refundId = 'rfnd_Synthetic123456';
  const refundInput = () => ({ amount: 75000, receipt: id(31), notes: { subscription_refund_operation_id: id(31), subscription_settlement_id: id(8) } });
  const refund = () => ({ id: refundId, entity: 'refund', payment_id: paymentId, amount: 75000, currency: 'INR', receipt: id(31), status: 'processed', notes: refundInput().notes });
  const service = () => new PaymentService({} as ExecutionContext, { RAZORPAY_KEY_ID: 'synthetic-key', RAZORPAY_KEY_SECRET: 'synthetic-secret', ENVIRONMENT: 'local' });
  it('uses documented refund endpoint, exact amount/body and supported idempotency header', async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json(refund())); vi.stubGlobal('fetch', fetcher);
    expect(await service().createRefund(paymentId, refundInput())).toEqual(refund());
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, options] = fetcher.mock.calls[0]; expect(url).toBe(`${RAZORPAY_API_BASE_URL}/payments/${paymentId}/refund`);
    expect(options.method).toBe('POST'); expect(options.headers['X-Refund-Idempotency']).toBe(id(31)); expect(JSON.parse(options.body)).toEqual(refundInput());
  });
  it.each(['pending', 'failed'])('retains provider %s rather than reporting refund success', async status => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ ...refund(), status })));
    expect((await service().createRefund(paymentId, refundInput())).status).toBe(status);
  });
  it('does not retry uncertain network results, server errors or malformed successful responses', async () => {
    for (const outcome of ['network', 'server', 'malformed']) {
      const fetcher = outcome === 'network' ? vi.fn().mockRejectedValue(new Error('uncertain')) : vi.fn().mockResolvedValue(outcome === 'server' ? Response.json({ error: 'unsafe provider detail' }, { status: 500 }) : Response.json({ id: refundId }));
      vi.stubGlobal('fetch', fetcher); await expect(service().createRefund(paymentId, refundInput())).rejects.toThrow(); expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });
  it('does not retry order creation on ambiguous failure', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => { }); vi.spyOn(console, 'error').mockImplementation(() => { });
    const fetcher = vi.fn().mockRejectedValue(new Error('uncertain')); vi.stubGlobal('fetch', fetcher);
    await expect(service().createOrder({ amount: 100000, currency: 'INR', receipt: id(7), notes: { subscription_quote_id: id(7) } })).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects invalid inputs before sending any mutation', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    for (const input of [{ ...refundInput(), amount: 0 }, { ...refundInput(), amount: 0.1 }, { ...refundInput(), receipt: 'short' }, { ...refundInput(), notes: { invalid: 'x'.repeat(257) } }]) await expect(service().createRefund(paymentId, input)).rejects.toThrow('INVALID_INPUT');
    await expect(service().createRefund('../foreign', refundInput())).rejects.toThrow('INVALID_INPUT');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('rejects altered amount, payment, currency, receipt, notes and unknown state from the provider', async () => {
    for (const changed of [{ amount: 1 }, { payment_id: 'pay_Foreign12345678' }, { currency: 'invalid' }, { receipt: id(99) }, { notes: {} }, { status: 'succeeded' }]) {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ ...refund(), ...changed })));
      await expect(service().createRefund(paymentId, refundInput())).rejects.toThrow('RAZORPAY_API_ERROR');
    }
  });
  it('fetches exact refund references and rejects foreign or invalid reference readback', async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json(refund())); vi.stubGlobal('fetch', fetcher);
    expect((await service().getRefund(paymentId, refundId)).id).toBe(refundId);
    expect(fetcher.mock.calls[0][0]).toBe(`${RAZORPAY_API_BASE_URL}/payments/${paymentId}/refunds/${refundId}`);
    fetcher.mockResolvedValue(Response.json({ ...refund(), id: 'rfnd_foreign' })); await expect(service().getRefund(paymentId, refundId)).rejects.toThrow();
    fetcher.mockClear(); await expect(service().getRefund(paymentId, '../foreign')).rejects.toThrow('INVALID_INPUT'); expect(fetcher).not.toHaveBeenCalled();
  });
});
function baseRequest() { return { kind: 'quote', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), purpose: 'purchase', revisionId: id(4), priceId: id(6) }; }
function fixture() {
  const operations = new Map<string, { identity: unknown; receipt: unknown }>(), quotes = new Map<string, { quote: CommerceQuote; provider_order_id: string | null; order_operation_id?: string | null }>();
  const captures: Record<string, unknown>[] = [];
  const rpc = vi.fn(async (name: string, args: Record<string, unknown>): Promise<unknown> => {
    const identity = args.p_identity as { operationId: string; request: { quoteId: string } }, operationId = identity.operationId;
    if (name === 'issue_subscription_commerce_quote' || name === 'issue_subscription_commerce_retake_quote') {
      const q = args.p_quote as CommerceQuote, result = { kind: 'quote', operationId, quote: q };
      operations.set(operationId, { identity, receipt: result }); quotes.set(q.id, { quote: q, provider_order_id: null, order_operation_id: null }); return result;
    }
    if (name === 'reserve_subscription_commerce_operation') {
      if (operations.has(operationId)) throw new Error('reserved');
      if ((identity.request as { kind?: string }).kind === 'order') { const q = quotes.get(identity.request.quoteId); if (q) q.order_operation_id = operationId; }
      operations.set(operationId, { identity, receipt: null }); return null;
    }
    if (name === 'complete_subscription_commerce_order') {
      const o = args.p_order as { id: string }, q = quotes.get(identity.request.quoteId)!; q.provider_order_id = o.id;
      const result = { kind: 'order', operationId, quoteId: q.quote.id, order: o }; operations.set(operationId, { identity, receipt: result }); return result;
    }
    if (name === 'void_unissued_subscription_commerce_order') {
      const o = operations.get(operationId)!, q = quotes.get(identity.request.quoteId)!;
      if (o.receipt !== null || q.provider_order_id !== null || Date.now() < q.quote.validUntil) throw new Error('Order already issued');
      const result = { kind: 'not_issued', operationId, quoteId: q.quote.id, voidedAt: Date.now() }; operations.set(operationId, { identity, receipt: result }); return result;
    }
    if (name === 'settle_subscription_commerce_payment') {
      const result = { kind: 'settlement', operationId, settlement: args.p_settlement }; operations.set(operationId, { identity, receipt: result }); return result;
    }
    throw new Error('Unexpected RPC ' + name);
  });
  const query = vi.fn(async (path: string) => {
    if (path.startsWith('subscriptions?select=id&')) return [];
    if (path.startsWith('subscription_commerce_operations?')) { const op = /operation_id=eq\.([^&]+)/.exec(path)![1]; return operations.has(op) ? [operations.get(op)!] : []; }
    if (path.startsWith('subscription_plan_publication_events?')) return [{ plan_id: id(3), revision_id: id(4), canonical_plan: { id: id(3), code: 'synthetic', productId: id(5), audiences: ['learner'], configuration: { subscription_lifecycle: paidLifecycle, subscription_commerce: policy, subscription_commerce_usage: { schemaVersion: 1, basis: 'time_proportional_service' } } } }];
    if (path.startsWith('subscription_plan_drafts?')) return [{ snapshot: { schemaVersion: 2, id: id(4), plan: { id: id(3), code: 'synthetic', productId: id(5) }, revisionNumber: 1, name: 'Synthetic', audiences: ['learner'], purchaseMode: 'self_service', prices: [price], features: [] } }];
    if (path.startsWith('subscription_commerce_quotes?')) { const q = /&id=eq\.([^&]+)/.exec(path)![1]; return quotes.has(q) ? [quotes.get(q)!] : []; }
    if (path.startsWith('subscription_commerce_captures?')) return captures;
    throw new Error('Unexpected query ' + path);
  });
  const database = { query, rpc, queryOne: vi.fn() };
  const provider: CommerceProvider = { createOrder: vi.fn(async () => order(purchase())), getOrder: vi.fn(async () => order(purchase())), getOrdersByReceipt: vi.fn(async () => ({ items: [] as ReturnType<typeof order>[] })), getPayment: vi.fn(async () => payment(purchase())), getOrderPayments: vi.fn(async () => ({ items: [payment(purchase())] })), createRefund: vi.fn(), getRefund: vi.fn() };
  return { database, provider, operations, rpc, quotes, captures };
}
describe('actual commerce issuer/provider boundary (isolated database contract)', () => {
  function upgradeFixture() {
    const f = fixture(), original = f.database.query.getMockImplementation()!;
    vi.spyOn(lifecyclePersistence, 'readSubscriptionLifecycle').mockResolvedValue({ state: freeState, policy: freeLifecycle, activatedAt: state.periodStartsAt });
    const changes = [{ fromRevisionId: state.revisionId, toRevisionId: id(40), operation: 'upgrade' }];
    f.database.query.mockImplementation(async path => {
      if (path.startsWith('subscription_plan_publication_events?')) {
        const target = path.includes(`revision_id=eq.${id(40)}`), revisionId = target ? id(40) : state.revisionId, planId = target ? id(30) : state.planId;
        return [{
          plan_id: planId, revision_id: revisionId, canonical_plan: {
            id: planId, code: 'pln_' + planId.replaceAll('-', ''), productId: state.productId, audiences: ['learner'],
            configuration: { subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: 2 }] }, subscription_commerce: policy, subscription_lifecycle: target ? paidLifecycle : freeLifecycle, ...(target ? { subscription_revision_changes: changes } : {}) }
          }
        }] as never;
      }
      if (path.startsWith('subscription_plan_drafts?')) {
        const target = path.includes(`id=eq.${id(40)}`), revisionId = target ? id(40) : state.revisionId, planId = target ? id(30) : state.planId;
        return [{ snapshot: { schemaVersion: 2, id: revisionId, plan: { id: planId, code: 'pln_' + planId.replaceAll('-', ''), productId: state.productId }, revisionNumber: 1, name: 'Synthetic', audiences: ['learner'], purchaseMode: target ? 'self_service' : 'free', prices: target ? [price] : [], features: [] } }] as never;
      }
      if (path.startsWith('subscription_lifecycle_operations?')) return [{ operation_id: id(9), transaction_id: id(9) }] as never;
      return original(path);
    });
    const request = { ...baseRequest(), purpose: 'upgrade', expectedVersion: 1, revisionId: id(40) };
    return { ...f, request, changes };
  }
  it('quotes perpetual free-to-paid against the existing identity and exact incoming published mapping', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = upgradeFixture();
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), f.request);
    expect(result).toMatchObject({ kind: 'quote', quote: { purpose: 'upgrade', subscriptionId: state.id, stateVersion: 1, expectedRevisionId: state.revisionId, periodStartsAt: now, periodEndsAt: commercePeriodEnd(now, price) } });
    expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it('starts a fresh paid interval for a finite free offer too', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = upgradeFixture();
    vi.mocked(lifecyclePersistence.readSubscriptionLifecycle).mockResolvedValue({ state: { ...state, renewalEnabled: false, downgradedAt: null }, policy: freeLifecycle, activatedAt: state.periodStartsAt });
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), f.request)).toMatchObject({ quote: { periodStartsAt: now, periodEndsAt: commercePeriodEnd(now, price) } });
  });
  it('rejects missing upgrade authority before issuing any quote or provider order', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = upgradeFixture(), original = f.database.query.getMockImplementation()!;
    f.database.query.mockImplementation(async path => {
      const rows = await original(path);
      if (!path.startsWith('subscription_plan_publication_events?')) return rows;
      return rows.map(row => {
        const value = row as unknown as { canonical_plan: { configuration: Record<string, unknown> } };
        return { ...row, canonical_plan: { ...value.canonical_plan, configuration: { ...value.canonical_plan.configuration, subscription_revision_changes: [] } } };
      }) as never;
    });
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), f.request)).rejects.toThrow('Approved upgrade transition unavailable');
    expect(f.rpc).not.toHaveBeenCalled(); expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it('requires real capture and prepares payment and lifecycle activation for the same atomic RPC', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = upgradeFixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), f.request);
    const q = f.quotes.get(id(7))!.quote;
    vi.mocked(f.provider.createOrder).mockResolvedValue(order(q)); vi.mocked(f.provider.getOrder).mockResolvedValue(order(q)); vi.mocked(f.provider.getPayment).mockResolvedValue(payment(q));
    const common = { subscriptionId: state.id, subject: actor.subject, expectedVersion: 1, expectedRevisionId: state.revisionId, quoteId: q.id };
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...common, kind: 'order' });
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), { ...common, kind: 'settle', paymentId: 'pay_test123' });
    expect(result).toMatchObject({ kind: 'settlement' });
    const [, args] = f.rpc.mock.calls.find(([name]) => name === 'settle_subscription_commerce_payment')!;
    expect(args.p_lifecycle_identity).toMatchObject({ operationId: id(9), state: freeState, policy: freeLifecycle, revisionChanges: f.changes });
    const decision = args.p_lifecycle_decision as ReturnType<typeof decideSubscriptionLifecycle>;
    expect(decision.next).toMatchObject({ id: state.id, version: 2, planId: id(30), revisionId: id(40), periodStartsAt: now, periodEndsAt: commercePeriodEnd(now, price), renewalEnabled: true, downgradedAt: null });
    expect(decision.next).not.toHaveProperty('validity');
    expect(readSubscriptionLifecycleAccess(decision.next, paidLifecycle, now).access).toBe('full');
    const prepared = args.p_lifecycle_identity as { request: unknown };
    const receipt = { operationId: id(9), decision, committedAt: new Date(now).toISOString() }, original = f.database.query.getMockImplementation()!;
    f.database.query.mockImplementation(async path => path.startsWith('subscription_lifecycle_operations?select=identity,receipt')
      ? [{ identity: args.p_lifecycle_identity, receipt }] as never : original(path));
    vi.setSystemTime(now + policy.quoteValidityMs + 1000);
    // The outer service's existing fulfillment step must become an exact replay,
    // even after the checkout deadline, rather than a second lifecycle mutation.
    expect(await lifecyclePersistence.readSubscriptionLifecycleReplay(f.database as never, id(9), prepared.request, actor.actorId, actor.subject, id(5), new Set(['upgrade']))).toEqual(receipt);
    await expect(lifecyclePersistence.readSubscriptionLifecycleReplay(f.database as never, id(9), { operation: 'upgrade', reason: 'changed' }, actor.actorId, actor.subject, id(5), new Set(['upgrade']))).rejects.toThrow('replay conflicts');
    const writes = f.rpc.mock.calls.length;
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), { ...common, kind: 'settle', paymentId: 'pay_test123' })).toEqual(result);
    expect(f.rpc).toHaveBeenCalledTimes(writes); expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
  });
  it('does not settle or activate an authorized but uncaptured payment', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = upgradeFixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), f.request); const q = f.quotes.get(id(7))!.quote;
    f.quotes.get(q.id)!.provider_order_id = 'order_test123'; vi.mocked(f.provider.getOrder).mockResolvedValue(order(q));
    vi.mocked(f.provider.getPayment).mockResolvedValue({ ...payment(q), status: 'authorized', captured: false });
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), { kind: 'settle', subscriptionId: state.id, subject: actor.subject, expectedVersion: 1, expectedRevisionId: state.revisionId, quoteId: q.id, paymentId: 'pay_test123' })).rejects.toThrow();
    expect(f.rpc.mock.calls.some(([name]) => name === 'settle_subscription_commerce_payment')).toBe(false);
  });
  it('rejects an initial purchase before quoting or creating an order when the subject already has a current subscription', async () => {
    const f = fixture(), original = f.database.query.getMockImplementation()!;
    f.database.query.mockImplementation(async path => path.startsWith('subscriptions?select=id&') ? [{ id: id(90) }] : original(path));
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest())).rejects.toThrow('explicit lifecycle transition');
    expect(f.rpc).not.toHaveBeenCalled(); expect(f.provider.createOrder).not.toHaveBeenCalled();
    expect(f.database.query).toHaveBeenCalledWith(expect.stringContaining(`user_id=eq.${actor.subject.id}&is_organization_subscription=not.is.true`), undefined, 'json-array');
  });
  it.each([undefined, { ...paidLifecycle, productId: id(99) }, freeLifecycle])('rejects unavailable or incompatible initial activation terms before a quote (%j)', async lifecycle => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture(), original = f.database.query.getMockImplementation()!;
    f.database.query.mockImplementation(async path => {
      const rows = await original(path); if (!path.startsWith('subscription_plan_publication_events?')) return rows;
      return rows.map(row => {
        const value = row as unknown as { canonical_plan: { configuration: Record<string, unknown> } };
        return { ...row, canonical_plan: { ...value.canonical_plan, configuration: { ...value.canonical_plan.configuration, subscription_lifecycle: lifecycle } } };
      }) as never;
    });
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest())).rejects.toThrow();
    expect(f.rpc).not.toHaveBeenCalled(); expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it('checks again before ordering when a current subscription appears after the quote', async () => {
    const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    const original = f.database.query.getMockImplementation()!;
    f.database.query.mockImplementation(async path => path.startsWith('subscriptions?select=id&') ? [{ id: id(90) }] : original(path));
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { kind: 'order', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7) })).rejects.toThrow('explicit lifecycle transition');
    expect(f.provider.createOrder).not.toHaveBeenCalled();
    expect(f.rpc).toHaveBeenCalledTimes(1);
  });
  it('reads the exact unpaid order without issuing another order or writing an operation', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    const request = { kind: 'order', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7) };
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), request);
    vi.mocked(f.provider.getOrder).mockResolvedValue({ ...order(purchase()), status: 'created', amount_paid: 0, amount_due: purchase().amountMinor });
    vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: [] });
    const writes = f.rpc.mock.calls.length;
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout' });
    expect(result).toMatchObject({ kind: 'checkout', status: 'unpaid', issued: { operationId: id(8), order: { id: 'order_test123' } } });
    expect(f.rpc).toHaveBeenCalledTimes(writes); expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
    vi.setSystemTime(now + policy.quoteValidityMs);
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout' })).toMatchObject({ status: 'expired' });
    for (const changed of [{ ...actor, actorId: id(90) }, { ...actor, subject: { kind: 'user' as const, id: id(91) } }]) {
      await expect(executeSubscriptionCommerce(f.database as never, f.provider, changed, id(5), id(8), { ...request, kind: 'checkout' })).rejects.toThrow();
    }
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(99), id(8), { ...request, kind: 'checkout' })).rejects.toThrow();
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout', quoteId: id(99) })).rejects.toThrow();
  });
  it.each(['authorized', 'created', 'captured', 'refunded'] as const)('keeps %s payment evidence out of the resumable path', async status => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    const request = { kind: 'order', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7) };
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), request);
    vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: [{ ...payment(purchase()), status, captured: status === 'captured' }] });
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout' })).toMatchObject({ status: status === 'captured' ? 'paid' : 'blocked' });
    expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
  });
  it('allows the original unpaid order to resume after created or failed attempts without another reservation', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture(), q = purchase();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    const request = { kind: 'order', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: q.id };
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), request);
    vi.mocked(f.provider.getOrder).mockResolvedValue({ ...order(q), status: 'attempted', amount_paid: 0, amount_due: q.amountMinor });
    const attempts = ['created', 'failed', 'created'].map((status, index) => ({ ...payment(q), id: `pay_attempt${index}`, status, captured: false }));
    vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: attempts });
    const writes = f.rpc.mock.calls.length;
    const check = () => executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout' });
    expect(await check()).toMatchObject({ kind: 'checkout', status: 'unpaid', issued: { operationId: id(8), quoteId: q.id, order: { id: 'order_test123' } } });
    vi.setSystemTime(q.validUntil);
    expect(await check()).toMatchObject({ status: 'expired' });
    expect(f.rpc).toHaveBeenCalledTimes(writes);
    expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
    expect(f.provider.getPayment).not.toHaveBeenCalled();
    expect(f.provider.createRefund).not.toHaveBeenCalled();
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), {
      ...request, kind: 'settle', reconcile: true,
    })).rejects.toThrow();
    expect(f.rpc.mock.calls.some(([name]) => name === 'settle_subscription_commerce_payment')).toBe(false);
  });
  it('keeps authorization, capture mismatches, refunds and inconsistent balances blocked alongside created attempts', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture(), q = purchase();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    const request = { kind: 'order', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: q.id };
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), request);
    const unpaid = { ...order(q), status: 'attempted', amount_paid: 0, amount_due: q.amountMinor };
    const created = { ...payment(q), id: 'pay_created', status: 'created', captured: false };
    for (const items of [[created, { ...created, id: 'pay_authorized', status: 'authorized' }], [{ ...created, captured: true }],
    [{ ...created, amount_refunded: 1 }]]) {
      vi.mocked(f.provider.getOrder).mockResolvedValue(unpaid);
      vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items });
      expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout' })).toMatchObject({ status: 'blocked' });
    }
    for (const balances of [{ amount_paid: 1, amount_due: q.amountMinor - 1 }, { amount_paid: 0, amount_due: q.amountMinor - 1 }]) {
      vi.mocked(f.provider.getOrder).mockResolvedValue({ ...unpaid, ...balances });
      vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: [created] });
      expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout' })).toMatchObject({ status: 'blocked' });
    }
    vi.mocked(f.provider.getOrder).mockResolvedValue(order(q));
    vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: [created, payment(q)] });
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...request, kind: 'checkout' })).toMatchObject({ status: 'blocked' });
    expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
  });
  it('creates an order after a real database client receives a 204 reservation response', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input), prefix = '/rest/v1/';
      const path = url.pathname.slice(prefix.length) + url.search;
      if (path.startsWith('rpc/')) {
        const name = path.slice(4), result = await f.rpc(name, JSON.parse(String(init?.body)));
        return name === 'reserve_subscription_commerce_operation' ? new Response(null, { status: 204 }) : Response.json(result);
      }
      return Response.json(await f.database.query(path));
    }));
    const database = db({ SUPABASE_URL: 'https://synthetic.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic' } as Parameters<typeof db>[0]);
    await executeSubscriptionCommerce(database, f.provider, actor, id(5), id(7), baseRequest());
    const request = { kind: 'order', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7) };
    const result = await executeSubscriptionCommerce(database, f.provider, actor, id(5), id(8), request);
    expect(result).toMatchObject({ kind: 'order', operationId: id(8), quoteId: id(7) });
    expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
    expect(await executeSubscriptionCommerce(database, f.provider, actor, id(5), id(8), request)).toEqual(result);
    expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
  });
  describe('approved recovery of a reserved order whose provider result was never recorded', () => {
    const orderRequest = { kind: 'order', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7) };
    const checkout = { ...orderRequest, kind: 'checkout' };
    async function stuck() {
      vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
      await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
      vi.spyOn(console, 'error').mockImplementation(() => { });
      vi.mocked(f.provider.createOrder).mockRejectedValueOnce(new Error('response lost'));
      await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), orderRequest)).rejects.toThrow('response lost');
      expect(f.operations.get(id(8))?.receipt).toBeNull(); expect(f.quotes.get(id(7))?.provider_order_id).toBeNull();
      vi.mocked(f.provider.createOrder).mockClear();
      return f;
    }
    const run = (f: ReturnType<typeof fixture>, request: Record<string, unknown> = checkout) => executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), request);
    const writes = (f: ReturnType<typeof fixture>, name: string) => f.rpc.mock.calls.filter(([called]) => called === name).length;
    it('voids an expired reservation as not issued only after the provider confirms no order, and replays idempotently', async () => {
      const f = await stuck(); vi.setSystemTime(purchase().validUntil);
      expect(await run(f)).toEqual({ kind: 'checkout', status: 'not_issued', operationId: id(8), quoteId: id(7) });
      expect(f.provider.getOrdersByReceipt).toHaveBeenCalledWith(id(7));
      expect(writes(f, 'void_unissued_subscription_commerce_order')).toBe(1);
      expect(f.operations.get(id(8))?.receipt).toMatchObject({ kind: 'not_issued', operationId: id(8), quoteId: id(7) });
      expect(await run(f)).toEqual({ kind: 'checkout', status: 'not_issued', operationId: id(8), quoteId: id(7) });
      expect(writes(f, 'void_unissued_subscription_commerce_order')).toBe(1);
      await expect(run(f, orderRequest)).rejects.toMatchObject({ code: 'checkout_released' });
      expect(f.provider.createOrder).not.toHaveBeenCalled(); expect(f.provider.getOrder).not.toHaveBeenCalled();
    });
    it('reports a pending order without voiding while the quote is still valid', async () => {
      const f = await stuck();
      expect(await run(f)).toEqual({ kind: 'checkout', status: 'order_pending', operationId: id(8), quoteId: id(7) });
      expect(writes(f, 'void_unissued_subscription_commerce_order')).toBe(0); expect(f.operations.get(id(8))?.receipt).toBeNull();
      expect(f.provider.createOrder).not.toHaveBeenCalled();
    });
    it('records exactly one verified provider order under the original identity and inspects it', async () => {
      const f = await stuck(), q = purchase();
      vi.mocked(f.provider.getOrdersByReceipt).mockResolvedValue({ items: [{ ...order(q), status: 'created', amount_paid: 0, amount_due: q.amountMinor }] });
      vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: [] });
      expect(await run(f)).toMatchObject({ kind: 'checkout', status: 'unpaid', issued: { kind: 'order', operationId: id(8), quoteId: id(7), order: { id: 'order_test123' } } });
      expect(f.quotes.get(id(7))?.provider_order_id).toBe('order_test123');
      expect(f.rpc.mock.calls.find(([name]) => name === 'complete_subscription_commerce_order')?.[1]).toMatchObject({ p_identity: { operationId: id(8), request: { kind: 'order', quoteId: id(7) } } });
      expect(writes(f, 'void_unissued_subscription_commerce_order')).toBe(0); expect(f.provider.createOrder).not.toHaveBeenCalled();
    });
    it('reports an unrecorded unpaid order on an expired quote as expired without writing, and paid evidence as reconciliation', async () => {
      const f = await stuck(), q = purchase(); vi.setSystemTime(q.validUntil);
      vi.mocked(f.provider.getOrdersByReceipt).mockResolvedValue({ items: [{ ...order(q), status: 'created', amount_paid: 0, amount_due: q.amountMinor }] });
      vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: [] });
      const before = f.rpc.mock.calls.length;
      expect(await run(f)).toMatchObject({ kind: 'checkout', status: 'expired', issued: { kind: 'order', operationId: id(8), quoteId: id(7), order: { id: 'order_test123' } } });
      vi.mocked(f.provider.getOrdersByReceipt).mockResolvedValue({ items: [order(q)] });
      vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items: [payment(q)] });
      await expect(run(f)).rejects.toMatchObject({ code: 'reconciliation_required' });
      expect(f.rpc).toHaveBeenCalledTimes(before); expect(f.operations.get(id(8))?.receipt).toBeNull();
    });
    it.each([
      ['multiple matching orders', (q: CommerceQuote) => [order(q), { ...order(q), id: 'order_other' }]],
      ['an order that differs from the quote', (q: CommerceQuote) => [{ ...order(q), amount: q.amountMinor + 1 }]],
    ])('requires reconciliation for %s without any write', async (_label, items) => {
      const f = await stuck(); vi.setSystemTime(purchase().validUntil);
      vi.mocked(f.provider.getOrdersByReceipt).mockResolvedValue({ items: items(purchase()) });
      const before = f.rpc.mock.calls.length;
      await expect(run(f)).rejects.toMatchObject({ code: 'reconciliation_required' });
      expect(f.rpc).toHaveBeenCalledTimes(before); expect(f.operations.get(id(8))?.receipt).toBeNull();
    });
    it('never voids when the provider lookup fails', async () => {
      const f = await stuck(); vi.setSystemTime(purchase().validUntil);
      vi.mocked(f.provider.getOrdersByReceipt).mockRejectedValue(new Error('RAZORPAY_API_ERROR: Unable to retrieve checkout order'));
      const failure = await run(f).catch(error => error);
      expect(failure).toBeInstanceOf(Error); expect(failure).not.toBeInstanceOf(CommerceRejection);
      expect(writes(f, 'void_unissued_subscription_commerce_order')).toBe(0); expect(f.operations.get(id(8))?.receipt).toBeNull();
    });
    it('classifies deterministic rejections with stable codes', async () => {
      const f = await stuck();
      await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), checkout)).rejects.toMatchObject({ code: 'order_unavailable' });
      await expect(run(f, orderRequest)).rejects.toMatchObject({ code: 'operation_pending' });
      vi.setSystemTime(purchase().validUntil);
      await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(10), orderRequest)).rejects.toMatchObject({ code: 'quote_expired' });
    });
  });
  it('institution purchase prices include retained learners without multiplying the institution price', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    const organizationActor = { ...actor, subject: { kind: 'organization' as const, id: id(80) } };
    const f = fixture(), original = f.database.query.getMockImplementation()!;
    f.database.query.mockImplementation(async path => {
      if (path.startsWith('subscription_plan_drafts?')) return (await original(path)).map(row => ({
        ...row, snapshot: {
          ...(row as { snapshot: object }).snapshot,
          features: [{ key: 'included_learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 500 } }]
        }
      })) as never;
      return original(path);
    });
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, organizationActor, id(5), id(7), { ...baseRequest(), subject: organizationActor.subject });
    expect(result).toMatchObject({ kind: 'quote', quote: { amountMinor: price.amountMinor, subject: organizationActor.subject, priceId: price.id } });
    expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it('quotes every negotiated paid retake without inventing a public contract price', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    vi.spyOn(lifecyclePersistence, 'readSubscriptionLifecycle').mockResolvedValue({ state, policy: paidLifecycle, activatedAt: state.periodStartsAt });
    const f = fixture(), original = f.database.query.getMockImplementation()!;
    f.database.query.mockImplementation(async path => {
      if (path.startsWith('subscription_plan_drafts?')) {
        const rows = await original(path);
        return rows.map(row => ({ ...row, snapshot: { ...(row as { snapshot: object }).snapshot, purchaseMode: 'contact_sales', prices: [] } })) as never;
      }
      if (path.startsWith('subscriptions?')) return [{ id: state.id, product_id: state.productId, plan_id: state.planId, plan_amount: 10000 }] as never;
      return original(path);
    });
    const request = { kind: 'quote', subscriptionId: state.id, subject: actor.subject, expectedVersion: state.version, expectedRevisionId: state.revisionId, purpose: 'retake', revisionId: state.revisionId, referenceId: id(10) };
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), request);
    expect(result).toMatchObject({ kind: 'quote', quote: { amountMinor: 9900, priceId: null, referenceId: id(10) } });
    expect(f.rpc).toHaveBeenLastCalledWith('issue_subscription_commerce_retake_quote', expect.objectContaining({ p_quote: expect.objectContaining({ amountMinor: 9900 }) }));
    expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it('rejects free, unpaid or foreign negotiated ownership before issuing retake quotes', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    vi.spyOn(lifecyclePersistence, 'readSubscriptionLifecycle').mockResolvedValue({ state, policy: paidLifecycle, activatedAt: state.periodStartsAt });
    for (const terms of [{ mode: 'free', amount: 0, plan: state.planId }, { mode: 'contact_sales', amount: 0, plan: state.planId }, { mode: 'contact_sales', amount: 100, plan: id(90) }]) {
      const f = fixture(), original = f.database.query.getMockImplementation()!;
      f.database.query.mockImplementation(async path => {
        if (path.startsWith('subscription_plan_drafts?')) return (await original(path)).map(row => ({ ...row, snapshot: { ...(row as { snapshot: object }).snapshot, purchaseMode: terms.mode, prices: [] } })) as never;
        if (path.startsWith('subscriptions?')) return [{ id: state.id, product_id: state.productId, plan_id: terms.plan, plan_amount: terms.amount }] as never;
        return original(path);
      });
      await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), { kind: 'quote', subscriptionId: state.id, subject: actor.subject, expectedVersion: 1, expectedRevisionId: state.revisionId, purpose: 'retake', revisionId: state.revisionId, referenceId: id(10) })).rejects.toThrow();
      expect(f.rpc).not.toHaveBeenCalled(); expect(f.provider.createOrder).not.toHaveBeenCalled();
    }
  });
  it('does not call the refund provider for missing, incomplete, foreign, stale or malformed usage valuation', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    vi.spyOn(lifecyclePersistence, 'readSubscriptionLifecycle').mockResolvedValue({ state, policy: paidLifecycle, activatedAt: state.periodStartsAt });
    const q = purchase(), settlement = verifyCommercePayment(q, order(q), payment(q), id(8), now);
    const complete = { settlement_id: id(8), subscription_id: id(2), product_id: id(5), subject: actor.subject, currency: 'INR', amount_minor: 25000, complete: true, through_at: new Date(now).toISOString() };
    for (const usage of [null, { ...complete, complete: false }, { ...complete, product_id: id(99) }, { ...complete, through_at: 'invalid' }, { ...complete, through_at: new Date(now - 1).toISOString() }, { ...complete, through_at: new Date(now + 1).toISOString() }]) {
      const f = fixture(), original = f.database.query.getMockImplementation()!;
      f.quotes.set(q.id, { quote: q, provider_order_id: 'order_test123' });
      f.database.query.mockImplementation(async path => {
        if (path.startsWith('subscription_commerce_settlements?')) return [{ evidence: settlement, quote_id: q.id }] as never;
        if (path.startsWith('subscription_commerce_usage_valuations?')) throw new Error('Separate valuation read is forbidden');
        return original(path);
      });
      f.rpc.mockImplementation(async name => { if (name === 'freeze_subscription_commerce_refund') return { amountMinor: 75000, usage, requestedAt: now }; throw new Error('Unexpected RPC'); });
      await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(31), { kind: 'refund', subscriptionId: id(2), subject: actor.subject, expectedVersion: 1, expectedRevisionId: id(4), settlementId: id(8) })).rejects.toThrow();
      expect(f.provider.createRefund).not.toHaveBeenCalled();
      expect(f.rpc.mock.calls.some(([name]) => name === 'reserve_subscription_commerce_operation')).toBe(false);
    }
  });
  it('calculates the refund from attributed usage and sends exact owner operation identity once', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    vi.spyOn(lifecyclePersistence, 'readSubscriptionLifecycle').mockResolvedValue({ state, policy: paidLifecycle, activatedAt: state.periodStartsAt });
    const f = fixture(), q = purchase(), settlement = verifyCommercePayment(q, order(q), payment(q), id(8), now), original = f.database.query.getMockImplementation()!;
    f.quotes.set(q.id, { quote: q, provider_order_id: 'order_test123' });
    f.database.query.mockImplementation(async path => {
      if (path.startsWith('subscription_commerce_settlements?')) return [{ evidence: settlement, quote_id: q.id }] as never;
      if (path.startsWith('subscription_commerce_usage_valuations?')) return [{ settlement_id: id(8), subscription_id: id(2), product_id: id(5), subject: actor.subject, currency: 'INR', amount_minor: 25000, complete: true, through_at: new Date(now).toISOString() }] as never;
      if (path.startsWith('subscription_commerce_refunds?')) return [{ amount_minor: 30000, status: 'processed' }] as never;
      return original(path);
    });
    vi.mocked(f.provider.createRefund).mockResolvedValue({ id: 'rfnd_test123', payment_id: settlement.providerPaymentId, amount: 45000, currency: 'INR', status: 'processed', notes: { subscription_refund_operation_id: id(31), subscription_settlement_id: id(8) } });
    f.rpc.mockImplementation(async (name, args) => {
      if (name === 'freeze_subscription_commerce_refund') { f.operations.set(id(31), { identity: args.p_identity, receipt: null }); return { amountMinor: 45000, requestedAt: now, usage: { settlement_id: id(8), subscription_id: id(2), product_id: id(5), subject: actor.subject, currency: 'INR', amount_minor: 25000, complete: true, through_at: new Date(now).toISOString() } }; }
      if (name === 'confirm_subscription_commerce_refund') return { kind: 'refund', operationId: id(31), status: 'processed', accessRevoked: true };
      throw new Error('Unexpected RPC');
    });
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(31), { kind: 'refund', subscriptionId: id(2), subject: actor.subject, expectedVersion: 1, expectedRevisionId: id(4), settlementId: id(8) });
    expect(f.provider.createRefund).toHaveBeenCalledExactlyOnceWith(settlement.providerPaymentId, { amount: 45000, receipt: id(31), notes: { subscription_refund_operation_id: id(31), subscription_settlement_id: id(8) } });
    expect(result).toEqual({ kind: 'refund', operationId: id(31), status: 'processed', accessRevoked: true });
  });
  it('issues from immutable publication, creates bound order and reads provider evidence before settlement', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    const common = { subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4) };
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), { ...common, kind: 'order', quoteId: id(7) });
    expect(f.provider.createOrder).toHaveBeenCalledWith({ amount: 100000, currency: 'INR', receipt: id(7), notes: { subscription_quote_id: id(7), subscription_id: id(2) } });
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), { ...common, kind: 'settle', quoteId: id(7), paymentId: 'pay_test123' });
    expect(f.provider.getPayment).toHaveBeenCalledWith('pay_test123');
    expect(f.rpc).toHaveBeenLastCalledWith('settle_subscription_commerce_payment', expect.objectContaining({ p_settlement: expect.objectContaining({ amountMinor: 100000, subject: actor.subject }) }));
  });
  it('explicitly reconciles a retained order without a callback and resumes the same pending operation', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    f.quotes.get(id(7))!.provider_order_id = 'order_test123';
    const request = { kind: 'settle', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7), reconcile: true };
    vi.mocked(f.provider.getOrderPayments).mockRejectedValueOnce(new Error('provider unavailable'));
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), request)).rejects.toThrow('unavailable');
    expect(f.operations.get(id(9))?.receipt).toBeNull();
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), request);
    expect(result).toMatchObject({ kind: 'settlement', settlement: { providerPaymentId: 'pay_test123' } });
    expect(f.provider.getOrderPayments).toHaveBeenCalledWith('order_test123');
    expect(f.provider.createOrder).not.toHaveBeenCalled(); expect(f.provider.getPayment).not.toHaveBeenCalled(); expect(f.provider.createRefund).not.toHaveBeenCalled();
    expect(f.rpc.mock.calls.filter(([name]) => name === 'reserve_subscription_commerce_operation')).toHaveLength(1);
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), request)).toEqual(result);
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), { ...request, reconcile: undefined, paymentId: 'pay_test123' })).rejects.toThrow();
  });
  it('settles delayed confirmation only from retained timely signed capture and replays without another payment read', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    f.quotes.get(id(7))!.provider_order_id = 'order_test123';
    f.captures.push({
      event_id: 'a'.repeat(64), quote_id: id(7), provider_payment_id: 'pay_test123', provider_order_id: 'order_test123',
      captured_at_ms: now + 1000, payment_created_at_ms: now, amount_minor: price.amountMinor, currency: price.currency
    });
    vi.setSystemTime(now + policy.quoteValidityMs + 10000);
    const request = { kind: 'settle', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7), reconcile: true };
    const result = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), request);
    expect(result).toMatchObject({ kind: 'settlement', settlement: { settledAt: now + 1000, providerPaymentId: 'pay_test123' } });
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), request)).toEqual(result);
    expect(f.provider.getOrderPayments).toHaveBeenCalledTimes(1);
    expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it.each([{}, { captured_at_ms: now + policy.quoteValidityMs }, { provider_payment_id: 'pay_Foreign' },
  { provider_order_id: 'order_Foreign' }, { quote_id: id(99) }, { amount_minor: 1 }, { currency: 'USD' },
  { payment_created_at_ms: now - 1000 }])('rejects missing or conflicting delayed capture evidence %j', async altered => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    f.quotes.get(id(7))!.provider_order_id = 'order_test123';
    if (Object.keys(altered).length) f.captures.push({
      event_id: 'a'.repeat(64), quote_id: id(7), provider_payment_id: 'pay_test123', provider_order_id: 'order_test123',
      captured_at_ms: now + 1000, payment_created_at_ms: now, amount_minor: price.amountMinor, currency: price.currency, ...altered
    });
    vi.setSystemTime(now + policy.quoteValidityMs + 10000);
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), {
      kind: 'settle', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7), reconcile: true
    })).rejects.toThrow();
    expect(f.rpc.mock.calls.some(([name]) => name === 'settle_subscription_commerce_payment')).toBe(false);
    expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it('never settles ambiguous, pending, refunded, foreign or unavailable reconciliation evidence', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    const p = payment(purchase());
    for (const items of [[], [p, { ...p, id: 'pay_other' }], [{ ...p, status: 'authorized', captured: false }], [{ ...p, amount_refunded: 1 }], [{ ...p, order_id: 'order_foreign' }]]) {
      const f = fixture(); await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest()); f.quotes.get(id(7))!.provider_order_id = 'order_test123';
      vi.mocked(f.provider.getOrderPayments).mockResolvedValue({ items });
      await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), { kind: 'settle', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7), reconcile: true })).rejects.toThrow();
      expect(f.rpc.mock.calls.some(([name]) => name === 'settle_subscription_commerce_payment')).toBe(false); expect(f.provider.createOrder).not.toHaveBeenCalled();
    }
  });
  it('replays exact receipt without provider mutation and rejects changed actor/request', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    const first = await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    expect(await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest())).toEqual(first);
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, { ...actor, actorId: id(90) }, id(5), id(7), baseRequest())).rejects.toThrow('replay');
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), { ...baseRequest(), priceId: id(91) })).rejects.toThrow('replay');
    expect(f.provider.createOrder).not.toHaveBeenCalled();
  });
  it('durably reserves before provider mutation, and an uncertain result cannot charge twice', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    vi.mocked(f.provider.createOrder).mockRejectedValue(new Error('uncertain provider result'));
    const request = { subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), kind: 'order', quoteId: id(7) };
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), request)).rejects.toThrow('uncertain');
    expect(f.operations.get(id(8))?.receipt).toBeNull();
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(8), request)).rejects.toThrow('pending');
    expect(f.provider.createOrder).toHaveBeenCalledTimes(1);
  });
  it('never marks a forged or mismatched captured payment as settled', async () => {
    vi.useFakeTimers(); vi.setSystemTime(now); const f = fixture();
    await executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(7), baseRequest());
    f.quotes.get(id(7))!.provider_order_id = 'order_test123';
    vi.mocked(f.provider.getPayment).mockResolvedValue({ ...payment(purchase()), amount: 1 });
    await expect(executeSubscriptionCommerce(f.database as never, f.provider, actor, id(5), id(9), { kind: 'settle', subscriptionId: id(2), subject: actor.subject, expectedVersion: 0, expectedRevisionId: id(4), quoteId: id(7), paymentId: 'pay_test123' })).rejects.toThrow();
    expect(f.rpc.mock.calls.some(([name]) => name === 'settle_subscription_commerce_payment')).toBe(false);
  });
  it('reads only positive processed scoped refund cancellation and owner-bound retake proof', async () => {
    const database = { query: vi.fn(async () => [{ subscription_id: id(2), product_id: id(5), subject: actor.subject, amount_minor: 1, status: 'processed' }]), rpc: vi.fn(), queryOne: vi.fn() };
    expect(await readRefundCancellation(database as never, id(2), id(5), actor.subject)).toBe(true);
    await expect(readRefundCancellation(database as never, id(2), id(90), actor.subject)).rejects.toThrow();
    const q = retake(), s = verifyCommercePayment(q, order(q), payment(q), id(8), now);
    database.query.mockResolvedValue([{ evidence: s }] as never);
    expect(await readSettledRetake(database as never, id(8), id(2), id(5), actor.subject, id(10))).toEqual(s);
    await expect(readSettledRetake(database as never, id(8), id(2), id(5), actor.subject, id(11))).rejects.toThrow();
  });
});
