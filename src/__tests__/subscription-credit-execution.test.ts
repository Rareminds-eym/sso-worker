import { beforeEach, describe, expect, it, vi } from 'vitest';
const io = vi.hoisted(() => ({ token: vi.fn(), query: vi.fn(), rpc: vi.fn(), lifecycle: vi.fn(), commit: vi.fn(), payment: vi.fn(), replay: vi.fn(),
  occurrence: vi.fn(), refresh: vi.fn(), bundle: vi.fn(), refunded: vi.fn(), frozen: vi.fn(), commerce: vi.fn(), retake: vi.fn() }));
vi.mock('../lib/subscriptions/credit-occurrences', () => ({ prepareIncludedCreditRefresh: io.refresh }));
vi.mock('../lib/jwt', () => ({ verifyAccessToken: io.token }));
vi.mock('../lib/db', () => ({ db: () => ({ query: io.query, rpc: io.rpc }) }));
vi.mock('../lib/subscriptions/lifecycle-persistence', () => ({ readSubscriptionLifecycle: io.lifecycle, commitSubscriptionLifecycle: io.commit, readSubscriptionLifecyclePayment: io.payment, readSubscriptionLifecycleReplay: io.replay }));
vi.mock('../lib/subscriptions/publication', () => ({ preparePublishedIncludedCreditOccurrence: io.occurrence }));
vi.mock('../lib/subscriptions/revision-bundle', () => ({ readPlanRevisionBundle: io.bundle }));
vi.mock('../lib/subscriptions/commerce-persistence', () => ({ readRefundCancellation: io.refunded, readSubscriptionCommerceFreeze: io.frozen, readSettledRetake: io.retake, executeSubscriptionCommerce: io.commerce }));
import { currentSubscriptionExecution, subscriptionActionContext, prepareSubscriptionRetakeSettlement, executeSubscriptionCommerce, executeSubscriptionLifecycle, prepareSubscriptionCreditExecution, readSubscriptionExecution, SubscriptionExecutionDenied } from '../lib/subscriptions/credit-execution';
import type { Env } from '../types';

const actor = 'a0000000-0000-4000-8000-000000000001', org = 'a0000000-0000-4000-8000-000000000002';
const subscription = 'b0000000-0000-4000-8000-000000000001', plan = 'c0000000-0000-4000-8000-000000000001';
const revision = 'd0000000-0000-4000-8000-000000000001', product = 'e0000000-0000-4000-8000-000000000001';
const ruleId = 'f0000000-0000-4000-8000-000000000001', operationId = 'f0000000-0000-4000-8000-000000000002';
const now = 1800000000000;
const policy = () => ({ id: ruleId, version: 1, productId: product, graceDurationMs: 10, graceAccess: 'restricted',
  expiredAccess: 'read_only', cancellationAccess: 'until_period_end', immediateDowngradeAllowed: false,
  paymentFailureRestrictedMs: 10, paymentFailureAfterAccess: 'read_only', paymentRetryOffsetsMs: [5],
  suspensionApprovalRequired: true, reactivationApprovalRequired: true });
const state = () => ({ id: subscription, subject: { kind: 'user', id: actor }, planId: plan, revisionId: revision,
  productId: product, version: 1, status: 'active', periodStartsAt: now - 1000, periodEndsAt: now + 1000,
  trialEndsAt: null, renewalEnabled: true, cancelledAt: null, paymentFailedAt: null, scheduledChange: null });
let canonical: Record<string, unknown>, row: Record<string, unknown>, live: Record<string, unknown>, user: Record<string, unknown>;
const env = {} as Env;
const request = () => ({ kind: 'consume', subscriptionId: subscription, recipientId: actor, poolKey: 'synthetic_pool',
  actionKey: 'synthetic_action', operationId });
const settings = () => canonical.configuration as Record<string, unknown>;
describe('owner-authorized refresh through the existing private credit RPC', () => {
  const refresh = () => ({ kind: 'refresh', subscriptionId: subscription, recipientId: actor, ruleId, cursor: null });
  const features = [{ key: 'synthetic_credit', type: 'metered' }];
  it('loads live allocate authority and retained terms before preparing a due page', async () => {
    const page = { schemaVersion: 1, subscriptionId: subscription, productId: product, occurrences: [], nextCursor: null };
    io.refresh.mockResolvedValue(page);
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product, refresh(), features)).toEqual({ kind: 'refresh', actorId: actor, ...page });
    expect(io.refresh).toHaveBeenCalledExactlyOnceWith(expect.anything(), expect.anything(), expect.objectContaining({
      subscriptionId: subscription, productId: product, planId: plan, revisionId: revision, ruleId,
      recipient: { kind: 'subscriber', id: actor }, cursor: 0, now,
    }), []);
  });
  it.each(['read_only', 'refunded', 'frozen', 'wrong_role', 'foreign_recipient'])('denies %s before preparing refresh authority', async scenario => {
    if (scenario === 'read_only') io.lifecycle.mockResolvedValue({ state: { ...state(), periodEndsAt: now - 1 }, policy: policy(), activatedAt: now - 1000 });
    if (scenario === 'refunded') io.refunded.mockResolvedValue(true);
    if (scenario === 'frozen') io.frozen.mockResolvedValue(true);
    if (scenario === 'wrong_role') live.roles = ['wrong_role'];
    const input = { ...refresh(), ...(scenario === 'foreign_recipient' ? { recipientId: org } : {}) };
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, input, features)).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.refresh).not.toHaveBeenCalled();
  });
  it('rejects client-selected occurrence authority and cursor use on other operations', async () => {
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, { ...refresh(), occurrenceIndex: 9 }, features)).rejects.toThrow('derives due');
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), cursor: 1 }, [])).rejects.toThrow('refresh only');
    expect(io.refresh).not.toHaveBeenCalled();
  });
});
beforeEach(() => {
  vi.resetAllMocks(); vi.spyOn(Date, 'now').mockReturnValue(now);
  io.refunded.mockResolvedValue(false);
  io.frozen.mockResolvedValue(false);
  io.token.mockResolvedValue({ sub: actor, org_id: org, exp: now / 1000 + 60, membership_status: 'active', is_email_verified: true, roles: ['forged_role'] });
  user = { id: actor, is_blocked: false, is_email_verified: true, user_metadata: {} };
  live = { membership_status: 'active', roles: ['configured_role'] };
  io.rpc.mockImplementation(async () => live);
  row = { id: subscription, user_id: actor, organization_id: null, is_organization_subscription: false, product_id: product,
    metadata: { subscription_execution: { audience: 'synthetic_audience', subscriptionEndsAt: now + 2000 } } };
  canonical = { id: plan, code: 'pln_' + 'a'.repeat(32), productId: product, audiences: ['synthetic_audience'], configuration: {
    subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'INR', minorUnit: 2 }] },
    subscription_lifecycle: policy(), subscription_revision_changes: [],
    subscription_credit_authoring: { schemaVersion: 1, pools: [{ key: 'synthetic_pool', featureKey: 'synthetic_credit', recipient: 'subscriber', audiences: ['synthetic_audience'] }], timePolicies: [] },
    subscription_execution: { schemaVersion: 1, operationRoles: { read: ['configured_role'], allocate: ['configured_role'], consume: ['configured_role'], cancel: ['configured_role'] },
      recipientRoles: {}, consumptionTariffs: [{ actionKey: 'synthetic_action', poolKey: 'synthetic_pool', featureKey: 'synthetic_credit', amount: 3, spendingOrder: 'expires_first' }] },
  } };
  io.query.mockImplementation(async (path: string) => path.startsWith('users?') ? [user]
    : path.startsWith('subscriptions?') ? [row]
    : path.startsWith('subscription_plan_publication_events?') ? [{ plan_id: plan, revision_id: revision, canonical_plan: canonical }] : []);
  io.lifecycle.mockResolvedValue({ state: state(), policy: policy(), activatedAt: now - 1000 });
  io.replay.mockResolvedValue(null);
  io.bundle.mockResolvedValue({ bundle: { draft: { plan: { id: plan } }, includedCredits: { rules: [{ id: ruleId, poolKey: 'synthetic_pool' }] } } });
  io.occurrence.mockImplementation(async (...args: unknown[]) => ({ ...(args[5] as object), poolKey: 'synthetic_pool', featureKey: 'synthetic_credit' }));
});
describe('subscription execution owner authority', () => {
  it('freezes new spending while permitting owner-scoped usage reads and exact replay lookup', async () => {
    io.frozen.mockResolvedValue(true);
    expect(await readSubscriptionExecution(env, 'signed', subscription, product)).toMatchObject({ access: 'read_only', commerceFrozen: true });
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, request(), [])).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product, { kind: 'usage', subscriptionId: subscription, recipientId: actor, poolKey: 'synthetic_pool' }, [])).toMatchObject({ kind: 'usage' });
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), kind: 'replay' }, [])).toMatchObject({ kind: 'replay', operationId });
    await expect(executeSubscriptionLifecycle(env, 'signed', product, operationId, { operation: 'cancel', subscriptionId: subscription,
      subject: { kind: 'user', id: actor }, expectedVersion: 1, expectedRevisionId: revision, reason: 'Synthetic cancellation' })).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.commit).not.toHaveBeenCalled();
    io.frozen.mockRejectedValue(new Error('Freeze owner unavailable'));
    await expect(readSubscriptionExecution(env, 'signed', subscription, product)).rejects.toThrow('Freeze owner unavailable');
  });
  it('authorizes reference-only activation without requiring a payment provider or accepting client contract terms', async () => {
    settings().subscription_commerce_eligibility = { schemaVersion: 1,
      bindings: [{ audience: 'synthetic_audience', subjectKind: 'user', roles: ['configured_role'] }] };
    const input = { kind: 'activate', subscriptionId: subscription, subject: { kind: 'user', id: actor },
      expectedVersion: 0, expectedRevisionId: revision, contractId: ruleId };
    const receipt = { kind: 'activation', operationId, contractId: ruleId, subscriptionId: subscription, productId: product,
      subject: input.subject, revisionId: revision };
    io.commerce.mockResolvedValue(receipt);
    expect(await executeSubscriptionCommerce(env, 'signed', product, operationId, input)).toEqual(receipt);
    expect(io.commerce).toHaveBeenCalledWith(expect.anything(), undefined,
      { actorId: actor, subject: input.subject, audience: 'synthetic_audience' }, product, operationId, input);
    await expect(executeSubscriptionCommerce(env, 'signed', product, operationId, { ...input, periodEndsAt: now + 5000 })).rejects.toThrow();
    live.roles = ['wrong_role'];
    await expect(executeSubscriptionCommerce(env, 'signed', product, operationId, input)).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    live.roles = ['configured_role'];
    await expect(executeSubscriptionCommerce(env, 'signed', product, operationId, { ...input, subject: { kind: 'user', id: org } })).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.commerce).toHaveBeenCalledTimes(1);
  });
  it.each(['operationId','contractId','subscriptionId','productId','revisionId','subject','kind','extra'])('rejects activation acknowledgement %s drift', async defect => {
    settings().subscription_commerce_eligibility = { schemaVersion: 1,
      bindings: [{ audience: 'synthetic_audience', subjectKind: 'user', roles: ['configured_role'] }] };
    const input = { kind: 'activate', subscriptionId: subscription, subject: { kind: 'user', id: actor },
      expectedVersion: 0, expectedRevisionId: revision, contractId: ruleId };
    const receipt: Record<string, unknown> = { kind: 'activation', operationId, contractId: ruleId, subscriptionId: subscription,
      productId: product, subject: input.subject, revisionId: revision };
    receipt[defect] = defect === 'subject' ? { kind: 'user', id: org } : defect === 'kind' ? 'settlement' : org;
    io.commerce.mockResolvedValue(receipt);
    await expect(executeSubscriptionCommerce(env, 'signed', product, operationId, input)).rejects.toThrow();
    expect(io.commit).not.toHaveBeenCalled();
  });
  it.each(['valid', 'transition', 'read_only', 'missing_operation', 'foreign_subject', 'foreign_product', 'wrong_revision', 'future_version', 'missing_publication', 'invalid_schema', 'suspended', 'refunded'])('authorizes retained historical pool discovery: %s', async scenario => {
    const historicalRevision = ruleId;
    const historicalPlan = structuredClone(canonical);
    if (scenario === 'invalid_schema') ((historicalPlan.configuration as Record<string, unknown>).subscription_execution as Record<string, unknown>).schemaVersion = 2;
    (settings().subscription_credit_authoring as { pools: unknown[] }).pools = [];
    const previous = { ...state(), revisionId: historicalRevision };
    if (scenario === 'foreign_subject') previous.subject.id = org;
    if (scenario === 'foreign_product') previous.productId = org;
    if (scenario === 'wrong_revision') previous.revisionId = org;
    if (scenario === 'future_version') previous.version = 3;
    io.lifecycle.mockResolvedValue({ state: { ...state(), version: 2, ...(scenario === 'suspended' ? { status: 'paused' } : {}),
      ...(scenario === 'read_only' ? { periodEndsAt: now - 100 } : {}) }, policy: policy(), activatedAt: now - 1000 });
    if (scenario === 'refunded') io.refunded.mockResolvedValue(true);
    const original = io.query.getMockImplementation()!;
    io.query.mockImplementation((path: string) => path.startsWith('subscription_lifecycle_operations?')
      ? Promise.resolve(scenario === 'missing_operation' ? [] : [scenario === 'transition'
        ? { kind: 'transition', receipt: { decision: { next: previous } } } : { kind: 'initialize', receipt: { state: previous } }])
      : path.startsWith('subscription_plan_publication_events?') && path.includes(`revision_id=eq.${historicalRevision}`)
        ? Promise.resolve(scenario === 'missing_publication' ? [] : [{ plan_id: plan, revision_id: historicalRevision, canonical_plan: historicalPlan }]) : original(path));
    const result = prepareSubscriptionCreditExecution(env, 'signed', product, { kind: 'history_pools', subscriptionId: subscription, revisionId: historicalRevision }, []);
    if (['valid', 'transition', 'read_only'].includes(scenario)) {
      expect(await result).toMatchObject({ kind: 'history_pools', actorId: actor, productId: product, subscriptionId: subscription,
        revisionId: historicalRevision, pools: [{ key: 'synthetic_pool' }] });
      expect(await prepareSubscriptionCreditExecution(env, 'signed', product, { kind: 'history', subscriptionId: subscription,
        revisionId: historicalRevision, poolKey: 'synthetic_pool', recipientId: actor }, [])).toMatchObject({ kind: 'usage', scope: { recipient: { kind: 'subscriber', id: actor }, poolKey: 'synthetic_pool' } });
      await expect(prepareSubscriptionCreditExecution(env, 'signed', product, { kind: 'history', subscriptionId: subscription,
        revisionId: historicalRevision, poolKey: 'synthetic_pool', recipientId: org }, [])).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    } else await expect(result).rejects.toThrow();
    expect(io.occurrence).not.toHaveBeenCalled(); expect(io.commit).not.toHaveBeenCalled();
  });
  it.each(['consume', 'allocate', 'usage'])('rejects historical terms for a %s operation', async kind => {
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), kind, revisionId: ruleId }, [])).rejects.toThrow('historical reads only');
    expect(io.lifecycle).not.toHaveBeenCalled();
  });
  it.each(['valid', 'foreign_payer', 'foreign_source', 'different_amount', 'read_only', 'owner_outage'])('prepares only live payer-scoped retake evidence: %s', async scenario => {
    (settings().subscription_execution as Record<string, unknown>).operationRoles = { commerce_retake: ['configured_role'] };
    const settlement = { id: operationId, quoteId: plan, subscriptionId: subscription, productId: product,
      subject: { kind: 'user', id: actor }, purpose: 'retake', referenceId: ruleId, providerPaymentId: 'pay_synthetic123456',
      amountMinor: 100, currency: 'INR', settledAt: now - 50 };
    const quote = { id: plan, actorId: actor, subscriptionId: subscription, productId: product, subject: settlement.subject,
      audience: 'synthetic_audience', purpose: 'retake', referenceId: ruleId, amountMinor: 100, currency: 'INR', createdAt: now - 100 };
    if (scenario === 'foreign_payer') quote.actorId = org;
    if (scenario === 'foreign_source') quote.referenceId = org;
    if (scenario === 'different_amount') quote.amountMinor++;
    if (scenario === 'read_only') io.lifecycle.mockResolvedValue({ state: { ...state(), periodEndsAt: now - 100 }, policy: policy(), activatedAt: now - 1000 });
    io.retake.mockResolvedValue(settlement);
    if (scenario === 'owner_outage') io.retake.mockRejectedValue(new Error('Retake owner unavailable'));
    const originalQuery = io.query.getMockImplementation()!;
    io.query.mockImplementation((path: string) => path.startsWith('subscription_commerce_quotes?') ? Promise.resolve([{ quote }]) : originalQuery(path));
    const result = prepareSubscriptionRetakeSettlement(env, 'signed', product, { subscriptionId: subscription, settlementId: operationId, referenceId: ruleId });
    if (scenario === 'valid') {
      expect(await result).toEqual({ schemaVersion: 1, actorId: actor, subscriptionId: subscription, productId: product,
        subject: settlement.subject, stateVersion: 1, validUntil: now + 1000, settlement });
      expect(io.retake).toHaveBeenCalledWith(expect.anything(), operationId, subscription, product, settlement.subject, ruleId);
    } else await expect(result).rejects.toThrow();
  });
  it('resolves initial purchase audience from retained eligibility and live roles, never caller choice', async () => {
    settings().subscription_commerce_eligibility = { schemaVersion: 1, bindings: [
      { audience: 'synthetic_audience', subjectKind: 'user', roles: ['configured_role'] },
    ] };
    io.commerce.mockResolvedValue({ synthetic: 'owner receipt' });
    const providerEnv = { PAYMENT_WORKER: {} } as Env;
    const input = { kind: 'quote', purpose: 'purchase', subscriptionId: subscription, subject: { kind: 'user', id: actor },
      expectedVersion: 0, expectedRevisionId: revision, revisionId: revision, priceId: plan };
    expect(await executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, input)).toEqual({ synthetic: 'owner receipt' });
    expect(io.commerce.mock.calls[0][2]).toEqual({ actorId: actor, subject: input.subject, audience: 'synthetic_audience' });
    live.roles = ['other'];
    await expect(executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, input)).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    await expect(executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, { ...input, audience: 'synthetic_audience' })).rejects.toThrow();
    await expect(executeSubscriptionCommerce(env, 'signed', product, operationId, input)).rejects.toThrow('payment owner unavailable');
  });
  it.each(['refunded', 'pending'])('requires explicit commerce authority and permits only refund readback for %s refunds', async status => {
    const input = { kind: 'refund_confirm', subscriptionId: subscription, subject: { kind: 'user', id: actor },
      expectedVersion: 1, expectedRevisionId: revision, settlementId: plan, refundId: 'rfnd_synthetic123456' };
    const providerEnv = { PAYMENT_WORKER: {} } as Env;
    await expect(executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, input)).rejects.toThrow();
    (settings().subscription_execution as Record<string, unknown>).operationRoles = { commerce_refund_confirm: ['configured_role'], commerce_refund: ['configured_role'] };
    io.refunded.mockResolvedValue(status === 'refunded');
    io.frozen.mockResolvedValue(status === 'pending');
    io.commerce.mockResolvedValue({ synthetic: 'confirmed receipt' });
    expect(await executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, input)).toEqual({ synthetic: 'confirmed receipt' });
    const { refundId: _refundId, ...common } = input;
    await expect(executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, { ...common, kind: 'refund' })).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
  });
  it('delegates a paid renewal extending contract coverage to the atomic settlement owner', async () => {
    (settings().subscription_execution as Record<string, unknown>).operationRoles = { renew: ['configured_role'] };
    const quote = { id: plan, revisionId: revision, planId: plan, productId: product, periodEndsAt: now + 5000 };
    io.payment.mockResolvedValue({ quote, settlement: { id: operationId } });
    io.commit.mockResolvedValue({ synthetic: 'atomic receipt' });
    expect(await executeSubscriptionLifecycle(env, 'signed', product, operationId, { operation: 'renew', subscriptionId: subscription,
      subject: { kind: 'user', id: actor }, expectedVersion: 1, expectedRevisionId: revision, reason: 'Renew', quoteId: plan, settlementId: operationId })).toEqual({ synthetic: 'atomic receipt' });
    expect(io.commit.mock.calls[0][5].quotes.get(plan)).toEqual(quote);
  });
  it('joins independent owner capture proof into lifecycle context without backdating now or mutating commercial evidence',async()=>{
    (settings().subscription_execution as Record<string,unknown>).operationRoles={renew:['configured_role']};
    const quote={id:plan,revisionId:revision,planId:plan,productId:product,periodEndsAt:now+5000};const settlement={id:operationId};
    const capture={eventId:'a'.repeat(64),actorId:actor,quoteId:plan,settlementId:operationId,productId:product,subscriptionId:subscription,
      subject:{kind:'user',id:actor},stateVersion:1,revisionId:revision,amountMinor:100,currency:'INR',providerPaymentId:'pay_synthetic',providerOrderId:'order_synthetic',
      capturedAt:now-2000,paymentCreatedAt:now-3000,quoteCreatedAt:now-4000};
    io.payment.mockResolvedValue({quote,settlement,capture});io.commit.mockResolvedValue({synthetic:'atomic receipt'});
    const request={operation:'renew',subscriptionId:subscription,subject:{kind:'user',id:actor},expectedVersion:1,expectedRevisionId:revision,reason:'Renew',quoteId:plan,settlementId:operationId};
    await executeSubscriptionLifecycle(env,'signed',product,operationId,request);
    const context=io.commit.mock.calls[0][5];expect(context.now).toBe(now);expect(context.captures.get(operationId)).toEqual(capture);
    expect(context.quotes.get(plan)).toEqual(quote);expect(context.settlements.get(operationId)).toEqual(settlement);
    await expect(executeSubscriptionLifecycle(env,'signed',product,operationId,{...request,capture})).rejects.toThrow('unsupported field');
    expect(io.commit).toHaveBeenCalledTimes(1);
  });
  it('joins payment confirmation to lifecycle fulfillment and resumes the same operation without another transition', async () => {
    (settings().subscription_execution as Record<string, unknown>).operationRoles = { commerce_settle: ['configured_role'], renew: ['configured_role'] };
    const providerEnv = { PAYMENT_WORKER: {} } as Env;
    const input = { kind: 'settle', subscriptionId: subscription, subject: { kind: 'user', id: actor },
      expectedVersion: 1, expectedRevisionId: revision, quoteId: plan, paymentId: 'pay_synthetic123456' };
    const saved = { kind: 'settlement', operationId, quoteId: plan, settlement: { id: operationId, quoteId: plan,
      subscriptionId: subscription, productId: product, subject: input.subject, purpose: 'renew', referenceId: null,
      providerPaymentId: input.paymentId, amountMinor: 100, currency: 'INR', settledAt: now } };
    io.commerce.mockResolvedValue(saved);
    io.payment.mockResolvedValue({ quote: { id: plan, revisionId: revision, planId: plan, productId: product, periodEndsAt: now + 5000 }, settlement: { id: operationId } });
    io.commit.mockResolvedValue({ operationId });
    expect(await executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, input)).toEqual(saved);
    expect(io.commit).toHaveBeenCalledTimes(1);
    io.replay.mockResolvedValue({ operationId });
    expect(await executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, input)).toEqual(saved);
    expect(io.commit).toHaveBeenCalledTimes(1);
    io.replay.mockResolvedValue(null); io.commit.mockRejectedValue(new Error('Fulfillment pending'));
    await expect(executeSubscriptionCommerce(providerEnv, 'signed', product, operationId, input)).rejects.toThrow('Fulfillment pending');
  });
  it('revokes subscription access immediately after a positive refunded cancellation', async () => {
    io.refunded.mockResolvedValue(true);
    expect((await currentSubscriptionExecution(env, 'signed', subscription, product)).access).toBe('suspended');
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), kind: 'usage' }, [])).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    await expect(executeSubscriptionLifecycle(env, 'signed', product, operationId, { operation: 'cancel', subscriptionId: subscription,
      subject: { kind: 'user', id: actor }, expectedVersion: 1, expectedRevisionId: revision, reason: 'Cancel' })).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.commit).not.toHaveBeenCalled();
  });
  it('fails closed when refund cancellation authority is unavailable', async () => {
    io.refunded.mockRejectedValue(new Error('Refund owner unavailable'));
    await expect(currentSubscriptionExecution(env, 'signed', subscription, product)).rejects.toThrow('Refund owner unavailable');
  });
  it('returns action rules from retained publication with full period and actor scope', async () => {
    const binding = { actionKey: 'synthetic_create', featureKey: 'synthetic_limit', mode: 'write',
      acceptedValues: ['included'], quota: { period: 'concurrent', countingEvent: 'created' } };
    settings().subscription_actions = { schemaVersion: 1, bindings: [binding] };
    expect(await subscriptionActionContext(env, 'signed', subscription, product)).toEqual({
      schemaVersion: 1, actorId: actor, state: state(), access: 'full', audience: 'synthetic_audience',
      activatedAt: now - 1000, subscriptionEndsAt: now + 2000, actions: { schemaVersion: 1, bindings: [binding] },
    });
  });
  it.each(['missing', 'duplicate', 'read_charge', 'unknown_field', 'invalid_boolean'])('rejects invalid retained action configuration: %s', async defect => {
    const binding: Record<string, unknown> = { actionKey: 'synthetic_action', featureKey: 'synthetic_feature', mode: 'write' };
    if (defect === 'read_charge') { binding.mode = 'read'; binding.paymentRequired = true; }
    if (defect === 'unknown_field') binding.allowLegacy = true;
    if (defect === 'invalid_boolean') binding.paymentRequired = 'yes';
    if (defect !== 'missing') settings().subscription_actions = { schemaVersion: 1, bindings: defect === 'duplicate' ? [binding, binding] : [binding] };
    await expect(subscriptionActionContext(env, 'signed', subscription, product)).rejects.toThrow();
  });
  it('loads retained terms and server-derived tariffs, using live rather than signed roles', async () => {
    const result = await prepareSubscriptionCreditExecution(env, 'signed', product, request(), []);
    expect(result).toMatchObject({ kind: 'consume', actorId: actor, command: { amount: 3, operationId, recipient: { kind: 'subscriber', id: actor } } });
    expect(io.query.mock.calls.every(([path]) => !String(path).startsWith('plans?'))).toBe(true);
    expect(io.rpc).toHaveBeenCalledWith('get_jwt_claims', { p_user_id: actor, p_org_id: org });
  });
  it.each(['amount', 'actorId', 'policy', 'receipt', 'ready'])('rejects caller authority field %s before persistence', async field => {
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), [field]: true }, [])).rejects.toThrow('unsupported field');
    expect(io.lifecycle).not.toHaveBeenCalled();
  });
  it.each(['blocked', 'unverified', 'password_change', 'inactive', 'role_revoked', 'other_subject', 'other_product'])('denies %s', async defect => {
    if (defect === 'blocked') user.is_blocked = true;
    if (defect === 'unverified') user.is_email_verified = false;
    if (defect === 'password_change') user.user_metadata = { must_change_password: true };
    if (defect === 'inactive') live.membership_status = 'inactive';
    if (defect === 'role_revoked') live.roles = ['other_role'];
    if (defect === 'other_subject') row.user_id = org;
    if (defect === 'other_product') row.product_id = org;
    await expect(readSubscriptionExecution(env, 'signed', subscription, product)).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
  });
  it('propagates owner outage without legacy balance or cached state', async () => {
    io.lifecycle.mockRejectedValue(new Error('unavailable'));
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, request(), [])).rejects.toThrow('unavailable');
    expect(io.occurrence).not.toHaveBeenCalled();
  });
  it('rejects mutable policy drift and missing explicit tariff', async () => {
    settings().subscription_lifecycle = { ...policy(), version: 2 };
    await expect(readSubscriptionExecution(env, 'signed', subscription, product)).rejects.toThrow('policy differs');
    settings().subscription_lifecycle = policy();
    (settings().subscription_execution as Record<string, unknown>).consumptionTariffs = [];
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, request(), [])).rejects.toThrow('explicit tariff');
  });
  it('evaluates current expiry at read time and refuses new spending', async () => {
    io.lifecycle.mockResolvedValue({ state: { ...state(), periodEndsAt: now - 100 }, policy: policy(), activatedAt: now - 1000 });
    expect((await currentSubscriptionExecution(env, 'signed', subscription, product)).access).toBe('read_only');
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, request(), [])).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
  });
  it.each([0, 149, 150, 899])('permits credit reads but no new mutations %i after finite-policy expiry', async elapsed => {
    const retained = { ...policy(), graceAccess: 'read_only', graceDurationMs: 150, readOnlyDurationMs: 900 };
    settings().subscription_lifecycle = retained;
    io.lifecycle.mockResolvedValue({ state: { ...state(), downgradedAt: null, periodEndsAt: now - elapsed }, policy: retained, activatedAt: now - 1000 });
    expect((await currentSubscriptionExecution(env, 'signed', subscription, product)).access).toBe('read_only');
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product,
      { kind: 'usage', subscriptionId: subscription, recipientId: actor, poolKey: 'synthetic_pool' }, []))
      .toMatchObject({ kind: 'usage', scope: { subscriptionId: subscription } });
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, request(), []))
      .rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product,
      { kind: 'allocate', subscriptionId: subscription, recipientId: actor, ruleId, occurrenceIndex: 0 }, []))
      .rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.occurrence).not.toHaveBeenCalled();
  });
  it.each([[899, 'read_only'], [900, 'suspended']] as const)('enforces downgrade retention %i after the event while the paid period remains active', async (elapsed, access) => {
    const retained = { ...policy(), graceAccess: 'read_only', graceDurationMs: 150, readOnlyDurationMs: 900 };
    settings().subscription_lifecycle = retained;
    io.lifecycle.mockResolvedValue({ state: { ...state(), downgradedAt: now - elapsed }, policy: retained, activatedAt: now - 1000 });
    expect((await currentSubscriptionExecution(env, 'signed', subscription, product)).access).toBe(access);
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, request(), []))
      .rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    const usage = prepareSubscriptionCreditExecution(env, 'signed', product,
      { kind: 'usage', subscriptionId: subscription, recipientId: actor, poolKey: 'synthetic_pool' }, []);
    if (access === 'read_only') await expect(usage).resolves.toMatchObject({ kind: 'usage' });
    else await expect(usage).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.occurrence).not.toHaveBeenCalled();
  });
  it.each(['usage', 'replay', 'allocation_replay', 'consume', 'allocate'])('denies %s at the finite retention suspension boundary', async kind => {
    const retained = { ...policy(), graceAccess: 'read_only', graceDurationMs: 150, readOnlyDurationMs: 900 };
    settings().subscription_lifecycle = retained;
    io.lifecycle.mockResolvedValue({ state: { ...state(), downgradedAt: null, periodEndsAt: now - 900 }, policy: retained, activatedAt: now - 1000 });
    expect((await currentSubscriptionExecution(env, 'signed', subscription, product)).access).toBe('suspended');
    const input = kind === 'usage' ? { kind, subscriptionId: subscription, recipientId: actor, poolKey: 'synthetic_pool' }
      : kind === 'allocate' || kind === 'allocation_replay' ? { kind, subscriptionId: subscription, recipientId: actor, ruleId, occurrenceIndex: 0 }
      : { ...request(), kind };
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, input, []))
      .rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.occurrence).not.toHaveBeenCalled();
  });
  it('prepares allocations using the owner period and recipient', async () => {
    const result = await prepareSubscriptionCreditExecution(env, 'signed', product,
      { kind: 'allocate', subscriptionId: subscription, recipientId: actor, ruleId, occurrenceIndex: 0 }, [{ key: 'synthetic_credit', type: 'metered' }]);
    expect(result.kind).toBe('allocate');
    expect(io.occurrence.mock.calls[0][5]).toMatchObject({ recipient: { kind: 'subscriber', id: actor }, activatedAt: now - 1000, occurrenceIndex: 0 });
  });
  it('refuses another recipient without asking the calculator to allocate', async () => {
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product,
      { kind: 'allocate', subscriptionId: subscription, recipientId: org, ruleId, occurrenceIndex: 0 }, [{ key: 'synthetic_credit', type: 'metered' }]))
      .rejects.toBeInstanceOf(SubscriptionExecutionDenied);
    expect(io.occurrence).not.toHaveBeenCalled();
  });
  it('forwards noncommercial decisions with actual subject and empty ungranted approval authority', async () => {
    io.commit.mockResolvedValue({ committed: true });
    await executeSubscriptionLifecycle(env, 'signed', product, operationId, { operation: 'cancel', subscriptionId: subscription,
      subject: { kind: 'user', id: actor }, expectedVersion: 1, expectedRevisionId: revision, reason: 'Synthetic request' });
    expect(io.commit.mock.calls[0][5]).toMatchObject({ actorId: actor, subject: { kind: 'user', id: actor }, approvals: new Map() });
  });
  it('binds organization recipients to the actual organization subject', async () => {
    row.is_organization_subscription = true; row.organization_id = org;
    io.lifecycle.mockResolvedValue({ state: { ...state(), subject: { kind: 'organization', id: org } }, policy: policy(), activatedAt: now - 1000 });
    const config = settings().subscription_credit_authoring as { pools: { recipient: string }[] };
    config.pools[0].recipient = 'organization';
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), recipientId: org }, []))
      .toMatchObject({ command: { recipient: { kind: 'organization', id: org } } });
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, request(), [])).rejects.toBeInstanceOf(SubscriptionExecutionDenied);
  });
  it('requires explicit managed-recipient roles and an active live eligible membership', async () => {
    row.is_organization_subscription = true; row.organization_id = org;
    io.lifecycle.mockResolvedValue({ state: { ...state(), subject: { kind: 'organization', id: org } }, policy: policy(), activatedAt: now - 1000 });
    (settings().subscription_credit_authoring as { pools: { recipient: string }[] }).pools[0].recipient = 'managed_learner';
    (settings().subscription_execution as Record<string, unknown>).recipientRoles = { synthetic_pool: ['learner_role'] };
    io.rpc.mockImplementation(async (_name: string, params: {p_user_id: string}) => params.p_user_id === plan
      ? { membership_status: 'active', roles: ['learner_role'] } : live);
    io.query.mockImplementation(async (path: string) => path.startsWith('users?')
      ? [{ ...user, id: path.includes(plan) ? plan : actor }] : path.startsWith('subscriptions?') ? [row]
      : [{ plan_id: plan, revision_id: revision, canonical_plan: canonical }]);
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), recipientId: plan }, []))
      .toMatchObject({ command: { recipient: { kind: 'managed_learner', id: plan } } });
    io.rpc.mockImplementation(async (_name: string, params: {p_user_id: string}) => params.p_user_id === plan
      ? { membership_status: 'inactive', roles: ['learner_role'] } : live);
    await expect(prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), recipientId: plan }, []))
      .rejects.toBeInstanceOf(SubscriptionExecutionDenied);
  });
  it('rejects absent payment-owner evidence before committing a paid transition', async () => {
    (settings().subscription_execution as Record<string, unknown>).operationRoles = { renew: ['configured_role'] };
    io.payment.mockRejectedValue(new Error('Completed transaction evidence missing'));
    await expect(executeSubscriptionLifecycle(env, 'signed', product, operationId, { operation: 'renew', subscriptionId: subscription,
      subject: { kind: 'user', id: actor }, expectedVersion: 1, expectedRevisionId: revision, reason: 'Renew', quoteId: plan, settlementId: operationId }))
      .rejects.toThrow('Completed transaction evidence missing');
    expect(io.commit).not.toHaveBeenCalled();
  });

  it('reads an authorized original lifecycle receipt before loading expired payment evidence', async () => {
    (settings().subscription_execution as Record<string, unknown>).operationRoles = { renew: ['configured_role'] };
    const stored = { operationId, decision: { expectedVersion: 1 }, committedAt: '2026-11-19T10:00:00Z' };
    io.replay.mockResolvedValue(stored);
    expect(await executeSubscriptionLifecycle(env, 'signed', product, operationId, { operation: 'renew', subscriptionId: subscription,
      subject: { kind: 'user', id: actor }, expectedVersion: 1, expectedRevisionId: revision, reason: 'Renew', quoteId: plan, settlementId: operationId }))
      .toEqual(stored);
    expect(io.payment).not.toHaveBeenCalled(); expect(io.commit).not.toHaveBeenCalled();
  });

  it('authorizes only receipt lookup after expiry without deriving a new tariff or spend', async () => {
    io.lifecycle.mockResolvedValue({ state: { ...state(), periodEndsAt: now - 100 }, policy: policy(), activatedAt: now - 1000 });
    (settings().subscription_execution as Record<string, unknown>).consumptionTariffs = [];
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product, { ...request(), kind: 'replay' }, []))
      .toMatchObject({ kind: 'replay', actorId: actor, actionKey: 'synthetic_action', operationId, scope: { subscriptionId: subscription } });
  });

  it('allows only an owner-derived allocation receipt lookup after expiry', async () => {
    io.lifecycle.mockResolvedValue({ state: { ...state(), periodEndsAt: now - 100 }, policy: policy(), activatedAt: now - 1000 });
    expect(await prepareSubscriptionCreditExecution(env, 'signed', product,
      { kind: 'allocation_replay', subscriptionId: subscription, recipientId: actor, ruleId, occurrenceIndex: 0 }, [{ key: 'synthetic_credit', type: 'metered' }]))
      .toMatchObject({ kind: 'allocation_replay', actorId: actor });
    expect(io.occurrence).toHaveBeenCalledTimes(1);
  });

  it('accepts canonical nullable user metadata without inventing a password-change requirement', async () => {
    user.user_metadata = null;
    expect((await readSubscriptionExecution(env, 'signed', subscription, product)).actorId).toBe(actor);
  });

});
