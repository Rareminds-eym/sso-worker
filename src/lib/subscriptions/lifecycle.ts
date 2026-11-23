import { array, choice, integer, invalid, record, text, uuid } from './validation';

export type LifecycleOperation = 'upgrade' | 'renew' | 'downgrade' | 'cancel' | 'expire' | 'payment_failed' | 'suspend' | 'reactivate';
export type LifecycleAccess = 'full' | 'restricted' | 'read_only' | 'suspended';
type Subject = { kind: 'user' | 'organization'; id: string };
type Revision = { planId: string; revisionId: string; productId: string };
export interface LifecycleState extends Revision {
  id: string; subject: Subject; version: number;
  status: 'active' | 'pending' | 'paused' | 'cancelled' | 'expired' | 'grace_period';
  periodStartsAt: number; periodEndsAt: number | null; trialEndsAt: number | null;
  /** Explicit marker, permitted only for published perpetual free terms. */
  validity?: 'perpetual';
  renewalEnabled: boolean; cancelledAt: number | null; paymentFailedAt: number | null;
  scheduledChange: (Revision & { effectiveAt: number }) | null;
  /** Explicit finite-retention state: null means no effective downgrade yet. */
  downgradedAt?: number | null;
}
export interface LifecyclePolicy {
  id: string; version: number; productId: string;
  /** Free offers explicitly have no payment-failure schedule or renewal boundary. */
  billing?: 'not_applicable';
  graceDurationMs: number; graceAccess: 'restricted' | 'read_only';
  expiredAccess: 'read_only' | 'suspended';
  /** Total elapsed read-only window from effective downgrade/expiry, including grace.
   * Explicitly supplied by new retained policies; historical published terms are not rewritten.
   */
  readOnlyDurationMs?: number;
  cancellationAccess: 'until_period_end' | 'read_only' | 'suspended';
  immediateDowngradeAllowed: boolean;
  paymentFailureRestrictedMs: number | null; paymentFailureAfterAccess: 'read_only' | 'suspended' | null;
  paymentRetryOffsetsMs: readonly number[];
  suspensionApprovalRequired: boolean; reactivationApprovalRequired: boolean;
}
export interface LifecycleQuote extends Revision {
  id: string; subscriptionId: string; subject: Subject; stateVersion: number;
  operation: 'upgrade' | 'renew'; amountMinor: number; currency: string;
  periodStartsAt: number; periodEndsAt: number; validUntil: number;
}
export interface LifecycleSettlement {
  id: string; quoteId: string; subscriptionId: string; subject: Subject;
  stateVersion: number; revisionId: string; amountMinor: number; currency: string;
  operation: 'upgrade' | 'renew';
  kind: 'verified_payment' | 'approved_invoice';
  recordedAt: number; validUntil: number | null;
}
export interface LifecycleCapture {
  eventId:string; actorId:string; quoteId:string; settlementId:string; productId:string; subscriptionId:string;
  subject:Subject; stateVersion:number; revisionId:string; amountMinor:number; currency:string;
  providerPaymentId:string; providerOrderId:string; capturedAt:number; paymentCreatedAt:number; quoteCreatedAt:number;
}
export function parseLifecycleCapture(value:unknown):LifecycleCapture {
  const c=record(value,'settlement.capture',['eventId','actorId','quoteId','settlementId','productId','subscriptionId','subject','stateVersion','revisionId','amountMinor','currency','providerPaymentId','providerOrderId','capturedAt','paymentCreatedAt','quoteCreatedAt']);
  const eventId=text(c.eventId,'capture.eventId'),providerPaymentId=text(c.providerPaymentId,'capture.paymentId'),providerOrderId=text(c.providerOrderId,'capture.orderId');
  if(!/^[a-f0-9]{64}$/.test(eventId)||!/^pay_[A-Za-z0-9]+$/.test(providerPaymentId)||!/^order_[A-Za-z0-9]+$/.test(providerOrderId))invalid('settlement.capture','invalid retained capture identity');
  return {eventId,providerPaymentId,providerOrderId,actorId:uuid(c.actorId,'capture.actorId'),quoteId:uuid(c.quoteId,'capture.quoteId'),settlementId:uuid(c.settlementId,'capture.settlementId'),
    productId:uuid(c.productId,'capture.productId'),subscriptionId:uuid(c.subscriptionId,'capture.subscriptionId'),subject:subject(c.subject,'capture.subject'),stateVersion:integer(c.stateVersion,'capture.stateVersion',1),
    revisionId:uuid(c.revisionId,'capture.revisionId'),amountMinor:integer(c.amountMinor,'capture.amountMinor',1),currency:text(c.currency,'capture.currency'),
    capturedAt:integer(c.capturedAt,'capture.at'),paymentCreatedAt:integer(c.paymentCreatedAt,'capture.paymentCreatedAt'),quoteCreatedAt:integer(c.quoteCreatedAt,'capture.quoteCreatedAt')};
}
export function assertLifecycleCapture(quote:LifecycleQuote,settlement:LifecycleSettlement,actorId:string,now:number,value:unknown):void {
  const c=parseLifecycleCapture(value);
  if(c.actorId!==actorId||c.quoteId!==quote.id||c.settlementId!==settlement.id||c.productId!==quote.productId||c.subscriptionId!==quote.subscriptionId
    ||!sameSubject(c.subject,quote.subject)||c.stateVersion!==quote.stateVersion||c.revisionId!==quote.revisionId||c.amountMinor!==quote.amountMinor||c.currency!==quote.currency
    ||c.capturedAt!==settlement.recordedAt||c.quoteCreatedAt>c.capturedAt||c.paymentCreatedAt>c.capturedAt||c.capturedAt>now||c.capturedAt+999>=quote.validUntil
    ||settlement.kind!=='verified_payment')invalid('settlement.capture','retained signed capture differs from paid lifecycle owner');
}
export interface LifecycleApproval {
  id: string; subscriptionId: string; subject: Subject; stateVersion: number;
  operation: 'suspend' | 'reactivate'; actorId: string; validUntil: number;
}
/** Owner-loaded, authenticated context. Never deserialize these maps or permissions from an HTTP request.
 * Payment verification, live approval loading, quote calculation and publication readback belong upstream.
 */
export interface LifecycleContext {
  now: number; actorId: string; subject: Subject;
  allowedOperations: ReadonlySet<LifecycleOperation>;
  quotes: ReadonlyMap<string, LifecycleQuote>;
  settlements: ReadonlyMap<string, LifecycleSettlement>;
  /** Independent owner-loaded evidence; never part of a commercial quote or settlement. */
  captures?: ReadonlyMap<string,LifecycleCapture>;
  approvals: ReadonlyMap<string, LifecycleApproval>;
  /** Verified retained published revisions for current subscribers, plus eligible change targets. */
  publishedRevisions: ReadonlyMap<string, Revision>;
  /** Authoritative policies loaded from the exact retained target publications. */
  targetPolicies?: ReadonlyMap<string, LifecyclePolicy>;
  revisionChanges: readonly { fromRevisionId: string; toRevisionId: string; operation: 'upgrade' | 'downgrade' }[];
}
export interface LifecycleDecision {
  expectedVersion: number; expectedRevisionId: string; next: LifecycleState;
  access: LifecycleAccess; retryAt: readonly number[];
  audit: { operation: LifecycleOperation; actorId: string; reason: string; at: number; policyId: string; policyVersion: number };
}
const operations: readonly LifecycleOperation[] = ['upgrade', 'renew', 'downgrade', 'cancel', 'expire', 'payment_failed', 'suspend', 'reactivate'];
/** Explicit directions on either exact retained endpoint publication, never inferred from price/name. */
export function publishedRevisionChanges(...configurations:readonly Record<string,unknown>[]) {
  const changes=configurations.flatMap(configuration=>configuration.subscription_revision_changes===undefined?[]
    :array(configuration.subscription_revision_changes,'revisionChanges').map(value=>{
      const c=record(value,'revisionChange',['fromRevisionId','toRevisionId','operation']);
      return {fromRevisionId:uuid(c.fromRevisionId,'change.from'),toRevisionId:uuid(c.toRevisionId,'change.to'),operation:choice(c.operation,'change.operation',['upgrade','downgrade'])};
    }));
  return changes.filter((c,i)=>changes.findIndex(other=>other.fromRevisionId===c.fromRevisionId&&other.toRevisionId===c.toRevisionId&&other.operation===c.operation)===i);
}
function bool(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') invalid(path, 'expected boolean');
  return value;
}
function nullableTime(value: unknown, path: string): number | null {
  return value === null ? null : integer(value, path);
}
function subject(value: unknown, path: string): Subject {
  const item = record(value, path, ['kind', 'id']);
  return { kind: choice(item.kind, `${path}.kind`, ['user', 'organization']), id: uuid(item.id, `${path}.id`) };
}
function sameSubject(left: Subject, right: Subject): boolean { return left.kind === right.kind && left.id === right.id; }
function revision(value: unknown, path: string): Revision {
  const item = record(value, path, ['planId', 'revisionId', 'productId']);
  return { planId: uuid(item.planId, `${path}.planId`), revisionId: uuid(item.revisionId, `${path}.revisionId`), productId: uuid(item.productId, `${path}.productId`) };
}
function addTime(base: number, offset: number, path: string): number { return integer(base + offset, path); }
export function validateSubscriptionLifecyclePolicy(value: unknown): LifecyclePolicy {
  const p = record(value, 'policy', ['id', 'version', 'productId', 'billing', 'graceDurationMs', 'graceAccess', 'expiredAccess', 'readOnlyDurationMs', 'cancellationAccess', 'immediateDowngradeAllowed', 'paymentFailureRestrictedMs', 'paymentFailureAfterAccess', 'paymentRetryOffsetsMs', 'suspensionApprovalRequired', 'reactivationApprovalRequired']);
  const noBilling = Object.hasOwn(p, 'billing');
  if (noBilling) {
    choice(p.billing, 'policy.billing', ['not_applicable']);
    if (p.paymentFailureRestrictedMs !== null || p.paymentFailureAfterAccess !== null || p.immediateDowngradeAllowed !== false) {
      invalid('policy.billing', 'non-billing policy requires explicit null payment terms and disabled immediate downgrade');
    }
    if (p.cancellationAccess === 'until_period_end') invalid('policy.cancellationAccess', 'non-billing cancellation requires immediate access terms');
    if (!Object.hasOwn(p, 'readOnlyDurationMs')) invalid('policy.readOnlyDurationMs', 'explicit free retention window required');
  }
  const retry = array(p.paymentRetryOffsetsMs, 'policy.paymentRetryOffsetsMs').map((v, i) => integer(v, `policy.paymentRetryOffsetsMs.${i}`, 1));
  if (noBilling ? retry.length !== 0 : retry.length === 0) invalid('policy.paymentRetryOffsetsMs', 'retry schedule must match explicit billing applicability');
  if (retry.some((v, i) => i > 0 && v <= retry[i - 1])) invalid('policy.paymentRetryOffsetsMs', 'retry offsets must be strictly increasing');
  const policy: LifecyclePolicy = {
    id: uuid(p.id, 'policy.id'), version: integer(p.version, 'policy.version', 1), productId: uuid(p.productId, 'policy.productId'),
    graceDurationMs: integer(p.graceDurationMs, 'policy.graceDurationMs'),
    graceAccess: choice(p.graceAccess, 'policy.graceAccess', ['restricted', 'read_only']),
    expiredAccess: choice(p.expiredAccess, 'policy.expiredAccess', ['read_only', 'suspended']),
    cancellationAccess: choice(p.cancellationAccess, 'policy.cancellationAccess', ['until_period_end', 'read_only', 'suspended']),
    immediateDowngradeAllowed: bool(p.immediateDowngradeAllowed, 'policy.immediateDowngradeAllowed'),
    ...(noBilling ? { billing: 'not_applicable' as const } : {}),
    paymentFailureRestrictedMs: noBilling ? null : integer(p.paymentFailureRestrictedMs, 'policy.paymentFailureRestrictedMs'),
    paymentFailureAfterAccess: noBilling ? null : choice(p.paymentFailureAfterAccess, 'policy.paymentFailureAfterAccess', ['read_only', 'suspended'] as const),
    paymentRetryOffsetsMs: retry, suspensionApprovalRequired: bool(p.suspensionApprovalRequired, 'policy.suspensionApprovalRequired'),
    reactivationApprovalRequired: bool(p.reactivationApprovalRequired, 'policy.reactivationApprovalRequired'),
  };
  if (Object.hasOwn(p, 'readOnlyDurationMs')) {
    policy.readOnlyDurationMs = integer(p.readOnlyDurationMs, 'policy.readOnlyDurationMs', 1);
    if (policy.readOnlyDurationMs < policy.graceDurationMs || policy.graceAccess !== 'read_only' || policy.expiredAccess !== 'read_only') {
      invalid('policy.readOnlyDurationMs', 'finite retention requires read-only grace and expiry within the total window');
    }
  }
  return policy;
}
function validateState(value: unknown, now: number): LifecycleState {
  const s = record(value, 'state', ['id', 'subject', 'planId', 'revisionId', 'productId', 'version', 'status', 'periodStartsAt', 'periodEndsAt', 'trialEndsAt', 'renewalEnabled', 'cancelledAt', 'paymentFailedAt', 'scheduledChange', 'downgradedAt', 'validity']);
  const current = revision({ planId: s.planId, revisionId: s.revisionId, productId: s.productId }, 'state.revision');
  const state: LifecycleState = { ...current, id: uuid(s.id, 'state.id'), subject: subject(s.subject, 'state.subject'), version: integer(s.version, 'state.version', 1),
    status: choice(s.status, 'state.status', ['active', 'pending', 'paused', 'cancelled', 'expired', 'grace_period']),
    periodStartsAt: integer(s.periodStartsAt, 'state.periodStartsAt'), periodEndsAt: nullableTime(s.periodEndsAt, 'state.periodEndsAt'),
    trialEndsAt: nullableTime(s.trialEndsAt, 'state.trialEndsAt'), renewalEnabled: bool(s.renewalEnabled, 'state.renewalEnabled'),
    cancelledAt: nullableTime(s.cancelledAt, 'state.cancelledAt'), paymentFailedAt: nullableTime(s.paymentFailedAt, 'state.paymentFailedAt'), scheduledChange: null };
  if (Object.hasOwn(s, 'validity')) state.validity = choice(s.validity, 'state.validity', ['perpetual'] as const);
  if ((state.periodEndsAt === null) !== (state.validity === 'perpetual')
    || (state.validity === 'perpetual' && (state.renewalEnabled || state.trialEndsAt !== null || s.scheduledChange !== null || state.paymentFailedAt !== null))) invalid('state.validity', 'explicit perpetual state required without renewal, trial or scheduled change');
  if (Object.hasOwn(s, 'downgradedAt')) {
    state.downgradedAt = nullableTime(s.downgradedAt, 'state.downgradedAt');
    if (state.downgradedAt !== null && state.downgradedAt > now) invalid('state.downgradedAt', 'effective downgrade is in the future');
  }
  if ((state.periodEndsAt !== null && state.periodStartsAt >= state.periodEndsAt) || state.periodStartsAt > now) invalid('state.period', 'invalid or future period');
  if (state.trialEndsAt !== null && (state.trialEndsAt <= state.periodStartsAt || (state.periodEndsAt === null || state.trialEndsAt > state.periodEndsAt))) invalid('state.trialEndsAt', 'outside subscription period');
  if ([state.cancelledAt, state.paymentFailedAt].some(v => v !== null && (v > now || v < state.periodStartsAt))) invalid('state', 'event timestamp outside current state');
  if ((state.status === 'cancelled') !== (state.cancelledAt !== null) || (state.cancelledAt !== null && state.renewalEnabled)) invalid('state.cancelledAt', 'inconsistent cancellation state');
  if (s.scheduledChange !== null) {
    const change = record(s.scheduledChange, 'state.scheduledChange', ['planId', 'revisionId', 'productId', 'effectiveAt']);
    state.scheduledChange = { ...revision({ planId: change.planId, revisionId: change.revisionId, productId: change.productId }, 'state.scheduledChange'), effectiveAt: integer(change.effectiveAt, 'state.scheduledChange.effectiveAt') };
    if (state.scheduledChange.productId !== state.productId || state.scheduledChange.revisionId === state.revisionId || state.scheduledChange.effectiveAt !== endAt(state)) invalid('state.scheduledChange', 'invalid scheduled change');
  }
  if ((state.status === 'expired' || state.status === 'grace_period') && now < endAt(state)) invalid('state.status', 'expiry status precedes the effective period end');
  return state;
}
/** A configured trial expiry is the effective renewal boundary while the trial remains current. */
function endAt(state: LifecycleState): number { return state.trialEndsAt ?? state.periodEndsAt ?? Number.POSITIVE_INFINITY; }
function validateRetentionBinding(state: LifecycleState, policy: LifecyclePolicy): void {
  if (policy.billing === 'not_applicable' && (state.renewalEnabled || state.paymentFailedAt !== null || state.scheduledChange !== null)) {
    invalid('state.billing', 'non-billing state cannot renew, retry payment or schedule a renewal change');
  }
  if (Object.hasOwn(state, 'downgradedAt') !== (policy.readOnlyDurationMs !== undefined)) {
    invalid('state.downgradedAt', 'explicit downgrade event marker must match the finite-retention policy');
  }
}
function recordEffectiveDowngrade(next: LifecycleState, policy: LifecyclePolicy, effectiveAt: number): void {
  if (policy.readOnlyDurationMs !== undefined) {
    next.downgradedAt = next.downgradedAt === null ? effectiveAt : Math.min(integer(next.downgradedAt, 'state.downgradedAt'), effectiveAt);
  }
}
function accessAt(state: LifecycleState, policy: LifecyclePolicy, now: number): LifecycleAccess {
  const levels: readonly LifecycleAccess[] = ['full', 'restricted', 'read_only', 'suspended'];
  const restrictions: LifecycleAccess[] = ['full'];
  if (state.status === 'paused' || state.status === 'pending') restrictions.push('suspended');
  if (state.cancelledAt !== null && policy.cancellationAccess !== 'until_period_end') restrictions.push(policy.cancellationAccess);
  // A null marker explicitly means no effective downgrade. Renewing the period must
  // never substitute a later expiry for an already retained downgrade event.
  const retentionStartsAt = state.downgradedAt === undefined || state.downgradedAt === null ? endAt(state) : Math.min(endAt(state), state.downgradedAt);
  const suspensionAt = policy.readOnlyDurationMs === undefined || !Number.isFinite(retentionStartsAt) ? undefined : addTime(retentionStartsAt, policy.readOnlyDurationMs, 'policy.readOnlyDurationMs');
  if (now >= retentionStartsAt) {
    restrictions.push(suspensionAt !== undefined && now >= suspensionAt ? 'suspended'
      : now < addTime(state.periodEndsAt === null ? retentionStartsAt : endAt(state), policy.graceDurationMs, 'policy.graceDurationMs') ? policy.graceAccess : policy.expiredAccess);
  }
  if (state.paymentFailedAt !== null) {
    if (policy.paymentFailureRestrictedMs === null || policy.paymentFailureAfterAccess === null) invalid('policy.billing', 'payment failure terms are inapplicable');
    restrictions.push(now < addTime(state.paymentFailedAt, policy.paymentFailureRestrictedMs, 'policy.paymentFailureRestrictedMs') ? 'restricted' : policy.paymentFailureAfterAccess);
  }
  return levels[Math.max(...restrictions.map(value => levels.indexOf(value)))];
}

/** Current access is evaluated at read time, never reused from a stale transition receipt. */
export function readSubscriptionLifecycleAccess(stateValue: unknown, policyValue: unknown, nowValue: unknown): { state: LifecycleState; policy: LifecyclePolicy; access: LifecycleAccess } {
  const now = integer(nowValue, 'context.now');
  const state = validateState(stateValue, now), policy = validateSubscriptionLifecyclePolicy(policyValue);
  if (state.productId !== policy.productId) invalid('policy.productId', 'subscription product mismatch');
  validateRetentionBinding(state, policy);
  if (state.status === 'expired' && now < addTime(endAt(state), policy.graceDurationMs, 'policy.graceDurationMs')) invalid('state.status', 'expired state contradicts configured grace');
  return { state, policy, access: accessAt(state, policy, now) };
}

export function evaluateSubscriptionAccess(stateValue: unknown, policyValue: unknown, nowValue: unknown): LifecycleAccess {
  return readSubscriptionLifecycleAccess(stateValue, policyValue, nowValue).access;
}

/** Deterministic domain decision only. It neither authenticates evidence nor writes subscriptions.
 * The persistence owner must atomically compare expectedVersion/revision, consume settlement evidence,
 * save next and its audit, and enqueue retries/notifications exactly once. No deletion/refund is implied.
 */
export function decideSubscriptionLifecycle(stateValue: unknown, requestValue: unknown, policyValue: unknown, context: LifecycleContext): LifecycleDecision {
  const now = integer(context.now, 'context.now');
  const actorId = uuid(context.actorId, 'context.actorId');
  const state = validateState(stateValue, now);
  const policy = validateSubscriptionLifecyclePolicy(policyValue);
  validateRetentionBinding(state, policy);
  const request = record(requestValue, 'request', ['operation', 'subscriptionId', 'subject', 'expectedVersion', 'expectedRevisionId', 'reason', 'targetRevisionId', 'timing', 'quoteId', 'settlementId', 'approvalId']);
  const operation = choice(request.operation, 'request.operation', operations);
  const reason = text(request.reason, 'request.reason');
  if (!context.allowedOperations.has(operation)) invalid('request.operation', 'operation is not authorized in owner context');
  if (uuid(request.subscriptionId, 'request.subscriptionId') !== state.id || integer(request.expectedVersion, 'request.expectedVersion', 1) !== state.version
    || uuid(request.expectedRevisionId, 'request.expectedRevisionId') !== state.revisionId) invalid('request', 'stale subscription version or revision');
  if (!sameSubject(subject(request.subject, 'request.subject'), state.subject) || !sameSubject(subject(context.subject, 'context.subject'), state.subject)) invalid('request.subject', 'subscription subject mismatch');
  if (policy.productId !== state.productId) invalid('policy.productId', 'subscription product mismatch');
  const current = context.publishedRevisions.get(state.revisionId);
  if (!current || current.revisionId !== state.revisionId || current.planId !== state.planId || current.productId !== state.productId) invalid('state.revisionId', 'owner-verified current revision required');
  const graceEndsAt = state.periodEndsAt === null ? Number.POSITIVE_INFINITY : addTime(endAt(state), policy.graceDurationMs, 'policy.graceDurationMs');
  if (state.status === 'expired' && now < graceEndsAt) invalid('state.status', 'expired state contradicts configured grace');
  if (state.scheduledChange !== null) {
    const scheduled = context.publishedRevisions.get(state.scheduledChange.revisionId);
    if (!scheduled || scheduled.planId !== state.scheduledChange.planId || scheduled.revisionId !== state.scheduledChange.revisionId || scheduled.productId !== state.productId) invalid('state.scheduledChange', 'owner-verified scheduled revision required');
  }
  const permitted = operation === 'upgrade' || operation === 'renew' ? ['quoteId', 'settlementId'] : operation === 'downgrade' ? ['targetRevisionId', 'timing'] : operation === 'suspend' || operation === 'reactivate' ? ['approvalId'] : [];
  for (const field of ['targetRevisionId', 'timing', 'quoteId', 'settlementId', 'approvalId']) if (request[field] !== undefined && !permitted.includes(field)) invalid(`request.${field}`, 'not applicable to operation');
  const next: LifecycleState = { ...state, version: integer(state.version + 1, 'next.version', 1) };
  let retryAt: number[] = [];
  if (policy.billing === 'not_applicable' && (operation === 'renew' || operation === 'payment_failed'
    || (operation === 'downgrade' && request.timing === 'next_renewal'))) invalid('request.operation', 'operation is inapplicable to a non-billing offer');
  const startsPaidPeriod = operation === 'upgrade' && policy.billing === 'not_applicable';
  let nextPolicy = policy;
  if ((operation === 'upgrade' || operation === 'renew' || operation === 'payment_failed') && state.periodEndsAt === null && !startsPaidPeriod) invalid('state.periodEndsAt', 'paid transitions require a finite commercial period');
  if (operation === 'upgrade' || operation === 'renew') {
    if (state.status === 'paused' || state.cancelledAt !== null) invalid('state.status', 'suspended or cancelled subscription requires explicit reactivation');
    const quoteId = uuid(request.quoteId, 'request.quoteId');
    const settlementId = uuid(request.settlementId, 'request.settlementId');
    const q = context.quotes.get(quoteId);
    const e = context.settlements.get(settlementId);
    if (!q || !e || q.id !== quoteId || e.id !== settlementId) invalid('request.settlementId', 'owner-verified quote and settlement required');
    if (q.operation !== operation || e.operation !== operation || q.subscriptionId !== state.id || e.subscriptionId !== state.id || q.stateVersion !== state.version || e.stateVersion !== state.version
      || !sameSubject(q.subject, state.subject) || !sameSubject(e.subject, state.subject) || q.productId !== state.productId || e.quoteId !== q.id || e.revisionId !== q.revisionId
      || text(q.currency, 'quote.currency') !== e.currency || integer(q.amountMinor, 'quote.amountMinor') !== integer(e.amountMinor, 'settlement.amountMinor')) invalid('settlement', 'identity, operation or commercial terms mismatch');
    const capture=context.captures?.get(settlementId);
    if(capture!==undefined)assertLifecycleCapture(q,e,actorId,now,capture);
    if ((integer(q.validUntil, 'quote.validUntil') <= now && capture===undefined) || (integer(e.recordedAt, 'settlement.recordedAt') > now || e.recordedAt < state.periodStartsAt)) invalid('settlement', 'expired quote without retained capture or future settlement');
    choice(e.kind, 'settlement.kind', ['verified_payment', 'approved_invoice']);
    if (e.kind === 'approved_invoice' && (e.validUntil === null || integer(e.validUntil, 'settlement.validUntil') <= now)) invalid('settlement', 'live invoice approval required');
    if (e.validUntil !== null && integer(e.validUntil, 'settlement.validUntil') <= now) invalid('settlement', 'expired evidence');
    const target = context.publishedRevisions.get(q.revisionId);
    if (!target || target.revisionId !== q.revisionId || target.planId !== q.planId || target.productId !== state.productId) invalid('quote.revisionId', 'owner-verified published revision required');
    if (startsPaidPeriod) {
      const publishedPolicy = context.targetPolicies?.get(q.revisionId);
      if (!publishedPolicy) invalid('quote.revisionId', 'explicit paid target policy required');
      nextPolicy = validateSubscriptionLifecyclePolicy(publishedPolicy);
      if (nextPolicy.productId !== state.productId || nextPolicy.billing === 'not_applicable') invalid('quote.revisionId', 'paid target policy required');
    }
    if (integer(q.periodStartsAt, 'quote.periodStartsAt') > now || integer(q.periodEndsAt, 'quote.periodEndsAt') <= now || q.periodStartsAt >= q.periodEndsAt) invalid('quote.period', 'settled period must be active now');
    if (operation === 'upgrade') {
      if (!context.revisionChanges.some(change => change.fromRevisionId === state.revisionId && change.toRevisionId === q.revisionId && change.operation === 'upgrade')) invalid('quote.revisionId', 'owner-approved upgrade transition required');
      if (state.status !== 'active' || q.revisionId === state.revisionId || state.scheduledChange !== null || now >= endAt(state)
        || (startsPaidPeriod ? q.periodStartsAt < state.periodStartsAt : q.periodStartsAt !== state.periodStartsAt || q.periodEndsAt !== state.periodEndsAt)) invalid('quote', 'upgrade must change current limits immediately within the current paid period');
    } else {
      if (state.scheduledChange !== null && now < state.scheduledChange.effectiveAt) invalid('state.scheduledChange.effectiveAt', 'scheduled transition is not effective');
      if (now < endAt(state) || q.periodStartsAt !== endAt(state) || (state.scheduledChange !== null ? q.revisionId !== state.scheduledChange.revisionId : q.revisionId !== state.revisionId)) invalid('quote', 'renewal must extend the current period and honor its scheduled revision');
    }
    if (operation === 'renew' && state.scheduledChange !== null) recordEffectiveDowngrade(next, policy, state.scheduledChange.effectiveAt);
    Object.assign(next, revision(target, 'publishedRevision'), { status: 'active', periodStartsAt: q.periodStartsAt, periodEndsAt: q.periodEndsAt, trialEndsAt: null, paymentFailedAt: null, scheduledChange: null });
    if (startsPaidPeriod) {
      delete next.validity;
      next.renewalEnabled = true;
      if (nextPolicy.readOnlyDurationMs === undefined) delete next.downgradedAt;
      else next.downgradedAt = null;
    }
  } else if (operation === 'downgrade') {
    if (state.status !== 'active' || now >= endAt(state) || state.cancelledAt !== null || state.scheduledChange !== null) invalid('state', 'downgrade requires an active period without a pending change');
    const id = uuid(request.targetRevisionId, 'request.targetRevisionId');
    const candidate = context.publishedRevisions.get(id);
    if (!candidate || candidate.revisionId !== id || candidate.productId !== state.productId || id === state.revisionId) invalid('request.targetRevisionId', 'different published revision in the same product required');
    const target = revision(candidate, 'publishedRevision');
    if (!context.revisionChanges.some(change => change.fromRevisionId === state.revisionId && change.toRevisionId === target.revisionId && change.operation === 'downgrade')) invalid('request.targetRevisionId', 'owner-approved downgrade transition required');
    const timing = choice(request.timing, 'request.timing', ['next_renewal', 'immediate']);
    if (timing === 'immediate') {
      if (!policy.immediateDowngradeAllowed) invalid('request.timing', 'immediate downgrade is not allowed by policy');
      Object.assign(next, target);
      recordEffectiveDowngrade(next, policy, now);
    } else {
      if (state.periodEndsAt === null) invalid('request.timing', 'perpetual entry has no renewal boundary');
      next.scheduledChange = { ...target, effectiveAt: endAt(state) };
    }
  } else if (operation === 'cancel') {
    if (state.periodEndsAt === null && policy.cancellationAccess === 'until_period_end') invalid('policy.cancellationAccess', 'perpetual cancellation needs explicit immediate access terms');
    if (state.cancelledAt !== null || ['pending', 'paused'].includes(state.status)) invalid('state', 'subscription cannot be cancelled from its current state');
    Object.assign(next, { status: 'cancelled', cancelledAt: now, renewalEnabled: false, scheduledChange: null });
  } else if (operation === 'expire') {
    if (now < endAt(state) || state.status === 'paused' || state.cancelledAt !== null || state.status === 'pending') invalid('state', 'subscription is not eligible for expiry');
    next.status = now < addTime(endAt(state), policy.graceDurationMs, 'policy.graceDurationMs') ? 'grace_period' : 'expired';
    if (next.status === state.status) invalid('state', 'expiry state is already current');
  } else if (operation === 'payment_failed') {
    if (state.paymentFailedAt !== null || state.cancelledAt !== null || state.status === 'paused' || state.status === 'pending') invalid('state', 'payment failure is not a new eligible event');
    next.paymentFailedAt = now;
    retryAt = policy.paymentRetryOffsetsMs.map(offset => addTime(now, offset, 'policy.paymentRetryOffsetsMs'));
  } else {
    const required = operation === 'suspend' ? policy.suspensionApprovalRequired : policy.reactivationApprovalRequired;
    if (required || request.approvalId !== undefined) {
      const approvalId = uuid(request.approvalId, 'request.approvalId');
      const a = context.approvals.get(approvalId);
      if (!a || a.id !== approvalId || a.subscriptionId !== state.id || !sameSubject(a.subject, state.subject) || a.stateVersion !== state.version || a.operation !== operation || a.actorId !== actorId || integer(a.validUntil, 'approval.validUntil') <= now) invalid('request.approvalId', 'matching live owner approval required');
    }
    if (operation === 'suspend') {
      if (state.status === 'paused' || state.cancelledAt !== null) invalid('state', 'subscription cannot be suspended from its current state');
      next.status = 'paused';
    } else {
      if (state.status !== 'paused' || now >= endAt(state) || state.cancelledAt !== null || state.paymentFailedAt !== null) invalid('state', 'reactivation requires an unexpired suspended subscription without unresolved payment failure');
      next.status = 'active';
    }
  }
  validateRetentionBinding(next, nextPolicy);
  return { expectedVersion: state.version, expectedRevisionId: state.revisionId, next, access: accessAt(next, nextPolicy, now), retryAt,
    audit: { operation, actorId, reason, at: now, policyId: policy.id, policyVersion: policy.version } };
}
