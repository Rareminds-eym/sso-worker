import { describe, expect, it } from 'vitest';
import { CatalogValidationError } from '../lib/subscriptions/validation';
import { decideSubscriptionLifecycle, evaluateSubscriptionAccess, readSubscriptionLifecycleAccess, type LifecycleContext, type LifecycleOperation, type LifecyclePolicy, type LifecycleQuote, type LifecycleSettlement, type LifecycleState } from '../lib/subscriptions/lifecycle';

// Isolated protocol fixtures; none are deployed plans, users, prices or policy defaults.
const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const subject = { kind: 'organization' as const, id: id(2) };
function fixture(operation: LifecycleOperation = 'upgrade', now = 1000) {
  const state: LifecycleState = { id: id(1), subject, productId: id(3), planId: id(4), revisionId: id(5), version: 2,
    status: 'active', periodStartsAt: 0, periodEndsAt: 2000, trialEndsAt: null, renewalEnabled: true,
    cancelledAt: null, paymentFailedAt: null, scheduledChange: null };
  const target = { planId: id(6), revisionId: id(7), productId: id(3) };
  const policy: LifecyclePolicy = { id: id(8), version: 1, productId: id(3), graceDurationMs: 200, graceAccess: 'restricted', expiredAccess: 'read_only', cancellationAccess: 'until_period_end', immediateDowngradeAllowed: false,
    paymentFailureRestrictedMs: 100, paymentFailureAfterAccess: 'suspended', paymentRetryOffsetsMs: [25, 50], suspensionApprovalRequired: true, reactivationApprovalRequired: true };
  const quote: LifecycleQuote = { ...target, id: id(9), subscriptionId: state.id, subject, stateVersion: state.version,
    operation: 'upgrade', amountMinor: 2500, currency: 'XYZ', periodStartsAt: state.periodStartsAt, periodEndsAt: 2000, validUntil: now + 100 };
  const settlement: LifecycleSettlement = { id: id(10), quoteId: quote.id, subscriptionId: state.id, subject, stateVersion: state.version,
    revisionId: target.revisionId, amountMinor: quote.amountMinor, currency: quote.currency, operation: 'upgrade', kind: 'verified_payment', recordedAt: now, validUntil: null };
  const context: LifecycleContext = { now, actorId: id(11), subject, allowedOperations: new Set([operation]), quotes: new Map([[quote.id, quote]]), settlements: new Map([[settlement.id, settlement]]), approvals: new Map(),
    publishedRevisions: new Map([[target.revisionId, target], [state.revisionId, { planId: state.planId, revisionId: state.revisionId, productId: state.productId }]]),
    revisionChanges: [{ fromRevisionId: state.revisionId, toRevisionId: target.revisionId, operation: 'upgrade' }, { fromRevisionId: state.revisionId, toRevisionId: target.revisionId, operation: 'downgrade' }] };
  const request: Record<string, unknown> = { operation, subscriptionId: state.id, subject, expectedVersion: state.version, expectedRevisionId: state.revisionId, reason: 'Synthetic reviewed request' };
  if (operation === 'upgrade' || operation === 'renew') Object.assign(request, { quoteId: quote.id, settlementId: settlement.id });
  if (operation === 'downgrade') Object.assign(request, { targetRevisionId: target.revisionId, timing: 'next_renewal' });
  return { state, policy, quote, settlement, context, request, target, decide: () => decideSubscriptionLifecycle(state, request, policy, context) };
}
function approve(f: ReturnType<typeof fixture>, operation: 'suspend' | 'reactivate') {
  f.request.approvalId = id(12);
  f.context.approvals = new Map([[id(12), { id: id(12), subscriptionId: f.state.id, subject, stateVersion: f.state.version, operation, actorId: f.context.actorId, validUntil: f.context.now + 1 }]]);
}
function renewal(now = 2000) {
  const f = fixture('renew', now);
  Object.assign(f.quote, { operation: 'renew', planId: f.state.planId, revisionId: f.state.revisionId, periodStartsAt: 2000, periodEndsAt: 4000 });
  Object.assign(f.settlement, { operation: 'renew', revisionId: f.state.revisionId });
  return f;
}
function finiteRetention(f: ReturnType<typeof fixture>) {
  Object.assign(f.policy, { graceAccess: 'read_only', expiredAccess: 'read_only', graceDurationMs: 150, readOnlyDurationMs: 900 });
  f.state.downgradedAt = null;
  return f;
}

describe('policy-driven subscription lifecycle decisions', () => {
  function nonBilling(operation: LifecycleOperation = 'cancel', perpetual = false) {
    const f = finiteRetention(fixture(operation));
    Object.assign(f.policy, { billing: 'not_applicable', cancellationAccess: 'read_only',
      paymentFailureRestrictedMs: null, paymentFailureAfterAccess: null, paymentRetryOffsetsMs: [] });
    f.state.renewalEnabled = false;
    if (perpetual) { f.state.periodEndsAt = null; f.state.validity = 'perpetual'; }
    return f;
  }
  it.each([false, true])('cancels an explicit non-billing offer with read-only access (perpetual=%s)', perpetual => {
    const f = nonBilling('cancel', perpetual);
    expect(f.decide()).toMatchObject({ access: 'read_only', retryAt: [], next: { status: 'cancelled', renewalEnabled: false } });
  });
  it.each(['renew', 'payment_failed', 'downgrade'] as const)('rejects %s on a non-billing offer', operation => {
    expect(nonBilling(operation).decide).toThrow('inapplicable');
  });
  it.each(['suspend', 'reactivate'] as const)('requires explicit owner approval for non-billing %s', operation => {
    const f = nonBilling(operation);
    if (operation === 'reactivate') f.state.status = 'paused';
    expect(f.decide).toThrow();
    approve(f, operation);
    expect(f.decide().next.status).toBe(operation === 'suspend' ? 'paused' : 'active');
  });
  it.each([
    { paymentRetryOffsetsMs: [1] }, { paymentFailureRestrictedMs: 1 }, { paymentFailureAfterAccess: 'suspended' },
    { immediateDowngradeAllowed: true }, { cancellationAccess: 'until_period_end' }, { billing: 'unknown' },
  ])('rejects inconsistent non-billing policy %j', patch => {
    const f = nonBilling(); Object.assign(f.policy, patch); expect(f.decide).toThrow();
  });
  it.each(['renewal', 'payment', 'scheduled'] as const)('rejects non-billing state with %s', kind => {
    const f = nonBilling();
    if (kind === 'renewal') f.state.renewalEnabled = true;
    if (kind === 'payment') f.state.paymentFailedAt = f.context.now;
    if (kind === 'scheduled') f.state.scheduledChange = { ...f.target, effectiveAt: 2000 };
    expect(() => evaluateSubscriptionAccess(f.state, f.policy, f.context.now)).toThrow('state.billing');
  });
  function capturedUpgrade() {
    const f=fixture('upgrade',3000);f.state.periodEndsAt=10000;f.quote.periodEndsAt=10000;f.quote.validUntil=2000;f.settlement.recordedAt=1000;
    const capture={eventId:'a'.repeat(64),actorId:f.context.actorId,quoteId:f.quote.id,settlementId:f.settlement.id,productId:f.state.productId,subscriptionId:f.state.id,
      subject:f.state.subject,stateVersion:f.state.version,revisionId:f.quote.revisionId,amountMinor:f.quote.amountMinor,currency:f.quote.currency,
      providerPaymentId:'pay_synthetic',providerOrderId:'order_synthetic',capturedAt:1000,paymentCreatedAt:500,quoteCreatedAt:500};
    f.context.captures=new Map([[f.settlement.id,capture]]);return {...f,capture};
  }
  it('uses exact owner-loaded timely capture for delayed paid decisions while retaining current audit/access time',()=>{
    const f=capturedUpgrade();const result=f.decide();expect(result.audit.at).toBe(3000);expect(result.next.periodEndsAt).toBe(10000);expect(result.access).toBe('full');
    expect(Object.keys(f.quote)).not.toContain('capture');expect(Object.keys(f.settlement)).not.toContain('capture');
  });
  it.each(['missing','actor','product','subject','amount','version','revision','payment_time','capture_time','quote_time','event'] as const)('rejects delayed lifecycle capture %s mismatch',field=>{
    const f=capturedUpgrade();
    if(field==='missing')f.context.captures=new Map();
    if(field==='actor')f.capture.actorId=id(90);
    if(field==='product')f.capture.productId=id(90);
    if(field==='subject')f.capture.subject={...f.capture.subject,id:id(90)};
    if(field==='amount')f.capture.amountMinor++;
    if(field==='version')f.capture.stateVersion++;
    if(field==='revision')f.capture.revisionId=id(90);
    if(field==='payment_time')f.capture.paymentCreatedAt=1001;
    if(field==='capture_time'){f.capture.capturedAt=2000;f.settlement.recordedAt=2000;}
    if(field==='quote_time')f.capture.quoteCreatedAt=1001;
    if(field==='event')f.capture.eventId='invalid';
    expect(()=>f.decide()).toThrow();
  });
  describe('explicit finite expiry read-only policy', () => {
    // Synthetic elapsed-time policy: the same proportions as 15/90 days without runtime defaults.
    function retained() {
      return finiteRetention(fixture('expire'));
    }
    it.each([[1999, 'full'], [2000, 'read_only'], [2149, 'read_only'], [2150, 'read_only'], [2899, 'read_only'], [2900, 'suspended'], [3050, 'suspended']] as const)(
      'evaluates finite access at %i from effective expiry, including grace', (now, access) => {
        const f = retained();
        expect(evaluateSubscriptionAccess(f.state, f.policy, now)).toBe(access);
      });
    it('retains the exact configured horizon through owner validation', () => {
      const f = retained();
      expect(readSubscriptionLifecycleAccess(f.state, f.policy, 2000).policy).toEqual(f.policy);
    });
    it('uses trial expiry rather than the later paid-period end', () => {
      const f = retained(); f.state.trialEndsAt = 1800;
      expect(evaluateSubscriptionAccess(f.state, f.policy, 2699)).toBe('read_only');
      expect(evaluateSubscriptionAccess(f.state, f.policy, 2700)).toBe('suspended');
    });
    it('does not restart retention when a delayed expiry transition is processed', () => {
      const f = retained(); f.context.now = 2900;
      const result = f.decide();
      expect(result).toMatchObject({ access: 'suspended', next: { status: 'expired', periodEndsAt: 2000 } });
      expect(evaluateSubscriptionAccess(result.next, f.policy, 3000)).toBe('suspended');
    });
    it('does not relax payment or administrative suspension during read-only grace', () => {
      const f = retained(); f.state.paymentFailedAt = 1800;
      expect(evaluateSubscriptionAccess(f.state, f.policy, 2000)).toBe('suspended');
      f.state.paymentFailedAt = null; f.state.status = 'paused';
      expect(evaluateSubscriptionAccess(f.state, f.policy, 2000)).toBe('suspended');
    });
    it('preserves already retained policy meaning without inventing a new horizon', () => {
      const f = fixture('expire');
      expect(evaluateSubscriptionAccess(f.state, f.policy, 2000)).toBe('restricted');
      expect(evaluateSubscriptionAccess(f.state, f.policy, 10000)).toBe('read_only');
      expect(readSubscriptionLifecycleAccess(f.state, f.policy, 10000).policy).not.toHaveProperty('readOnlyDurationMs');
    });
    it.each([
      ['null duration', { readOnlyDurationMs: null }],
      ['zero duration', { readOnlyDurationMs: 0 }],
      ['negative duration', { readOnlyDurationMs: -1 }],
      ['fractional duration', { readOnlyDurationMs: 900.5 }],
      ['unsafe duration', { readOnlyDurationMs: Number.MAX_SAFE_INTEGER + 1 }],
      ['duration shorter than grace', { readOnlyDurationMs: 149 }],
      ['write-capable grace', { graceAccess: 'restricted' }],
      ['early suspension after grace', { expiredAccess: 'suspended' }],
      ['overflowing suspension instant', { readOnlyDurationMs: Number.MAX_SAFE_INTEGER }],
    ])('rejects %s instead of substituting access', (_, policy) => {
      const f = retained(); Object.assign(f.policy, policy);
      expect(() => evaluateSubscriptionAccess(f.state, f.policy, 2000)).toThrow(CatalogValidationError);
    });
    it('does not mutate either retained state or policy during access reads', () => {
      const f = retained(); const before = structuredClone({ state: f.state, policy: f.policy });
      evaluateSubscriptionAccess(f.state, f.policy, 2900);
      expect({ state: f.state, policy: f.policy }).toEqual(before);
    });
  });
  describe('durable effective downgrade retention', () => {
    it('starts immediate downgrade read-only access before period expiry', () => {
      const f = finiteRetention(fixture('downgrade'));
      f.policy.immediateDowngradeAllowed = true; f.request.timing = 'immediate';
      const result = f.decide();
      expect(result.next.downgradedAt).toBe(1000);
      expect(result.access).toBe('read_only');
      expect(evaluateSubscriptionAccess(result.next, f.policy, 1899)).toBe('read_only');
      expect(evaluateSubscriptionAccess(result.next, f.policy, 1900)).toBe('suspended');
    });
    it.each([2000, 2200])('anchors a settled scheduled downgrade at its effective boundary, processed at %i', now => {
      const scheduled = finiteRetention(fixture('downgrade'));
      const pending = scheduled.decide();
      expect(pending.access).toBe('full'); expect(pending.next.downgradedAt).toBeNull();
      expect(evaluateSubscriptionAccess(pending.next, scheduled.policy, 1999)).toBe('full');
      const f = finiteRetention(renewal(now)); Object.assign(f.state, pending.next);
      f.request.expectedVersion = f.state.version;
      Object.assign(f.quote, f.target, { stateVersion: f.state.version });
      Object.assign(f.settlement, { revisionId: f.target.revisionId, stateVersion: f.state.version });
      const result = f.decide();
      expect(result.next).toMatchObject({ downgradedAt: 2000, periodStartsAt: 2000, periodEndsAt: 4000, scheduledChange: null });
      expect(result.access).toBe('read_only');
      expect(evaluateSubscriptionAccess(result.next, f.policy, 2899)).toBe('read_only');
      expect(evaluateSubscriptionAccess(result.next, f.policy, 2900)).toBe('suspended');
    });
    it('does not restart the clock on another immediate downgrade', () => {
      const f = finiteRetention(fixture('downgrade')); f.state.downgradedAt = 800;
      f.policy.immediateDowngradeAllowed = true; f.request.timing = 'immediate';
      const result = f.decide(); expect(result.next.downgradedAt).toBe(800);
      expect(evaluateSubscriptionAccess(result.next, f.policy, 1700)).toBe('suspended');
    });
    it('retains an earlier scheduled event when historical events were initialized out of order', () => {
      const f = finiteRetention(renewal(2200)); f.state.downgradedAt = 2100;
      f.state.scheduledChange = { ...f.target, effectiveAt: 2000 };
      Object.assign(f.quote, f.target); f.settlement.revisionId = f.target.revisionId;
      const result = f.decide(); expect(result.next.downgradedAt).toBe(2000);
      expect(evaluateSubscriptionAccess(result.next, f.policy, 2900)).toBe('suspended');
    });
    it('does not restart the clock on ordinary paid renewal or upgrade', () => {
      for (const f of [finiteRetention(renewal()), finiteRetention(fixture('upgrade'))]) {
        f.state.downgradedAt = 800;
        const result = f.decide(); expect(result.next.downgradedAt).toBe(800);
        expect(evaluateSubscriptionAccess(result.next, f.policy, 2500)).toBe('suspended');
      }
    });
    it.each(['cancel', 'payment_failed', 'suspend', 'reactivate'] as const)('preserves the clock across %s', operation => {
      const f = finiteRetention(fixture(operation)); f.state.downgradedAt = 800;
      f.policy.suspensionApprovalRequired = false; f.policy.reactivationApprovalRequired = false;
      if (operation === 'reactivate') f.state.status = 'paused';
      const result = f.decide(); expect(result.next.downgradedAt).toBe(800);
      expect(evaluateSubscriptionAccess(result.next, f.policy, 1700)).toBe('suspended');
    });
    it('uses the earlier downgrade/expiry event even across billing periods', () => {
      const f = finiteRetention(fixture('expire')); f.state.downgradedAt = 1000;
      f.state.periodStartsAt = 1200; f.state.periodEndsAt = 3000;
      expect(evaluateSubscriptionAccess(f.state, f.policy, 1899)).toBe('read_only');
      expect(evaluateSubscriptionAccess(f.state, f.policy, 1900)).toBe('suspended');
    });
    it.each([undefined, -1, 0.5, 1001, '800', Number.MAX_SAFE_INTEGER + 1])('rejects an invalid stored downgrade timestamp %s', value => {
      const f = finiteRetention(fixture()); Object.assign(f.state, { downgradedAt: value });
      expect(() => evaluateSubscriptionAccess(f.state, f.policy, 1000)).toThrow(CatalogValidationError);
    });
    it('requires an explicit null/event marker for finite-retention initialization', () => {
      const f = finiteRetention(fixture()); delete f.state.downgradedAt;
      expect(() => evaluateSubscriptionAccess(f.state, f.policy, 1000)).toThrow(CatalogValidationError);
    });
    it('does not attach a new retention clock to a historical policy without that contract', () => {
      const f = fixture(); f.state.downgradedAt = null;
      expect(() => evaluateSubscriptionAccess(f.state, f.policy, 1000)).toThrow(CatalogValidationError);
    });
  });
  it('upgrades immediately with owner-verified settlement and preserves inputs', () => {
    const f = fixture(); const before = structuredClone(f.state);
    const result = f.decide();
    expect(result.next.revisionId).toBe(f.target.revisionId); expect(result.next.planId).toBe(f.target.planId);
    expect(result.next.version).toBe(3); expect(result.expectedVersion).toBe(2); expect(result.expectedRevisionId).toBe(before.revisionId);
    expect(result.access).toBe('full'); expect(result.audit).toMatchObject({ operation: 'upgrade', actorId: f.context.actorId, policyId: f.policy.id, policyVersion: 1, at: 1000 });
    expect(f.state).toEqual(before); expect(result.next).not.toBe(f.state);
  });
  it('accepts a live approved invoice without pretending it is payment', () => {
    const f = fixture(); f.settlement.kind = 'approved_invoice'; f.settlement.validUntil = 1001;
    expect(f.decide().next.revisionId).toBe(f.target.revisionId);
  });
  it('renews at the boundary from settled exact terms', () => {
    const f = renewal(); f.state.paymentFailedAt = 1900;
    expect(f.decide()).toMatchObject({ access: 'full', next: { status: 'active', periodStartsAt: 2000, periodEndsAt: 4000, paymentFailedAt: null, scheduledChange: null } });
  });
  it('renews a trial at its explicit earlier expiry', () => {
    const f = renewal(1800); f.state.trialEndsAt = 1800; f.quote.periodStartsAt = 1800;
    expect(f.decide().next.trialEndsAt).toBeNull();
  });
  it('honors the scheduled downgrade only on settled renewal', () => {
    const f = renewal(); f.state.scheduledChange = { ...f.target, effectiveAt: 2000 };
    Object.assign(f.quote, f.target); f.settlement.revisionId = f.target.revisionId;
    expect(f.decide().next).toMatchObject({ revisionId: f.target.revisionId, scheduledChange: null });
  });
  it('rejects a trial renewal consuming a scheduled target before its recorded effective date', () => {
    const f = renewal(1800); f.state.trialEndsAt = 1800;
    f.state.scheduledChange = { ...f.target, effectiveAt: 2000 };
    Object.assign(f.quote, f.target, { periodStartsAt: 1800 }); f.settlement.revisionId = f.target.revisionId;
    expect(f.decide).toThrow(CatalogValidationError);
  });
  it.each([[1799, false], [1800, true]] as const)('trial downgrade scheduling and renewal share the effective boundary at %i', (now, effective) => {
    const scheduled = fixture('downgrade'); scheduled.state.trialEndsAt = 1800;
    const next = scheduled.decide().next;
    expect(next.scheduledChange).toEqual({ ...scheduled.target, effectiveAt: 1800 });
    expect(next.periodEndsAt).toBe(2000);
    const f = renewal(now); Object.assign(f.state, next);
    f.request.expectedVersion = next.version;
    Object.assign(f.quote, f.target, { stateVersion: next.version, periodStartsAt: 1800 });
    Object.assign(f.settlement, { revisionId: f.target.revisionId, stateVersion: next.version });
    if (!effective) expect(f.decide).toThrow(CatalogValidationError);
    else expect(f.decide().next).toMatchObject({ revisionId: f.target.revisionId, scheduledChange: null, trialEndsAt: null, periodStartsAt: 1800 });
  });
  it('schedules downgrade without changing current limits', () => {
    const f = fixture('downgrade'); const result = f.decide();
    expect(result.next.revisionId).toBe(f.state.revisionId); expect(result.next.scheduledChange).toEqual({ ...f.target, effectiveAt: 2000 });
  });
  it('applies immediate downgrade only with explicit policy', () => {
    const f = fixture('downgrade'); f.request.timing = 'immediate'; f.policy.immediateDowngradeAllowed = true;
    expect(f.decide().next.revisionId).toBe(f.target.revisionId);
  });
  it.each([[1999, false], [2000, true]])('expiry checks exact end boundary %i', (now, allowed) => {
    const f = fixture('expire', now);
    if (!allowed) expect(f.decide).toThrow(CatalogValidationError); else expect(f.decide()).toMatchObject({ access: 'restricted', next: { status: 'grace_period' } });
  });
  it.each([[2199, 'restricted', 'grace_period'], [2200, 'read_only', 'expired'], [2400, 'read_only', 'expired']])('configured grace ends precisely at %i', (now, access, status) => {
    const f = fixture('expire', now); expect(f.decide()).toMatchObject({ access, next: { status } });
  });
  it('zero grace expires immediately and can suspend without deleting data', () => {
    const f = fixture('expire', 2000); f.policy.graceDurationMs = 0; f.policy.expiredAccess = 'suspended';
    expect(f.decide()).toMatchObject({ access: 'suspended', next: { status: 'expired', planId: f.state.planId, revisionId: f.state.revisionId } });
  });
  it('trial expiry uses its explicit boundary', () => {
    const f = fixture('expire', 1500); f.state.trialEndsAt = 1500;
    expect(f.decide().next.status).toBe('grace_period');
  });
  it.each(['until_period_end', 'read_only', 'suspended'] as const)('cancellation stops renewal with configured access %s', mode => {
    const f = fixture('cancel'); f.policy.cancellationAccess = mode;
    expect(f.decide()).toMatchObject({ access: mode === 'until_period_end' ? 'full' : mode, next: { status: 'cancelled', renewalEnabled: false, cancelledAt: 1000, scheduledChange: null } });
  });
  it('payment failure emits explicit retry instants and restricts access', () => {
    const f = fixture('payment_failed');
    expect(f.decide()).toMatchObject({ access: 'restricted', retryAt: [1025, 1050], next: { paymentFailedAt: 1000 } });
  });
  it('does not relax a payment suspension when grace would grant restricted access', () => {
    const f = fixture('expire', 2000); f.state.paymentFailedAt = 1800;
    expect(f.decide().access).toBe('suspended');
  });
  it('cancellation does not relax a payment suspension', () => {
    const f = fixture('cancel', 1200); f.state.paymentFailedAt = 1000;
    expect(f.decide().access).toBe('suspended');
  });
  it('suspension captures reason/actor/time and requires live approval', () => {
    const f = fixture('suspend'); approve(f, 'suspend');
    expect(f.decide()).toMatchObject({ access: 'suspended', next: { status: 'paused' }, audit: { reason: f.request.reason, actorId: f.context.actorId, at: 1000 } });
  });
  it('reactivates only a current unexpired suspended subscription', () => {
    const f = fixture('reactivate'); f.state.status = 'paused'; approve(f, 'reactivate');
    expect(f.decide()).toMatchObject({ access: 'full', next: { status: 'active' } });
  });
  it('policy may explicitly dispense with manual approval, while permission remains required', () => {
    const f = fixture('suspend'); f.policy.suspensionApprovalRequired = false;
    expect(f.decide().next.status).toBe('paused'); f.context.allowedOperations = new Set(); expect(f.decide).toThrow(CatalogValidationError);
  });

  const invalidUpgrade: [string, (f: ReturnType<typeof fixture>) => void][] = [
    ['missing policy', f => { delete (f.policy as Partial<LifecyclePolicy>).graceAccess; }],
    ['unknown policy field', f => { Object.assign(f.policy, { inventedGraceDays: 3 }); }],
    ['negative grace', f => { f.policy.graceDurationMs = -1; }],
    ['empty retry schedule', f => { f.policy.paymentRetryOffsetsMs = []; }],
    ['fractional retry', f => { f.policy.paymentRetryOffsetsMs = [0.5]; }],
    ['duplicate retry', f => { f.policy.paymentRetryOffsetsMs = [2, 2]; }],
    ['descending retry', f => { f.policy.paymentRetryOffsetsMs = [2, 1]; }],
    ['wrong policy product', f => { f.policy.productId = id(30); }],
    ['absent permission', f => { f.context.allowedOperations = new Set(); }],
    ['stale state version', f => { f.request.expectedVersion = 1; }],
    ['stale revision', f => { f.request.expectedRevisionId = id(30); }],
    ['wrong subscription', f => { f.request.subscriptionId = id(30); }],
    ['wrong request subject', f => { f.request.subject = { ...subject, id: id(30) }; }],
    ['wrong owner subject', f => { f.context.subject = { ...subject, id: id(30) }; }],
    ['same UUID different subject kind', f => { f.request.subject = { ...subject, kind: 'user' }; }],
    ['client ready flag', f => { f.request.ready = true; }],
    ['wrong current plan', f => { f.state.planId = id(30); }],
    ['grace time overflow', f => { f.policy.graceDurationMs = Number.MAX_SAFE_INTEGER; }],
    ['absent reason', f => { delete f.request.reason; }],
    ['foreign operation evidence', f => { f.request.approvalId = id(12); }],
    ['no quote', f => { f.context.quotes = new Map(); }],
    ['no settlement', f => { f.context.settlements = new Map(); }],
    ['payment subscription', f => { f.settlement.subscriptionId = id(30); }],
    ['payment subject', f => { f.settlement.subject = { ...subject, id: id(30) }; }],
    ['payment revision', f => { f.settlement.revisionId = id(30); }],
    ['payment amount', f => { f.settlement.amountMinor++; }],
    ['payment currency', f => { f.settlement.currency = 'OTHER'; }],
    ['payment quote', f => { f.settlement.quoteId = id(30); }],
    ['payment version', f => { f.settlement.stateVersion--; }],
    ['payment operation', f => { f.settlement.operation = 'renew'; }],
    ['future payment', f => { f.settlement.recordedAt++; }],
    ['quote expired at boundary', f => { f.quote.validUntil = 1000; }],
    ['invoice missing live approval', f => { f.settlement.kind = 'approved_invoice'; }],
    ['invoice expired at boundary', f => { f.settlement.kind = 'approved_invoice'; f.settlement.validUntil = 1000; }],
    ['publication missing', f => { f.context.publishedRevisions = new Map(); }],
    ['publication plan mismatch', f => { f.quote.planId = id(30); }],
    ['upgrade direction unapproved', f => { f.context.revisionChanges = []; }],
    ['upgrade falsely classified', f => { f.context.revisionChanges = f.context.revisionChanges.filter(v => v.operation === 'downgrade'); }],
    ['upgrade period future', f => { f.quote.periodStartsAt++; }],
    ['upgrade period changes expiry', f => { f.quote.periodEndsAt++; }],
    ['version overflow', f => { f.state.version = Number.MAX_SAFE_INTEGER; f.request.expectedVersion = f.state.version; }],
    ['invalid trial', f => { f.state.trialEndsAt = 2001; }],
    ['future state event', f => { f.state.paymentFailedAt = 1001; }],
    ['future expired status', f => { f.state.status = 'expired'; }],
    ['cancelled with renewal enabled', f => { f.state.status = 'cancelled'; f.state.cancelledAt = 999; }],
  ];
  it.each(invalidUpgrade)('rejects %s', (_, change) => { const f = fixture(); change(f); expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects scheduled revision plan corruption', () => {
    const f = renewal(); f.state.scheduledChange = { ...f.target, planId: id(30), effectiveAt: 2000 }; expect(f.decide).toThrow(CatalogValidationError);
  });
  it('rejects expired status before configured grace has ended', () => {
    const f = fixture('expire', 2100); f.state.status = 'expired'; expect(f.decide).toThrow(CatalogValidationError);
  });
  it('rejects renewal before period boundary', () => { const f = renewal(1999); expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects renewal that ignores a scheduled revision', () => { const f = renewal(); f.state.scheduledChange = { ...f.target, effectiveAt: 2000 }; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects immediate downgrade without its policy', () => { const f = fixture('downgrade'); f.request.timing = 'immediate'; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects downgrade without an explicit transition direction', () => { const f = fixture('downgrade'); f.context.revisionChanges = []; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects overriding a scheduled downgrade', () => { const f = fixture('downgrade'); f.state.scheduledChange = { ...f.target, effectiveAt: 2000 }; expect(f.decide).toThrow(CatalogValidationError); });
  it.each(['suspend', 'reactivate'] as const)('rejects missing approval for %s', op => { const f = fixture(op); if (op === 'reactivate') f.state.status = 'paused'; expect(f.decide).toThrow(CatalogValidationError); });
  it.each(['actorId', 'subscriptionId', 'stateVersion', 'operation', 'validUntil', 'subject'] as const)('rejects invalid approval %s', field => {
    const f = fixture('suspend'); approve(f, 'suspend'); const a = f.context.approvals.get(id(12))!;
    const values = { actorId: id(30), subscriptionId: id(30), stateVersion: 1, operation: 'reactivate', validUntil: 1000, subject: { ...subject, id: id(30) } };
    Object.assign(a, { [field]: values[field] }); expect(f.decide).toThrow(CatalogValidationError);
  });
  it('rejects unexpired repeated expiry', () => { const f = fixture('expire', 2100); f.state.status = 'grace_period'; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects repeated payment failure', () => { const f = fixture('payment_failed'); f.state.paymentFailedAt = 999; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects retry timestamp overflow', () => { const f = fixture('payment_failed'); f.policy.paymentRetryOffsetsMs = [Number.MAX_SAFE_INTEGER]; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects cancellation of a suspended account to prevent access restoration', () => { const f = fixture('cancel'); f.state.status = 'paused'; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects repeat cancellation', () => { const f = fixture('cancel'); f.state.status = 'cancelled'; f.state.cancelledAt = 999; f.state.renewalEnabled = false; expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects reactivation after expiry', () => { const f = fixture('reactivate', 2000); f.state.status = 'paused'; approve(f, 'reactivate'); expect(f.decide).toThrow(CatalogValidationError); });
  it('rejects reactivation with unresolved failure', () => { const f = fixture('reactivate'); f.state.status = 'paused'; f.state.paymentFailedAt = 999; approve(f, 'reactivate'); expect(f.decide).toThrow(CatalogValidationError); });
});
