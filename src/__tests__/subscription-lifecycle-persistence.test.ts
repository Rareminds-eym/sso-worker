import { describe, expect, it, vi } from 'vitest';
import { commitSubscriptionLifecycle, readSubscriptionLifecycle, readSubscriptionLifecyclePayment, readSubscriptionLifecycleReplay } from '../lib/subscriptions/lifecycle-persistence';
import { decideSubscriptionLifecycle, type LifecycleContext, type LifecyclePolicy, type LifecycleQuote, type LifecycleSettlement, type LifecycleState } from '../lib/subscriptions/lifecycle';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const iso = (time: number) => new Date(time).toISOString();
function fixture(operation: 'cancel' | 'upgrade' | 'payment_failed' | 'suspend' = 'cancel') {
  const subject = { kind: 'organization' as const, id: id(2) };
  const state: LifecycleState = { id: id(1), subject, planId: id(3), revisionId: id(4), productId: id(5), version: 2, status: 'active',
    periodStartsAt: 500, periodEndsAt: 2000, trialEndsAt: null, renewalEnabled: true, cancelledAt: null, paymentFailedAt: null, scheduledChange: null };
  const policy: LifecyclePolicy = { id: id(6), version: 1, productId: state.productId, graceDurationMs: 200, graceAccess: 'restricted', expiredAccess: 'read_only', cancellationAccess: 'until_period_end', immediateDowngradeAllowed: false,
    paymentFailureRestrictedMs: 50, paymentFailureAfterAccess: 'suspended', paymentRetryOffsetsMs: [25, 50], suspensionApprovalRequired: true, reactivationApprovalRequired: true };
  const target = { planId: id(7), revisionId: id(8), productId: state.productId };
  const quote: LifecycleQuote = { ...target, id: id(9), subscriptionId: state.id, subject, stateVersion: state.version, operation: 'upgrade', amountMinor: 2500, currency: 'TST', periodStartsAt: 500, periodEndsAt: 2000, validUntil: 1100 };
  const settlement: LifecycleSettlement = { id: id(10), quoteId: quote.id, subscriptionId: state.id, subject, stateVersion: state.version, revisionId: quote.revisionId, amountMinor: quote.amountMinor, currency: quote.currency, operation: quote.operation, kind: 'verified_payment', recordedAt: 950, validUntil: null };
  const context: LifecycleContext = { now: 1000, actorId: id(11), subject, allowedOperations: new Set([operation]), quotes: new Map([[quote.id, quote]]), settlements: new Map([[settlement.id, settlement]]), approvals: new Map(),
    publishedRevisions: new Map([[state.revisionId, state], [target.revisionId, target]]), revisionChanges: [{ fromRevisionId: state.revisionId, toRevisionId: target.revisionId, operation: 'upgrade' }] };
  const request = { operation, subscriptionId: state.id, subject, expectedVersion: state.version, expectedRevisionId: state.revisionId, reason: 'Synthetic authorized request', ...(operation === 'upgrade' ? { quoteId: quote.id, settlementId: settlement.id } : {}) };
  const row: Record<string, unknown> = { id: state.id, user_id: id(12), organization_id: subject.id, is_organization_subscription:true, product_id:state.productId, metadata:{subscription_execution:{audience:'synthetic',subscriptionEndsAt:4000}},plan_id: state.planId, plan_revision_id: state.revisionId, status: state.status, auto_renew: state.renewalEnabled,
    subscription_start_date: iso(state.periodStartsAt), subscription_end_date: state.periodEndsAt === null ? null : iso(state.periodEndsAt), cancelled_at: null, lifecycle_state: structuredClone(state), lifecycle_policy: structuredClone(policy), lifecycle_activated_at: iso(500) };
  const pub = (planId: string, revisionId: string) => ({ plan_id: planId, revision_id: revisionId, canonical_plan: { id: planId, code: `pln_${planId.replaceAll('-', '')}`, productId: state.productId, audiences: ['synthetic'], configuration: {
    subscription_authoring: { schemaVersion: 1, currencies: [{ code: quote.currency, minorUnit: 2 }] }, subscription_lifecycle: structuredClone(policy), subscription_revision_changes: structuredClone(context.revisionChanges),
  } } });
  const publications = [pub(state.planId, state.revisionId), pub(target.planId, target.revisionId)];
  const tx: Record<string, unknown> = { id: settlement.id, subscription_id: state.id, user_id: row.user_id, organization_id: subject.id,product_id:state.productId,status: 'completed', transaction_type: 'upgrade', amount: '25.00', currency: quote.currency,
    metadata: { subscription_lifecycle: { productId: state.productId, quote: structuredClone(quote), settlement: structuredClone(settlement), currencyMinorUnit: 2 } }, updated_at: iso(settlement.recordedAt) };
  const stored: Record<string, unknown>[] = [];
  const query = vi.fn(async (path: string): Promise<unknown[]> => {
    if (path.startsWith('subscription_lifecycle_operations?')) return structuredClone(stored);
    if (path.startsWith('subscriptions?')) return [structuredClone(row)];
    if (path.startsWith('subscription_plan_publication_events?')) return structuredClone(publications.filter(value => path.includes(`plan_id=eq.${value.plan_id}`) && path.includes(`revision_id=eq.${value.revision_id}`)));
    if (path.startsWith('transactions?')) return [structuredClone(tx)];
    throw new Error('Unexpected isolated query');
  });
  const rpc = vi.fn(async (_fn: string, args?: Record<string, unknown>): Promise<unknown> => {
    const identity = args!.p_identity as { operationId: string };
    const receipt = { operationId: identity.operationId, decision: structuredClone(args!.p_decision), committedAt: iso(1001) };
    stored.push({ identity: structuredClone(identity), receipt });
    return structuredClone(receipt);
  });
  // Generic casts are confined to this isolated fake transport, never the production validation boundary.
  const database = { query: async <T>(path: string) => await query(path) as T[], queryOne: async <T>() => null as T | null,
    rpc: async <T>(fn: string, args?: Record<string, unknown>) => await rpc(fn, args) as T };
  const commit = () => commitSubscriptionLifecycle(database, id(20), state, request, policy, context);
  return { state, policy, target, quote, settlement, context, request, row, tx, publications, stored, query, rpc, database, commit };
}

describe('subscription lifecycle persistence boundary (isolated transport, no SQL execution)', () => {
  function delayed() {
    const f=fixture('upgrade');f.state.periodEndsAt=20000;f.quote.periodEndsAt=20000;f.quote.validUntil=11000;f.settlement.recordedAt=4000;f.context.now=12000;
    f.row.lifecycle_state=structuredClone(f.state);f.row.subscription_end_date=iso(20000);f.row.metadata={subscription_execution:{audience:'synthetic',subscriptionEndsAt:40000}};
    f.tx.metadata={subscription_lifecycle:{productId:f.state.productId,quote:structuredClone(f.quote),settlement:structuredClone(f.settlement),currencyMinorUnit:2}};f.tx.updated_at=iso(4000);
    const captured:Record<string,unknown>={event_id:'a'.repeat(64),quote_id:f.quote.id,provider_payment_id:'pay_synthetic',provider_order_id:'order_synthetic',captured_at_ms:4000,payment_created_at_ms:3000,amount_minor:2500,currency:'TST'};
    const commercial:Record<string,unknown>={id:f.quote.id,actorId:f.context.actorId,subscriptionId:f.state.id,productId:f.state.productId,subject:f.state.subject,audience:'synthetic',stateVersion:f.state.version,expectedRevisionId:f.state.revisionId,
      planId:f.quote.planId,revisionId:f.quote.revisionId,purpose:'upgrade',referenceId:null,priceId:id(40),amountMinor:2500,currency:'TST',minorUnit:2,periodStartsAt:f.quote.periodStartsAt,periodEndsAt:20000,createdAt:3000,validUntil:11000};
    const paid:Record<string,unknown>={id:f.settlement.id,quote_id:f.quote.id,subscription_id:f.state.id,product_id:f.state.productId,subject:f.state.subject,purpose:'upgrade',amount_minor:2500,currency:'TST',provider_payment_id:'pay_synthetic',settled_at:iso(4000)};
    const original=f.query.getMockImplementation()!;
    f.query.mockImplementation(async path=>{
      if(path.startsWith('subscription_commerce_captures?'))return [structuredClone(captured)];
      if(path.startsWith('subscription_commerce_quotes?'))return [{quote:structuredClone(commercial),provider_order_id:'order_synthetic'}];
      if(path.startsWith('subscription_commerce_settlements?'))return [structuredClone(paid)];
      return original(path);
    });
    f.rpc.mockImplementation(async(_fn,args)=>{const identity=args!.p_identity;const receipt={operationId:id(20),decision:structuredClone(args!.p_decision),committedAt:iso(12001)};f.stored.push({identity:structuredClone(identity),receipt});return structuredClone(receipt);});
    return {...f,captured,commercial,paid};
  }
  it('loads timely capture independently, joins it without changing commercial schemas, and preserves current-time decision replay',async()=>{
    const f=delayed();const verified=await readSubscriptionLifecyclePayment(f.database,f.settlement.id,f.quote.id,f.state,f.context.now);
    expect(verified.capture).toMatchObject({actorId:f.context.actorId,capturedAt:4000,quoteCreatedAt:3000,settlementId:f.settlement.id});
    f.context.captures=new Map([[f.settlement.id,verified.capture!]]);
    const result=await f.commit();expect(result.decision.audit.at).toBe(12000);
    const identity=(f.rpc.mock.calls[0][1]!.p_identity as Record<string,unknown>);expect(identity.capture).toEqual(verified.capture);
    expect(identity.quote).toEqual(f.quote);expect(identity.settlement).toEqual(f.settlement);
    f.context.now=30000;expect(await f.commit()).toEqual(result);
    expect(await readSubscriptionLifecycleReplay(f.database,id(20),f.request,f.context.actorId,f.state.subject,f.state.productId,new Set(['upgrade']))).toEqual(result);
    expect(f.rpc).toHaveBeenCalledTimes(1);
  });
  it.each(['event','foreign_payment','late','product','money','version','issuer','quote','missing'] as const)('rejects missing/foreign delayed payment owner %s before mutation',async field=>{
    const f=delayed();
    if(field==='event')f.captured.event_id='invalid';
    if(field==='foreign_payment')f.captured.provider_payment_id='pay_foreign';
    if(field==='late'){f.captured.captured_at_ms=11000;f.paid.settled_at=iso(11000);f.settlement.recordedAt=11000;(f.tx.metadata as {subscription_lifecycle:{settlement:LifecycleSettlement}}).subscription_lifecycle.settlement.recordedAt=11000;f.tx.updated_at=iso(11000);}
    if(field==='product')f.paid.product_id=id(90);
    if(field==='money')f.captured.amount_minor=2501;
    if(field==='version')f.commercial.stateVersion=9;
    if(field==='issuer')f.commercial.actorId=id(90);
    if(field==='quote')f.captured.quote_id=id(90);
    if(field==='missing')f.query.mockImplementation(async()=>[]);
    if(field==='issuer'){
      const verified=await readSubscriptionLifecyclePayment(f.database,f.settlement.id,f.quote.id,f.state,f.context.now);f.context.captures=new Map([[f.settlement.id,verified.capture!]]);
      await expect(f.commit()).rejects.toThrow('capture');
    }else await expect(readSubscriptionLifecyclePayment(f.database,f.settlement.id,f.quote.id,f.state,f.context.now)).rejects.toThrow();
    expect(f.rpc).not.toHaveBeenCalled();
  });
  function retain(f: ReturnType<typeof fixture>, downgradedAt: number | null = 800) {
    Object.assign(f.policy, { graceAccess: 'read_only', expiredAccess: 'read_only', readOnlyDurationMs: 900 });
    f.state.downgradedAt = downgradedAt;
    f.row.lifecycle_state = structuredClone(f.state); f.row.lifecycle_policy = structuredClone(f.policy);
    f.publications.forEach(p => { p.canonical_plan.configuration.subscription_lifecycle = structuredClone(f.policy); });
    return f;
  }
  it.each([null, 800])('reads and retains an explicit downgrade marker %s', async downgradedAt => {
    const f = retain(fixture(), downgradedAt);
    const result = await readSubscriptionLifecycle(f.database, f.state.id, f.state.productId, f.state.subject);
    expect(result.state.downgradedAt).toBe(downgradedAt); expect(result.policy).toEqual(f.policy);
    expect(f.rpc).not.toHaveBeenCalled();
  });
  it('rejects a downgrade timestamp before original activation', async () => {
    const f = retain(fixture(), 499);
    await expect(readSubscriptionLifecycle(f.database, f.state.id, f.state.productId, f.state.subject)).rejects.toThrow('downgrade precedes activation');
  });
  it('preserves the exact downgrade marker in commit and authenticated replay', async () => {
    const f = retain(fixture()); const original = await f.commit();
    expect(original.decision.next.downgradedAt).toBe(800);
    f.row.lifecycle_state = { ...f.state, version: 99 }; f.context.now = 10000;
    expect(await f.commit()).toEqual(original);
    expect(await readSubscriptionLifecycleReplay(f.database, id(20), f.request, f.context.actorId, f.state.subject, f.state.productId, new Set(['cancel']))).toEqual(original);
    expect(f.rpc).toHaveBeenCalledTimes(1);
  });
  it('rejects a replay receipt that resets the downgrade clock', async () => {
    const f = retain(fixture()); await f.commit();
    (f.stored[0].receipt as { decision: { next: LifecycleState } }).decision.next.downgradedAt = 900;
    await expect(f.commit()).rejects.toThrow('receipt decision differs');
    expect(f.rpc).toHaveBeenCalledTimes(1);
  });
  it('reads explicit existing binding and retained policy without writing', async () => {
    const f = fixture();
    await expect(readSubscriptionLifecycle(f.database, f.state.id, f.state.productId, f.state.subject)).resolves.toEqual({ state: f.state, policy: f.policy, activatedAt: 500 });
    expect(f.rpc).not.toHaveBeenCalled();
  });
  it('commits existing decision and exact full identity in one RPC', async () => {
    const f = fixture(); const expected = decideSubscriptionLifecycle(f.state, f.request, f.policy, f.context);
    const result = await f.commit();
    expect(result).toEqual({ operationId: id(20), decision: expected, committedAt: iso(1001) });
    expect(f.rpc).toHaveBeenCalledExactlyOnceWith('commit_subscription_lifecycle', expect.objectContaining({ p_decision: expected, p_identity: expect.objectContaining({ state: f.state, request: f.request, policy: f.policy, actorId: f.context.actorId, subject: f.state.subject }) }));
  });
  it('verifies completed transaction against quote, currency and owner metadata', async () => {
    const f = fixture('upgrade');
    expect((await f.commit()).decision.next.revisionId).toBe(f.target.revisionId);
    expect(f.query.mock.calls.some(([path]) => path.startsWith('transactions?'))).toBe(true);
  });
  it('compares replay before reading newer state and returns exact original receipt after quote expiry', async () => {
    const f = fixture('upgrade'); const original = await f.commit();
    f.context.now = 10000; f.row.lifecycle_state = { ...f.state, version: 9 }; f.query.mockClear();
    expect(await f.commit()).toEqual(original);
    expect(f.rpc).toHaveBeenCalledTimes(1);
    expect(f.query.mock.calls).toHaveLength(1);
  });
  it('accepts JSON object key order changes without changing replay identity', async () => {
    const f = fixture(); const original = await f.commit();
    f.row.lifecycle_state = null;
    const reordered = Object.fromEntries(Object.entries(f.request).reverse());
    expect(await commitSubscriptionLifecycle(f.database, id(20), f.state, reordered, f.policy, f.context)).toEqual(original);
  });
  it('loads original replay before expired payment lookup or newer state', async () => {
    const f = fixture('upgrade'); const original = await f.commit();
    f.row.lifecycle_state = { ...f.state, version: 9 }; f.tx.metadata = {}; f.query.mockClear();
    expect(await readSubscriptionLifecycleReplay(f.database,id(20),f.request,f.context.actorId,f.state.subject,f.state.productId,new Set(['upgrade']))).toEqual(original);
    expect(f.query.mock.calls.some(([path]) => path.startsWith('transactions?') || path.startsWith('subscriptions?'))).toBe(false);
  });
  it('distinguishes a new operation from an existing replay', async () => {
    const f = fixture(); expect(await readSubscriptionLifecycleReplay(f.database,id(20),f.request,f.context.actorId,f.state.subject,f.state.productId,new Set(['cancel']))).toBeNull();
  });
  it.each(['actor','subject','product','request','permission','direction','receipt'] as const)('rejects authenticated replay %s mismatch', async field => {
    const f = fixture('upgrade'); await f.commit();
    let actor=f.context.actorId,owner:LifecycleState['subject']=f.state.subject,product=f.state.productId;
    const permissions = new Set<LifecycleContext['allowedOperations'] extends ReadonlySet<infer T> ? T : never>(['upgrade']);
    if (field === 'actor') actor=id(30);
    if (field === 'subject') owner={kind:'user',id:owner.id};
    if (field === 'product') product=id(30);
    if (field === 'request') f.request.reason='Altered replay';
    if (field === 'permission') permissions.clear();
    if (field === 'direction') f.publications[0].canonical_plan.configuration.subscription_revision_changes=[];
    if (field === 'receipt') (f.stored[0].receipt as {decision:{next:{version:number}}}).decision.next.version++;
    await expect(readSubscriptionLifecycleReplay(f.database,id(20),f.request,actor,owner,product,permissions)).rejects.toThrow();
  });
  it('reads valid expired state after a nonzero grace period', async () => {
    const f=fixture(); f.row.status='expired'; f.row.lifecycle_state={...f.state,status:'expired'};
    expect((await readSubscriptionLifecycle(f.database,f.state.id,f.state.productId,f.state.subject)).state.status).toBe('expired');
  });
  it('loads genuine payment evidence independently for server context construction', async () => {
    const f=fixture('upgrade'); expect(await readSubscriptionLifecyclePayment(f.database,f.settlement.id,f.quote.id,f.state,f.context.now)).toEqual({quote:f.quote,settlement:f.settlement});
  });
  it('rejects unknown payment envelope fields', async () => {
    const f=fixture('upgrade'); Object.assign((f.tx.metadata as {subscription_lifecycle:unknown}).subscription_lifecycle!,{approved:true});
    await expect(readSubscriptionLifecyclePayment(f.database,f.settlement.id,f.quote.id,f.state,f.context.now)).rejects.toThrow('unsupported field');
  });
  it.each(['actor','request','state','policy','subject','settlement'] as const)('rejects altered replay %s', async field => {
    const f = fixture('upgrade'); await f.commit();
    if (field === 'actor') f.context.actorId = id(30);
    if (field === 'request') f.request.reason = 'Altered reason';
    if (field === 'state') f.state.version++;
    if (field === 'policy') f.policy.version++;
    if (field === 'subject') f.context.subject = { ...f.state.subject, id: id(30) };
    if (field === 'settlement') f.settlement.amountMinor++;
    await expect(f.commit()).rejects.toThrow('replay conflicts'); expect(f.rpc).toHaveBeenCalledTimes(1);
  });
  it('still requires current server-side permission before replay disclosure', async () => {
    const f = fixture(); await f.commit(); f.context.allowedOperations = new Set();
    await expect(f.commit()).rejects.toThrow('not authorized');
  });
  it('accepts a concurrent exact replay committed at its original decision instant', async () => {
    const f=fixture();
    f.rpc.mockImplementation(async()=>({operationId:id(20),decision:decideSubscriptionLifecycle(f.state,f.request,f.policy,{...f.context,now:999}),committedAt:iso(1001)}));
    expect((await f.commit()).decision.audit.at).toBe(999);
  });
  it.each(['state','policy','activated'] as const)('rejects missing explicit initialization %s', async key => {
    const f = fixture(); f.row[key === 'state' ? 'lifecycle_state' : key === 'policy' ? 'lifecycle_policy' : 'lifecycle_activated_at'] = null;
    await expect(f.commit()).rejects.toThrow('not initialized'); expect(f.rpc).not.toHaveBeenCalled();
  });
  const drifts: [string, (f: ReturnType<typeof fixture>) => void][] = [
    ['subject', f => { f.row.organization_id = id(30); }],
    ['subject kind', f => { f.row.organization_id = null; f.row.user_id = f.state.subject.id; }],
    ['organization flag', f=>{f.row.is_organization_subscription=false;}], ['subscription product', f=>{f.row.product_id=id(30);}],
    ['absent contract', f=>{f.row.metadata={};}], ['short contract',f=>{f.row.metadata={subscription_execution:{audience:'synthetic',subscriptionEndsAt:1999}};}],
    ['foreign audience',f=>{f.row.metadata={subscription_execution:{audience:'foreign',subscriptionEndsAt:4000}};}],
    ['plan', f => { f.row.plan_id = id(30); }], ['revision', f => { f.row.plan_revision_id = id(30); }],
    ['status', f => { f.row.status = 'expired'; }], ['renewal', f => { f.row.auto_renew = false; }],
    ['period', f => { f.row.subscription_end_date = iso(2001); }], ['event', f => { f.row.cancelled_at = iso(900); }],
    ['stored version', f => { f.row.lifecycle_state = { ...f.state, version: 1 }; }],
    ['stored policy', f => { f.row.lifecycle_policy = { ...f.policy, version: 2 }; }],
    ['publication', f => { f.publications.length = 0; }],
    ['publication product', f => { f.publications[0].canonical_plan.productId = id(30); }],
    ['published policy', f => { f.publications[0].canonical_plan.configuration.subscription_lifecycle.version++; }],
  ];
  it.each(drifts)('rejects %s drift before commit', async (_, mutate) => {
    const f = fixture(); mutate(f); await expect(f.commit()).rejects.toThrow(); expect(f.rpc).not.toHaveBeenCalled();
  });
  it('rejects caller-supplied product mismatch on read', async () => {
    const f = fixture(); await expect(readSubscriptionLifecycle(f.database, f.state.id, id(30), f.state.subject)).rejects.toThrow('product differs');
  });
  it('rejects stale request version before RPC', async () => {
    const f = fixture(); f.request.expectedVersion--; await expect(f.commit()).rejects.toThrow('stale'); expect(f.rpc).not.toHaveBeenCalled();
  });
  const paymentDrifts: [string, (f: ReturnType<typeof fixture>) => void][] = [
    ['status', f => { f.tx.status = 'pending'; }], ['transaction identity', f => { f.tx.id = id(30); }],
    ['subscription', f => { f.tx.subscription_id = id(30); }], ['organization', f => { f.tx.organization_id = id(30); }],
    ['product',f=>{f.tx.product_id=id(30);}],['payer',f=>{f.tx.user_id=id(30);}],
    ['operation', f => { f.tx.transaction_type = 'addon'; }], ['amount', f => { f.tx.amount = '24.99'; }],
    ['fractional minor units', f => { f.tx.amount = '25.001'; }], ['currency', f => { f.tx.currency = 'BAD'; }],
    ['recorded instant', f => { f.tx.updated_at = iso(951); }], ['absent owner metadata', f => { f.tx.metadata = {}; }],
    ['forged ready flag', f => { f.tx.metadata = { ready: true }; }],
    ['different target publication', f => { f.publications[1].canonical_plan.productId = id(30); }],
    ['different configured currency', f => { f.publications[1].canonical_plan.configuration.subscription_authoring.currencies[0].code = 'BAD'; }],
    ['different minor unit', f => { f.publications[1].canonical_plan.configuration.subscription_authoring.currencies[0].minorUnit = 3; }],
  ];
  it.each(paymentDrifts)('rejects payment %s evidence without a commit', async (_, mutate) => {
    const f = fixture('upgrade'); mutate(f); await expect(f.commit()).rejects.toThrow(); expect(f.rpc).not.toHaveBeenCalled();
  });
  it('rejects fabricated invoice despite an engine-valid context', async () => {
    const f = fixture('upgrade'); f.settlement.kind = 'approved_invoice'; f.settlement.validUntil = 1100;
    expect(decideSubscriptionLifecycle(f.state, f.request, f.policy, f.context).next.status).toBe('active');
    await expect(f.commit()).rejects.toThrow('invoice owner is unavailable'); expect(f.rpc).not.toHaveBeenCalled();
  });
  it('rejects fabricated manual approval despite an engine-valid context', async () => {
    const f = fixture('suspend'); const approval = { id: id(40), subscriptionId: f.state.id, subject: f.state.subject, stateVersion: f.state.version, operation: 'suspend' as const, actorId: f.context.actorId, validUntil: 1100 };
    Object.assign(f.request, { approvalId: approval.id }); f.context.approvals = new Map([[approval.id, approval]]);
    expect(decideSubscriptionLifecycle(f.state, f.request, f.policy, f.context).next.status).toBe('paused');
    await expect(f.commit()).rejects.toThrow('approval owner is unavailable'); expect(f.rpc).not.toHaveBeenCalled();
  });
  it('uses explicit policy without inventing approval when approval is not required', async () => {
    const f = fixture('suspend'); f.policy.suspensionApprovalRequired = false;
    f.row.lifecycle_policy = structuredClone(f.policy); f.publications.forEach(p => { p.canonical_plan.configuration.subscription_lifecycle = structuredClone(f.policy); });
    expect((await f.commit()).decision.next.status).toBe('paused');
  });
  it('persists emitted retry instants rather than delivering effects in this boundary', async () => {
    const f = fixture('payment_failed'); expect((await f.commit()).decision.retryAt).toEqual([1025, 1050]); expect(f.rpc).toHaveBeenCalledTimes(1);
  });
  it('surfaces an uncertain commit once without automatic retry or reread', async () => {
    const f = fixture(); f.rpc.mockRejectedValue(new Error('Isolated timeout after possible commit'));
    await expect(f.commit()).rejects.toThrow('possible commit'); expect(f.rpc).toHaveBeenCalledTimes(1);
    expect(f.query.mock.calls.filter(([path]) => path.startsWith('subscription_lifecycle_operations?'))).toHaveLength(1);
  });
  it.each(['operation','decision','timestamp'] as const)('rejects returned receipt %s tampering', async key => {
    const f = fixture();
    f.rpc.mockImplementation(async (_fn, args) => {
      const decision = structuredClone(args!.p_decision) as ReturnType<typeof decideSubscriptionLifecycle>;
      if (key === 'decision') decision.next.version++;
      return { operationId: key === 'operation' ? id(30) : id(20), decision, committedAt: key === 'timestamp' ? iso(999) : iso(1001) };
    });
    await expect(f.commit()).rejects.toThrow(); expect(f.rpc).toHaveBeenCalledTimes(1);
  });
  it('rejects duplicate stored operation responses', async () => {
    const f = fixture(); await f.commit(); f.stored.push(structuredClone(f.stored[0])); await expect(f.commit()).rejects.toThrow('at most once');
  });
});
