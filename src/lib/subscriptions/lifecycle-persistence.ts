import { subscriptionEntryEnd } from './entry-validity';
import type { DbClient } from '../db';
import { validatePlanAuthoringSnapshot } from './authoring-context';
import { assertLifecycleCapture, decideSubscriptionLifecycle, parseLifecycleCapture, publishedRevisionChanges, readSubscriptionLifecycleAccess, validateSubscriptionLifecyclePolicy, type LifecycleCapture, type LifecycleContext, type LifecycleDecision, type LifecycleOperation, type LifecyclePolicy, type LifecycleQuote, type LifecycleSettlement, type LifecycleState } from './lifecycle';
import { CatalogPersistenceError, validStagingTimestamp } from './repository';
import { array, choice, integer, invalid, record, text, uuid } from './validation';

type Database = Pick<DbClient, 'query' | 'queryOne' | 'rpc'>;
type Subject = LifecycleState['subject'];
export interface LifecycleCommitReceipt { operationId: string; decision: LifecycleDecision; committedAt: string }

/** JSON identity ignores object insertion order, preserves array order, and rejects non-JSON values. */
function stable(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${Array.from(value, stable).join(',')}]`;
  if (typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${stable(object[key])}`).join(',')}}`;
  }
  throw new CatalogPersistenceError('Lifecycle identity must contain exact JSON values');
}
function equal(left: unknown, right: unknown): boolean { return stable(left) === stable(right); }
function fail(reason: string): never { throw new CatalogPersistenceError(reason); }
function subject(value: unknown): Subject {
  const parsed = record(value, 'subject', ['kind', 'id']);
  if (parsed.kind !== 'user' && parsed.kind !== 'organization') invalid('subject.kind', 'unsupported subject');
  return { kind: parsed.kind, id: uuid(parsed.id, 'subject.id') };
}
function milliseconds(value: unknown): number {
  if (!validStagingTimestamp(value)) fail('Invalid lifecycle owner timestamp');
  return Date.parse(value);
}
function mirror(row: Record<string, unknown>, state: LifecycleState): void {
  if (row.id !== state.id || row.plan_id !== state.planId || row.plan_revision_id !== state.revisionId
    || row.product_id !== state.productId
    || row.status !== state.status || row.auto_renew !== state.renewalEnabled
    || milliseconds(row.subscription_start_date) !== state.periodStartsAt || (row.subscription_end_date === null ? null : milliseconds(row.subscription_end_date)) !== state.periodEndsAt
    || (row.cancelled_at === null ? null : milliseconds(row.cancelled_at)) !== state.cancelledAt
    || (row.is_organization_subscription === true ? state.subject.kind !== 'organization' || row.organization_id !== state.subject.id : state.subject.kind !== 'user' || row.user_id !== state.subject.id)) {
    fail('Lifecycle binding differs from existing subscription');
  }
}
async function publication(database: Database, state: Pick<LifecycleState, 'planId' | 'revisionId' | 'productId'>) {
  const rows = await database.query<Record<string, unknown>>('subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan'
    + `&plan_id=eq.${uuid(state.planId, 'planId')}&revision_id=eq.${uuid(state.revisionId, 'revisionId')}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length !== 1) fail('Retained publication must resolve exactly once');
  const event = record(rows[0], 'publication', ['plan_id', 'revision_id', 'canonical_plan']);
  const canonical = record(event.canonical_plan, 'publication.canonical', ['id', 'code', 'productId', 'audiences', 'configuration']);
  if (event.plan_id !== state.planId || event.revision_id !== state.revisionId || canonical.id !== state.planId || canonical.productId !== state.productId) fail('Publication binding differs');
  return validatePlanAuthoringSnapshot({ id: canonical.id, plan_code: canonical.code, product_id: canonical.productId,
    applicable_entities: canonical.audiences, entity_config: canonical.configuration }, state.planId);
}

/** Read only explicitly initialized existing rows; a legacy row is never implicitly activated. */
export async function readSubscriptionLifecycle(database: Database, subscriptionId: string, productId: string, owner: Subject): Promise<{ state: LifecycleState; policy: LifecyclePolicy; activatedAt: number }> {
  const id = uuid(subscriptionId, 'subscriptionId'), product = uuid(productId, 'productId'), expectedSubject = subject(owner);
  const rows = await database.query<Record<string, unknown>>('subscriptions?select=id,user_id,organization_id,is_organization_subscription,product_id,metadata,plan_id,plan_revision_id,status,auto_renew,subscription_start_date,subscription_end_date,cancelled_at,lifecycle_state,lifecycle_policy,lifecycle_activated_at'
    + `&id=eq.${id}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length !== 1) fail('Subscription must resolve exactly once');
  const row = rows[0];
  if (!row || row.lifecycle_state === null || row.lifecycle_policy === null || row.lifecycle_activated_at === null) fail('Subscription lifecycle is not initialized');
  const activatedAt = milliseconds(row.lifecycle_activated_at);
  const now = Date.now();
  if (activatedAt > now) fail('Lifecycle activation is in the future');
  const { state, policy } = readSubscriptionLifecycleAccess(row.lifecycle_state, row.lifecycle_policy, now);
  if (activatedAt > state.periodStartsAt) fail('Lifecycle activation exceeds period anchor');
  if (state.downgradedAt !== undefined && state.downgradedAt !== null && state.downgradedAt < activatedAt) fail('Lifecycle downgrade precedes activation anchor');
  if (state.id !== id || state.productId !== product || !equal(state.subject, expectedSubject)) fail('Lifecycle subject or product differs');
  mirror(row, state);
  const published = await publication(database, state);
  if (!equal(published.configuration.subscription_lifecycle, policy)) fail('Lifecycle policy differs from retained publication');
  const metadata = row.metadata !== null && typeof row.metadata === 'object' ? row.metadata as Record<string, unknown> : {};
  const execution = record(metadata.subscription_execution,'subscription.execution',['audience','subscriptionEndsAt']);
  if (!published.context.audiences.includes(text(execution.audience,'subscription.audience')) || (state.periodEndsAt === null ? execution.subscriptionEndsAt !== null || subscriptionEntryEnd(published.configuration.subscription_entry, activatedAt) !== null : execution.subscriptionEndsAt === null || integer(execution.subscriptionEndsAt,'subscription.endsAt',1) < state.periodEndsAt)) fail('Subscription commercial binding differs');
  return { state, policy, activatedAt };
}

function commandIdentity(operationId: string, state: unknown, request: unknown, policy: unknown, context: LifecycleContext) {
  const input = record(request, 'request', ['operation','subscriptionId','subject','expectedVersion','expectedRevisionId','reason','targetRevisionId','timing','quoteId','settlementId','approvalId']);
  const operation = input.operation;
  if (typeof operation !== 'string' || !context.allowedOperations.has(operation as LifecycleDecision['audit']['operation'])) invalid('request.operation', 'operation is not authorized in owner context');
  const selected = (map: ReadonlyMap<string, unknown>, value: unknown) => value === undefined ? null : map.get(uuid(value, 'evidence.id')) ?? null;
  const capture=input.settlementId===undefined?undefined:context.captures?.get(uuid(input.settlementId,'capture.settlementId'));
  return { operationId: uuid(operationId, 'operationId'), state, request, policy, actorId: uuid(context.actorId, 'actorId'), subject: subject(context.subject),
    quote: selected(context.quotes, input.quoteId), settlement: selected(context.settlements, input.settlementId), approval: selected(context.approvals, input.approvalId), revisionChanges: context.revisionChanges,
    ...(capture===undefined?{}:{capture:parseLifecycleCapture(capture)}) };
}
function receipt(value: unknown, identity: ReturnType<typeof commandIdentity>, context: LifecycleContext): LifecycleCommitReceipt {
  const row = record(value, 'receipt', ['operationId','decision','committedAt']);
  if (uuid(row.operationId, 'receipt.operationId') !== identity.operationId || !validStagingTimestamp(row.committedAt)) fail('Lifecycle receipt identity differs');
  const decision = record(row.decision, 'receipt.decision', ['expectedVersion','expectedRevisionId','next','access','retryAt','audit']);
  const audit = record(decision.audit, 'receipt.audit', ['operation','actorId','reason','at','policyId','policyVersion']);
  // Reconstruct at the original decision instant so exact replay remains readable after expiry/newer state.
  const expected = decideSubscriptionLifecycle(identity.state, identity.request, identity.policy, { ...context, now: integer(audit.at, 'receipt.audit.at') });
  if (!equal(row.decision, expected) || milliseconds(row.committedAt) < expected.audit.at || milliseconds(row.committedAt) > Date.now()) fail('Lifecycle receipt decision differs');
  return { operationId: identity.operationId, decision: expected, committedAt: row.committedAt };
}
function amountMinor(value: unknown, minorUnit: number): bigint {
  const decimal = typeof value === 'number' || typeof value === 'string' ? String(value) : '';
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/.exec(decimal);
  const fraction = match?.[2]?.replace(/0+$/, '') ?? '';
  // The public engine represents minor amounts as safe integers. More precision cannot produce
  // a nonzero exact amount in that representation for the existing numeric(10,2) owner column.
  if (!match || minorUnit > String(Number.MAX_SAFE_INTEGER).length || fraction.length > minorUnit) fail('Transaction amount is not exact configured minor units');
  return BigInt(match[1]) * 10n ** BigInt(minorUnit) + BigInt(fraction.padEnd(minorUnit, '0') || '0');
}

/** Load actual completed payment evidence; metadata is owner-written linkage, never HTTP authority.
 * A missing quote/settlement owner envelope rejects the paid operation. This does not create a quote.
 */
function paymentEvidence(quoteValue: unknown, settlementValue: unknown): { quote: LifecycleQuote; settlement: LifecycleSettlement } {
  const q = record(quoteValue, 'quote', ['id','planId','revisionId','productId','subscriptionId','subject','stateVersion','operation','amountMinor','currency','periodStartsAt','periodEndsAt','validUntil']);
  const e = record(settlementValue, 'settlement', ['id','quoteId','subscriptionId','subject','stateVersion','revisionId','amountMinor','currency','operation','kind','recordedAt','validUntil']);
  const quote: LifecycleQuote = { id: uuid(q.id,'quote.id'), planId: uuid(q.planId,'quote.planId'), revisionId: uuid(q.revisionId,'quote.revisionId'), productId: uuid(q.productId,'quote.productId'),
    subscriptionId: uuid(q.subscriptionId,'quote.subscriptionId'), subject: subject(q.subject), stateVersion: integer(q.stateVersion,'quote.stateVersion',1),
    operation: choice(q.operation,'quote.operation',['upgrade','renew']), amountMinor: integer(q.amountMinor,'quote.amountMinor'), currency: text(q.currency,'quote.currency'),
    periodStartsAt: integer(q.periodStartsAt,'quote.periodStartsAt'), periodEndsAt: integer(q.periodEndsAt,'quote.periodEndsAt'), validUntil: integer(q.validUntil,'quote.validUntil') };
  const settlement: LifecycleSettlement = { id: uuid(e.id,'settlement.id'), quoteId: uuid(e.quoteId,'settlement.quoteId'), subscriptionId: uuid(e.subscriptionId,'settlement.subscriptionId'), subject: subject(e.subject),
    stateVersion: integer(e.stateVersion,'settlement.stateVersion',1), revisionId: uuid(e.revisionId,'settlement.revisionId'), amountMinor: integer(e.amountMinor,'settlement.amountMinor'), currency: text(e.currency,'settlement.currency'),
    operation: choice(e.operation,'settlement.operation',['upgrade','renew']), kind: choice(e.kind,'settlement.kind',['verified_payment']), recordedAt: integer(e.recordedAt,'settlement.recordedAt'),
    validUntil: e.validUntil === null ? null : integer(e.validUntil,'settlement.validUntil') };
  return {quote,settlement};
}

export async function readSubscriptionLifecyclePayment(database: Database, settlementId: string, quoteId: string, state: LifecycleState, nowValue: number): Promise<{ quote: LifecycleQuote; settlement: LifecycleSettlement; capture?:LifecycleCapture }> {
  const now = integer(nowValue, 'now'), transactionId = uuid(settlementId, 'settlementId'), expectedQuote = uuid(quoteId, 'quoteId');
  const transactions = await database.query<Record<string, unknown>>(`transactions?select=id,subscription_id,user_id,organization_id,product_id,status,transaction_type,amount,currency,metadata,updated_at&id=eq.${transactionId}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(transactions) || transactions.length !== 1) fail('Completed transaction must resolve exactly once');
  const tx = transactions[0];
  const metadata = tx.metadata !== null && typeof tx.metadata === 'object' ? tx.metadata as Record<string, unknown> : {};
  const envelope = record(metadata.subscription_lifecycle, 'transaction.lifecycle', ['productId','quote','settlement','currencyMinorUnit']);
  const {quote,settlement} = paymentEvidence(envelope.quote,envelope.settlement);
  const target = await publication(database, quote);
  const subscribers = await database.query<Record<string, unknown>>(`subscriptions?select=id,user_id,organization_id,is_organization_subscription,product_id&id=eq.${uuid(state.id,'state.id')}&limit=2`,undefined,'json-array');
  if (!Array.isArray(subscribers) || subscribers.length !== 1) fail('Transaction subscription owner must resolve exactly once');
  const subscriber = subscribers[0];
  const currency = target.context.currencies.find(value => value.code === quote.currency);
  if (!currency) fail('Settlement currency policy is unavailable');
  if (quote.id !== expectedQuote || quote.subscriptionId !== state.id || settlement.subscriptionId !== state.id || quote.productId !== state.productId
    || quote.stateVersion !== state.version || settlement.stateVersion !== state.version || !equal(quote.subject,state.subject) || !equal(settlement.subject,state.subject)
    || settlement.quoteId !== quote.id || settlement.revisionId !== quote.revisionId || settlement.amountMinor !== quote.amountMinor || settlement.currency !== quote.currency || settlement.operation !== quote.operation
    || quote.periodStartsAt > now || quote.periodEndsAt <= now || quote.periodStartsAt >= quote.periodEndsAt
    || settlement.recordedAt > now || settlement.recordedAt < state.periodStartsAt || (settlement.validUntil !== null && settlement.validUntil <= now)
    || tx.id !== transactionId || settlement.id !== transactionId || tx.subscription_id !== state.id || tx.status !== 'completed' || tx.product_id !== state.productId
    || subscriber.id !== state.id || subscriber.product_id !== state.productId || tx.user_id !== subscriber.user_id || tx.organization_id !== subscriber.organization_id
    || tx.transaction_type !== (quote.operation === 'upgrade' ? 'upgrade' : 'subscription') || tx.currency !== quote.currency
    || (subscriber.is_organization_subscription === true ? state.subject.kind !== 'organization' || tx.organization_id !== state.subject.id : state.subject.kind !== 'user' || tx.user_id !== state.subject.id)
    || amountMinor(tx.amount,currency.minorUnit) !== BigInt(quote.amountMinor) || milliseconds(tx.updated_at) !== settlement.recordedAt
    || !equal(envelope,{ productId: state.productId, quote, settlement, currencyMinorUnit: currency.minorUnit })) fail('Transaction lifecycle evidence differs');
  if(quote.validUntil>now)return {quote,settlement};
  const load=async(path:string)=>{
    const rows=await database.query<Record<string,unknown>>(path,undefined,'json-array');
    if(!Array.isArray(rows)||rows.length!==1)throw new CatalogPersistenceError('Exact retained capture owner required');
    return rows[0];
  };
  const captured=await load(`subscription_commerce_captures?select=event_id,quote_id,provider_payment_id,provider_order_id,captured_at_ms,payment_created_at_ms,amount_minor,currency&quote_id=eq.${quote.id}&limit=2`);
  const issued=await load(`subscription_commerce_quotes?select=quote,provider_order_id&id=eq.${quote.id}&limit=2`);
  const paid=await load(`subscription_commerce_settlements?select=id,quote_id,subscription_id,product_id,subject,purpose,amount_minor,currency,provider_payment_id,settled_at&id=eq.${settlement.id}&limit=2`);
  const commercial=record(issued.quote,'capture.commercialQuote',['id','actorId','subscriptionId','productId','subject','audience','stateVersion','expectedRevisionId','planId','revisionId','purpose','referenceId','priceId','amountMinor','currency','minorUnit','periodStartsAt','periodEndsAt','createdAt','validUntil']);
  for(const key of ['id','subscriptionId','productId','subject','stateVersion','planId','revisionId','amountMinor','currency','periodStartsAt','periodEndsAt','validUntil'] as const)if(!equal(commercial[key],quote[key]))fail('Captured quote commercial scope differs');
  if(commercial.purpose!==quote.operation||commercial.expectedRevisionId!==state.revisionId||captured.quote_id!==quote.id
    ||issued.provider_order_id!==captured.provider_order_id||paid.id!==settlement.id||paid.quote_id!==quote.id||paid.subscription_id!==state.id
    ||paid.product_id!==state.productId||!equal(paid.subject,state.subject)||paid.purpose!==quote.operation||Number(paid.amount_minor)!==quote.amountMinor
    ||paid.currency!==quote.currency||paid.provider_payment_id!==captured.provider_payment_id||milliseconds(paid.settled_at)!==settlement.recordedAt)fail('Retained capture settlement scope differs');
  const capture=parseLifecycleCapture({eventId:captured.event_id,actorId:commercial.actorId,quoteId:quote.id,settlementId:settlement.id,productId:state.productId,subscriptionId:state.id,
    subject:state.subject,stateVersion:quote.stateVersion,revisionId:quote.revisionId,amountMinor:Number(captured.amount_minor),currency:captured.currency,
    providerPaymentId:captured.provider_payment_id,providerOrderId:captured.provider_order_id,capturedAt:Number(captured.captured_at_ms),paymentCreatedAt:Number(captured.payment_created_at_ms),quoteCreatedAt:commercial.createdAt});
  assertLifecycleCapture(quote,settlement,capture.actorId,now,capture);
  return {quote,settlement,capture};
}

/** Authenticated replay read before current-state decisions or expiry-sensitive payment lookups.
 * Immutable operation identity supplies the original evidence, revalidated against retained publication.
 */
export async function readSubscriptionLifecycleReplay(database: Database, operationId: string, request: unknown, actorId: string, owner: Subject, productId: string, allowedOperations: ReadonlySet<LifecycleOperation>): Promise<LifecycleCommitReceipt | null> {
  const id = uuid(operationId,'operationId'), actor = uuid(actorId,'actorId'), expectedSubject = subject(owner), product = uuid(productId,'productId');
  const rows = await database.query<Record<string, unknown>>(`subscription_lifecycle_operations?select=identity,receipt&operation_id=eq.${id}&limit=2`,undefined,'json-array');
  if (!Array.isArray(rows) || rows.length > 1) fail('Lifecycle operation must resolve at most once');
  if (!rows.length) return null;
  const saved = record(rows[0].identity,'replay.identity',['operationId','state','request','policy','actorId','subject','quote','settlement','approval','revisionChanges','capture']);
  if (saved.operationId !== id || saved.actorId !== actor || !equal(saved.subject,expectedSubject) || !equal(saved.request,request) || saved.approval !== null) fail('Lifecycle replay conflicts with original identity');
  const rawReceipt = record(rows[0].receipt,'replay.receipt',['operationId','decision','committedAt']);
  const rawDecision = record(rawReceipt.decision,'replay.decision',['expectedVersion','expectedRevisionId','next','access','retryAt','audit']);
  const audit = record(rawDecision.audit,'replay.audit',['operation','actorId','reason','at','policyId','policyVersion']);
  const now = integer(audit.at,'replay.audit.at');
  const {state,policy} = readSubscriptionLifecycleAccess(saved.state,saved.policy,now);
  const rawNext=record(rawDecision.next,'replay.next',['id','subject','planId','revisionId','productId','version','status','periodStartsAt','periodEndsAt','trialEndsAt','renewalEnabled','cancelledAt','paymentFailedAt','scheduledChange','downgradedAt','validity']);
  const target=await publication(database,{planId:uuid(rawNext.planId,'replay.planId'),revisionId:uuid(rawNext.revisionId,'replay.revisionId'),productId:product});
  const targetPolicy=validateSubscriptionLifecyclePolicy(target.configuration.subscription_lifecycle);
  if(!equal(targetPolicy,policy)&&!(audit.operation==='upgrade'&&policy.billing==='not_applicable'&&targetPolicy.billing!=='not_applicable'))fail('Lifecycle replay target policy differs');
  const {state: next} = readSubscriptionLifecycleAccess(rawDecision.next,targetPolicy,now);
  if (state.productId !== product || !equal(state.subject,expectedSubject)) fail('Lifecycle replay product or subject differs');
  const current = await publication(database,state);
  const revisionChanges = array(saved.revisionChanges,'replay.revisionChanges').map(value => {
    const change = record(value,'replay.revisionChange',['fromRevisionId','toRevisionId','operation']);
    return { fromRevisionId: uuid(change.fromRevisionId,'replay.fromRevisionId'),toRevisionId: uuid(change.toRevisionId,'replay.toRevisionId'),operation: choice(change.operation,'replay.operation',['upgrade','downgrade']) };
  });
  const publishedChanges=publishedRevisionChanges(current.configuration,target.configuration),sourceChanges=publishedRevisionChanges(current.configuration);
  if (!equal(current.configuration.subscription_lifecycle,policy)
    ||revisionChanges.some(c=>!publishedChanges.some(p=>equal(c,p)))||sourceChanges.some(c=>!revisionChanges.some(p=>equal(c,p)))) fail('Lifecycle replay publication evidence differs');
  const revisions = [state,next,...(state.scheduledChange === null ? [] : [state.scheduledChange]),...(next.scheduledChange === null ? [] : [next.scheduledChange])];
  const publications = new Map<string, {planId:string;revisionId:string;productId:string}>();
  for (const candidate of revisions) {
    await publication(database,candidate);
    publications.set(candidate.revisionId,{planId:candidate.planId,revisionId:candidate.revisionId,productId:candidate.productId});
  }
  const payment = saved.quote === null && saved.settlement === null ? null : paymentEvidence(saved.quote,saved.settlement);
  const capture=saved.capture===undefined?undefined:parseLifecycleCapture(saved.capture);
  const context: LifecycleContext = {now,actorId:actor,subject:expectedSubject,allowedOperations,quotes:new Map(payment === null ? [] : [[payment.quote.id,payment.quote]]),settlements:new Map(payment === null ? [] : [[payment.settlement.id,payment.settlement]]),captures:new Map(capture===undefined?[]:[[capture.settlementId,capture]]),approvals:new Map(),publishedRevisions:publications,targetPolicies:new Map([[next.revisionId,targetPolicy]]),revisionChanges};
  const identity = commandIdentity(id,state,request,policy,context);
  if (!equal(saved,identity)) fail('Lifecycle replay identity is malformed');
  return receipt(rawReceipt,identity,context);
}

/** Internal, server-context-only execution. RPC owns CAS, audit and settlement consumption atomically.
 * A rejected or uncertain RPC is surfaced once; callers must read the same operation before any retry.
 */
/** Prepare an owner decision for an atomic commerce/lifecycle database transaction. */
export function prepareLifecycleCommit(operationId: string, state: LifecycleState, request: unknown, policy: LifecyclePolicy, context: LifecycleContext) {
  const identity = commandIdentity(operationId, state, request, policy, context);
  stable(identity);
  return { identity, decision: decideSubscriptionLifecycle(state, request, policy, context) };
}

export async function commitSubscriptionLifecycle(database: Database, operationId: string, state: LifecycleState, request: unknown, policy: LifecyclePolicy, context: LifecycleContext): Promise<LifecycleCommitReceipt> {
  const identity = commandIdentity(operationId, state, request, policy, context);
  stable(identity);
  const existing = await database.query<Record<string, unknown>>(`subscription_lifecycle_operations?select=identity,receipt&operation_id=eq.${identity.operationId}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(existing) || existing.length > 1) fail('Lifecycle operation must resolve at most once');
  if (existing.length === 1) {
    if (!equal(existing[0].identity, identity)) fail('Lifecycle replay conflicts with original identity');
    return receipt(existing[0].receipt, identity, context);
  }
  const decision = decideSubscriptionLifecycle(state, request, policy, context);
  const current = await readSubscriptionLifecycle(database, state.id, state.productId, state.subject);
  if (!equal(current.state, state) || !equal(current.policy, policy)) fail('Stale lifecycle state or policy');
  const retained = await publication(database,state);
  if (!equal(retained.configuration.subscription_revision_changes,context.revisionChanges)) fail('Revision direction differs from retained publication');
  for (const candidate of [decision.next, ...(decision.next.scheduledChange === null ? [] : [decision.next.scheduledChange])]) {
    const target = await publication(database,candidate);
    if (!equal(target.configuration.subscription_lifecycle,policy)) fail('Target lifecycle policy differs');
  }
  if (identity.approval !== null || ((decision.audit.operation === 'suspend' && policy.suspensionApprovalRequired) || (decision.audit.operation === 'reactivate' && policy.reactivationApprovalRequired))) fail('Lifecycle approval owner is unavailable');
  if (identity.settlement !== null) {
    const settlement = context.settlements.get(String((identity.settlement as { id: string }).id));
    const quote = context.quotes.get(String((identity.quote as { id: string }).id));
    if (!settlement || !quote || settlement.kind !== 'verified_payment') fail('Approved invoice owner is unavailable');
    const verified = await readSubscriptionLifecyclePayment(database,settlement.id,quote.id,state,context.now);
    const capture=context.captures?.get(settlement.id);
    if (!equal(verified,{quote,settlement,...(capture===undefined?{}:{capture})})) fail('Transaction lifecycle evidence differs from owner context');
  }
  const raw = await database.rpc('commit_subscription_lifecycle', { p_identity: identity, p_decision: decision });
  // Another exact invocation may have committed between our lookup and RPC. Validate the original
  // receipt at its own instant rather than insisting this invocation won that operation lock.
  return receipt(raw, identity, context);
}
