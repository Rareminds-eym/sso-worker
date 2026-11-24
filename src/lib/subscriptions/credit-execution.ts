import { earlierSubscriptionEnd } from './entry-validity';
import { errors } from 'jose';
import type { Env } from '../../types';
import { db } from '../db';
import { verifyAccessToken } from '../jwt';
import { readSubscriptionLifecycle, commitSubscriptionLifecycle, readSubscriptionLifecyclePayment, readSubscriptionLifecycleReplay } from './lifecycle-persistence';
import { evaluateSubscriptionAccess, type LifecycleCapture, type LifecycleQuote, type LifecycleSettlement, type LifecycleApproval } from './lifecycle';
import { preparePublishedIncludedCreditOccurrence } from './publication';
import { validatePlanAuthoringSnapshot } from './authoring-context';
import { createPlanAuthoringRegistry } from './authoring';
import { readPlanRevisionBundle } from './revision-bundle';
import { validateCreditAuthoringContext } from './credit-authoring-context';
import { array, choice, integer, invalid, record, text, uuid, databaseUuid } from './validation';
import { readRefundCancellation, readSubscriptionCommerceFreeze, readSettledRetake, executeSubscriptionCommerce as executeCommerce } from './commerce-persistence';
import { parseCommerceRequest } from './commerce';
import { prepareIncludedCreditRefresh } from './credit-occurrences';

export class SubscriptionExecutionDenied extends Error {}
const object = (value: unknown, path: string) => record(value, path,
  value && typeof value === 'object' ? Object.keys(value) : []);

/** Resolve commerce identity from signed membership and retained owner eligibility only. */
export async function executeSubscriptionCommerce(env: Env, token: unknown, productId: unknown, operationId: unknown, input: unknown) {
  const request = parseCommerceRequest(input), product = uuid(productId, 'commerce.productId');
  if (request.kind !== 'activate' && !env.PAYMENT_WORKER) throw new Error('Subscription payment owner unavailable');
  if (request.expectedVersion !== 0) {
    const context = await readSubscriptionExecution(env, token, request.subscriptionId, product, `commerce_${request.kind === 'checkout' ? 'order' : request.kind}`);
    // Refund confirmation reads provider evidence for billing reconciliation after access revocation.
    if ((context.refundedCancellation || context.commerceFrozen) && request.kind !== 'refund_confirm') throw new SubscriptionExecutionDenied();
    const receipt = await executeCommerce(context.database, env.PAYMENT_WORKER,
      { actorId: context.actorId, subject: context.subject, audience: context.audience }, product, uuid(operationId, 'commerce.operationId'), request);
    if (request.kind === 'settle') {
      const saved = record(receipt, 'commerce.receipt', ['kind', 'operationId', 'quoteId', 'settlement']);
      const settlement = record(saved.settlement, 'commerce.settlement', ['id', 'quoteId', 'subscriptionId', 'productId', 'subject', 'purpose', 'referenceId', 'providerPaymentId', 'amountMinor', 'currency', 'settledAt']);
      if (saved.kind !== 'settlement' || saved.operationId !== operationId || saved.quoteId !== request.quoteId
        || settlement.id !== operationId || settlement.quoteId !== request.quoteId || settlement.subscriptionId !== context.state.id
        || settlement.productId !== product || !equal(settlement.subject, context.subject)) throw new Error('Commerce settlement acknowledgement differs');
      const purpose = choice(settlement.purpose, 'commerce.settlement.purpose', ['renew', 'upgrade', 'retake'] as const);
      if (purpose !== 'retake') {
        // Settlement is durable before fulfillment. Explicit same-operation replay resumes
        // this owner transition; a failed transition never becomes a fulfilled acknowledgement.
        await executeSubscriptionLifecycle(env, token, product, operationId, { operation: purpose,
          subscriptionId: context.state.id, subject: context.subject, expectedVersion: request.expectedVersion,
          expectedRevisionId: request.expectedRevisionId, quoteId: request.quoteId, settlementId: operationId,
          reason: purpose === 'renew' ? 'Paid subscription renewal' : 'Paid subscription upgrade' });
      }
    }
    return receipt;
  }
  const owner = await readSubscriptionActor(env, token);
  if (request.subject.kind === 'user' ? request.subject.id !== owner.actorId : request.subject.id !== owner.orgId) throw new SubscriptionExecutionDenied();
  const rows = await owner.database.query<Record<string, unknown>>(
    `subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan&revision_id=eq.${uuid(request.expectedRevisionId, 'commerce.revisionId')}&limit=2`, undefined, 'json-array');
  if (rows.length !== 1 || rows[0].revision_id !== request.expectedRevisionId) throw new Error('Commerce publication unavailable');
  const canonical = record(rows[0].canonical_plan, 'commerce.publication', ['id', 'code', 'productId', 'audiences', 'configuration']);
  if (canonical.productId !== product || canonical.id !== rows[0].plan_id) throw new SubscriptionExecutionDenied();
  const config = object(canonical.configuration, 'commerce.configuration');
  const eligibility = record(config.subscription_commerce_eligibility, 'commerce.eligibility', ['schemaVersion', 'bindings']);
  if (eligibility.schemaVersion !== 1) invalid('commerce.eligibility', 'unsupported version');
  const audiences = array(canonical.audiences, 'commerce.audiences').map(value => text(value, 'commerce.audience'));
  const matches = array(eligibility.bindings, 'commerce.eligibility.bindings').map(value => {
    const binding = record(value, 'commerce.eligibility.binding', ['audience', 'subjectKind', 'roles']);
    return { audience: text(binding.audience, 'commerce.eligibility.audience'),
      subjectKind: choice(binding.subjectKind, 'commerce.eligibility.subjectKind', ['user', 'organization'] as const),
      roles: array(binding.roles, 'commerce.eligibility.roles').map(role => text(role, 'commerce.eligibility.role')) };
  }).filter(binding => binding.subjectKind === request.subject.kind && audiences.includes(binding.audience)
    && binding.roles.some(role => owner.roles.includes(role)));
  if (matches.length !== 1) throw new SubscriptionExecutionDenied();
  const receipt = await executeCommerce(owner.database, env.PAYMENT_WORKER,
    { actorId: owner.actorId, subject: request.subject, audience: matches[0].audience }, product, uuid(operationId, 'commerce.operationId'), request);
  if (request.kind === 'activate') {
    const saved = record(receipt, 'commerce.activation', ['kind', 'operationId', 'contractId', 'subscriptionId', 'productId', 'subject', 'revisionId']);
    if (saved.kind !== 'activation' || saved.operationId !== operationId || saved.contractId !== request.contractId
      || saved.subscriptionId !== request.subscriptionId || saved.productId !== product
      || saved.revisionId !== request.expectedRevisionId || !equal(saved.subject, request.subject)) {
      throw new Error('Commerce activation acknowledgement differs');
    }
  }
  return receipt;
}
function equal(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object') return false;
  if (Array.isArray(left) || Array.isArray(right)) return Array.isArray(left) && Array.isArray(right)
    && left.length === right.length && left.every((v, i) => equal(v, right[i]));
  const a = left as Record<string, unknown>, b = right as Record<string, unknown>;
  return Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(k => Object.hasOwn(b, k) && equal(a[k], b[k]));
}

/** Signed identity plus live canonical membership; no caller-supplied roles or actor. */
export async function readSubscriptionActor(env: Env, token: unknown) {
  if (typeof token !== 'string' || !token) throw new SubscriptionExecutionDenied();
  let claims;
  try { claims = await verifyAccessToken(token, env); }
  catch (error) { if (error instanceof errors.JOSEError) throw new SubscriptionExecutionDenied(); throw error; }
  if (!('exp' in claims) || typeof claims.exp !== 'number' || claims.exp <= Date.now() / 1000
    || claims.membership_status !== 'active' || claims.is_email_verified !== true) throw new SubscriptionExecutionDenied();
  const actorId = uuid(claims.sub, 'actor'), orgId = databaseUuid(claims.org_id, 'actor.organization');
  const database = db(env);
  const users = await database.query<Record<string, unknown>>(
    `users?select=id,is_blocked,is_email_verified,user_metadata&id=eq.${actorId}&limit=2`, undefined, 'json-array');
  if (users.length !== 1 || users[0].id !== actorId || users[0].is_blocked !== false || users[0].is_email_verified !== true
    || (users[0].user_metadata !== null && object(users[0].user_metadata, 'actor.metadata').must_change_password === true)) throw new SubscriptionExecutionDenied();
  const live = object(await database.rpc('get_jwt_claims', { p_user_id: actorId, p_org_id: orgId }), 'actor.claims');
  if (live.membership_status !== 'active') throw new SubscriptionExecutionDenied();
  const roles = array(live.roles, 'actor.roles').map(v => text(v, 'actor.role'));
  return { database, actorId, orgId, roles };
}

/** Internal trusted application transport. Product and feature inventory come from the app owner. */
export async function readSubscriptionExecution(env: Env, token: unknown, subscriptionId: unknown, productId: unknown,
  operation: string = 'read') {
  const owner = await readSubscriptionActor(env, token), id = uuid(subscriptionId, 'subscription.id'), product = uuid(productId, 'product.id');
  const rows = await owner.database.query<Record<string, unknown>>(
    `subscriptions?select=id,user_id,organization_id,is_organization_subscription,product_id,metadata&id=eq.${id}&limit=2`, undefined, 'json-array');
  if (rows.length !== 1 || rows[0].id !== id || rows[0].product_id !== product) throw new SubscriptionExecutionDenied();
  const row = rows[0];
  const subject = row.is_organization_subscription === true
    ? { kind: 'organization' as const, id: uuid(row.organization_id, 'subscription.organization') }
    : { kind: 'user' as const, id: uuid(row.user_id, 'subscription.user') };
  if ((subject.kind === 'user' && subject.id !== owner.actorId)
    || (subject.kind === 'organization' && subject.id !== owner.orgId)) throw new SubscriptionExecutionDenied();
  const stored = await readSubscriptionLifecycle(owner.database, id, product, subject);
  const { state, policy } = stored;
  const events = await owner.database.query<Record<string, unknown>>(
    'subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan'
    + `&plan_id=eq.${state.planId}&revision_id=eq.${state.revisionId}&limit=2`, undefined, 'json-array');
  if (events.length !== 1 || events[0].plan_id !== state.planId || events[0].revision_id !== state.revisionId) throw new Error('Published subscription terms unavailable');
  const canonical = record(events[0].canonical_plan, 'publication', ['id', 'code', 'productId', 'audiences', 'configuration']);
  const snapshot = validatePlanAuthoringSnapshot({ id: canonical.id, plan_code: canonical.code, product_id: canonical.productId,
    applicable_entities: canonical.audiences, entity_config: canonical.configuration }, state.planId);
  if (snapshot.context.plan.productId !== product || !equal(snapshot.configuration.subscription_lifecycle, policy)) throw new Error('Published lifecycle policy differs');
  const execution = record(snapshot.configuration.subscription_execution, 'execution', ['schemaVersion', 'operationRoles', 'recipientRoles', 'consumptionTariffs']);
  if (execution.schemaVersion !== 1) invalid('execution.schemaVersion', 'unsupported schema version');
  const operationRoles = object(execution.operationRoles, 'execution.operationRoles');
  const allowed = array(operationRoles[operation], 'execution.operationRoles.operation').map(v => text(v, 'execution.role'));
  if (!allowed.length || !owner.roles.some(role => allowed.includes(role))) throw new SubscriptionExecutionDenied();
  const binding = record(object(row.metadata, 'subscription.metadata').subscription_execution, 'subscription.execution', ['audience', 'subscriptionEndsAt']);
  const audience = text(binding.audience, 'subscription.audience'), subscriptionEndsAt = binding.subscriptionEndsAt === null ? null : integer(binding.subscriptionEndsAt, 'subscription.endsAt', 1);
  if (!snapshot.context.audiences.includes(audience) || (state.periodEndsAt === null ? subscriptionEndsAt !== null : subscriptionEndsAt === null || subscriptionEndsAt < state.periodEndsAt)) throw new Error('Subscription commercial binding differs');
  const refundedCancellation = await readRefundCancellation(owner.database, id, product, subject);
  const commerceFrozen = await readSubscriptionCommerceFreeze(owner.database, id, product, subject);
  const lifecycleAccess = evaluateSubscriptionAccess(state, policy, Date.now());
  return { ...owner, ...stored, subject, productId: product, audience, subscriptionEndsAt, configuration: snapshot.configuration,
    execution, authoringContext: snapshot.context, refundedCancellation, commerceFrozen,
    access: refundedCancellation ? 'suspended' as const : commerceFrozen && lifecycleAccess === 'full' ? 'read_only' as const : lifecycleAccess };
}

/** Rules travel from the retained canonical revision; applications own action execution. */
export async function subscriptionActionContext(env: Env, token: unknown, subscriptionId: unknown, productId: unknown) {
  const context = await readSubscriptionExecution(env, token, subscriptionId, productId);
  const configured = record(context.configuration.subscription_actions, 'actions', ['schemaVersion', 'bindings']);
  if (configured.schemaVersion !== 1) invalid('actions.schemaVersion', 'unsupported schema version');
  const seen = new Set<string>();
  const bindings = array(configured.bindings, 'actions.bindings').map(value => {
    const binding = record(value, 'actions.binding', ['actionKey', 'featureKey', 'mode', 'assessmentCategory', 'paymentRequired', 'acceptedValues', 'quota']);
    const actionKey = text(binding.actionKey, 'actions.actionKey');
    const result = {
      actionKey, featureKey: text(binding.featureKey, 'actions.featureKey'),
      mode: choice(binding.mode, 'actions.mode', ['read', 'write'] as const),
      ...(binding.assessmentCategory === undefined ? {} : { assessmentCategory: text(binding.assessmentCategory, 'actions.assessmentCategory') }),
      ...(binding.paymentRequired === undefined ? {} : { paymentRequired: binding.paymentRequired }),
      ...(binding.acceptedValues === undefined ? {} : { acceptedValues: array(binding.acceptedValues, 'actions.acceptedValues').map(v => text(v, 'actions.acceptedValue')) }),
      ...(binding.quota === undefined ? {} : { quota: (() => {
        const quota = record(binding.quota, 'actions.quota', ['period', 'countingEvent']);
        return { period: choice(quota.period, 'actions.quota.period', ['subscription', 'billing_period', 'concurrent'] as const),
          countingEvent: text(quota.countingEvent, 'actions.quota.countingEvent') };
      })() }),
    };
    const identity = JSON.stringify([result.actionKey, result.mode, result.assessmentCategory ?? null]);
    if (seen.has(identity)) invalid('actions.actionKey', 'duplicate action/category');
    seen.add(identity);
    if (result.paymentRequired !== undefined && typeof result.paymentRequired !== 'boolean') invalid('actions.paymentRequired', 'expected boolean');
    if (result.acceptedValues && (!result.acceptedValues.length || new Set(result.acceptedValues).size !== result.acceptedValues.length)) invalid('actions.acceptedValues', 'expected unique non-empty values');
    if (result.mode === 'read' && (result.quota || result.paymentRequired === true)) invalid('actions.binding', 'read actions cannot charge or reserve quota');
    return result;
  });
  return { schemaVersion: 1 as const, actorId: context.actorId, state: context.state, access: context.access,
    audience: context.audience, activatedAt: context.activatedAt, subscriptionEndsAt: context.subscriptionEndsAt,
    actions: { schemaVersion: 1 as const, bindings } };
}

/** Trusted application transport only. The application consumes this evidence once with its attempt. */
export async function prepareSubscriptionRetakeSettlement(env: Env, token: unknown, productId: unknown, input: unknown) {
  const request = record(input, 'retake', ['subscriptionId', 'settlementId', 'referenceId']);
  const context = await readSubscriptionExecution(env, token, request.subscriptionId, productId, 'commerce_retake');
  const validUntil = earlierSubscriptionEnd(context.state.periodEndsAt, context.subscriptionEndsAt);
  if (context.access !== 'full' || validUntil === null || validUntil <= Date.now()) throw new SubscriptionExecutionDenied();
  const referenceId = uuid(request.referenceId, 'retake.referenceId'), settlementId = uuid(request.settlementId, 'retake.settlementId');
  const settlement = record(await readSettledRetake(context.database, settlementId, context.state.id, context.productId, context.subject, referenceId),
    'retake.settlement', ['id', 'quoteId', 'subscriptionId', 'productId', 'subject', 'purpose', 'referenceId', 'providerPaymentId', 'amountMinor', 'currency', 'settledAt']);
  const quoteId = uuid(settlement.quoteId, 'retake.quoteId');
  const rows = await context.database.query<Record<string, unknown>>(
    `subscription_commerce_quotes?select=quote&id=eq.${quoteId}&limit=2`, undefined, 'json-array');
  if (rows.length !== 1) throw new Error('Retake purchase provenance unavailable');
  const quote = object(rows[0].quote, 'retake.quote');
  if (quote.id !== quoteId || quote.actorId !== context.actorId || quote.subscriptionId !== context.state.id
    || quote.productId !== context.productId || quote.audience !== context.audience || !equal(quote.subject, context.subject)
    || quote.purpose !== 'retake' || quote.referenceId !== referenceId || settlement.id !== settlementId
    || settlement.subscriptionId !== context.state.id || settlement.productId !== context.productId || !equal(settlement.subject, context.subject)
    || settlement.purpose !== 'retake' || settlement.referenceId !== referenceId
    || settlement.amountMinor !== quote.amountMinor || settlement.currency !== quote.currency) throw new SubscriptionExecutionDenied();
  integer(settlement.amountMinor, 'retake.amountMinor', 1);
  const settledAt = integer(settlement.settledAt, 'retake.settledAt');
  if (settledAt > Date.now() || settledAt < integer(quote.createdAt, 'retake.createdAt')
    || !/^[A-Z]{3}$/.test(text(settlement.currency, 'retake.currency'))
    || !/^pay_[A-Za-z0-9]+$/.test(text(settlement.providerPaymentId, 'retake.paymentId'))) throw new Error('Retake payment evidence differs');
  return { schemaVersion: 1 as const, actorId: context.actorId, subscriptionId: context.state.id, productId: context.productId,
    subject: context.subject, stateVersion: context.state.version, validUntil, settlement };
}

async function recipientFor(context: Awaited<ReturnType<typeof readSubscriptionExecution>>, poolKey: string, recipientId: unknown) {
  const credit = validateCreditAuthoringContext(context.authoringContext, context.configuration);
  const pool = credit.credit.pools.find(p => p.key === poolKey && p.audiences.includes(context.audience));
  if (!pool) invalid('credit.pool', 'published pool unavailable for this audience');
  const id = uuid(recipientId, 'credit.recipientId');
  if (pool.recipient === 'subscriber' && (context.subject.kind !== 'user' || id !== context.subject.id)) throw new SubscriptionExecutionDenied();
  if (pool.recipient === 'organization' && (context.subject.kind !== 'organization' || id !== context.subject.id)) throw new SubscriptionExecutionDenied();
  if (pool.recipient === 'managed_learner') {
    if (context.subject.kind !== 'organization') throw new SubscriptionExecutionDenied();
    const roles = array(object(context.execution.recipientRoles, 'execution.recipientRoles')[poolKey], 'execution.recipientRoles.pool')
      .map(v => text(v, 'execution.recipientRole'));
    if (!roles.length) invalid('execution.recipientRoles.pool', 'explicit recipient roles required');
    const live = object(await context.database.rpc('get_jwt_claims', { p_user_id: id, p_org_id: context.subject.id }), 'recipient.claims');
    if (live.membership_status !== 'active' || !array(live.roles, 'recipient.roles').some(role => roles.includes(String(role)))) throw new SubscriptionExecutionDenied();
    const users = await context.database.query<Record<string, unknown>>(`users?select=id,is_blocked&id=eq.${id}&limit=2`, undefined, 'json-array');
    if (users.length !== 1 || users[0].id !== id || users[0].is_blocked !== false) throw new SubscriptionExecutionDenied();
  }
  return { pool, recipient: { kind: pool.recipient, id } };
}

/** Historical terms are read only after immutable lifecycle evidence binds them to this subscription. */
async function historicalCreditContext(context: Awaited<ReturnType<typeof readSubscriptionExecution>>, revisionId: unknown) {
  const revision = uuid(revisionId, 'history.revisionId');
  if (revision === context.state.revisionId) return context;
  const operations = await context.database.query<Record<string, unknown>>(
    'subscription_lifecycle_operations?select=kind,receipt'
    + `&subscription_id=eq.${context.state.id}`
    + `&or=(receipt->state->>revisionId.eq.${revision},receipt->decision->next->>revisionId.eq.${revision})&limit=1`, undefined, 'json-array');
  if (!Array.isArray(operations) || operations.length !== 1) throw new SubscriptionExecutionDenied();
  const row = record(operations[0], 'history.operation', ['kind', 'receipt']);
  const receipt = object(row.receipt, 'history.receipt');
  const previous = object(row.kind === 'initialize' ? receipt.state
    : row.kind === 'transition' ? object(receipt.decision, 'history.decision').next : null, 'history.state');
  if (previous.id !== context.state.id || previous.productId !== context.productId
    || previous.revisionId !== revision || !equal(previous.subject, context.subject)
    || integer(previous.version, 'history.version', 1) > context.state.version) throw new SubscriptionExecutionDenied();
  const planId = uuid(previous.planId, 'history.planId');
  const events = await context.database.query<Record<string, unknown>>(
    `subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan&plan_id=eq.${planId}&revision_id=eq.${revision}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(events) || events.length !== 1 || events[0].plan_id !== planId || events[0].revision_id !== revision) throw new Error('Historical publication unavailable');
  const canonical = record(events[0].canonical_plan, 'history.publication', ['id', 'code', 'productId', 'audiences', 'configuration']);
  if (canonical.id !== planId || canonical.productId !== context.productId) throw new SubscriptionExecutionDenied();
  const snapshot = validatePlanAuthoringSnapshot({ id: canonical.id, plan_code: canonical.code, product_id: canonical.productId,
    applicable_entities: canonical.audiences, entity_config: canonical.configuration }, planId);
  if (!snapshot.context.audiences.includes(context.audience)) throw new SubscriptionExecutionDenied();
  const execution = record(snapshot.configuration.subscription_execution, 'history.execution', ['schemaVersion', 'operationRoles', 'recipientRoles', 'consumptionTariffs']);
  if (execution.schemaVersion !== 1) invalid('history.execution', 'unsupported version');
  return { ...context, configuration: snapshot.configuration, authoringContext: snapshot.context,
    execution };
}

export async function prepareSubscriptionCreditExecution(env: Env, token: unknown, productId: unknown, input: unknown, features: unknown) {
  const request = record(input, 'credit', ['kind', 'subscriptionId', 'recipientId', 'ruleId', 'occurrenceIndex', 'actionKey', 'poolKey', 'operationId', 'revisionId', 'cursor']);
  const kind = choice(request.kind, 'credit.kind', ['allocate', 'refresh', 'consume', 'usage', 'replay', 'allocation_replay', 'history', 'history_pools']);
  if (kind !== 'refresh' && Object.hasOwn(request, 'cursor')) invalid('credit.cursor', 'refresh only');
  const historical = kind === 'history' || kind === 'history_pools';
  if (!historical && Object.hasOwn(request, 'revisionId')) invalid('credit.revisionId', 'historical reads only');
  const context = await readSubscriptionExecution(env, token, request.subscriptionId, productId, historical || kind === 'usage' ? 'read' : kind === 'replay' ? 'consume' : kind === 'allocation_replay' || kind === 'refresh' ? 'allocate' : kind);
  if (historical) {
    if (context.access === 'suspended') throw new SubscriptionExecutionDenied();
    const allowed = kind === 'history_pools' ? ['kind', 'subscriptionId', 'revisionId'] : ['kind', 'subscriptionId', 'revisionId', 'poolKey', 'recipientId'];
    if (Object.keys(request).some(key => !allowed.includes(key))) invalid('credit.history', 'unsupported historical field');
    const retained = await historicalCreditContext(context, request.revisionId);
    if (kind === 'history_pools') {
      const credit = validateCreditAuthoringContext(retained.authoringContext, retained.configuration);
      return { kind, actorId: context.actorId, productId: context.productId, subscriptionId: context.state.id,
        revisionId: uuid(request.revisionId, 'history.revisionId'), audience: context.audience,
        pools: credit.credit.pools.filter(pool => pool.audiences.includes(context.audience)) };
    }
    const { pool, recipient } = await recipientFor(retained, text(request.poolKey, 'history.poolKey'), request.recipientId);
    return { kind: 'usage' as const, actorId: context.actorId, scope: { productId: context.productId,
      subscriptionId: context.state.id, recipient, featureKey: pool.featureKey, poolKey: pool.key } };
  }
  // Finite retention ends domain-data access as well as new spending. Account/billing
  // management may still read its access status through currentSubscriptionExecution.
  if (context.refundedCancellation || (context.policy.readOnlyDurationMs !== undefined && context.access === 'suspended')) throw new SubscriptionExecutionDenied();
  if (kind !== 'usage' && kind !== 'replay' && kind !== 'allocation_replay' && context.access !== 'full') throw new SubscriptionExecutionDenied();
  const common = { productId: context.productId, subscriptionId: context.state.id };
  if (kind === 'allocate' || kind === 'allocation_replay' || kind === 'refresh') {
    if (['actionKey', 'poolKey', 'operationId'].some(k => Object.hasOwn(request, k))) invalid('credit', 'fields do not apply to allocation');
    // The occurrence reader resolves the exact rule from the retained immutable bundle.
    const ruleId = uuid(request.ruleId, 'credit.ruleId');
    const credit = validateCreditAuthoringContext(context.authoringContext, context.configuration);
    const registry = createPlanAuthoringRegistry(credit, context.productId, features);
    const staged = await readPlanRevisionBundle(context.database, context.state.revisionId, registry);
    if (staged.bundle.draft.plan.id !== context.state.planId) throw new Error('Credit revision scope differs');
    const rule = staged.bundle.includedCredits.rules.find(value => value.id === ruleId);
    if (!rule) invalid('credit.ruleId', 'published allocation rule unavailable');
    const { recipient, pool } = await recipientFor(context, rule.poolKey, request.recipientId);
    if (kind === 'refresh') {
      if (Object.hasOwn(request, 'occurrenceIndex')) invalid('credit.refresh', 'refresh derives due occurrences');
      const page = await prepareIncludedCreditRefresh(staged.bundle, registry,
        { ...common, planId: context.state.planId, revisionId: context.state.revisionId, ruleId, audience: context.audience,
          recipient, activatedAt: context.activatedAt, subscriptionEndsAt: context.subscriptionEndsAt,
          periodStartsAt: context.state.periodStartsAt, periodEndsAt: context.state.periodEndsAt,
          cursor: request.cursor === null ? 0 : integer(request.cursor, 'credit.cursor'), now: Date.now() }, credit.credit.timePolicies);
      return { kind, actorId: context.actorId, ...page };
    }
    const occurrence = await preparePublishedIncludedCreditOccurrence(context.database, context.state.planId,
      context.state.revisionId, context.productId, features, { ...common, planId: context.state.planId, revisionId: context.state.revisionId,
        ruleId, audience: context.audience, recipient,
        activatedAt: context.activatedAt, subscriptionEndsAt: context.subscriptionEndsAt, periodStartsAt: context.state.periodStartsAt,
        periodEndsAt: context.state.periodEndsAt, occurrenceIndex: integer(request.occurrenceIndex, 'credit.occurrenceIndex') });
    if (occurrence.poolKey !== pool.key || occurrence.featureKey !== pool.featureKey
      || occurrence.recipient.kind !== recipient.kind || occurrence.recipient.id !== recipient.id) throw new Error('Prepared allocation scope differs');
    return { kind, actorId: context.actorId, occurrence };
  }
  if (['ruleId', 'occurrenceIndex'].some(k => Object.hasOwn(request, k))) invalid('credit', 'fields do not apply to consumption or usage');
  const { pool, recipient } = await recipientFor(context, text(request.poolKey, 'credit.poolKey'), request.recipientId);
  const scope = { ...common, recipient, featureKey: pool.featureKey, poolKey: pool.key };
  if (kind === 'usage') {
    if (['actionKey', 'operationId'].some(k => Object.hasOwn(request, k))) invalid('credit', 'fields do not apply to usage');
    return { kind, actorId: context.actorId, scope };
  }
  const actionKey = text(request.actionKey, 'credit.actionKey');
  if (kind === 'replay') return { kind, actorId: context.actorId, scope, actionKey,
    operationId: uuid(request.operationId, 'credit.operationId') };
  const tariffs = array(context.execution.consumptionTariffs, 'execution.consumptionTariffs').map(value =>
    record(value, 'execution.tariff', ['actionKey', 'poolKey', 'featureKey', 'amount', 'spendingOrder']));
  const matches = tariffs.filter(t => t.actionKey === actionKey && t.poolKey === pool.key && t.featureKey === pool.featureKey);
  if (matches.length !== 1) invalid('execution.tariff', 'action requires exactly one explicit tariff');
  const tariff = matches[0], amount = integer(tariff.amount, 'execution.tariff.amount', 1);
  if (amount > 2147483647) invalid('execution.tariff.amount', 'outside ledger integer range');
  return { kind, actorId: context.actorId, command: { ...scope, operationId: uuid(request.operationId, 'credit.operationId'), amount,
    actionKey, spendingOrder: choice(tariff.spendingOrder, 'execution.tariff.spendingOrder', ['expires_first', 'oldest_first']) } };
}

export async function currentSubscriptionExecution(env: Env, token: unknown, subscriptionId: unknown, productId: unknown) {
  const context = await readSubscriptionExecution(env, token, subscriptionId, productId);
  const credit = validateCreditAuthoringContext(context.authoringContext, context.configuration);
  return { schemaVersion: 1 as const, actorId: context.actorId, state: context.state, access: context.access,
    audience: context.audience, activatedAt: context.activatedAt, subscriptionEndsAt: context.subscriptionEndsAt,
    pools: credit.credit.pools.filter(pool => pool.audiences.includes(context.audience)) };
}

/** Evidence is loaded by its owner; request fields remain references, never quote/payment objects. */
export async function executeSubscriptionLifecycle(env: Env, token: unknown, productId: unknown, operationId: unknown, input: unknown) {
  const request = record(input, 'lifecycle.request', ['operation', 'subscriptionId', 'subject', 'expectedVersion', 'expectedRevisionId',
    'reason', 'targetRevisionId', 'timing', 'quoteId', 'settlementId', 'approvalId']);
  const operation = choice(request.operation, 'lifecycle.operation', ['upgrade', 'renew', 'downgrade', 'cancel', 'expire', 'payment_failed', 'suspend', 'reactivate']);
  const context = await readSubscriptionExecution(env, token, request.subscriptionId, productId, operation);
  const replay = await readSubscriptionLifecycleReplay(context.database, uuid(operationId, 'lifecycle.operationId'),
    request, context.actorId, context.subject, context.productId, new Set([operation]));
  if (replay) return replay;
  if (context.refundedCancellation || context.commerceFrozen) throw new SubscriptionExecutionDenied();
  const publishedRevisions = new Map([[context.state.revisionId, { planId: context.state.planId, revisionId: context.state.revisionId, productId: context.productId }]]);
  const changes = array(context.configuration.subscription_revision_changes, 'lifecycle.revisionChanges').map(value => {
    const item = record(value, 'lifecycle.change', ['fromRevisionId', 'toRevisionId', 'operation']);
    return { fromRevisionId: uuid(item.fromRevisionId, 'lifecycle.change.from'), toRevisionId: uuid(item.toRevisionId, 'lifecycle.change.to'),
      operation: choice(item.operation, 'lifecycle.change.operation', ['upgrade', 'downgrade']) };
  });
  const now = Date.now(), quotes = new Map<string, LifecycleQuote>(), settlements = new Map<string, LifecycleSettlement>(),captures=new Map<string,LifecycleCapture>();
  if (operation === 'upgrade' || operation === 'renew') {
    const verified = await readSubscriptionLifecyclePayment(context.database, uuid(request.settlementId, 'lifecycle.settlementId'),
      uuid(request.quoteId, 'lifecycle.quoteId'), context.state, now);
    // The paid quote is the contract amendment. Persistence extends the commercial
    // end atomically with this exact settlement and retains the original operation evidence.
    quotes.set(verified.quote.id, verified.quote); settlements.set(verified.settlement.id, verified.settlement);
    if(verified.capture)captures.set(verified.settlement.id,verified.capture);
    publishedRevisions.set(verified.quote.revisionId, { planId: verified.quote.planId, revisionId: verified.quote.revisionId, productId: verified.quote.productId });
  }
  const targets = new Set<string>();
  if (request.targetRevisionId !== undefined) targets.add(uuid(request.targetRevisionId, 'lifecycle.target'));
  if (context.state.scheduledChange) targets.add(context.state.scheduledChange.revisionId);
  for (const id of targets) {
    const rows = await context.database.query<Record<string, unknown>>(
      `subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan&revision_id=eq.${id}&limit=2`, undefined, 'json-array');
    if (rows.length !== 1 || rows[0].revision_id !== id) throw new Error('Published target unavailable');
    const canonical = object(rows[0].canonical_plan, 'lifecycle.target');
    if (canonical.productId !== context.productId || canonical.id !== rows[0].plan_id) throw new Error('Published target product differs');
    publishedRevisions.set(id, { planId: uuid(rows[0].plan_id, 'lifecycle.target.plan'), revisionId: id, productId: context.productId });
  }
  // No invoice/approval owner exists for this path. Empty approval authority
  // deliberately rejects approval-required operations, never fabricates approval.
  // Paid evidence above must already exist in the completed payment owner's records.
  const domain = {
    now, actorId: context.actorId, subject: context.subject, allowedOperations: new Set([operation]),
    quotes, settlements, captures, approvals: new Map<string, LifecycleApproval>(), publishedRevisions, revisionChanges: changes,
  };
  return commitSubscriptionLifecycle(context.database, uuid(operationId, 'lifecycle.operationId'), context.state, request, context.policy, domain);
}
