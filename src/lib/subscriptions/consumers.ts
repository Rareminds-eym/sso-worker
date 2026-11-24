import type { Env } from '../../types';
import { db, type DbClient } from '../db';
import { authorizeSubscriptionAdministrator, createPlanAuthoringRegistry } from './authoring';
import { validatePlanAuthoringSnapshot } from './authoring-context';
import { validateCreditAuthoringContext } from './credit-authoring-context';
import { readSubscriptionActor, readSubscriptionExecution, SubscriptionExecutionDenied } from './credit-execution';
import { validatePlanPublicationCompleteness } from './publication-readiness';
import { readPlanRevisionBundles } from './revision-bundle';
import { loadCatalogAudiences, resolveCatalogAudience } from './catalog-audience';
import { loadCatalogOwnerInputs } from './catalog-owner-inputs';
import { validatePresentationCopy } from './hybrid-offer';
import { loadTaxPolicy, type TaxPolicy } from './tax-policy';
import { array, choice, integer, invalid, record, text, uuid } from './validation';

const PAGE_SIZE = 50; // Operational response budget, not a commercial limit.
const lifecycleOperations = ['upgrade', 'renew', 'downgrade', 'cancel', 'expire', 'payment_failed', 'suspend', 'reactivate'] as const;
const statuses = ['active', 'pending', 'paused', 'cancelled', 'expired', 'grace_period'] as const;
function cursorValue(value: unknown): string | null {
  return value === null || value === undefined ? null : uuid(value, 'cursor');
}

/** Discover only canonical subjects bound to the signed actor's live organization. */
export async function listSubscriptionExecutions(env: Env, token: unknown, productId: unknown, cursor?: unknown) {
  const owner = await readSubscriptionActor(env, token), product = uuid(productId, 'product'), after = cursorValue(cursor);
  const rows = await owner.database.query<Record<string, unknown>>(
    'subscriptions?select=id,user_id,organization_id,is_organization_subscription,product_id,plan_id,status,lifecycle_state,plan_revision_id'
    + `&product_id=eq.${product}&or=(and(is_organization_subscription.is.true,organization_id.eq.${owner.orgId}),and(is_organization_subscription.not.is.true,user_id.eq.${owner.actorId}))`
    + `&order=id.asc&limit=${PAGE_SIZE}` + (after ? `&id=gt.${after}` : ''), undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length > PAGE_SIZE) throw new Error('Subscription discovery exceeded response budget');
  const items: {
    id: string; planId: string; productId: string; subject: { kind: 'user' | 'organization'; id: string };
    status: typeof statuses[number]; kind: 'initialized' | 'uninitialized'; revisionId: string | null;
    version: number | null; lifecycleOperations: typeof lifecycleOperations[number][]
  }[] = [];
  let last = after;
  for (const raw of rows) {
    const row = record(raw, 'subscription', ['id', 'user_id', 'organization_id', 'is_organization_subscription', 'product_id', 'plan_id', 'status', 'lifecycle_state', 'plan_revision_id']);
    const id = uuid(row.id, 'subscription.id'), planId = uuid(row.plan_id, 'subscription.planId');
    const subject = row.is_organization_subscription === true
      ? { kind: 'organization' as const, id: uuid(row.organization_id, 'subscription.organization') }
      : { kind: 'user' as const, id: uuid(row.user_id, 'subscription.user') };
    if ((last && id <= last) || row.product_id !== product
      || (subject.kind === 'user' ? subject.id !== owner.actorId : subject.id !== owner.orgId)) {
      throw new Error('Subscription discovery returned an inconsistent scope or cursor');
    }
    last = id;
    const status = choice(row.status, 'subscription.status', statuses);
    if (row.lifecycle_state === null) {
      if (row.plan_revision_id !== null) throw new Error('Incomplete lifecycle binding');
      items.push({ id, planId, productId: product, subject, status, kind: 'uninitialized', revisionId: null, version: null, lifecycleOperations: [] });
      continue;
    }
    try {
      const context = await readSubscriptionExecution(env, token, id, product);
      if (context.state.planId !== planId || context.state.revisionId !== row.plan_revision_id
        || context.state.status !== status || context.subject.id !== subject.id || context.subject.kind !== subject.kind) {
        throw new Error('Subscription discovery changed while reading authoritative state');
      }
      const roles = record(context.execution.operationRoles, 'execution.operationRoles',
        context.execution.operationRoles && typeof context.execution.operationRoles === 'object'
          ? Object.keys(context.execution.operationRoles) : []);
      const permitted = lifecycleOperations.filter(operation => {
        if (!Object.hasOwn(roles, operation)) return false; // Absent permission is never granted.
        const configured = array(roles[operation], 'execution.operationRoles').map(value => {
          if (typeof value !== 'string' || !value.trim() || value !== value.trim()) invalid('execution.role', 'explicit role required');
          return value;
        });
        return configured.some(role => context.roles.includes(role));
      });
      items.push({
        id, planId, productId: product, subject, status, kind: 'initialized', revisionId: context.state.revisionId,
        version: integer(context.state.version, 'subscription.version', 1), lifecycleOperations: permitted
      });
    } catch (error) {
      // Denied rows are excluded, but owner failures cannot become a misleading empty catalog.
      if (!(error instanceof SubscriptionExecutionDenied)) throw error;
    }
  }
  // A short page may be a PostgREST row cap; continue until an actual empty page.
  return { schemaVersion: 1 as const, actorId: owner.actorId, productId: product, items, nextCursor: rows.length ? last : null };
}

/** Published display terms only; no raw configuration, authorization grant or checkout quote. */
/**
 * Display terms recorded in the immutable published configuration. Every published offer must carry them,
 * so all surfaces render the same badge, "From" label and tax display; none is inferred from plan names.
 */
export function publishedPresentation(configuration: Record<string, unknown>, tax: TaxPolicy) {
  const value = record(configuration.subscription_presentation, 'publication.presentation', ['schemaVersion', 'priceLabel', 'taxInclusive', 'badge', 'copy']);
  if (value.schemaVersion !== 1) invalid('publication.presentation.schemaVersion', 'unsupported schema version');
  const taxInclusive = value.taxInclusive;
  if (typeof taxInclusive !== 'boolean' || taxInclusive !== (tax.priceDisplay === 'inclusive')) invalid('publication.presentation.taxInclusive', 'published tax display differs from the tax policy');
  return {
    priceLabel: choice(value.priceLabel, 'publication.presentation.priceLabel', ['exact', 'starting_at'] as const), taxInclusive,
    badge: value.badge === null ? null : text(value.badge, 'publication.presentation.badge'),
    // Optional owner card copy (e.g. Hybrid); absent copy is published as null, never invented.
    copy: value.copy === undefined ? null : validatePresentationCopy(value.copy, 'publication.presentation.copy')
  };
}

/**
 * The single published-catalog reader for every surface: customer cards, quotes and the admin view read the same
 * immutable published terms. `audience` null with `allAudiences` false lists nothing (fail closed).
 */
async function readPublishedPage(database: DbClient, product: string, features: unknown, after: string | null,
  include: (audiences: readonly string[]) => boolean) {
  const tax = loadTaxPolicy();
  const rows = await database.query<Record<string, unknown>>(
    'subscription_plan_publications?select=plan_id,revision_id,plans!inner(id,product_id,is_active)'
    + `&plans.product_id=eq.${product}&plans.is_active=eq.true&order=plan_id.asc&limit=${PAGE_SIZE}`
    + (after ? `&plan_id=gt.${after}` : ''), undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length > PAGE_SIZE) throw new Error('Published catalog exceeded response budget');
  let last = after;
  const pointers = rows.map(raw => {
    const pointer = record(raw, 'publication.pointer', ['plan_id', 'revision_id', 'plans']);
    const planId = uuid(pointer.plan_id, 'publication.planId'), revisionId = uuid(pointer.revision_id, 'publication.revisionId');
    const plan = record(pointer.plans, 'publication.plan', ['id', 'product_id', 'is_active']);
    if (plan.id !== planId || plan.product_id !== product || plan.is_active !== true || (last && planId <= last)) {
      throw new Error('Published catalog pointer differs');
    }
    last = planId;
    return { planId, revisionId };
  });
  // Capture pointers once. Events and drafts are immutable, so a later publication cannot mix revisions.
  const events = pointers.length ? await database.query<Record<string, unknown>>(
    'subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan'
    + `&or=(${pointers.map(item => `and(plan_id.eq.${item.planId},revision_id.eq.${item.revisionId})`).join(',')})&limit=${pointers.length + 1}`,
    undefined, 'json-array') : [];
  if (!Array.isArray(events) || events.length !== pointers.length) throw new Error('Published catalog event unavailable');
  const expected = new Map(pointers.map(item => [item.revisionId, item.planId]));
  if (expected.size !== pointers.length) throw new Error('Published catalog revision differs');
  const byRevision = new Map<string, Record<string, unknown>>();
  for (const raw of events) {
    const event = record(raw, 'publication.event', ['plan_id', 'revision_id', 'canonical_plan']);
    const revisionId = uuid(event.revision_id, 'publication.event.revisionId');
    if (expected.get(revisionId) !== event.plan_id || byRevision.has(revisionId)) throw new Error('Published catalog event unavailable');
    byRevision.set(revisionId, event);
  }
  const contexts = pointers.map(({ planId, revisionId }) => {
    const canonical = record(byRevision.get(revisionId)!.canonical_plan, 'publication.canonical', ['id', 'code', 'productId', 'audiences', 'configuration']);
    const snapshot = validatePlanAuthoringSnapshot({
      id: canonical.id, plan_code: canonical.code, product_id: canonical.productId,
      applicable_entities: canonical.audiences, entity_config: canonical.configuration
    }, planId);
    if (snapshot.context.plan.productId !== product) throw new Error('Published catalog product differs');
    const credit = validateCreditAuthoringContext(snapshot.context, snapshot.configuration);
    const registry = createPlanAuthoringRegistry(credit, product, features);
    return { planId, revisionId, snapshot, credit, registry };
  });
  const revisions = await readPlanRevisionBundles(database, contexts);
  const plans = [];
  for (const { planId, revisionId, snapshot, credit, registry } of contexts) {
    const staged = revisions.get(revisionId)!;
    const bundle = validatePlanPublicationCompleteness(staged.bundle, credit, snapshot.configuration, registry);
    if (bundle.draft.id !== revisionId || bundle.draft.plan.id !== planId || bundle.draft.plan.productId !== product) throw new Error('Published catalog revision differs');
    const { id: _, schemaVersion: _schema, ...terms } = bundle.draft;
    if (!include(terms.audiences)) continue;
    plans.push({ ...terms, revisionId, presentation: publishedPresentation(snapshot.configuration, tax) });
  }
  return { tax: { kind: tax.kind, rateBasisPoints: tax.rateBasisPoints, priceDisplay: tax.priceDisplay }, plans, nextCursor: rows.length ? last : null };
}

export async function listPublishedSubscriptionPlans(env: Env, token: unknown, productId: unknown, features: unknown, cursor?: unknown) {
  const owner = await readSubscriptionActor(env, token), product = uuid(productId, 'product'), after = cursorValue(cursor);
  const inputs = loadCatalogOwnerInputs();
  // Each buyer browses only its own audience (owner decision); no organization type means no plans.
  const organizations = await owner.database.query<{ id: string; metadata: unknown }>(
    `organizations?select=id,metadata&id=eq.${owner.orgId}&deleted_at=is.null&limit=2`, undefined, 'json-array');
  if (organizations.length > 1 || (organizations.length === 1 && organizations[0].id !== owner.orgId)) throw new Error('Actor organization differs');
  const audience = resolveCatalogAudience(organizations[0] ?? null, owner.roles, inputs, loadCatalogAudiences(inputs));
  const page = await readPublishedPage(owner.database, product, features, after, audiences => audience !== null && audiences.includes(audience));
  return {
    // The buyer subject for this audience (owner input): individuals buy for themselves, institutions for the organization.
    schemaVersion: 1 as const, actorId: owner.actorId, productId: product, audience,
    subjectKind: audience === null ? null : inputs.audiences.get(audience)!.subjectKind, ...page,
  };
}

/** Super-administrator view of every published, available offer across audiences, from the same reader as customers. */
export async function listPublishedCatalogForAdministration(env: Env, token: unknown, productId: unknown, features: unknown, cursor?: unknown) {
  const actorId = await authorizeSubscriptionAdministrator(env, token);
  const product = uuid(productId, 'product'), after = cursorValue(cursor);
  return { schemaVersion: 1 as const, actorId, productId: product, ...(await readPublishedPage(db(env), product, features, after, () => true)) };
}
