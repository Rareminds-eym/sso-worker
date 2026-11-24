import type { Env } from '../../types';
import { db, type DbClient } from '../db';
import { AuthoringForbidden, authorizeSubscriptionAdministrator, createPlanAuthoringRegistry } from './authoring';
import { readPlanAuthoringSnapshot, validatePlanAuthoringSnapshot } from './authoring-context';
import { validateCreditAuthoringContext } from './credit-authoring-context';
import { prepareIncludedCreditOccurrence, type IncludedCreditOccurrence } from './credit-occurrences';
import { createPlanPublicationProjection, verifyPlanPublicationProjection } from './publication-projection';
import { validatePlanPublicationCompleteness } from './publication-readiness';
import { CatalogPersistenceError, validStagingTimestamp } from './repository';
import { readPlanRevisionBundle } from './revision-bundle';
import { CatalogValidationError, array, invalid, record, uuid } from './validation';

export interface PlanPublicationReceipt {
  readonly planId: string;
  readonly revisionId: string;
  readonly previousRevisionId: string | null;
  readonly publishedBy: string;
  readonly publishedAt: string;
}

/**
 * Internal preparation against recorded publication terms, including historical revisions.
 * The caller must authorize the operation and load the actual subscription/recipient context and
 * application feature registry. Neither a publication event nor this result authorizes allocation.
 * No mutable plan query, latest-revision substitution, write, retry or external HTTP route.
 */
export async function preparePublishedIncludedCreditOccurrence(
  client: { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> },
  planId: unknown, revisionId: unknown, productId: unknown, featureDefinitions: unknown, occurrenceContext: unknown,
): Promise<IncludedCreditOccurrence> {
  const plan = uuid(planId, 'publication.planId'), revision = uuid(revisionId, 'publication.revisionId');
  const product = uuid(productId, 'publication.productId');
  const rows = await client.query('subscription_plan_publication_events?select=plan_id,revision_id,published_by,published_at,canonical_plan'
    + `&plan_id=eq.${plan}&revision_id=eq.${revision}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length !== 1) throw new CatalogPersistenceError('Published revision must resolve exactly once');
  const snapshot = persisted(() => {
    const event = record(rows[0], 'publication.event', ['plan_id', 'revision_id', 'published_by', 'published_at', 'canonical_plan']);
    if (uuid(event.plan_id, 'publication.event.planId') !== plan || uuid(event.revision_id, 'publication.event.revisionId') !== revision
      || !validStagingTimestamp(event.published_at)) invalid('publication.event', 'recorded publication identity or timestamp differs');
    uuid(event.published_by, 'publication.event.publishedBy');
    const canonical = record(event.canonical_plan, 'publication.event.canonical', ['id', 'code', 'productId', 'audiences', 'configuration']);
    const result = validatePlanAuthoringSnapshot({
      id: canonical.id, plan_code: canonical.code, product_id: canonical.productId,
      applicable_entities: canonical.audiences, entity_config: canonical.configuration
    }, plan);
    if (result.context.plan.productId !== product) invalid('publication.event.productId', 'recorded product differs');
    return result;
  });
  const context = persisted(() => validateCreditAuthoringContext(snapshot.context, snapshot.configuration));
  // Features are supplied by the trusted application owner, never inferred from customer input.
  const registry = persisted(() => createPlanAuthoringRegistry(context, product, featureDefinitions));
  const staged = await readPlanRevisionBundle(client, revision, registry).catch(error => {
    if (error instanceof CatalogValidationError) throw new CatalogPersistenceError('Stored published bundle differs');
    throw error;
  });
  const bundle = persisted(() => validatePlanPublicationCompleteness(staged.bundle, context, snapshot.configuration, registry));
  return prepareIncludedCreditOccurrence(bundle, registry, occurrenceContext, context.credit.timePolicies);
}

/** Invalid owner data is an unavailable persistence boundary, not a malformed user request. */
function persisted<T>(read: () => T): T {
  try { return read(); }
  catch (error) {
    if (error instanceof CatalogValidationError) throw new CatalogPersistenceError('Stored publication evidence differs');
    throw error;
  }
}

/** Private service arguments contain owner-loaded features; HTTP callers may supply references only. */
async function preparation(env: Env, token: unknown, planId: unknown, revisionId: unknown,
  productId: unknown, featureDefinitions: unknown) {
  const actor = await authorizeSubscriptionAdministrator(env, token);
  const product = uuid(productId, 'publication.productId');
  const snapshot = await readPlanAuthoringSnapshot(db(env), uuid(planId, 'publication.planId'));
  if (snapshot.context.plan.productId !== product) invalid('publication.productId', 'canonical product differs');
  const context = validateCreditAuthoringContext(snapshot.context, snapshot.configuration);
  const definitions = array(featureDefinitions, 'publication.features').map(value => {
    const feature = record(value, 'publication.feature', ['id', 'key', 'type', 'options']);
    return { feature, id: uuid(feature.id, 'publication.feature.id') };
  });
  const registry = createPlanAuthoringRegistry(context, product, definitions.map(({ feature }) => {
    const { id: _, ...terms } = feature;
    return terms;
  }));
  const staged = await readPlanRevisionBundle(db(env), uuid(revisionId, 'publication.revisionId'), registry);
  const features = definitions.map(({ feature, id }) => {
    // The common owner parser has already validated each key/type/options pair.
    const key = feature.key;
    if (typeof key !== 'string') invalid('publication.feature.key', 'invalid owner key');
    const type = registry.catalog.featureTypes.get(key);
    if (!type) invalid('publication.feature.type', 'unregistered owner type');
    return { id, key, type };
  });
  const projection = createPlanPublicationProjection(staged.bundle, context, snapshot.configuration, registry, features);
  return { actor, snapshot, context, registry, features, projection };
}

export async function preparePlanPublication(env: Env, token: unknown, planId: unknown,
  revisionId: unknown, productId: unknown, features: unknown) {
  try {
    const result = await preparation(env, token, planId, revisionId, productId, features);
    return { kind: 'prepared' as const, projection: result.projection, preparedBy: result.actor };
  } catch (error) {
    if (error instanceof AuthoringForbidden) return { kind: 'forbidden' as const };
    if (error instanceof CatalogValidationError) return { kind: 'invalid' as const };
    throw error;
  }
}

async function applicationProjection(env: Env, planId: string, revisionId: string): Promise<unknown> {
  if (typeof env.SKILLPASSPORT_URL !== 'string' || !env.INTERNAL_WEBHOOK_SECRET) {
    throw new CatalogPersistenceError('Application publication owner is not configured');
  }
  const origin = new URL(env.SKILLPASSPORT_URL);
  if (origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/'
    || (origin.protocol !== 'https:' && !(origin.protocol === 'http:'
      && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)))) {
    throw new CatalogPersistenceError('Application publication owner is invalid');
  }
  const target = new URL('/api/internal/subscriptions/projection', origin);
  target.searchParams.set('planId', planId); target.searchParams.set('revisionId', revisionId);
  const response = await fetch(target, {
    // Workers reject redirect 'error'; 'manual' surfaces any 3xx, which the exact 200 check below refuses.
    method: 'GET', redirect: 'manual',
    headers: { Authorization: `Bearer ${env.INTERNAL_WEBHOOK_SECRET}`, Accept: 'application/json' },
    signal: AbortSignal.timeout(15000)
  });
  if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') {
    await response.body?.cancel(); throw new CatalogPersistenceError('Application publication readback failed');
  }
  const reader = response.body?.getReader();
  if (!reader) throw new CatalogPersistenceError('Application publication readback is empty');
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
  let size = 0, body = '';
  try {
    for (; ;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 8388608) { await reader.cancel(); throw new CatalogPersistenceError('Application publication readback exceeds budget'); }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
  } finally { reader.releaseLock(); }
  return JSON.parse(body);
}

/**
 * Publish a catalog pointer only after independent owner readback. Application preparation is
 * immutable; failure here leaves it staged. No activation, allocation, retry or compensation.
 */
export async function publishPlanRevision(env: Env, token: unknown, planId: unknown, revisionId: unknown,
  expectedPreviousRevisionId: unknown, productId: unknown, featureDefinitions: unknown) {
  try {
    const result = await preparation(env, token, planId, revisionId, productId, featureDefinitions);
    const previous = expectedPreviousRevisionId === null ? null : uuid(expectedPreviousRevisionId, 'publication.previousRevisionId');
    const draft = result.projection.bundle.draft;
    const rawStored = await applicationProjection(env, draft.plan.id, draft.id);
    const stored = persisted(() => record(rawStored, 'publication.application', ['projection', 'stagedBy', 'stagedAt']));
    persisted(() => uuid(stored.stagedBy, 'publication.application.stagedBy'));
    if (!validStagingTimestamp(stored.stagedAt)) throw new CatalogPersistenceError('Invalid application staging timestamp');
    persisted(() => verifyPlanPublicationProjection(stored.projection, result.projection.bundle, result.context,
      result.snapshot.configuration, result.registry, result.features));
    const rawReceipt = await db(env).rpc('publish_subscription_plan_revision', {
      p_plan_id: draft.plan.id, p_revision_id: draft.id, p_expected_previous_revision_id: previous,
      p_actor_id: result.actor, p_expected_plan: {
        ...draft.plan, audiences: result.context.audiences,
        configuration: result.snapshot.configuration
      },
    });
    const value = persisted(() => record(rawReceipt, 'publication.receipt', ['planId', 'revisionId', 'previousRevisionId', 'publishedBy', 'publishedAt']));
    const receipt: PlanPublicationReceipt = persisted(() => ({
      planId: uuid(value.planId, 'publication.receipt.planId'), revisionId: uuid(value.revisionId, 'publication.receipt.revisionId'),
      previousRevisionId: value.previousRevisionId === null ? null : uuid(value.previousRevisionId, 'publication.receipt.previousRevisionId'),
      publishedBy: uuid(value.publishedBy, 'publication.receipt.publishedBy'), publishedAt: String(value.publishedAt),
    }));
    if (!validStagingTimestamp(value.publishedAt) || receipt.planId !== draft.plan.id || receipt.revisionId !== draft.id
      || receipt.previousRevisionId !== previous || receipt.publishedBy !== result.actor) {
      throw new CatalogPersistenceError('Publication receipt differs from the authorized transition');
    }
    return { kind: 'published' as const, receipt };
  } catch (error) {
    if (error instanceof AuthoringForbidden) return { kind: 'forbidden' as const };
    if (error instanceof CatalogValidationError) return { kind: 'invalid' as const };
    throw error;
  }
}

/** Independent publication proof for catalog availability: the recorded canonical plan, the
 * immutable staged bundle and the application projection must agree. Authorization is the caller's. */
export async function readVerifiedPlanPublication(env: Env, planId: unknown, revisionId: unknown, productId: unknown, featureDefinitions: unknown) {
  const plan = uuid(planId, 'availability.planId'), revision = uuid(revisionId, 'availability.revisionId'), product = uuid(productId, 'availability.productId');
  const rows = await db(env).query<Record<string, unknown>>('subscription_plan_publication_events?select=plan_id,revision_id,canonical_plan'
    + `&plan_id=eq.${plan}&revision_id=eq.${revision}&limit=2`, undefined, 'json-array');
  if (rows.length !== 1) throw new CatalogPersistenceError('Published revision must resolve exactly once');
  const canonical = persisted(() => record(rows[0].canonical_plan, 'availability.canonical', ['id', 'code', 'productId', 'audiences', 'configuration']));
  const snapshot = persisted(() => validatePlanAuthoringSnapshot({
    id: canonical.id, plan_code: canonical.code, product_id: canonical.productId,
    applicable_entities: canonical.audiences, entity_config: canonical.configuration
  }, plan));
  if (snapshot.context.plan.productId !== product) throw new CatalogPersistenceError('Published product differs');
  const context = persisted(() => validateCreditAuthoringContext(snapshot.context, snapshot.configuration));
  const definitions = array(featureDefinitions, 'availability.features').map(value => record(value, 'availability.feature', ['id', 'key', 'type', 'options']));
  const registry = persisted(() => createPlanAuthoringRegistry(context, product, definitions.map(({ id: _, ...terms }) => terms)));
  const staged = await readPlanRevisionBundle(db(env), revision, registry);
  const features = definitions.map(feature => ({
    id: uuid(feature.id, 'availability.feature.id'), key: String(feature.key),
    type: registry.catalog.featureTypes.get(String(feature.key)) ?? invalid('availability.feature.type', 'unregistered owner type')
  }));
  const raw = await applicationProjection(env, plan, revision);
  const projection = persisted(() => record(raw, 'availability.application', ['projection', 'stagedBy', 'stagedAt']));
  persisted(() => verifyPlanPublicationProjection(projection.projection, staged.bundle, context, snapshot.configuration, registry, features));
  return { planId: plan, revisionId: revision, productId: product, canonicalPlan: rows[0].canonical_plan };
}
