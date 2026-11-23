import { db } from '../db';
import type { Env } from '../../types';
import { AuthoringForbidden, authorizeSubscriptionAdministrator, createPlanAuthoringRegistry } from './authoring';
import { loadBrdCatalog } from './brd-catalog';
import { loadCatalogOwnerInputs, resolveCatalogOwnerContract, type SavedCatalogProfile } from './catalog-owner-inputs';
import { installCanonicalCatalog, prepareCatalogInstallation, type CatalogContractOwner, type CatalogProfileProposal } from './catalog-rollout';
import { commitCatalogAvailability, commitCatalogTransition, prepareCatalogAvailability, prepareCatalogTransition, prepareHybridIdentityTransition,
  type CatalogTransitionSnapshot } from './catalog-transition';
import { validateCreditAuthoringContext } from './credit-authoring-context';
import { validatePlanAuthoringSnapshot } from './authoring-context';
import { buildHybridCatalogOffer, loadHybridOffer, validateHybridIdentities } from './hybrid-offer';
import { createPlanPublicationProjection } from './publication-projection';
import { validatePlanRevisionBundle } from './revision-bundle';
import { readVerifiedPlanPublication } from './publication';
import { CatalogValidationError, array, invalid, record, text, uuid } from './validation';

/** PostgREST page size; the local and remote owners cap responses at 1000 rows. */
const PAGE_SIZE = 1000;
type Database = ReturnType<typeof db>;

function outcome<T>(run: () => Promise<T>) {
  return run().catch(error => {
    if (error instanceof AuthoringForbidden) return { kind: 'forbidden' as const };
    if (error instanceof CatalogValidationError) return { kind: 'invalid' as const };
    throw error;
  });
}
/** Owner-loaded feature registry entries arrive with application ids; the registry parser takes key/type/options only. */
function registryFeatures(featureDefinitions: unknown) {
  return array(featureDefinitions, 'administration.features').map(value => {
    const { id: _, ...terms } = record(value, 'administration.feature', ['id', 'key', 'type', 'options']);
    return terms;
  });
}
async function pages<T>(database: Database, path: (after: string | null) => string): Promise<T[]> {
  const rows: T[] = [];
  for (let after: string | null = null; ;) {
    const page: (T & { id: string })[] = await database.query<T & { id: string }>(path(after), undefined, 'json-array');
    rows.push(...page);
    if (page.length < PAGE_SIZE) return rows;
    after = page[page.length - 1].id;
  }
}

/** Install the 21 approved BRD profiles as inactive candidates through the existing owner RPC. */
export function installSubscriptionCatalog(env: Env, accessToken: unknown, productId: unknown, value: unknown, featureDefinitions: unknown) {
  return outcome(async () => {
    const actor = await authorizeSubscriptionAdministrator(env, accessToken);
    const product = uuid(productId, 'installation.productId');
    const request = record(value, 'installation.request', ['schemaVersion', 'operationId', 'hybridPlanId', 'approvalReference', 'profiles']);
    const catalog = loadBrdCatalog(), inputs = loadCatalogOwnerInputs(), database = db(env);
    // `state` is the reviewed preparation label; it grants nothing and is not forwarded.
    const saved = array(request.profiles, 'installation.profiles').map(profile => {
      const { state: _, ...rest } = record(profile, 'installation.profile', ['reference', 'state', 'cells', 'unresolved', 'bundle', 'proposedOwnerConfiguration']);
      return rest as unknown as SavedCatalogProfile;
    });
    const roles = new Set((await database.query<{ name: string }>('roles?select=name&limit=1000', undefined, 'json-array')).map(row => text(row.name, 'installation.role')));
    const features = registryFeatures(featureDefinitions);
    const resolved = new Map(catalog.profiles.map(source => {
      const profile = saved.find(item => item.reference === source.reference);
      if (!profile) return [source.reference, null] as const;
      return [source.reference, resolveCatalogOwnerContract(source, profile, inputs, catalog.currency)] as const;
    }));
    const owner = (reference: string): CatalogContractOwner => {
      const entry = resolved.get(reference);
      if (!entry) invalid('installation.profiles', 'source mapping absent');
      const draft = record((entry.proposal.bundle as Record<string, unknown>).draft, 'installation.draft', ['schemaVersion', 'id', 'plan', 'revisionNumber', 'name', 'audiences', 'purchaseMode', 'prices', 'features']);
      const plan = record(draft.plan, 'installation.plan', ['id', 'code', 'productId']);
      const context = { schemaVersion: 1 as const, plan: { id: uuid(plan.id, 'installation.plan.id'), code: text(plan.code, 'installation.plan.code'), productId: uuid(plan.productId, 'installation.plan.productId') },
        audiences: array(draft.audiences, 'installation.audiences').map(item => text(item, 'installation.audience')),
        currencies: [{ code: catalog.currency.code, minorUnit: catalog.currency.minorUnit }] };
      const registry = createPlanAuthoringRegistry(validateCreditAuthoringContext(context, entry.configuration), product, features);
      return { context, configuration: entry.configuration, registry, registeredRoles: roles, monthlyTimePolicyId: entry.monthlyTimePolicyId };
    };
    const proposals: CatalogProfileProposal[] = catalog.profiles.map(source => {
      const entry = resolved.get(source.reference);
      if (!entry) invalid('installation.profiles', 'source mapping absent');
      return entry.proposal;
    });
    const plans = await database.query<Record<string, unknown>>(`plans?select=*&product_id=eq.${product}&limit=${PAGE_SIZE}`, undefined, 'json-array');
    const candidateIds = proposals.map(proposal => text(((proposal.bundle as Record<string, Record<string, Record<string, unknown>>>).draft.plan).id, 'installation.plan.id'));
    const purchased = await database.query<{ plan_id: string }>(`subscriptions?select=plan_id&plan_id=in.(${candidateIds.join(',')})&limit=${PAGE_SIZE}`, undefined, 'json-array');
    const published = await database.query<{ plan_id: string }>(`subscription_plan_publications?select=plan_id&limit=${PAGE_SIZE}`, undefined, 'json-array');
    const entries = catalog.profiles.map((source, index) => {
      const trusted = owner(source.reference);
      const proposal = proposals[index];
      const draft = (proposal.bundle as { draft: { name: string; audiences: string[] } }).draft;
      const audience = inputs.audiences.get(draft.audiences[0]);
      if (!audience || draft.audiences.some(item => inputs.audiences.get(item)?.businessType !== audience.businessType)) invalid('installation.audience', 'one business type per candidate required');
      const existing = plans.filter(row => row.id === trusted.context.plan.id);
      return { reference: source.reference, expected: existing.length === 1 ? existing[0] : null,
        plan: { id: trusted.context.plan.id, plan_code: trusted.context.plan.code, product_id: product, name: draft.name,
          business_type: audience.businessType, applicable_entities: draft.audiences, pricing_matrix: {}, base_features: [],
          entity_config: trusted.configuration, display_order: index, is_active: false as const } };
    });
    const command = prepareCatalogInstallation({ schemaVersion: 1, operationId: request.operationId, productId: product,
      hybridPlanId: request.hybridPlanId, approvalReference: request.approvalReference, entries }, catalog, proposals, owner,
      { productId: product, hybridPlanId: uuid(request.hybridPlanId, 'installation.hybridPlanId'), plans,
        purchasedPlanIds: new Set(purchased.map(row => row.plan_id)), publishedPlanIds: new Set(published.map(row => row.plan_id)) }, actor);
    return { kind: 'installed' as const, receipt: await installCanonicalCatalog(database, command) };
  });
}

async function transitionSnapshot(database: Database, product: string, hybridPlanId: string, planIds: readonly string[]): Promise<CatalogTransitionSnapshot> {
  const ids = [...new Set([...planIds, hybridPlanId])];
  const plans = (await database.query<{ id: string; plan_code: string; is_active: boolean }>(
    `plans?select=id,plan_code,is_active&product_id=eq.${product}&id=in.(${ids.join(',')})&limit=${PAGE_SIZE}`, undefined, 'json-array'))
    .map(row => ({ id: row.id, code: row.plan_code, active: row.is_active }));
  const publications = (await database.query<{ plan_id: string; revision_id: string }>(
    `subscription_plan_publications?select=plan_id,revision_id&plan_id=in.(${ids.join(',')})&limit=${PAGE_SIZE}`, undefined, 'json-array'))
    .map(row => ({ planId: row.plan_id, revisionId: row.revision_id, productId: product }));
  // Mirrors the owner SQL purchase snapshot field-for-field; the database repeats the comparison under locks.
  const columns = 'id,plan_id,plan_code,plan_type,plan_amount,billing_cycle,features,subscription_start_date,subscription_end_date,plan_revision_id,lifecycle_state,lifecycle_policy,metadata';
  const subscriptions = (await pages<Record<string, unknown>>(database, after => `subscriptions?select=${columns}&product_id=eq.${product}`
    + `&plan_id=in.(${ids.join(',')})&order=id.asc&limit=${PAGE_SIZE}` + (after ? `&id=gt.${after}` : '')))
    .map(row => ({ id: String(row.id), planId: String(row.plan_id), purchasedTerms: { planCode: row.plan_code, planType: row.plan_type,
      amount: row.plan_amount, billingCycle: row.billing_cycle, features: row.features, startsAt: row.subscription_start_date,
      endsAt: row.subscription_end_date, revisionId: row.plan_revision_id, lifecycleState: row.lifecycle_state,
      lifecyclePolicy: row.lifecycle_policy, metadata: row.metadata } }));
  return { productId: product, hybridPlanId, plans, publications, subscriptions };
}

/** Activate exactly the listed inactive, owner-published revisions after independent projection proof. */
export function makeSubscriptionCatalogAvailable(env: Env, accessToken: unknown, productId: unknown, value: unknown, featureDefinitions: unknown) {
  return outcome(async () => {
    const actor = await authorizeSubscriptionAdministrator(env, accessToken);
    const product = uuid(productId, 'availability.productId'), database = db(env);
    const request = record(value, 'availability.request', ['schemaVersion', 'operationId', 'hybridPlanId', 'approvalReference', 'entries']);
    const entries = array(request.entries, 'availability.entries').map(item => record(item, 'availability.entry', ['planId', 'revisionId', 'expectedActive']));
    const now = Date.now();
    const snapshot = await transitionSnapshot(database, product, uuid(request.hybridPlanId, 'availability.hybridPlanId'), entries.map(entry => uuid(entry.planId, 'availability.planId')));
    const command = await prepareCatalogAvailability({ ...request, productId: product, effectiveAt: now }, snapshot, actor,
      (planId, revisionId) => readVerifiedPlanPublication(env, planId, revisionId, product, featureDefinitions), now);
    return { kind: 'available' as const, receipt: await commitCatalogAvailability(database, command) };
  });
}

/** Retire legacy offers by explicit replacement; purchases are only compared, never rewritten. */
export function retireLegacySubscriptionCatalog(env: Env, accessToken: unknown, productId: unknown, value: unknown) {
  return outcome(async () => {
    const actor = await authorizeSubscriptionAdministrator(env, accessToken);
    const product = uuid(productId, 'transition.productId'), database = db(env);
    const request = record(value, 'transition.request', ['schemaVersion', 'operationId', 'hybridPlanId', 'approvalReference', 'replacements']);
    const replacements = array(request.replacements, 'transition.replacements').map(item => record(item, 'transition.replacement', ['legacyPlanId', 'planId', 'revisionId']));
    const hybridPlanId = uuid(request.hybridPlanId, 'transition.hybridPlanId');
    const snapshot = await transitionSnapshot(database, product, hybridPlanId,
      replacements.flatMap(row => [uuid(row.legacyPlanId, 'transition.legacyPlanId'), uuid(row.planId, 'transition.planId')]));
    const now = Date.now();
    const { command } = prepareCatalogTransition({ schemaVersion: 1, operationId: request.operationId, productId: product, actorId: actor,
      approvalReference: request.approvalReference, effectiveAt: now, hybridPlanId, expectedPlans: snapshot.plans,
      replacements: request.replacements, retainedSubscriptions: snapshot.subscriptions,
      preservation: 'retain_original_purchases_and_history' }, snapshot, now);
    return { kind: 'retired' as const, receipt: await commitCatalogTransition(database, command) };
  });
}

/**
 * Adopt the retained Hybrid plan as a sales-led catalog offer (owner decision 1a): one atomic owner RPC sets the
 * opaque canonical code and the owner subscription configuration. The request carries reviewed identities only;
 * every term comes from owner configuration and is compiled with the production validators before any write.
 */
export function adoptHybridCatalogOffer(env: Env, accessToken: unknown, productId: unknown, value: unknown, featureDefinitions: unknown) {
  return outcome(async () => {
    const actor = await authorizeSubscriptionAdministrator(env, accessToken);
    const product = uuid(productId, 'hybridAdoption.productId'), database = db(env);
    const request = record(value, 'hybridAdoption.request', ['schemaVersion', 'operationId', 'identityOperationId', 'hybridPlanId', 'approvalReference', 'identities']);
    if (request.schemaVersion !== 1) invalid('hybridAdoption.schemaVersion', 'unsupported schema version');
    const operationId = uuid(request.operationId, 'hybridAdoption.operationId'), identityOperationId = uuid(request.identityOperationId, 'hybridAdoption.identityOperationId');
    if (operationId === identityOperationId) invalid('hybridAdoption.identityOperationId', 'distinct operation identities required');
    const hybridPlanId = uuid(request.hybridPlanId, 'hybridAdoption.hybridPlanId');
    const approvalReference = text(request.approvalReference, 'hybridAdoption.approvalReference');
    const identities = validateHybridIdentities(request.identities);
    const inputs = loadCatalogOwnerInputs(), offer = loadHybridOffer(inputs);
    const rows = await database.query<{ id: string; plan_code: string; product_id: string; is_active: boolean; applicable_entities: unknown; entity_config: unknown }>(
      `plans?select=id,plan_code,product_id,is_active,applicable_entities,entity_config&id=eq.${hybridPlanId}&limit=2`, undefined, 'json-array');
    if (rows.length !== 1 || rows[0].product_id !== product || rows[0].is_active !== true) invalid('hybridAdoption.plan', 'retained active Hybrid required');
    const current = record(rows[0].entity_config, 'hybridAdoption.currentConfiguration', rows[0].entity_config && typeof rows[0].entity_config === 'object' ? Object.keys(rows[0].entity_config) : []);
    if (Object.keys(current).some(key => key.startsWith('subscription_'))) invalid('hybridAdoption.currentConfiguration', 'Hybrid already carries owner subscription configuration');
    const entities = array(rows[0].applicable_entities, 'hybridAdoption.audiences').map(item => text(item, 'hybridAdoption.audience'));
    if (JSON.stringify([...entities].sort()) !== JSON.stringify([...offer.audiences].sort())) invalid('hybridAdoption.audiences', 'approved Hybrid audiences differ from the retained plan');
    // Hybrid has never been staged, so its first catalog revision is 1; staging re-checks the next number.
    const { configuration, bundle } = buildHybridCatalogOffer(offer, inputs, hybridPlanId, product, identities, 1);
    const snapshot = validatePlanAuthoringSnapshot({ id: hybridPlanId, plan_code: identities.targetCode, product_id: product, applicable_entities: entities, entity_config: configuration }, hybridPlanId);
    const context = validateCreditAuthoringContext(snapshot.context, snapshot.configuration);
    const definitions = array(featureDefinitions, 'hybridAdoption.features').map(item => record(item, 'hybridAdoption.feature', ['id', 'key', 'type', 'options']));
    const registry = createPlanAuthoringRegistry(context, product, definitions.map(({ id: _, ...terms }) => terms));
    createPlanPublicationProjection(validatePlanRevisionBundle(bundle, registry), context, snapshot.configuration, registry,
      definitions.map(feature => ({ id: uuid(feature.id, 'hybridAdoption.feature.id'), key: String(feature.key),
        type: registry.catalog.featureTypes.get(String(feature.key)) ?? invalid('hybridAdoption.feature.type', 'unregistered owner type') })));
    const now = Date.now();
    const transition = await transitionSnapshot(database, product, hybridPlanId, []);
    const identity = prepareHybridIdentityTransition({ schemaVersion: 1, operationId: identityOperationId, productId: product, actorId: actor, approvalReference,
      effectiveAt: now, hybridPlanId, expectedCode: rows[0].plan_code, targetCode: identities.targetCode,
      retainedSubscriptions: transition.subscriptions.filter(row => row.planId === hybridPlanId), preservation: 'retain_original_purchases_and_history' }, transition, now);
    const raw = record(await database.rpc('adopt_subscription_hybrid_catalog_offer', { p_command: { schemaVersion: 1, operationId, productId: product, actorId: actor,
      approvalReference, hybridPlanId, identity: identity.command, expectedConfiguration: current, configuration } }),
    'hybridAdoption.receipt', ['operationId', 'identity', 'plan', 'configurationKeys']);
    const plan = record(raw.plan, 'hybridAdoption.receipt.plan', ['id', 'code', 'productId']);
    const identityReceipt = record(raw.identity, 'hybridAdoption.receipt.identity', ['operationId', 'command', 'plan', 'preservedSubscriptionIds']);
    if (raw.operationId !== operationId || identityReceipt.operationId !== identityOperationId || plan.id !== hybridPlanId
      || plan.code !== identities.targetCode || plan.productId !== product
      || JSON.stringify(raw.configurationKeys) !== JSON.stringify(Object.keys(configuration).sort())) invalid('hybridAdoption.receipt', 'owner acknowledgement differs');
    return { kind: 'adopted' as const, receipt: { operationId, plan: { id: hybridPlanId, code: identities.targetCode, productId: product },
      preservedSubscriptionIds: identity.preservedSubscriptionIds, configurationKeys: Object.keys(configuration).sort() } };
  });
}
