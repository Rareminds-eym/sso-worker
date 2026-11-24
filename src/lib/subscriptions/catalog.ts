import type {
  CatalogRegistry, ConfiguredLimit, EntryPlanBinding, EntryPlanCandidate,
  EntryPlanReference, FeatureGrant, PlanIdentity, PlanRevisionDraft, PriceOption,
} from './types';

export { CatalogValidationError } from './validation';
import { array, choice, integer, invalid, record, text, uuid } from './validation';

const PLAN_CODE = /^pln_[0-9a-f]{32}$/;

function audiences(value: unknown, path: string, allowed: ReadonlySet<string>): readonly string[] {
  const result = array(value, path).map((item, index) => text(item, `${path}[${index}]`));
  if (!result.length || result.some(key => !allowed.has(key)) || new Set(result).size !== result.length) {
    invalid(path, 'expected unique registered audiences');
  }
  return Object.freeze(result);
}

export function validatePlanIdentity(value: unknown): PlanIdentity {
  const input = record(value, 'plan', ['id', 'code', 'productId']);
  const code = text(input.code, 'plan.code');
  if (!PLAN_CODE.test(code)) invalid('plan.code', 'expected an opaque plan code');
  return Object.freeze({ id: uuid(input.id, 'plan.id'), code, productId: uuid(input.productId, 'plan.productId') });
}

/** Identity creation never inserts a row or changes an existing Hybrid identity. */
export function createPlanIdentity(productId: string): PlanIdentity {
  const product = uuid(productId, 'plan.productId');
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const code = `pln_${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}`;
  return Object.freeze({ id: crypto.randomUUID(), code, productId: product });
}

function limit(value: unknown, path: string): ConfiguredLimit {
  const input = record(value, path, ['kind', 'value']);
  const kind = choice(input.kind, `${path}.kind`, ['finite', 'unlimited', 'contract_required']);
  if (kind === 'finite') return Object.freeze({ kind, value: integer(input.value, `${path}.value`) });
  if (Object.hasOwn(input, 'value')) invalid(path, 'only finite limits have a value');
  return Object.freeze({ kind });
}

function feature(value: unknown, path: string, registry: CatalogRegistry, salesOnly: boolean, schemaVersion: 1 | 2): FeatureGrant {
  const input = record(value, path, ['key', 'type', 'enabled', 'limit', 'value']);
  const key = text(input.key, `${path}.key`);
  const type = choice(input.type, `${path}.type`, ['boolean', 'numeric_limit', 'metered', 'enum']);
  if (registry.featureTypes.get(key) !== type) invalid(`${path}.key`, 'feature is unregistered or has a different type');
  if (typeof input.enabled !== 'boolean') invalid(`${path}.enabled`, 'expected boolean');
  if (type === 'enum') {
    if (schemaVersion !== 2 || Object.hasOwn(input, 'limit')) invalid(path, 'enum terms require schema 2 and no numeric limit');
    const options = registry.featureOptions?.get(key);
    if (!options?.size || [...options].some(option => typeof option !== 'string' || !/^[a-z][a-z0-9_]*$/.test(option))) {
      invalid(`${path}.value`, 'enum requires an explicit registered option domain');
    }
    if (!input.enabled) {
      if (input.value !== null) invalid(`${path}.value`, 'disabled enum terms require explicit null');
      return Object.freeze({ key, type, enabled: false, value: null });
    }
    const selected = text(input.value, `${path}.value`);
    if (!options.has(selected)) invalid(`${path}.value`, 'unregistered enum value');
    return Object.freeze({ key, type, enabled: true, value: selected });
  }
  if (Object.hasOwn(input, 'value')) invalid(`${path}.value`, 'only enum features have a selected value');
  if (type === 'boolean') {
    if (Object.hasOwn(input, 'limit')) invalid(`${path}.limit`, 'boolean features do not have limits');
    return Object.freeze({ key, type, enabled: input.enabled });
  }
  if (type === 'metered' && schemaVersion === 2) {
    const allocation = record(input.limit, `${path}.limit`, ['kind']);
    if (allocation.kind !== 'allocation_policy') invalid(`${path}.limit`, 'schema 2 metered quantities belong exclusively to the bound allocation policy');
    return Object.freeze({ key, type, enabled: input.enabled, limit: Object.freeze({ kind: 'allocation_policy' }) });
  }
  const configuredLimit = limit(input.limit, `${path}.limit`);
  if (configuredLimit.kind === 'contract_required' && !salesOnly) invalid(`${path}.limit`, 'unresolved terms require contact sales');
  if (type === 'metered' && configuredLimit.kind === 'unlimited') invalid(`${path}.limit`, 'metered allocations must have explicit finite or negotiated terms');
  return Object.freeze({ key, type, enabled: input.enabled, limit: configuredLimit });
}

function price(value: unknown, path: string, registry: CatalogRegistry, eligibleAudiences: ReadonlySet<string>): PriceOption {
  const input = record(value, path, ['id', 'currency', 'minorUnit', 'amountMinor', 'intervalUnit', 'intervalCount', 'quantityBasis', 'audiences']);
  const currency = text(input.currency, `${path}.currency`);
  const minorUnit = integer(input.minorUnit, `${path}.minorUnit`);
  if (registry.currencies.get(currency) !== minorUnit) invalid(`${path}.currency`, 'currency and precision must match the registered terms');
  return Object.freeze({
    id: uuid(input.id, `${path}.id`), currency, minorUnit,
    amountMinor: integer(input.amountMinor, `${path}.amountMinor`),
    intervalUnit: choice(input.intervalUnit, `${path}.intervalUnit`, ['month', 'year']),
    intervalCount: integer(input.intervalCount, `${path}.intervalCount`, 1),
    quantityBasis: choice(input.quantityBasis, `${path}.quantityBasis`, ['subscription', 'seat']),
    audiences: audiences(input.audiences, `${path}.audiences`, eligibleAudiences),
  });
}

/** Strict authoring contract. Validation neither publishes a plan nor authorizes a purchase. */
export function validatePlanRevision(value: unknown, registry: CatalogRegistry): PlanRevisionDraft {
  const input = record(value, 'revision', ['schemaVersion', 'id', 'plan', 'revisionNumber', 'name', 'audiences', 'purchaseMode', 'prices', 'features']);
  if (input.schemaVersion !== 1 && input.schemaVersion !== 2) invalid('revision.schemaVersion', 'unsupported schema version');
  const schemaVersion = input.schemaVersion;
  const plan = validatePlanIdentity(input.plan);
  if (!registry.productIds.has(plan.productId)) invalid('plan.productId', 'unregistered product');
  const eligible = audiences(input.audiences, 'revision.audiences', registry.audienceKeys);
  const purchaseMode = choice(input.purchaseMode, 'revision.purchaseMode', ['self_service', 'contact_sales', 'free']);
  const prices = array(input.prices, 'revision.prices').map((item, index) => price(item, `revision.prices[${index}]`, registry, new Set(eligible)));
  const priceIds = new Set<string>();
  const priceScopes = new Set<string>();
  for (const option of prices) {
    if (priceIds.has(option.id)) invalid('revision.prices', 'duplicate price identity');
    priceIds.add(option.id);
    for (const audience of option.audiences) {
      const scope = JSON.stringify([audience, option.currency, option.intervalUnit, option.intervalCount, option.quantityBasis]);
      if (priceScopes.has(scope)) invalid('revision.prices', 'ambiguous price scope');
      priceScopes.add(scope);
    }
  }
  if (purchaseMode === 'self_service' && !prices.length) invalid('revision.prices', 'self-service requires explicit prices');
  // Free entry has no billing cadence. Its activation validity is supplied by the
  // entry owner independently of this immutable offer; never invent a year here.
  if (purchaseMode === 'free' && prices.length) invalid('revision.prices', 'free entry cannot contain billing prices');
  if (purchaseMode === 'self_service' && eligible.some(audience => !prices.some(option => option.audiences.includes(audience)))) {
    invalid('revision.prices', 'every self-service audience requires a price');
  }
  const features = array(input.features, 'revision.features').map((item, index) => feature(item, `revision.features[${index}]`, registry, purchaseMode === 'contact_sales', schemaVersion));
  if (new Set(features.map(item => item.key)).size !== features.length) invalid('revision.features', 'duplicate feature');
  return Object.freeze({
    schemaVersion, id: uuid(input.id, 'revision.id'), plan,
    revisionNumber: integer(input.revisionNumber, 'revision.revisionNumber', 1),
    name: text(input.name, 'revision.name'), audiences: eligible, purchaseMode,
    prices: Object.freeze(prices), features: Object.freeze(features),
  });
}

/** Select a configured reference only. The publication owner must supply verified candidate state. */
export function selectEntryPlan(
  productId: string, audience: string, bindings: readonly EntryPlanBinding[], candidates: readonly EntryPlanCandidate[],
): EntryPlanReference {
  const product = uuid(productId, 'entry.productId');
  const key = text(audience, 'entry.audience');
  const matching = bindings.filter(item => uuid(item.productId, 'binding.productId') === product && item.audience === key);
  if (matching.length !== 1) invalid('entry', 'exactly one configured entry plan is required');
  const planId = uuid(matching[0].planId, 'binding.planId');
  const plans = candidates.filter(item => uuid(item.id, 'candidate.id') === planId);
  if (plans.length !== 1) invalid('entry', 'configured plan must resolve exactly once');
  const plan = plans[0];
  if (plan.isActive !== true || uuid(plan.productId, 'candidate.productId') !== product || !plan.audiences.includes(key)) {
    invalid('entry', 'configured plan is inactive or ineligible');
  }
  return Object.freeze({ planId, revisionId: uuid(plan.publishedRevisionId, 'candidate.publishedRevisionId') });
}
