import type { PlanAuthoringContext } from './authoring-context';
import type { CreditPolicyRegistry } from './credit-policy';
import { validatePlanPublicationCompleteness } from './publication-readiness';
import type { PlanRevisionBundle } from './revision-bundle';
import type { FeatureType } from './types';
import { array, invalid, record, text, uuid } from './validation';

/** Service contract for the application's existing plan_entitlements value columns. */
export interface PublicationEntitlement {
  readonly plan_id: string;
  readonly feature_id: string;
  readonly is_enabled: boolean;
  readonly value_numeric: number | null;
  readonly value_text: string | null;
}

export interface PlanPublicationProjection {
  readonly schemaVersion: 1;
  /** Retain all prices, audiences and credit rules; row equality alone cannot bind a revision. */
  readonly bundle: PlanRevisionBundle;
  readonly entitlements: readonly PublicationEntitlement[];
}

/** Application owner inventory; IDs and types must never come from the draft submitter. */
export interface PublicationFeatureDefinition {
  readonly id: string;
  readonly key: string;
  readonly type: FeatureType;
}

/**
 * Compile desired state only. No database write, allocation, authorization or readiness assertion.
 * The application owns applying these rows and retaining the bound revision and credit policy.
 */
export function createPlanPublicationProjection(
  value: unknown, context: PlanAuthoringContext, configuration: Record<string, unknown>,
  registry: CreditPolicyRegistry, definitions: readonly PublicationFeatureDefinition[],
): PlanPublicationProjection {
  const bundle = validatePlanPublicationCompleteness(value, context, configuration, registry);
  // Sales-led offers may publish negotiated ("Custom") terms for display only: no checkout price,
  // contract-required seats project as disabled rows and contract-required credit rules are retained
  // in the bundle but refused by allocation until a signed customer contract resolves them.
  const salesLed = bundle.draft.purchaseMode === 'contact_sales' && bundle.draft.prices.length === 0;
  if (!salesLed && bundle.includedCredits.rules.some(rule => rule.quantity.kind === 'contract_required')) {
    invalid('projection.credits', 'unresolved contract quantities cannot be projected as executable allocations');
  }
  const ids = new Set<string>(), features = new Map<string, string>();
  for (const value of array(definitions, 'projection.features')) {
    const definition = record(value, 'projection.features', ['id', 'key', 'type']);
    const id = uuid(definition.id, 'projection.features.id');
    const key = text(definition.key, 'projection.features.key');
    if (ids.has(id) || features.has(key)) invalid('projection.features', 'duplicate owner feature identity');
    if (!registry.catalog.featureTypes.has(key) || registry.catalog.featureTypes.get(key) !== definition.type) {
      invalid('projection.features', 'owner feature type differs from the trusted registry');
    }
    ids.add(id); features.set(key, id);
  }
  const entitlements = bundle.draft.features.map(grant => {
    const featureId = features.get(grant.key);
    if (!featureId) invalid('projection.features', 'revision feature has no application-owned identity');
    let numeric: number | null = null, selected: string | null = null, enabled = grant.enabled;
    if (grant.type === 'enum') selected = grant.value;
    if (grant.type === 'numeric_limit') {
      if (grant.limit.kind === 'contract_required') {
        // NULL means unlimited to the current consumer. Negotiated terms cannot be encoded as NULL,
        // so a sales-led display-only row is disabled; any other offer must resolve the limit first.
        if (!salesLed) invalid('projection.entitlements', 'unresolved contract limits cannot be projected as executable grants');
        enabled = false;
      }
      if (grant.limit.kind === 'finite') numeric = grant.limit.value;
    }
    // Metered quantities stay in their bound policy: different recipients/cadences cannot be summed.
    return Object.freeze({
      plan_id: bundle.draft.plan.id, feature_id: featureId,
      is_enabled: enabled, value_numeric: numeric, value_text: selected
    });
  });
  return Object.freeze({ schemaVersion: 1, bundle, entitlements: Object.freeze(entitlements) });
}

/**
 * Compare an owner-read projection with desired immutable state. This proves equality of supplied
 * values only: an authenticated transport, atomic owner transaction and publication pointer are
 * separate requirements. Never accept a client acknowledgement as proof of persisted readiness.
 */
export function verifyPlanPublicationProjection(
  value: unknown, expectedBundle: unknown, context: PlanAuthoringContext,
  configuration: Record<string, unknown>, registry: CreditPolicyRegistry,
  definitions: readonly PublicationFeatureDefinition[],
): PlanPublicationProjection {
  const expected = createPlanPublicationProjection(expectedBundle, context, configuration, registry, definitions);
  const input = record(value, 'projection', ['schemaVersion', 'bundle', 'entitlements']);
  if (input.schemaVersion !== 1) invalid('projection.schemaVersion', 'unsupported schema version');
  const actual = validatePlanPublicationCompleteness(input.bundle, context, configuration, registry);
  if (JSON.stringify(actual) !== JSON.stringify(expected.bundle)) {
    invalid('projection.bundle', 'immutable revision terms differ');
  }
  const rows = array(input.entitlements, 'projection.entitlements');
  if (rows.length !== expected.entitlements.length) invalid('projection.entitlements', 'feature coverage differs');
  const remaining = new Map(expected.entitlements.map(row => [row.feature_id, row]));
  for (const value of rows) {
    const row = record(value, 'projection.entitlement', ['plan_id', 'feature_id', 'is_enabled', 'value_numeric', 'value_text']);
    const featureId = uuid(row.feature_id, 'projection.entitlement.feature_id');
    const desired = remaining.get(featureId);
    if (!desired || uuid(row.plan_id, 'projection.entitlement.plan_id') !== desired.plan_id
      || row.is_enabled !== desired.is_enabled || row.value_numeric !== desired.value_numeric
      || row.value_text !== desired.value_text) invalid('projection.entitlements', 'stored grant differs or is duplicated');
    remaining.delete(featureId);
  }
  return expected;
}
