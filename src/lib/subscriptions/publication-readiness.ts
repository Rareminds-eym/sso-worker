import type { DbClient } from '../db';
import { readPlanAuthoringSnapshot, type PlanAuthoringContext } from './authoring-context';
import type { CreditPolicyRegistry } from './credit-policy';
import { validateSubscriptionLifecyclePolicy } from './lifecycle';
import { readPlanRevisionBundle, validatePlanRevisionBundle, type PlanRevisionBundle, type StagedPlanRevisionBundle } from './revision-bundle';
import { array, invalid, record, text } from './validation';

interface PublicationCoverage {
  readonly featureKeys: readonly string[];
  readonly creditAllocations: readonly { readonly poolKey: string; readonly audiences: readonly string[] }[];
}

/** Owner configuration, never an author-supplied list or a plan-name convention. */
function requiredCoverage(
  configuration: Record<string, unknown>, context: PlanAuthoringContext, registry: CreditPolicyRegistry,
): PublicationCoverage {
  const coverage = record(configuration.subscription_publication,
    'publication.coverage', ['schemaVersion', 'requiredFeatureKeys', 'requiredCreditAllocations']);
  if (coverage.schemaVersion !== 1 && coverage.schemaVersion !== 2) {
    invalid('publication.coverage.schemaVersion', 'unsupported schema version');
  }
  const keys = array(coverage.requiredFeatureKeys, 'publication.coverage.requiredFeatureKeys')
    .map(key => text(key, 'publication.coverage.requiredFeatureKeys'));
  if (!keys.length || new Set(keys).size !== keys.length) {
    invalid('publication.coverage.requiredFeatureKeys', 'expected a non-empty unique explicit feature list');
  }
  if (keys.some(key => !registry.catalog.featureTypes.has(key))) {
    invalid('publication.coverage.requiredFeatureKeys', 'every required feature must have an app-owned registered type');
  }
  if (coverage.schemaVersion === 1) {
    if (Object.hasOwn(coverage, 'requiredCreditAllocations')) {
      invalid('publication.coverage', 'allocation coverage requires schema 2');
    }
    // Schema 1 certifies feature terms only; it has never certified separate credit pools.
    return { featureKeys: keys, creditAllocations: [] };
  }
  const scopes = new Set<string>();
  const creditAllocations = array(coverage.requiredCreditAllocations, 'publication.coverage.requiredCreditAllocations').map(value => {
    const allocation = record(value, 'publication.coverage.allocation', ['poolKey', 'audiences']);
    const poolKey = text(allocation.poolKey, 'publication.coverage.allocation.poolKey');
    const pool = registry.pools.get(poolKey);
    if (!pool || registry.catalog.featureTypes.get(pool.featureKey) !== 'metered' || !keys.includes(pool.featureKey)) {
      invalid('publication.coverage.allocation.poolKey', 'required pool must bind a required registered metered feature');
    }
    const audiences = array(allocation.audiences, 'publication.coverage.allocation.audiences')
      .map(value => text(value, 'publication.coverage.allocation.audiences'));
    if (!audiences.length || audiences.some(audience => !context.audiences.includes(audience) || !pool.audiences.has(audience))) {
      invalid('publication.coverage.allocation.audiences', 'expected explicit canonical plan and pool audiences');
    }
    for (const audience of audiences) {
      const scope = JSON.stringify([poolKey, audience]);
      if (scopes.has(scope)) invalid('publication.coverage.requiredCreditAllocations', 'duplicate allocation scope');
      scopes.add(scope);
    }
    return { poolKey, audiences };
  });
  return { featureKeys: keys, creditAllocations };
}

/**
 * Completeness only. A successful result is neither permission nor publication eligibility:
 * approvals, application-rule readiness and an atomic revision transition remain separate.
 * The caller must supply canonical owner context/configuration and current trusted registries.
 */
export function validatePlanPublicationCompleteness(
  value: unknown, context: PlanAuthoringContext, configuration: Record<string, unknown>, registry: CreditPolicyRegistry,
): PlanRevisionBundle {
  const coverage = requiredCoverage(configuration, context, registry);
  const bundle = validatePlanRevisionBundle(value, registry);
  const { draft } = bundle;
  if (draft.plan.id !== context.plan.id || draft.plan.code !== context.plan.code
    || draft.plan.productId !== context.plan.productId) invalid('publication.plan', 'canonical identity differs');
  // Free activation initializes lifecycle state atomically. Certify its required
  // owner policy before publication rather than discovering absent terms at signup.
  if (draft.purchaseMode === 'free') {
    const policy = validateSubscriptionLifecyclePolicy(configuration.subscription_lifecycle);
    if (policy.productId !== context.plan.productId) invalid('publication.lifecycle', 'policy belongs to another product');
    if (policy.billing !== 'not_applicable') invalid('publication.lifecycle', 'free offers require explicit non-billing lifecycle terms');
  }
  const audiences = new Set(context.audiences);
  if (draft.audiences.length !== audiences.size || draft.audiences.some(key => !audiences.has(key))) {
    invalid('publication.audiences', 'revision must cover exactly the canonical plan audiences');
  }
  const grants = new Set(draft.features.map(feature => feature.key));
  if (coverage.featureKeys.some(key => !grants.has(key))) invalid('publication.features', 'revision omits required feature terms');
  for (const allocation of coverage.creditAllocations) {
    if (allocation.audiences.some(audience => !bundle.includedCredits.rules.some(rule =>
      rule.poolKey === allocation.poolKey && rule.audiences.includes(audience)))) {
      invalid('publication.creditAllocations', 'revision omits required included pool and audience terms');
    }
  }
  return bundle;
}

/** Read-only preparation against a persisted immutable revision. Performs no RPC, activation or retry. */
export async function readPlanPublicationCompleteness(
  client: { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> },
  planId: string, revisionId: string, registry: CreditPolicyRegistry,
): Promise<StagedPlanRevisionBundle> {
  const { context, configuration } = await readPlanAuthoringSnapshot(client, planId);
  // Reject absent or invalid coverage before loading immutable terms.
  requiredCoverage(configuration, context, registry);
  const staged = await readPlanRevisionBundle(client, revisionId, registry);
  validatePlanPublicationCompleteness(staged.bundle, context, configuration, registry);
  return staged;
}
