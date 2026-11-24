import { validatePlanRevision } from './catalog';
import type { CatalogRegistry, PlanRevisionDraft } from './types';
import { array, choice, integer, invalid, record, text, uuid } from './validation';

export interface CreditPoolDefinition {
  readonly featureKey: string;
  readonly recipient: 'subscriber' | 'organization' | 'managed_learner';
  readonly audiences: ReadonlySet<string>;
}

/** Trusted owner-supplied references. An approval ID's existence is not inferred from client input. */
export interface CreditPolicyRegistry {
  readonly catalog: CatalogRegistry;
  readonly pools: ReadonlyMap<string, CreditPoolDefinition>;
  readonly timePolicyIds: ReadonlySet<string>;
  readonly rolloverApprovalIds: ReadonlySet<string>;
  readonly expiryApprovalIds: ReadonlySet<string>;
}

export type CreditCadence =
  | { readonly kind: 'activation' | 'purchase' | 'subscription_period' }
  | { readonly kind: 'monthly'; readonly timePolicyId: string };
export type CreditExpiry =
  | { readonly kind: 'subscription_end' | 'allocation_period_end' }
  | { readonly kind: 'after_months'; readonly months: number; readonly timePolicyId: string };
export type CreditQuantity = { readonly kind: 'finite'; readonly value: number } | { readonly kind: 'contract_required' };
export type CreditRollover = { readonly kind: 'none' } | { readonly kind: 'approved'; readonly approvalId: string };

export interface CreditAllocationRule {
  readonly id: string;
  readonly featureKey: string;
  readonly poolKey: string;
  readonly recipient: CreditPoolDefinition['recipient'];
  readonly audiences: readonly string[];
  /** Units per recipient per configured allocation occurrence, not an aggregate tenant balance. */
  readonly quantity: CreditQuantity;
  readonly cadence: CreditCadence;
  readonly expiry: CreditExpiry;
  readonly rollover: CreditRollover;
  readonly expiryApprovalId?: string;
}

/** Authoring contract; only a revision bundle persists included terms. Never executable allocation. */
export interface CreditAllocationPolicy {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly revisionId: string;
  readonly funding: 'included' | 'top_up';
  readonly rules: readonly CreditAllocationRule[];
}

function reference(value: unknown, path: string, registered: ReadonlySet<string>): string {
  const id = uuid(value, path);
  if (!registered.has(id)) invalid(path, 'unregistered policy or approval reference');
  return id;
}

function cadence(value: unknown, path: string, registry: CreditPolicyRegistry): CreditCadence {
  const input = record(value, path, ['kind', 'timePolicyId']);
  const kind = choice(input.kind, `${path}.kind`, ['activation', 'purchase', 'subscription_period', 'monthly']);
  if (kind === 'monthly') return Object.freeze({ kind, timePolicyId: reference(input.timePolicyId, `${path}.timePolicyId`, registry.timePolicyIds) });
  if (Object.hasOwn(input, 'timePolicyId')) invalid(path, 'time policy applies only to monthly cadence');
  return Object.freeze({ kind });
}

function expiry(value: unknown, path: string, registry: CreditPolicyRegistry): CreditExpiry {
  const input = record(value, path, ['kind', 'months', 'timePolicyId']);
  const kind = choice(input.kind, `${path}.kind`, ['subscription_end', 'allocation_period_end', 'after_months']);
  if (kind === 'after_months') return Object.freeze({
    kind, months: integer(input.months, `${path}.months`, 1),
    timePolicyId: reference(input.timePolicyId, `${path}.timePolicyId`, registry.timePolicyIds),
  });
  if (Object.hasOwn(input, 'months') || Object.hasOwn(input, 'timePolicyId')) invalid(path, 'only relative expiry has month/time terms');
  return Object.freeze({ kind });
}

function quantity(value: unknown, path: string, salesOnly: boolean): CreditQuantity {
  const input = record(value, path, ['kind', 'value']);
  const kind = choice(input.kind, `${path}.kind`, ['finite', 'contract_required']);
  if (kind === 'finite') {
    const units = integer(input.value, `${path}.value`);
    // Existing SkillPassport credit_ledger.amount and debit RPC inputs are PostgreSQL integer.
    if (units > 2147483647) invalid(`${path}.value`, 'quantity exceeds existing ledger integer capacity');
    return Object.freeze({ kind, value: units });
  }
  if (!salesOnly || Object.hasOwn(input, 'value')) invalid(path, 'unresolved quantity requires contact sales and no implied value');
  return Object.freeze({ kind });
}

function rollover(value: unknown, path: string, registry: CreditPolicyRegistry): CreditRollover {
  const input = record(value, path, ['kind', 'approvalId']);
  const kind = choice(input.kind, `${path}.kind`, ['none', 'approved']);
  if (kind === 'approved') return Object.freeze({ kind, approvalId: reference(input.approvalId, `${path}.approvalId`, registry.rolloverApprovalIds) });
  if (Object.hasOwn(input, 'approvalId')) invalid(path, 'no-rollover terms cannot carry an approval');
  return Object.freeze({ kind });
}

function rule(
  value: unknown, path: string, draft: PlanRevisionDraft,
  registry: CreditPolicyRegistry, funding: CreditAllocationPolicy['funding'],
): CreditAllocationRule {
  const input = record(value, path, ['id', 'featureKey', 'poolKey', 'recipient', 'audiences', 'quantity', 'cadence', 'expiry', 'rollover', 'expiryApprovalId']);
  const featureKey = text(input.featureKey, `${path}.featureKey`);
  if (registry.catalog.featureTypes.get(featureKey) !== 'metered'
    || !draft.features.some(feature => feature.key === featureKey && feature.type === 'metered' && feature.enabled)) {
    invalid(`${path}.featureKey`, 'allocation requires an enabled registered metered feature');
  }
  const poolKey = text(input.poolKey, `${path}.poolKey`);
  const pool = registry.pools.get(poolKey);
  const recipient = choice(input.recipient, `${path}.recipient`, ['subscriber', 'organization', 'managed_learner']);
  if (!pool || pool.featureKey !== featureKey || pool.recipient !== recipient) invalid(`${path}.poolKey`, 'pool does not match feature and recipient');
  const audiences = array(input.audiences, `${path}.audiences`).map((item, index) => text(item, `${path}.audiences[${index}]`));
  if (!audiences.length || new Set(audiences).size !== audiences.length
    || audiences.some(audience => !draft.audiences.includes(audience) || !pool.audiences.has(audience))) {
    invalid(`${path}.audiences`, 'expected unique revision and pool eligible audiences');
  }
  const allocationCadence = cadence(input.cadence, `${path}.cadence`, registry);
  const allocationExpiry = expiry(input.expiry, `${path}.expiry`, registry);
  if ((funding === 'top_up') !== (allocationCadence.kind === 'purchase')) invalid(`${path}.cadence`, 'top-ups require purchase cadence; included rules cannot use it');
  if (allocationExpiry.kind === 'allocation_period_end' && !['monthly', 'subscription_period'].includes(allocationCadence.kind)) {
    invalid(`${path}.expiry`, 'period expiry requires a recurring allocation period');
  }
  let expiryApprovalId: string | undefined;
  if (Object.hasOwn(input, 'expiryApprovalId')) {
    if (funding !== 'top_up') invalid(`${path}.expiryApprovalId`, 'top-up expiry approval cannot apply to included credits');
    expiryApprovalId = reference(input.expiryApprovalId, `${path}.expiryApprovalId`, registry.expiryApprovalIds);
  }
  if (funding === 'top_up' && (allocationExpiry.kind !== 'after_months' || allocationExpiry.months !== 6) && !expiryApprovalId) {
    invalid(`${path}.expiry`, 'top-ups require explicit six-month expiry or a registered expiry approval');
  }
  const allocationQuantity = quantity(input.quantity, `${path}.quantity`, draft.purchaseMode === 'contact_sales');
  if (funding === 'top_up' && allocationQuantity.kind === 'finite' && allocationQuantity.value === 0) {
    invalid(`${path}.quantity`, 'purchased allocations must have positive quantity');
  }
  return Object.freeze({
    id: uuid(input.id, `${path}.id`), featureKey, poolKey, recipient, audiences: Object.freeze(audiences),
    quantity: allocationQuantity,
    cadence: allocationCadence, expiry: allocationExpiry, rollover: rollover(input.rollover, `${path}.rollover`, registry),
    ...(expiryApprovalId === undefined ? {} : { expiryApprovalId }),
  });
}

export function validateCreditAllocationPolicy(
  value: unknown, revision: unknown, registry: CreditPolicyRegistry,
): CreditAllocationPolicy {
  const draft = validatePlanRevision(revision, registry.catalog);
  const input = record(value, 'creditPolicy', ['schemaVersion', 'id', 'revisionId', 'funding', 'rules']);
  if (input.schemaVersion !== 1) invalid('creditPolicy.schemaVersion', 'unsupported schema version');
  const revisionId = uuid(input.revisionId, 'creditPolicy.revisionId');
  if (revisionId !== draft.id) invalid('creditPolicy.revisionId', 'policy must bind the supplied revision');
  const funding = choice(input.funding, 'creditPolicy.funding', ['included', 'top_up']);
  const rules = array(input.rules, 'creditPolicy.rules').map((value, index) => rule(value, `creditPolicy.rules[${index}]`, draft, registry, funding));
  const ids = new Set<string>(), scopes = new Set<string>();
  for (const item of rules) {
    if (ids.has(item.id)) invalid('creditPolicy.rules', 'duplicate allocation rule identity');
    ids.add(item.id);
    for (const audience of item.audiences) {
      const scope = JSON.stringify([item.featureKey, item.poolKey, audience]);
      if (scopes.has(scope)) invalid('creditPolicy.rules', 'overlapping allocation scope');
      scopes.add(scope);
    }
  }
  if (funding === 'top_up' && !rules.length) invalid('creditPolicy.rules', 'top-up policy requires an allocation rule');
  if (funding === 'included') {
    for (const feature of draft.features.filter(feature => feature.type === 'metered' && feature.enabled)) {
      if (draft.audiences.some(audience => !rules.some(item => item.featureKey === feature.key && item.audiences.includes(audience)))) {
        invalid('creditPolicy.rules', 'every enabled metered feature and audience requires included terms');
      }
    }
  }
  return Object.freeze({ schemaVersion: 1, id: uuid(input.id, 'creditPolicy.id'), revisionId, funding, rules: Object.freeze(rules) });
}
