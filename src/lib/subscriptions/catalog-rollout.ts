import configuration from '../../../config/subscriptions/approved-policy.json';
import runtimeContracts from '../../../config/subscriptions/runtime-contracts.json';
import type { PlanAuthoringContext } from './authoring-context';
import type { BrdCatalog, BrdCatalogProfile } from './brd-catalog';
import { validatePlanIdentity } from './catalog';
import { loadCatalogOwnerInputs, validateFreeEntryTerms } from './catalog-owner-inputs';
import { validateCreditAuthoringContext } from './credit-authoring-context';
import type { CreditPolicyRegistry } from './credit-policy';
import { validatePlanPublicationCompleteness } from './publication-readiness';
import type { PlanRevisionBundle } from './revision-bundle';
import { array, choice, integer, invalid, record, text, uuid } from './validation';

export function validateApprovedSubscriptionPolicy(value: unknown) {
  const input = record(value, 'approvedPolicy', ['schemaVersion', 'source', 'ai', 'licensing', 'courseLte', 'assessments', 'refunds', 'retention', 'enterprise']);
  if (input.schemaVersion !== 1) invalid('approvedPolicy', 'unsupported schema version');
  const ai = record(input.ai, 'approvedPolicy.ai', ['conversion', 'costSource', 'chargeTiming', 'billedAttempts', 'unpricedAttempts', 'creditPrecisionDecimals', 'rateSource']);
  // Token billing: credits come from provider-reported cost through a versioned tariff; values live in the tariff owner.
  if (ai.conversion !== 'provider_cost' || ai.costSource !== 'openrouter_usage_cost' || ai.chargeTiming !== 'after_call'
    || ai.billedAttempts !== 'all_provider_billed' || ai.unpricedAttempts !== 'record_without_charge' || ai.rateSource !== 'tariff_version') invalid('approvedPolicy.ai', 'approved provider-cost token billing required');
  const creditPrecisionDecimals = integer(ai.creditPrecisionDecimals, 'approvedPolicy.ai.creditPrecisionDecimals', 0);
  if (creditPrecisionDecimals > 8) invalid('approvedPolicy.ai.creditPrecisionDecimals', 'outside supported precision');
  const licensing = record(input.licensing, 'approvedPolicy.licensing', ['includedLearnerCapacity']);
  const courseLte = record(input.courseLte, 'approvedPolicy.courseLte', ['included', 'preserveConfiguredQuantities']);
  if (licensing.includedLearnerCapacity !== true || courseLte.included !== true || courseLte.preserveConfiguredQuantities !== true) invalid('approvedPolicy', 'included access must preserve capacity');
  const assessment = record(input.assessments, 'approvedPolicy.assessments', ['categories', 'excludeFree', 'retake']);
  const categories = array(assessment.categories, 'approvedPolicy.assessments.categories').map(value => text(value, 'approvedPolicy.category'));
  if (!categories.length || categories.some(value => value !== value.trim()) || new Set(categories).size !== categories.length || assessment.excludeFree !== true) invalid('approvedPolicy.assessments', 'explicit unique nonempty categories and free exclusion required');
  const retake = record(assessment.retake, 'approvedPolicy.retake', ['currency', 'minorUnit', 'amountMinor', 'everyRetake']);
  const currency = text(retake.currency, 'approvedPolicy.retake.currency');
  if (!/^[A-Z]{3}$/.test(currency) || retake.everyRetake !== true) invalid('approvedPolicy.retake', 'every retake needs explicit money');
  const refunds = record(input.refunds, 'approvedPolicy.refunds', ['windowDays', 'calculation', 'revokeAfterRefundedCancellation']);
  if (refunds.calculation !== 'paid_less_recorded_usage_less_previous_refunds' || refunds.revokeAfterRefundedCancellation !== true) invalid('approvedPolicy.refunds', 'usage-based refund and revocation required');
  const retention = record(input.retention, 'approvedPolicy.retention', ['graceDays', 'readOnlyDays', 'suspendAtEnd', 'preserveHistory']);
  const graceDays = integer(retention.graceDays, 'approvedPolicy.graceDays', 1);
  const readOnlyDays = integer(retention.readOnlyDays, 'approvedPolicy.readOnlyDays', 1);
  if (graceDays > readOnlyDays || retention.suspendAtEnd !== true || retention.preserveHistory !== true) invalid('approvedPolicy.retention', 'grace must fit inside preserved read-only window');
  const enterprise = record(input.enterprise, 'approvedPolicy.enterprise', ['terms']);
  if (enterprise.terms !== 'negotiated_existing_hybrid_owner') invalid('approvedPolicy.enterprise', 'existing contract owner required');
  return Object.freeze({
    schemaVersion: 1 as const, source: text(input.source, 'approvedPolicy.source'),
    ai: Object.freeze({
      conversion: 'provider_cost' as const, costSource: 'openrouter_usage_cost' as const, chargeTiming: 'after_call' as const,
      billedAttempts: 'all_provider_billed' as const, unpricedAttempts: 'record_without_charge' as const, creditPrecisionDecimals, rateSource: 'tariff_version' as const
    }), licensing: Object.freeze({ includedLearnerCapacity: true as const }),
    courseLte: Object.freeze({ included: true as const, preserveConfiguredQuantities: true as const }),
    assessments: Object.freeze({
      categories: Object.freeze(categories), excludeFree: true as const,
      retake: Object.freeze({ currency, minorUnit: integer(retake.minorUnit, 'approvedPolicy.retake.minorUnit'), amountMinor: integer(retake.amountMinor, 'approvedPolicy.retake.amountMinor', 1), everyRetake: true as const })
    }),
    refunds: Object.freeze({ windowDays: integer(refunds.windowDays, 'approvedPolicy.refunds.windowDays', 1), calculation: 'paid_less_recorded_usage_less_previous_refunds' as const, revokeAfterRefundedCancellation: true as const }),
    retention: Object.freeze({ graceDays, readOnlyDays, suspendAtEnd: true as const, preserveHistory: true as const }),
    enterprise: Object.freeze({ terms: 'negotiated_existing_hybrid_owner' as const })
  });
}
export function loadApprovedSubscriptionPolicy() { return validateApprovedSubscriptionPolicy(configuration); }

export interface RolloutCell {
  readonly row: number;
  readonly label: string;
  readonly sourceText: string;
  readonly disposition: 'mapped' | 'approved_override' | 'unresolved';
  readonly featureKeys: readonly string[];
  readonly evidence: string;
}
export interface CatalogProfileProposal {
  readonly reference: string;
  readonly cells: readonly RolloutCell[];
  readonly unresolved: readonly string[];
  readonly bundle: unknown;
}

export interface CatalogContractOwner {
  readonly context: PlanAuthoringContext;
  readonly configuration: Record<string, unknown>;
  readonly registry: CreditPolicyRegistry;
  readonly registeredRoles: ReadonlySet<string>;
  /** Explicit reference selected by the owner, never the first available calendar. */
  readonly monthlyTimePolicyId?: string;
}

/** Join a saved identity/source mapping to current trusted owner inputs. This is
 * deliberately separate from preparation: proposed registry rows cannot register
 * themselves, and a complete source mapping is not a published revision. */
export function materializeCatalogContract(source: BrdCatalogProfile, proposal: CatalogProfileProposal,
  owner: CatalogContractOwner): PlanRevisionBundle {
  const { configuration, registry, context } = owner;
  const creditContext = validateCreditAuthoringContext(context, configuration);
  const commerce = record(configuration.subscription_commerce, 'rollout.commerce',
    ['schemaVersion', 'quoteValidityMs', 'refundWindowMs', 'retake']);
  if (commerce.schemaVersion !== 1) invalid('rollout.commerce', 'unsupported schema version');
  integer(commerce.quoteValidityMs, 'rollout.commerce.quoteValidityMs', 1);
  const policy = loadApprovedSubscriptionPolicy();
  if (commerce.refundWindowMs !== policy.refunds.windowDays * 24 * 60 * 60 * 1000) invalid('rollout.commerce', 'approved refund window differs');
  const retake = record(commerce.retake, 'rollout.commerce.retake', ['currency', 'minorUnit', 'amountMinor', 'everyRetake']);
  if (retake.currency !== policy.assessments.retake.currency || retake.minorUnit !== policy.assessments.retake.minorUnit
    || retake.amountMinor !== policy.assessments.retake.amountMinor || retake.everyRetake !== true) invalid('rollout.commerce', 'approved every-retake charge differs');
  const roles = (value: unknown, path: string) => {
    const values = array(value, path).map(value => text(value, path));
    if (!values.length || new Set(values).size !== values.length || values.some(role => !owner.registeredRoles.has(role))) invalid(path, 'explicit unique registered roles required');
    return values;
  };
  const eligibility = record(configuration.subscription_commerce_eligibility, 'rollout.eligibility', ['schemaVersion', 'bindings']);
  if (eligibility.schemaVersion !== 1) invalid('rollout.eligibility', 'unsupported schema version');
  const bindings = array(eligibility.bindings, 'rollout.eligibility.bindings').map(value => {
    const binding = record(value, 'rollout.eligibility.binding', ['audience', 'subjectKind', 'roles']);
    const audience = text(binding.audience, 'rollout.eligibility.audience');
    if (!context.audiences.includes(audience)) invalid('rollout.eligibility.audience', 'foreign audience');
    choice(binding.subjectKind, 'rollout.eligibility.subjectKind', ['user', 'organization'] as const);
    roles(binding.roles, 'rollout.eligibility.roles');
    return binding;
  });
  if (context.audiences.some(audience => bindings.filter(binding => binding.audience === audience).length !== 1)) invalid('rollout.eligibility', 'exactly one subject owner per audience required');
  const execution = record(configuration.subscription_execution, 'rollout.execution', ['schemaVersion', 'operationRoles', 'recipientRoles', 'consumptionTariffs']);
  if (execution.schemaVersion !== 1) invalid('rollout.execution', 'unsupported schema version');
  const operationRoles = record(execution.operationRoles, 'rollout.operationRoles',
    execution.operationRoles && typeof execution.operationRoles === 'object' ? Object.keys(execution.operationRoles) : []);
  if (!Object.keys(operationRoles).length) invalid('rollout.operationRoles', 'explicit execution operations required');
  for (const [operation, allowed] of Object.entries(operationRoles)) roles(allowed, `rollout.operationRoles.${operation}`);
  const recipientRoles = record(execution.recipientRoles, 'rollout.recipientRoles',
    execution.recipientRoles && typeof execution.recipientRoles === 'object' ? Object.keys(execution.recipientRoles) : []);
  const bundle = record(proposal.bundle, 'rollout.bundle', ['schemaVersion', 'draft', 'includedCredits']);
  const credit = record(bundle.includedCredits, 'rollout.credit', ['schemaVersion', 'id', 'revisionId', 'funding', 'rules']);
  const rules = array(credit.rules, 'rollout.rules').map(value => {
    const rule = record(value, 'rollout.rule', ['id', 'featureKey', 'poolKey', 'recipient', 'audiences', 'quantity', 'cadence', 'expiry', 'rollover', 'expiryApprovalId']);
    const poolKey = text(rule.poolKey, 'rollout.poolKey');
    const configuredPool = creditContext.credit.pools.find(pool => pool.key === poolKey);
    if (!configuredPool || configuredPool.featureKey !== rule.featureKey || configuredPool.recipient !== rule.recipient) invalid('rollout.poolKey', 'owner configuration must bind the exact recipient pool');
    if (rule.recipient === 'managed_learner') roles(recipientRoles[poolKey], `rollout.recipientRoles.${poolKey}`);
    const cadence = record(rule.cadence, 'rollout.cadence', ['kind', 'timePolicyId']);
    if (cadence.kind !== 'monthly') return rule;
    const timePolicyId = uuid(owner.monthlyTimePolicyId, 'rollout.monthlyTimePolicyId');
    if (!registry.timePolicyIds.has(timePolicyId) || !creditContext.credit.timePolicies.some(policy => policy.id === timePolicyId)) invalid('rollout.monthlyTimePolicyId', 'registered configured calendar required');
    if (cadence.timePolicyId !== null && cadence.timePolicyId !== timePolicyId) invalid('rollout.monthlyTimePolicyId', 'saved calendar cannot be silently replaced');
    return { ...rule, cadence: { kind: 'monthly', timePolicyId } };
  });
  const tariffScopes = new Set<string>();
  for (const raw of array(execution.consumptionTariffs, 'rollout.consumptionTariffs')) {
    const tariff = record(raw, 'rollout.tariff', ['actionKey', 'poolKey', 'featureKey', 'amount', 'spendingOrder']);
    const actionKey = text(tariff.actionKey, 'rollout.tariff.actionKey');
    const poolKey = text(tariff.poolKey, 'rollout.tariff.poolKey');
    const pool = registry.pools.get(poolKey);
    if (!pool || pool.featureKey !== tariff.featureKey || !rules.some(rule => rule.poolKey === poolKey)) invalid('rollout.tariff', 'tariff must bind an included registered pool');
    if (integer(tariff.amount, 'rollout.tariff.amount', 1) > 2147483647) invalid('rollout.tariff.amount', 'outside ledger integer range');
    choice(tariff.spendingOrder, 'rollout.tariff.spendingOrder', ['expires_first', 'oldest_first'] as const);
    const scope = JSON.stringify([actionKey, poolKey]);
    if (tariffScopes.has(scope)) invalid('rollout.tariff', 'ambiguous consumption tariff');
    tariffScopes.add(scope);
  }
  const resolvedPrefixes = ['ownerInputs.quoteValidityMs:', 'ownerInputs.operationRoles.', 'ownerInputs.monthlyTimePolicy:'];
  if (proposal.unresolved.some(message => !resolvedPrefixes.some(prefix => message.startsWith(prefix)))) invalid('rollout.unresolved', 'unresolved source semantics');
  return compileCatalogProfile(source, { ...proposal, unresolved: [], bundle: { ...bundle, includedCredits: { ...credit, rules } } },
    context, configuration, registry);
}

/** Pure compilation, using the actual publication owner validator. No RPC or implicit registration. */
export function compileCatalogProfile(source: BrdCatalogProfile, proposal: CatalogProfileProposal,
  context: PlanAuthoringContext, ownerConfiguration: Record<string, unknown>, registry: CreditPolicyRegistry): PlanRevisionBundle {
  if (proposal.reference !== source.reference || proposal.cells.length !== source.cells.length) invalid('rollout.cells', 'source profile must be complete');
  if (proposal.unresolved.length) invalid('rollout.unresolved', proposal.unresolved.join('; '));
  const bundle = validatePlanPublicationCompleteness(proposal.bundle, context, ownerConfiguration, registry);
  for (const [index, sourceCell] of source.cells.entries()) {
    const cell = proposal.cells[index];
    if (cell.row !== sourceCell.row || cell.label !== sourceCell.label || cell.sourceText !== sourceCell.text) invalid('rollout.cells', 'source cell differs');
    if (!['mapped', 'approved_override'].includes(cell.disposition)) invalid('rollout.unresolved', 'unresolved source term');
    text(cell.evidence, 'rollout.cell.evidence');
    if (cell.disposition === 'mapped' && sourceCell.row !== 1 && !cell.featureKeys.length) invalid('rollout.cells', 'mapped source term requires an owner feature');
    if (new Set(cell.featureKeys).size !== cell.featureKeys.length) invalid('rollout.cells', 'duplicate mapped feature');
    if (cell.featureKeys.some(key => !bundle.draft.features.some(feature => feature.key === key))) invalid('rollout.cells', 'mapped feature absent from validated bundle');
    const trialCapacity = cell.disposition === 'approved_override' && cell.evidence === 'ownerInputs.trialLearnerCapacities'
      ? loadCatalogOwnerInputs().trialLearnerCapacities.get(source.reference) : undefined;
    if (cell.disposition === 'approved_override' && !(cell.label === 'Assessments' && cell.evidence === 'approvedPolicy.assessments')
      && !(trialCapacity !== undefined && cell.label === 'Learner limit' && cell.featureKeys.length === 1 && cell.featureKeys[0] === 'included_learner_capacity')) {
      invalid('rollout.cells', 'override requires approved policy reference');
    }
    if (sourceCell.row !== 1) {
      const qualitative = runtimeContracts.features.find(feature => feature.label === sourceCell.label);
      if (qualitative) {
        const term = qualitative.terms.find(term => term.text === sourceCell.text);
        const grant = bundle.draft.features.find(feature => feature.key === qualitative.key);
        if (!term || cell.featureKeys.length !== 1 || cell.featureKeys[0] !== qualitative.key || grant?.type !== 'enum'
          || grant.enabled !== term.enabled || grant.value !== (term.enabled ? term.value : null)
          || cell.evidence !== `runtimeContracts.${qualitative.key}`) invalid('rollout.qualitative', 'exact owner-bound source semantics required');
        continue;
      }
      const assessment = cell.disposition === 'approved_override' && cell.label === 'Assessments';
      const grants = bundle.draft.features.filter(feature => cell.featureKeys.includes(feature.key));
      if (assessment) {
        // Included starts and paid retakes have different owners. A source cell
        // may cover both; neither the display name nor array order grants access.
        if (grants.length !== 2 || grants.filter(grant => grant.type === 'numeric_limit').length !== 1
          || grants.filter(grant => grant.type === 'boolean').length !== 1) invalid('rollout.cells', 'assessment requires distinct quantity and access grants');
        const actions = record(ownerConfiguration.subscription_actions, 'rollout.actions', ['schemaVersion', 'bindings']);
        if (actions.schemaVersion !== 1) invalid('rollout.actions', 'unsupported schema version');
        const bindings = array(actions.bindings, 'rollout.actions.bindings').map(value => record(value, 'rollout.binding',
          ['actionKey', 'featureKey', 'mode', 'assessmentCategory', 'paymentRequired', 'acceptedValues', 'quota']));
        const policy = loadApprovedSubscriptionPolicy();
        for (const category of [undefined, ...policy.assessments.categories]) {
          for (const action of ['assessment.start', 'assessment.retake']) {
            const matches = bindings.filter(binding => binding.actionKey === action && binding.mode === 'write' && binding.assessmentCategory === category);
            const grantType = action === 'assessment.start' ? 'numeric_limit' : 'boolean';
            const matchingGrant = grants.find(grant => grant.type === grantType);
            if (matches.length !== 1 || matches[0].featureKey !== matchingGrant?.key
              || (action === 'assessment.retake' && (matches[0].paymentRequired !== true || matches[0].quota !== undefined))
              || (action === 'assessment.start' && (matches[0].paymentRequired === true || matches[0].quota === undefined))) {
              invalid('rollout.assessments', 'included starts and every paid retake require exact configured category owners');
            }
            if (action === 'assessment.start') {
              const quota = record(matches[0].quota, 'rollout.assessment.quota', ['period', 'countingEvent']);
              choice(quota.period, 'rollout.assessment.quota.period', ['subscription', 'billing_period', 'concurrent'] as const);
              text(quota.countingEvent, 'rollout.assessment.quota.countingEvent');
            }
          }
        }
        if (grants.find(grant => grant.type === 'boolean')?.enabled !== (source.price.amountMinor !== 0)) {
          invalid('rollout.assessments', 'assessment access must exclude free plans');
        }
      } else if (cell.featureKeys.length !== 1) invalid('rollout.cells', 'supported quantitative source term requires exactly one feature binding');
      const grant = assessment ? grants.find(feature => feature.type === 'numeric_limit') : grants[0];
      if (!grant) invalid('rollout.cells', 'bound feature absent');
      const excludedAssessment = assessment && source.price.amountMinor === 0;
      const number = sourceCell.text.match(/^(?:(?:Up to|Assign up to|Pilot up to|Multi-department up to) )?([\d,]+)(?:\b|$)/);
      const expected = trialCapacity !== undefined ? trialCapacity : excludedAssessment ? 0 : /^(Not included|No|Not applicable|Demo\/sample only|Preview only|Sample listing view)$/.test(sourceCell.text) ? 0
        : number ? Number(number[1].replaceAll(',', '')) : /custom/i.test(sourceCell.text) ? null : undefined;
      if (expected === undefined) invalid('rollout.cells', 'qualitative semantics require an explicit owner compiler');
      if (grant.type === 'numeric_limit') {
        if ((expected === null && grant.limit.kind !== 'contract_required')
          || (expected !== null && (grant.limit.kind !== 'finite' || grant.limit.value !== expected))
          || grant.enabled !== (expected === null || expected > 0)) invalid('rollout.quantity', 'source quantity differs');
      } else if (grant.type === 'metered') {
        const rules = bundle.includedCredits.rules.filter(rule => rule.featureKey === grant.key);
        const institutional = source.section >= 7 && source.section <= 9;
        // Recruiter (section 10) subscriptions are organization-owned, like institutions; only learners subscribe individually.
        const organizationOwned = source.section >= 7 && source.section <= 10;
        const primary = rules.filter(rule => rule.recipient === (organizationOwned ? 'organization' : 'subscriber'));
        const learner = sourceCell.text.match(/\+ ([\d,]+) credits\/learner\/month/);
        const customLearner = /custom learner AI pool/.test(sourceCell.text);
        const expectedCount = learner || customLearner ? 2 : 1;
        if (rules.length !== expectedCount || primary.length !== 1) invalid('rollout.quantity', 'exact source recipient pools required');
        const checkQuantity = (quantity: typeof primary[number]['quantity'], expected: number | null) => {
          if ((expected === null && quantity.kind !== 'contract_required')
            || (expected !== null && (quantity.kind !== 'finite' || quantity.value !== expected))) invalid('rollout.quantity', 'source allocation differs');
        };
        checkQuantity(primary[0].quantity, expected);
        const primaryCadence = /\/month/.test(sourceCell.text) && !institutional ? 'monthly' : /trial/.test(sourceCell.text) ? 'activation' : 'subscription_period';
        if (primary[0].cadence.kind !== primaryCadence || primary[0].rollover.kind !== 'none'
          || primary[0].expiry.kind !== (primaryCadence === 'monthly' ? 'allocation_period_end' : 'subscription_end')) invalid('rollout.cadence', 'source credit period differs');
        if (learner || customLearner) {
          const managed = rules.filter(rule => rule.recipient === 'managed_learner');
          if (managed.length !== 1 || managed[0].cadence.kind !== 'monthly' || managed[0].expiry.kind !== 'allocation_period_end'
            || managed[0].rollover.kind !== 'none') invalid('rollout.cadence', 'per learner monthly pool required');
          checkQuantity(managed[0].quantity, learner ? Number(learner[1].replaceAll(',', '')) : null);
        }
      } else invalid('rollout.cells', 'qualitative or boolean mappings require an explicit owner compiler');
    }
  }
  if (bundle.draft.name !== source.displayName) invalid('rollout.name', 'source display name differs');
  if (source.price.amountMinor === 0 && source.price.intervalUnit === null) {
    if (bundle.draft.purchaseMode !== 'free' || bundle.draft.prices.length) invalid('rollout.price', 'free entry must not fabricate a billing duration');
    const entry = record(ownerConfiguration.subscription_entry, 'rollout.entry', ['schemaVersion', 'validity', 'durationDays']);
    if (entry.schemaVersion !== 1) invalid('rollout.entry', 'explicit owner validity contract required');
    // Approved free entry is either an owner contract or explicit owner terms; never an implied duration.
    if (entry.validity !== 'owner_contract_required') validateFreeEntryTerms({ validity: entry.validity, durationDays: entry.durationDays }, 'rollout.entry');
  } else if (source.price.kind === 'starting_at') {
    const presentation = ownerConfiguration.subscription_presentation === undefined ? null
      : record(ownerConfiguration.subscription_presentation, 'rollout.presentation', ['schemaVersion', 'priceLabel', 'taxInclusive', 'badge', 'copy']);
    if (bundle.draft.purchaseMode === 'self_service' && presentation?.schemaVersion === 1 && presentation.priceLabel === 'starting_at') {
      // Approved self-serve "From" price: one exact charge at the advertised floor for the stated included capacity.
      if (bundle.draft.prices.length !== 1) invalid('rollout.price', 'self-serve starting-at terms require one explicit option');
      const price = bundle.draft.prices[0];
      if (price.amountMinor !== source.price.amountMinor || price.intervalUnit !== source.price.intervalUnit || price.intervalCount !== 1 || price.quantityBasis !== 'subscription') invalid('rollout.price', 'self-serve starting-at price or counting basis differs');
    } else if (bundle.draft.purchaseMode !== 'contact_sales' || bundle.draft.prices.length) invalid('rollout.price', 'starting-at terms require negotiated contract, never a fabricated exact charge');
  } else {
    if (source.price.intervalUnit === null) invalid('rollout.price', 'free duration requires an explicit owner decision');
    if (bundle.draft.prices.length !== 1) invalid('rollout.price', 'source price requires one explicit option');
    const price = bundle.draft.prices[0];
    if (price.amountMinor !== source.price.amountMinor || price.intervalUnit !== source.price.intervalUnit || price.intervalCount !== 1 || price.quantityBasis !== 'subscription') invalid('rollout.price', 'source price or counting basis differs');
  }
  return bundle;
}

export function compileCatalogRollout(catalog: BrdCatalog, proposals: readonly CatalogProfileProposal[],
  owner: (reference: string) => { context: PlanAuthoringContext; configuration: Record<string, unknown>; registry: CreditPolicyRegistry }) {
  if (proposals.length !== catalog.profiles.length || new Set(proposals.map(value => value.reference)).size !== proposals.length) invalid('rollout.profiles', 'exact complete unique profile set required');
  const bundles = catalog.profiles.map(source => {
    const proposal = proposals.find(value => value.reference === source.reference);
    if (!proposal) invalid('rollout.profiles', 'source profile missing');
    const snapshot = owner(source.reference);
    const bundle = compileCatalogProfile(source, proposal, snapshot.context, snapshot.configuration, snapshot.registry);
    if (bundle.draft.prices.some(price => price.currency !== catalog.currency.code || price.minorUnit !== catalog.currency.minorUnit)) invalid('rollout.currency', 'source currency differs');
    return bundle;
  });
  if (new Set(bundles.map(value => value.draft.plan.id)).size !== bundles.length
    || new Set(bundles.map(value => value.draft.plan.code)).size !== bundles.length) invalid('rollout.identities', 'canonical identities must be unique');
  return Object.freeze(bundles);
}

/** Existing customers retain purchase snapshots; transition is never a name-derived rewrite. */
export function validateCatalogTransition(value: unknown, existingHybridId: string) {
  const input = record(value, 'transition', ['hybridPlanId', 'preservePurchasedSnapshots', 'preserveHistory', 'existingCustomers', 'newCustomers', 'retireLegacy', 'effectiveAt']);
  const hybridPlanId = uuid(input.hybridPlanId, 'transition.hybridPlanId');
  if (hybridPlanId !== uuid(existingHybridId, 'transition.existingHybridId')) invalid('transition.hybridPlanId', 'existing Hybrid identity must be preserved');
  if (input.preservePurchasedSnapshots !== true || input.preserveHistory !== true || input.existingCustomers !== 'retain_original_terms'
    || input.newCustomers !== 'explicit_published_revision_only' || input.retireLegacy !== false || input.effectiveAt !== null) invalid('transition', 'preparation cannot migrate, retire or rewrite customer history');
  return Object.freeze({
    hybridPlanId, preservePurchasedSnapshots: true as const, preserveHistory: true as const,
    existingCustomers: 'retain_original_terms' as const, newCustomers: 'explicit_published_revision_only' as const,
    retireLegacy: false as const, effectiveAt: null
  });
}

export interface CanonicalCatalogPlan {
  id: string;
  plan_code: string;
  product_id: string;
  name: string;
  business_type: string;
  applicable_entities: readonly string[];
  pricing_matrix: Record<string, unknown>;
  base_features: readonly unknown[] | null;
  entity_config: Record<string, unknown>;
  display_order: number | null;
  is_active: false;
}
export interface CatalogInstallationCommand {
  schemaVersion: 1;
  operationId: string;
  actorId: string;
  productId: string;
  hybridPlanId: string;
  approvalReference: string;
  entries: readonly { reference: string; expected: Record<string, unknown> | null; plan: CanonicalCatalogPlan }[];
}
export interface CatalogInstallationSnapshot {
  productId: string;
  hybridPlanId: string;
  /** Complete rows read by the owning service, including timestamp/unknown columns. */
  plans: readonly Record<string, unknown>[];
  purchasedPlanIds: ReadonlySet<string>;
  publishedPlanIds: ReadonlySet<string>;
}
function exactJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(exactJson).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const row = value as Record<string, unknown>;
    return `{${Object.keys(row).sort().map(key => `${JSON.stringify(key)}:${exactJson(row[key])}`).join(',')}}`;
  }
  return invalid('catalogInstallation', 'exact JSON values required');
}
function installationCommand(value: unknown): CatalogInstallationCommand {
  const input = record(value, 'catalogInstallation', ['schemaVersion', 'operationId', 'actorId', 'productId', 'hybridPlanId', 'approvalReference', 'entries']);
  if (input.schemaVersion !== 1) invalid('catalogInstallation', 'unsupported schema version');
  const productId = uuid(input.productId, 'catalogInstallation.productId');
  const hybridPlanId = uuid(input.hybridPlanId, 'catalogInstallation.hybridPlanId');
  const entries = array(input.entries, 'catalogInstallation.entries').map(value => {
    const entry = record(value, 'catalogInstallation.entry', ['reference', 'expected', 'plan']);
    const row = record(entry.plan, 'catalogInstallation.plan', ['id', 'plan_code', 'product_id', 'name', 'business_type',
      'applicable_entities', 'pricing_matrix', 'base_features', 'entity_config', 'display_order', 'is_active']);
    const identity = validatePlanIdentity({ id: row.id, code: row.plan_code, productId: row.product_id });
    if (identity.productId !== productId || identity.id === hybridPlanId || row.is_active !== false) invalid('catalogInstallation.plan', 'same product inactive non-Hybrid candidates required');
    const audiences = array(row.applicable_entities, 'catalogInstallation.audiences').map(value => text(value, 'catalogInstallation.audience'));
    if (!audiences.length || new Set(audiences).size !== audiences.length) invalid('catalogInstallation.audiences', 'unique explicit audiences required');
    const object = (value: unknown, path: string) => {
      const result = record(value, path, value && typeof value === 'object' ? Object.keys(value) : []);
      exactJson(result); return result;
    };
    const plan: CanonicalCatalogPlan = {
      id: identity.id, plan_code: identity.code, product_id: identity.productId,
      name: text(row.name, 'catalogInstallation.name'), business_type: text(row.business_type, 'catalogInstallation.businessType'),
      applicable_entities: audiences, pricing_matrix: object(row.pricing_matrix, 'catalogInstallation.pricingMatrix'),
      base_features: row.base_features === null ? null : array(row.base_features, 'catalogInstallation.baseFeatures'), entity_config: object(row.entity_config, 'catalogInstallation.configuration'),
      display_order: row.display_order === null ? null : integer(row.display_order, 'catalogInstallation.displayOrder', -2147483648), is_active: false
    };
    if (plan.display_order !== null && plan.display_order > 2147483647) invalid('catalogInstallation.displayOrder', 'outside PostgreSQL integer range');
    exactJson(plan);
    const expected = entry.expected === null ? null : object(entry.expected, 'catalogInstallation.expected');
    if (expected && (expected.id !== plan.id || expected.product_id !== productId || expected.plan_code !== plan.plan_code || expected.is_active !== false)) invalid('catalogInstallation.expected', 'existing candidate identity and inactive state must be retained');
    return { reference: text(entry.reference, 'catalogInstallation.reference'), expected, plan };
  });
  for (const property of ['reference', 'id', 'code'] as const) {
    const values = entries.map(entry => property === 'reference' ? entry.reference : property === 'id' ? entry.plan.id : entry.plan.plan_code);
    if (new Set(values).size !== values.length) invalid('catalogInstallation.entries', 'duplicate source or canonical identity');
  }
  if (!entries.length) invalid('catalogInstallation.entries', 'explicit installation entries required');
  return {
    schemaVersion: 1, operationId: uuid(input.operationId, 'catalogInstallation.operationId'),
    actorId: uuid(input.actorId, 'catalogInstallation.actorId'), productId, hybridPlanId,
    approvalReference: text(input.approvalReference, 'catalogInstallation.approvalReference'), entries
  };
}

/** Only canonical inactive plan/configuration persistence; the existing immutable
 * staging and projection/publication owners remain separate subsequent steps. */
export function prepareCatalogInstallation(value: unknown, catalog: BrdCatalog, proposals: readonly CatalogProfileProposal[],
  owner: (reference: string) => CatalogContractOwner, snapshot: CatalogInstallationSnapshot, actorId: string): CatalogInstallationCommand {
  const input = record(value, 'catalogInstallation.request', ['schemaVersion', 'operationId', 'productId', 'hybridPlanId', 'approvalReference', 'entries']);
  const command = installationCommand({ ...input, actorId });
  if (command.productId !== snapshot.productId || command.hybridPlanId !== snapshot.hybridPlanId
    || snapshot.plans.filter(row => row.id === snapshot.hybridPlanId && row.product_id === snapshot.productId).length !== 1) invalid('catalogInstallation.scope', 'trusted retained Hybrid/product baseline required');
  if (command.entries.length !== catalog.profiles.length || proposals.length !== catalog.profiles.length
    || new Set(proposals.map(proposal => proposal.reference)).size !== catalog.profiles.length) invalid('catalogInstallation.profiles', 'exact complete source profile set required');
  for (const source of catalog.profiles) {
    const entry = command.entries.find(entry => entry.reference === source.reference);
    const proposal = proposals.find(proposal => proposal.reference === source.reference);
    if (!entry || !proposal) invalid('catalogInstallation.profiles', 'source mapping absent');
    const trusted = owner(source.reference);
    const compiled = materializeCatalogContract(source, proposal, trusted);
    const plan = entry.plan;
    if (plan.id !== compiled.draft.plan.id || plan.plan_code !== compiled.draft.plan.code || plan.product_id !== compiled.draft.plan.productId
      || plan.name !== compiled.draft.name || exactJson(plan.applicable_entities) !== exactJson(compiled.draft.audiences)
      || exactJson(plan.entity_config) !== exactJson(trusted.configuration)) invalid('catalogInstallation.plan', 'validated owner materialization differs');
    const rows = snapshot.plans.filter(row => row.id === plan.id);
    if (rows.length > 1 || (rows.length === 0 ? entry.expected !== null : exactJson(rows[0]) !== exactJson(entry.expected))) invalid('catalogInstallation.baseline', 'exact existing row or explicit absence required');
    if (snapshot.plans.some(row => row.id !== plan.id && row.plan_code === plan.plan_code)) invalid('catalogInstallation.identity', 'canonical code collision');
    if (snapshot.purchasedPlanIds.has(plan.id) || snapshot.publishedPlanIds.has(plan.id)) invalid('catalogInstallation.history', 'purchased or published plans cannot be overwritten');
    if (entry.expected) {
      for (const key of Object.keys(plan).filter(key => key !== 'entity_config')) {
        if (exactJson(entry.expected[key]) !== exactJson(plan[key as keyof CanonicalCatalogPlan])) invalid('catalogInstallation.expected', 'existing candidate fields cannot be rewritten');
      }
      const prior = record(entry.expected.entity_config, 'catalogInstallation.priorConfiguration',
        entry.expected.entity_config && typeof entry.expected.entity_config === 'object' ? Object.keys(entry.expected.entity_config) : []);
      for (const [key, priorValue] of Object.entries(prior)) {
        if (!key.startsWith('subscription_') && (!Object.hasOwn(plan.entity_config, key)
          || exactJson(priorValue) !== exactJson(plan.entity_config[key]))) invalid('catalogInstallation.configuration', 'unrelated existing configuration must be preserved');
      }
    }
  }
  return command;
}
export async function installCanonicalCatalog(database: { rpc(name: string, parameters: Record<string, unknown>): Promise<unknown> }, value: CatalogInstallationCommand) {
  const command = installationCommand(value);
  const receipt = record(await database.rpc('install_subscription_catalog_candidates', { p_command: command }),
    'catalogInstallation.receipt', ['operationId', 'actorId', 'command', 'planIds']);
  const ids = command.entries.map(entry => entry.plan.id);
  if (receipt.operationId !== command.operationId || receipt.actorId !== command.actorId
    || exactJson(receipt.command) !== exactJson(command) || exactJson(receipt.planIds) !== exactJson(ids)) invalid('catalogInstallation.receipt', 'exact owner acknowledgement required');
  return { operationId: command.operationId, actorId: command.actorId, command, planIds: ids };
}
