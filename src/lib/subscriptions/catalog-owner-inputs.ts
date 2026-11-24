import ownerInputs from '../../../config/subscriptions/owner-inputs.json';
import type { BrdCatalogProfile } from './brd-catalog';
import type { CatalogProfileProposal } from './catalog-rollout';
import { loadApprovedSubscriptionPolicy } from './catalog-rollout';
import { validateCreditTimePolicies } from './credit-authoring-context';
import { validateSubscriptionLifecyclePolicy, type LifecyclePolicy } from './lifecycle';
import { array, choice, integer, invalid, record, text, uuid } from './validation';

/** Owner-approved inputs that the saved source mapping deliberately left unresolved. */
export interface CatalogOwnerInputs {
  readonly quoteValidityMs: number;
  readonly trialLearnerCapacities: ReadonlyMap<string, number>;
  readonly freeLifecycle: Omit<LifecyclePolicy, 'productId' | 'graceDurationMs' | 'graceAccess' | 'expiredAccess' | 'readOnlyDurationMs'>;
  readonly paidLifecycle: Readonly<Record<string, unknown>>;
  readonly upgradePaths: ReadonlyMap<string, readonly string[]>;
  readonly monthlyTimePolicy: ReturnType<typeof validateCreditTimePolicies>[number];
  readonly audiences: ReadonlyMap<string, { subjectKind: 'user' | 'organization'; businessType: 'b2b' | 'b2c'; managerRoles: readonly string[]; memberRoles: readonly string[] }>;
  readonly managedLearnerRoles: readonly string[];
  readonly managerOperations: readonly string[];
  readonly memberOperations: readonly string[];
  readonly freeEntry: ReadonlyMap<string, FreeEntryTerms>;
  readonly selfServeStartingAt: ReadonlyMap<string, { priceId: string }>;
  readonly presentationBadges: ReadonlyMap<string, string>;
  /** Legacy plan_code -> BRD reference; codes identify retained legacy rows only, never access. */
  readonly legacyReplacements: ReadonlyMap<string, string>;
}
export type FreeEntryTerms = { validity: 'perpetual' } | { validity: 'fixed_duration'; durationDays: number };

/** Saved per-profile preparation produced by the reviewed rollout proposal. */
export interface SavedCatalogProfile extends CatalogProfileProposal {
  readonly proposedOwnerConfiguration: Record<string, unknown>;
}

function roles(value: unknown, path: string, allowEmpty = false): readonly string[] {
  const values = array(value, path).map(entry => text(entry, path));
  if ((!allowEmpty && !values.length) || new Set(values).size !== values.length || values.some(entry => entry !== entry.trim())) invalid(path, 'explicit unique roles required');
  return Object.freeze(values);
}

export function validateFreeEntryTerms(value: unknown, path: string): FreeEntryTerms {
  const terms = record(value, path, ['validity', 'durationDays']);
  const validity = choice(terms.validity, `${path}.validity`, ['perpetual', 'fixed_duration'] as const);
  if (validity === 'perpetual') {
    if (terms.durationDays !== undefined) invalid(path, 'perpetual entry cannot carry a duration');
    return Object.freeze({ validity });
  }
  const durationDays = integer(terms.durationDays, `${path}.durationDays`, 1);
  if (durationDays > 3650) invalid(`${path}.durationDays`, 'outside supported entry duration');
  return Object.freeze({ validity, durationDays });
}

export function validateCatalogOwnerInputs(value: unknown): CatalogOwnerInputs {
  const input = record(value, 'ownerInputs', ['schemaVersion', 'source', 'quoteValidityMs', 'monthlyTimePolicy', 'audiences', 'managedLearnerRoles',
    'managerOperations', 'memberOperations', 'unboundOperations', 'freeEntry', 'freeLifecycle', 'paidLifecycle', 'upgradePaths', 'trialLearnerCapacities', 'selfServeStartingAt', 'presentationBadges', 'legacyReplacements']);
  if (input.schemaVersion !== 1) invalid('ownerInputs', 'unsupported schema version');
  text(input.source, 'ownerInputs.source');
  const quoteValidityMs = integer(input.quoteValidityMs, 'ownerInputs.quoteValidityMs', 1);
  const paidLifecycle = record(input.paidLifecycle, 'ownerInputs.paidLifecycle', ['id', 'version', 'cancellationAccess',
    'immediateDowngradeAllowed', 'paymentFailureRestrictedMs', 'paymentFailureAfterAccess', 'paymentRetryOffsetsMs',
    'suspensionApprovalRequired', 'reactivationApprovalRequired']);
  const paths = record(input.upgradePaths, 'ownerInputs.upgradePaths', input.upgradePaths && typeof input.upgradePaths === 'object' ? Object.keys(input.upgradePaths) : []);
  const upgradePaths = new Map(Object.entries(paths).map(([from, raw]) => {
    const targets = roles(raw, `ownerInputs.upgradePaths.${from}`);
    if (!/^brd:\d+:\d+$/.test(from) || targets.some(to => to === from || !/^brd:\d+:\d+$/.test(to))) invalid('ownerInputs.upgradePaths', 'explicit distinct catalog references required');
    return [from, targets] as const;
  }));
  if (!upgradePaths.size) invalid('ownerInputs.upgradePaths', 'explicit upgrade routes required');
  const freeLifecycle = record(input.freeLifecycle, 'ownerInputs.freeLifecycle', ['id', 'version', 'billing', 'cancellationAccess',
    'immediateDowngradeAllowed', 'paymentFailureRestrictedMs', 'paymentFailureAfterAccess', 'paymentRetryOffsetsMs',
    'suspensionApprovalRequired', 'reactivationApprovalRequired']);
  const freeLifecycleId = uuid(freeLifecycle.id, 'ownerInputs.freeLifecycle.id');
  const freeLifecycleVersion = integer(freeLifecycle.version, 'ownerInputs.freeLifecycle.version', 1);
  const cancellationAccess = choice(freeLifecycle.cancellationAccess, 'ownerInputs.freeLifecycle.cancellationAccess', ['read_only', 'suspended'] as const);
  if (freeLifecycle.billing !== 'not_applicable'
    || freeLifecycle.immediateDowngradeAllowed !== false || freeLifecycle.paymentFailureRestrictedMs !== null
    || freeLifecycle.paymentFailureAfterAccess !== null || array(freeLifecycle.paymentRetryOffsetsMs, 'ownerInputs.freeLifecycle.paymentRetryOffsetsMs').length !== 0
    || typeof freeLifecycle.suspensionApprovalRequired !== 'boolean' || typeof freeLifecycle.reactivationApprovalRequired !== 'boolean') {
    invalid('ownerInputs.freeLifecycle', 'explicit approved free lifecycle terms required');
  }
  const [monthlyTimePolicy] = validateCreditTimePolicies([input.monthlyTimePolicy]);
  const audienceRecord = record(input.audiences, 'ownerInputs.audiences', input.audiences && typeof input.audiences === 'object' ? Object.keys(input.audiences) : []);
  if (!Object.keys(audienceRecord).length) invalid('ownerInputs.audiences', 'explicit audiences required');
  const audiences = new Map(Object.entries(audienceRecord).map(([audience, raw]) => {
    const entry = record(raw, `ownerInputs.audiences.${audience}`, ['subjectKind', 'businessType', 'managerRoles', 'memberRoles']);
    return [audience, Object.freeze({
      subjectKind: choice(entry.subjectKind, `ownerInputs.audiences.${audience}.subjectKind`, ['user', 'organization'] as const),
      businessType: choice(entry.businessType, `ownerInputs.audiences.${audience}.businessType`, ['b2b', 'b2c'] as const),
      managerRoles: roles(entry.managerRoles, `ownerInputs.audiences.${audience}.managerRoles`),
      memberRoles: roles(entry.memberRoles, `ownerInputs.audiences.${audience}.memberRoles`, true)
    })] as const;
  }));
  const managerOperations = roles(input.managerOperations, 'ownerInputs.managerOperations');
  const memberOperations = roles(input.memberOperations, 'ownerInputs.memberOperations', true);
  if (memberOperations.some(operation => !managerOperations.includes(operation))) invalid('ownerInputs.memberOperations', 'members cannot exceed manager operations');
  const unbound = record(input.unboundOperations, 'ownerInputs.unboundOperations', input.unboundOperations && typeof input.unboundOperations === 'object' ? Object.keys(input.unboundOperations) : []);
  for (const [operation, reason] of Object.entries(unbound)) {
    text(reason, `ownerInputs.unboundOperations.${operation}`);
    if (managerOperations.includes(operation)) invalid('ownerInputs.unboundOperations', 'an operation cannot be both bound and unbound');
  }
  const free = record(input.freeEntry, 'ownerInputs.freeEntry', input.freeEntry && typeof input.freeEntry === 'object' ? Object.keys(input.freeEntry) : []);
  const freeEntry = new Map(Object.entries(free).map(([reference, raw]) => [reference, validateFreeEntryTerms(raw, `ownerInputs.freeEntry.${reference}`)] as const));
  const capacities = record(input.trialLearnerCapacities, 'ownerInputs.trialLearnerCapacities',
    input.trialLearnerCapacities && typeof input.trialLearnerCapacities === 'object' ? Object.keys(input.trialLearnerCapacities) : []);
  const trialLearnerCapacities = new Map(Object.entries(capacities).map(([reference, raw]) => {
    const capacity = integer(raw, `ownerInputs.trialLearnerCapacities.${reference}`, 1);
    if (capacity > 2147483647 || freeEntry.get(reference)?.validity !== 'fixed_duration') {
      invalid('ownerInputs.trialLearnerCapacities', 'positive PostgreSQL seat capacity for an explicit trial required');
    }
    return [reference, capacity] as const;
  }));
  const selfServe = record(input.selfServeStartingAt, 'ownerInputs.selfServeStartingAt', input.selfServeStartingAt && typeof input.selfServeStartingAt === 'object' ? Object.keys(input.selfServeStartingAt) : []);
  const selfServeStartingAt = new Map(Object.entries(selfServe).map(([reference, raw]) => {
    const entry = record(raw, `ownerInputs.selfServeStartingAt.${reference}`, ['priceId']);
    return [reference, Object.freeze({ priceId: uuid(entry.priceId, `ownerInputs.selfServeStartingAt.${reference}.priceId`) })] as const;
  }));
  const priceIds = [...selfServeStartingAt.values()].map(entry => entry.priceId);
  if (new Set(priceIds).size !== priceIds.length) invalid('ownerInputs.selfServeStartingAt', 'price identities must be unique');
  const badgeRecord = record(input.presentationBadges, 'ownerInputs.presentationBadges', input.presentationBadges && typeof input.presentationBadges === 'object' ? Object.keys(input.presentationBadges) : []);
  const presentationBadges = new Map(Object.entries(badgeRecord).map(([reference, raw]) => {
    const badge = text(raw, `ownerInputs.presentationBadges.${reference}`);
    if (badge !== badge.trim()) invalid(`ownerInputs.presentationBadges.${reference}`, 'trimmed badge copy required');
    return [reference, badge] as const;
  }));
  const replacementRecord = record(input.legacyReplacements, 'ownerInputs.legacyReplacements', input.legacyReplacements && typeof input.legacyReplacements === 'object' ? Object.keys(input.legacyReplacements) : []);
  const legacyReplacements = new Map(Object.entries(replacementRecord).map(([code, reference]) => [code, text(reference, `ownerInputs.legacyReplacements.${code}`)] as const));
  if (!legacyReplacements.size) invalid('ownerInputs.legacyReplacements', 'explicit legacy replacement mapping required');
  return Object.freeze({
    quoteValidityMs, trialLearnerCapacities, freeLifecycle: Object.freeze({ id: freeLifecycleId, version: freeLifecycleVersion,
      billing: 'not_applicable' as const, cancellationAccess, immediateDowngradeAllowed: false,
      paymentFailureRestrictedMs: null, paymentFailureAfterAccess: null, paymentRetryOffsetsMs: Object.freeze([]),
      suspensionApprovalRequired: freeLifecycle.suspensionApprovalRequired, reactivationApprovalRequired: freeLifecycle.reactivationApprovalRequired }),
    paidLifecycle: Object.freeze({ ...paidLifecycle }), upgradePaths,
    monthlyTimePolicy, presentationBadges, legacyReplacements, audiences, managedLearnerRoles: roles(input.managedLearnerRoles, 'ownerInputs.managedLearnerRoles'),
    managerOperations, memberOperations, freeEntry, selfServeStartingAt
  });
}
export function loadCatalogOwnerInputs() { return validateCatalogOwnerInputs(ownerInputs); }

export interface CatalogRevisionBinding {
  reference: string; revisionId: string; productId: string; audiences: readonly string[];
}
/** Explicit revision identities come from retained publications and prepared drafts, never plan names or prices. */
export function bindCatalogUpgradeChanges(inputs: CatalogOwnerInputs, retained: readonly CatalogRevisionBinding[],
  targets: readonly (CatalogRevisionBinding & { purchaseMode: string })[]) {
  const targetMap = new Map(targets.map(target => [target.reference, target]));
  if (targetMap.size !== targets.length) invalid('upgrade.targets', 'unique catalog references required');
  const changes: { fromRevisionId: string; toRevisionId: string; operation: 'upgrade' }[] = [];
  const seen = new Set<string>();
  for (const [reference, destinations] of inputs.upgradePaths) {
    const sources = retained.filter(source => source.reference === reference);
    if (!sources.length) invalid('upgrade.sources', `retained revision required for ${reference}`);
    for (const source of sources) for (const destination of destinations) {
      const target = targetMap.get(destination);
      if (!target || target.purchaseMode !== 'self_service' || target.productId !== source.productId
        || !source.audiences.length || source.audiences.length !== target.audiences.length
        || source.audiences.some(audience => !target.audiences.includes(audience))) invalid('upgrade.targets', 'same product, audience and self-service terms required');
      const fromRevisionId = uuid(source.revisionId, 'upgrade.from'), toRevisionId = uuid(target.revisionId, 'upgrade.to');
      uuid(source.productId, 'upgrade.product');
      if (fromRevisionId === toRevisionId) invalid('upgrade.targets', 'an upgrade must change revision');
      const key = `${fromRevisionId}:${toRevisionId}`;
      if (seen.has(key)) invalid('upgrade.sources', 'duplicate retained revision mapping');
      seen.add(key); changes.push({ fromRevisionId, toRevisionId, operation: 'upgrade' });
    }
  }
  return changes;
}

/** Join one saved source mapping to the approved owner inputs. Registry and live
 * role registration remain the caller's authority; this never registers anything. */
export function resolveCatalogOwnerContract(source: BrdCatalogProfile, saved: SavedCatalogProfile, inputs: CatalogOwnerInputs,
  currency: { code: string; minorUnit: number }) {
  if (saved.reference !== source.reference) invalid('ownerInputs.reference', 'saved profile differs from source');
  const bundle = record(saved.bundle, 'ownerInputs.bundle', ['schemaVersion', 'draft', 'includedCredits']);
  const draft = record(bundle.draft, 'ownerInputs.draft', bundle.draft && typeof bundle.draft === 'object' ? Object.keys(bundle.draft) : []);
  const audiences = array(draft.audiences, 'ownerInputs.draft.audiences').map(value => text(value, 'ownerInputs.audience'));
  const owners = audiences.map(audience => inputs.audiences.get(audience) ?? invalid('ownerInputs.audiences', `no owner roles for ${audience}`));
  const unique = (values: readonly string[]) => [...new Set(values)];
  const managerRoles = unique(owners.flatMap(owner => owner.managerRoles));
  const memberRoles = unique(owners.flatMap(owner => owner.memberRoles));
  const operationRoles = Object.fromEntries(inputs.managerOperations.map(operation =>
    [operation, unique([...managerRoles, ...(inputs.memberOperations.includes(operation) ? memberRoles : [])])]));
  const credits = record(bundle.includedCredits, 'ownerInputs.credits', ['schemaVersion', 'id', 'revisionId', 'funding', 'rules']);
  const rules = array(credits.rules, 'ownerInputs.rules').map(value => record(value, 'ownerInputs.rule', value && typeof value === 'object' ? Object.keys(value) : []));
  const recipientRoles = Object.fromEntries(rules.filter(rule => rule.recipient === 'managed_learner')
    .map(rule => [text(rule.poolKey, 'ownerInputs.poolKey'), [...inputs.managedLearnerRoles]]));
  const proposed = saved.proposedOwnerConfiguration;
  const creditAuthoring = record(proposed.subscription_credit_authoring, 'ownerInputs.creditAuthoring', ['schemaVersion', 'pools', 'timePolicies']);
  const commerce = record(proposed.subscription_commerce, 'ownerInputs.commerce', ['schemaVersion', 'quoteValidityMs', 'refundWindowMs', 'retake']);
  const free = source.price.amountMinor === 0 && source.price.intervalUnit === null;
  const entryTerms = inputs.freeEntry.get(source.reference);
  if (free !== (entryTerms !== undefined)) invalid('ownerInputs.freeEntry', 'free entry terms must cover exactly the free profiles');
  const trialCapacity = inputs.trialLearnerCapacities.get(source.reference);
  const organizationTrial = entryTerms?.validity === 'fixed_duration' && owners.every(owner => owner.subjectKind === 'organization');
  if (organizationTrial !== (trialCapacity !== undefined)) invalid('ownerInputs.trialLearnerCapacities', 'exact organization trial capacity required');
  const features = array(draft.features, 'ownerInputs.features').map(value =>
    record(value, 'ownerInputs.feature', value && typeof value === 'object' ? Object.keys(value) : []));
  if (trialCapacity !== undefined && features.filter(feature => feature.key === 'included_learner_capacity' && feature.type === 'numeric_limit').length !== 1) {
    invalid('ownerInputs.trialLearnerCapacities', 'exact numeric learner capacity feature required');
  }
  const boundFeatures = features.map(feature => trialCapacity !== undefined && feature.key === 'included_learner_capacity'
    ? { ...feature, enabled: true, limit: { kind: 'finite', value: trialCapacity } } : feature);
  const selfServe = inputs.selfServeStartingAt.get(source.reference);
  if (selfServe && source.price.kind !== 'starting_at') invalid('ownerInputs.selfServeStartingAt', 'only starting-at profiles can be made self-serve');
  const retention = loadApprovedSubscriptionPolicy().retention;
  const plan = record(draft.plan, 'ownerInputs.plan', ['id', 'code', 'productId']);
  const selfService = draft.purchaseMode === 'self_service' || selfServe !== undefined;
  const lifecycle = entryTerms || selfService ? validateSubscriptionLifecyclePolicy({ ...(entryTerms ? inputs.freeLifecycle : inputs.paidLifecycle), productId: plan.productId,
    graceDurationMs: retention.graceDays * 24 * 60 * 60 * 1000, graceAccess: 'read_only', expiredAccess: 'read_only',
    readOnlyDurationMs: retention.readOnlyDays * 24 * 60 * 60 * 1000 }) : undefined;
  const configuration: Record<string, unknown> = {
    ...proposed,
    subscription_credit_authoring: { ...creditAuthoring, timePolicies: [inputs.monthlyTimePolicy] },
    subscription_commerce: { ...commerce, quoteValidityMs: inputs.quoteValidityMs },
    subscription_commerce_eligibility: {
      schemaVersion: 1, bindings: audiences.map((audience, index) => ({
        audience,
        subjectKind: owners[index].subjectKind, roles: [...owners[index].managerRoles]
      }))
    },
    subscription_execution: { schemaVersion: 1, operationRoles, recipientRoles, consumptionTariffs: [] },
    subscription_presentation: {
      schemaVersion: 1, priceLabel: source.price.kind === 'starting_at' ? 'starting_at' : 'exact', taxInclusive: false,
      badge: inputs.presentationBadges.get(source.reference) ?? null
    },
    ...(entryTerms ? { subscription_entry: { schemaVersion: 1, ...entryTerms } } : {}),
    ...(lifecycle ? { subscription_lifecycle: lifecycle } : {}),
  };
  const prices = selfServe ? [{
    id: selfServe.priceId, currency: currency.code, minorUnit: currency.minorUnit, amountMinor: source.price.amountMinor,
    intervalUnit: source.price.intervalUnit, intervalCount: 1, quantityBasis: 'subscription', audiences
  }] : draft.prices;
  // Monthly rules are prepared without a calendar; bind the one owner-approved monthly time policy.
  const boundRules = rules.map(rule => {
    const cadence = record(rule.cadence, 'ownerInputs.rule.cadence', rule.cadence && typeof rule.cadence === 'object' ? Object.keys(rule.cadence) : []);
    if (cadence.kind !== 'monthly') return rule;
    if (cadence.timePolicyId !== null && cadence.timePolicyId !== inputs.monthlyTimePolicy.id) invalid('ownerInputs.rule.cadence.timePolicyId', 'monthly rule names another time policy');
    return { ...rule, cadence: { ...cadence, timePolicyId: inputs.monthlyTimePolicy.id } };
  });
  const proposal: CatalogProfileProposal = {
    reference: saved.reference, cells: saved.cells.map(cell => trialCapacity !== undefined && cell.featureKeys.includes('included_learner_capacity')
      ? { ...cell, disposition: 'approved_override' as const, evidence: 'ownerInputs.trialLearnerCapacities' } : cell), unresolved: saved.unresolved,
    bundle: {
      ...bundle, draft: { ...draft, features: boundFeatures, ...(selfServe ? { purchaseMode: 'self_service', prices } : {}) },
      includedCredits: { ...credits, rules: boundRules }
    }
  };
  return Object.freeze({ proposal, configuration, monthlyTimePolicyId: inputs.monthlyTimePolicy.id, roles: new Set([...managerRoles, ...memberRoles, ...inputs.managedLearnerRoles]) });
}
