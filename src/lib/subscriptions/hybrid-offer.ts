import configuration from '../../../config/subscriptions/hybrid-offer.json';
import runtimeContracts from '../../../config/subscriptions/runtime-contracts.json';
import { loadBrdCatalog } from './brd-catalog';
import { loadCatalogOwnerInputs, type CatalogOwnerInputs } from './catalog-owner-inputs';
import { loadApprovedSubscriptionPolicy } from './catalog-rollout';
import { array, choice, invalid, record, text, uuid } from './validation';

/**
 * Owner-approved Hybrid offer (decisions 1a, a–d): a sales-led catalog plan whose every limit is negotiated.
 * Display-only until a signed customer contract resolves the terms; no automatic credit allocation.
 */
export interface HybridOfferConfiguration {
  readonly name: string;
  readonly audiences: readonly string[];
  readonly numericFeatureKeys: readonly string[];
  readonly credit: { readonly featureKey: string; readonly poolKey: string; readonly recipient: 'organization' };
  readonly actions: readonly Record<string, unknown>[];
  readonly copy: PresentationCopy;
}
export interface PresentationCopy {
  readonly tagline: string; readonly positioning: string; readonly description: string;
  readonly priceText: string; readonly termsNote: string; readonly highlights: readonly string[];
}
/** Reviewed immutable identities for one Hybrid revision; generated once, never by the server. */
export interface HybridOfferIdentities {
  readonly targetCode: string; readonly revisionId: string; readonly includedCreditsId: string; readonly ruleId: string;
}

export function validatePresentationCopy(value: unknown, path: string): PresentationCopy {
  const input = record(value, path, ['tagline', 'positioning', 'description', 'priceText', 'termsNote', 'highlights']);
  const field = (key: string, max: number) => { const result = text(input[key], `${path}.${key}`); if (result.length > max) invalid(`${path}.${key}`, 'copy too long'); return result; };
  const highlights = array(input.highlights, `${path}.highlights`).map((item, index) => text(item, `${path}.highlights[${index}]`));
  if (!highlights.length || highlights.length > 12 || highlights.some(item => item.length > 120)) invalid(`${path}.highlights`, 'one to twelve short highlights required');
  return Object.freeze({ tagline: field('tagline', 120), positioning: field('positioning', 60), description: field('description', 600),
    priceText: field('priceText', 40), termsNote: field('termsNote', 300), highlights: Object.freeze(highlights) });
}

export function validateHybridOffer(value: unknown, inputs: CatalogOwnerInputs): HybridOfferConfiguration {
  const input = record(value, 'hybridOffer', ['schemaVersion', 'source', 'name', 'audiences', 'numericFeatureKeys', 'credit', 'actions', 'copy']);
  if (input.schemaVersion !== 1) invalid('hybridOffer.schemaVersion', 'unsupported schema version');
  text(input.source, 'hybridOffer.source');
  const audiences = array(input.audiences, 'hybridOffer.audiences').map(item => text(item, 'hybridOffer.audience'));
  if (!audiences.length || new Set(audiences).size !== audiences.length
    || audiences.some(audience => inputs.audiences.get(audience)?.subjectKind !== 'organization' || inputs.audiences.get(audience)?.businessType !== 'b2b')) {
    invalid('hybridOffer.audiences', 'distinct organization audiences required');
  }
  const numericFeatureKeys = array(input.numericFeatureKeys, 'hybridOffer.numericFeatureKeys').map(item => text(item, 'hybridOffer.numericFeatureKey'));
  if (!numericFeatureKeys.length || new Set(numericFeatureKeys).size !== numericFeatureKeys.length) invalid('hybridOffer.numericFeatureKeys', 'distinct limits required');
  const credit = record(input.credit, 'hybridOffer.credit', ['featureKey', 'poolKey', 'recipient']);
  const actions = array(input.actions, 'hybridOffer.actions').map((item, index) => {
    const binding = record(item, `hybridOffer.actions[${index}]`, ['mode', 'quota', 'actionKey', 'featureKey', 'assessmentCategory', 'paymentRequired']);
    if (!numericFeatureKeys.includes(text(binding.featureKey, `hybridOffer.actions[${index}].featureKey`))) invalid(`hybridOffer.actions[${index}]`, 'action must bind a Hybrid limit');
    return Object.freeze({ ...binding });
  });
  return Object.freeze({ name: text(input.name, 'hybridOffer.name'), audiences: Object.freeze(audiences), numericFeatureKeys: Object.freeze(numericFeatureKeys),
    credit: Object.freeze({ featureKey: text(credit.featureKey, 'hybridOffer.credit.featureKey'), poolKey: text(credit.poolKey, 'hybridOffer.credit.poolKey'),
      recipient: choice(credit.recipient, 'hybridOffer.credit.recipient', ['organization'] as const) }),
    actions: Object.freeze(actions), copy: validatePresentationCopy(input.copy, 'hybridOffer.copy') });
}
export function loadHybridOffer(inputs = loadCatalogOwnerInputs()) { return validateHybridOffer(configuration, inputs); }

export function validateHybridIdentities(value: unknown): HybridOfferIdentities {
  const input = record(value, 'hybridOffer.identities', ['targetCode', 'revisionId', 'includedCreditsId', 'ruleId']);
  const targetCode = text(input.targetCode, 'hybridOffer.identities.targetCode');
  if (!/^pln_[0-9a-f]{32}$/.test(targetCode)) invalid('hybridOffer.identities.targetCode', 'opaque canonical code required');
  const ids = [uuid(input.revisionId, 'hybridOffer.identities.revisionId'), uuid(input.includedCreditsId, 'hybridOffer.identities.includedCreditsId'), uuid(input.ruleId, 'hybridOffer.identities.ruleId')];
  if (new Set(ids).size !== ids.length) invalid('hybridOffer.identities', 'distinct identities required');
  return Object.freeze({ targetCode, revisionId: ids[0], includedCreditsId: ids[1], ruleId: ids[2] });
}

/** Deterministic owner configuration and first revision bundle for the retained Hybrid plan. */
export function buildHybridCatalogOffer(offer: HybridOfferConfiguration, inputs: CatalogOwnerInputs, planId: string, productId: string,
  identities: HybridOfferIdentities, revisionNumber: number) {
  const catalog = loadBrdCatalog(), policy = loadApprovedSubscriptionPolicy();
  const owners = offer.audiences.map(audience => inputs.audiences.get(audience)!);
  const unique = (values: readonly string[]) => [...new Set(values)];
  const managerRoles = unique(owners.flatMap(owner => owner.managerRoles)), memberRoles = unique(owners.flatMap(owner => owner.memberRoles));
  const audiences = [...offer.audiences];
  const configuration = {
    subscription_authoring: { schemaVersion: 1, currencies: [{ code: catalog.currency.code, minorUnit: catalog.currency.minorUnit }] },
    subscription_credit_authoring: { schemaVersion: 1, pools: [{ key: offer.credit.poolKey, featureKey: offer.credit.featureKey, recipient: offer.credit.recipient, audiences }], timePolicies: [] },
    subscription_entry: runtimeContracts.entry,
    subscription_commerce_usage: runtimeContracts.commercialUsage,
    subscription_publication: { schemaVersion: 2, requiredFeatureKeys: [...offer.numericFeatureKeys, offer.credit.featureKey],
      requiredCreditAllocations: [{ poolKey: offer.credit.poolKey, audiences }] },
    subscription_actions: { schemaVersion: 1, bindings: offer.actions.map(binding => ({ ...binding })) },
    subscription_commerce: { schemaVersion: 1, quoteValidityMs: inputs.quoteValidityMs, refundWindowMs: policy.refunds.windowDays * 24 * 60 * 60 * 1000,
      retake: { ...policy.assessments.retake } },
    subscription_commerce_eligibility: { schemaVersion: 1, bindings: offer.audiences.map((audience, index) => ({ audience, subjectKind: owners[index].subjectKind, roles: [...owners[index].managerRoles] })) },
    subscription_execution: { schemaVersion: 1, recipientRoles: {}, consumptionTariffs: [],
      operationRoles: Object.fromEntries(inputs.managerOperations.map(operation => [operation, unique([...managerRoles, ...(inputs.memberOperations.includes(operation) ? memberRoles : [])])])) },
    subscription_presentation: { schemaVersion: 1, priceLabel: 'exact', taxInclusive: false, badge: null, copy: { ...offer.copy, highlights: [...offer.copy.highlights] } },
  };
  const plan = { id: planId, code: identities.targetCode, productId };
  const bundle = { schemaVersion: 1, draft: { schemaVersion: 2, id: identities.revisionId, plan, revisionNumber, name: offer.name, audiences,
    purchaseMode: 'contact_sales', prices: [],
    features: [...offer.numericFeatureKeys.map(key => ({ key, type: 'numeric_limit', enabled: true, limit: { kind: 'contract_required' } })),
      { key: offer.credit.featureKey, type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }] },
    includedCredits: { schemaVersion: 1, id: identities.includedCreditsId, revisionId: identities.revisionId, funding: 'included',
      rules: [{ id: identities.ruleId, featureKey: offer.credit.featureKey, poolKey: offer.credit.poolKey, recipient: offer.credit.recipient, audiences,
        quantity: { kind: 'contract_required' }, cadence: { kind: 'subscription_period' }, expiry: { kind: 'subscription_end' }, rollover: { kind: 'none' } }] } };
  return { configuration, bundle };
}
