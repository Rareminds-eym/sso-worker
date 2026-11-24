import { describe, expect, it, vi } from 'vitest';
import proposal from '../../../audit-evidence/local-subscription-db-audit/catalog-rollout.json';
import approved from '../../config/subscriptions/approved-policy.json';
import { loadBrdCatalog } from '../lib/subscriptions/brd-catalog';
import { compileCatalogProfile, compileCatalogRollout, loadApprovedSubscriptionPolicy, validateApprovedSubscriptionPolicy, validateCatalogTransition } from '../lib/subscriptions/catalog-rollout';
import type { CatalogProfileProposal } from '../lib/subscriptions/catalog-rollout';
import type { BrdCatalogProfile } from '../lib/subscriptions/brd-catalog';
import type { CreditPolicyRegistry } from '../lib/subscriptions/credit-policy';
import type { PlanAuthoringContext } from '../lib/subscriptions/authoring-context';
import baseline from '../../../audit-evidence/local-subscription-db-audit/authoring-readiness.json';
import runtimeContracts from '../../config/subscriptions/runtime-contracts.json';
import { installCanonicalCatalog, materializeCatalogContract, prepareCatalogInstallation } from '../lib/subscriptions/catalog-rollout';
import type { FeatureType } from '../lib/subscriptions/types';

const plan = { id: '10000000-0000-4000-8000-000000000001', code: 'pln_1234567890abcdef1234567890abcdef', productId: '20000000-0000-4000-8000-000000000001' };
const revisionId = '30000000-0000-4000-8000-000000000001';
const context: PlanAuthoringContext = { schemaVersion: 1, plan, audiences: ['individual'], currencies: [{ code: 'INR', minorUnit: 2 }] };
const registry: CreditPolicyRegistry = { catalog: { productIds: new Set([plan.productId]), audienceKeys: new Set(context.audiences), currencies: new Map([['INR', 2]]), featureTypes: new Map([['capacity', 'numeric_limit']]) }, pools: new Map(), timePolicyIds: new Set(), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set() };
const config = { subscription_publication: { schemaVersion: 1, requiredFeatureKeys: ['capacity'] } };
const source: BrdCatalogProfile = { reference: 'brd:6:1', section: 6, column: 1, displayName: 'Synthetic source', price: { kind: 'fixed', amountMinor: 500, intervalUnit: 'year' }, cells: [
  { row: 1, label: 'Public price', text: 'Synthetic price', interpretation: 'source_only', policyRequirement: null },
  { row: 2, label: 'Capacity', text: '2', interpretation: 'source_only', policyRequirement: null },
] };
function candidate(): CatalogProfileProposal {
  return { reference: source.reference, cells: source.cells.map(cell => ({ row: cell.row, label: cell.label, sourceText: cell.text, disposition: 'mapped', featureKeys: cell.row === 1 ? [] : ['capacity'], evidence: 'Synthetic authoritative owner binding' })), unresolved: [], bundle: {
    schemaVersion: 1, draft: { schemaVersion: 2, id: revisionId, plan, revisionNumber: 1, name: source.displayName, audiences: ['individual'], purchaseMode: 'self_service', prices: [{ id: '40000000-0000-4000-8000-000000000001', currency: 'INR', minorUnit: 2, amountMinor: 500, intervalUnit: 'year', intervalCount: 1, quantityBasis: 'subscription', audiences: ['individual'] }], features: [{ key: 'capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 2 } }] }, includedCredits: { schemaVersion: 1, id: '50000000-0000-4000-8000-000000000001', revisionId, funding: 'included', rules: [] } } };
}
function realProfileOwner(saved: typeof proposal.profiles[number]) {
  const calendarId = '60000000-0000-4000-8000-000000000001';
  const draft = saved.bundle.draft;
  const registry: CreditPolicyRegistry = {
    catalog: { productIds: new Set([draft.plan.productId]), audienceKeys: new Set(draft.audiences),
      currencies: new Map([['INR', 2]]),
      featureTypes: new Map(draft.features.map(feature => [feature.key, feature.type as FeatureType])),
      featureOptions: new Map(runtimeContracts.features.map(feature => [feature.key, new Set(feature.terms.map(term => term.value))])) },
    pools: new Map(saved.bundle.includedCredits.rules.map(rule => [rule.poolKey,
      { featureKey: rule.featureKey, recipient: rule.recipient as 'subscriber' | 'organization' | 'managed_learner', audiences: new Set(rule.audiences) }])),
    timePolicyIds: new Set([calendarId]), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set(),
  };
  const configuration = { ...saved.proposedOwnerConfiguration,
    ...(draft.purchaseMode === 'free' ? { subscription_lifecycle: {
      id: '70000000-0000-4000-8000-000000000001', version: 1, productId: draft.plan.productId,
      billing: 'not_applicable', graceDurationMs: 150, readOnlyDurationMs: 900,
      graceAccess: 'read_only', expiredAccess: 'read_only', cancellationAccess: 'read_only',
      immediateDowngradeAllowed: false, paymentFailureRestrictedMs: null, paymentFailureAfterAccess: null,
      paymentRetryOffsetsMs: [], suspensionApprovalRequired: true, reactivationApprovalRequired: true,
    } } : {}),
    subscription_credit_authoring: { ...saved.proposedOwnerConfiguration.subscription_credit_authoring,
      timePolicies: [{ id: calendarId, timeZone: 'UTC', monthlyAnchor: 'subscription_anniversary',
        monthDayOverflow: 'clamp', ambiguousTime: 'reject', nonexistentTime: 'reject' }] },
    subscription_commerce: { ...saved.proposedOwnerConfiguration.subscription_commerce, quoteValidityMs: 12345 },
    subscription_commerce_eligibility: { schemaVersion: 1, bindings: draft.audiences.map(audience => ({ audience,
      subjectKind: audience === 'individual' ? 'user' : 'organization', roles: ['synthetic_owner'] })) },
    subscription_execution: { schemaVersion: 1, operationRoles: { read: ['synthetic_owner'] },
      recipientRoles: Object.fromEntries(saved.bundle.includedCredits.rules.filter(rule => rule.recipient === 'managed_learner')
        .map(rule => [rule.poolKey, ['synthetic_owner']])), consumptionTariffs: [] },
  };
  const owner = { context: { schemaVersion: 1 as const, plan: draft.plan, audiences: draft.audiences, currencies: [{ code: 'INR', minorUnit: 2 }] },
    configuration, registry, registeredRoles: new Set(['synthetic_owner']), monthlyTimePolicyId: calendarId };
  return owner;
}
describe('approved policy owner configuration', () => {
  it('loads the approved values without embedding them in consumers', () => {
    expect(loadApprovedSubscriptionPolicy()).toEqual(approved);
    expect(loadApprovedSubscriptionPolicy().assessments.retake).toEqual({ currency: 'INR', minorUnit: 2, amountMinor: 9900, everyRetake: true });
    expect(loadApprovedSubscriptionPolicy().retention).toMatchObject({ graceDays: 15, readOnlyDays: 90 });
  });
  it('accepts additional configured assessment categories and rejects empty or duplicate categories', () => {
    const categories = [...approved.assessments.categories, 'synthetic_configured_category'];
    expect(validateApprovedSubscriptionPolicy({ ...approved, assessments: { ...approved.assessments, categories } }).assessments.categories).toEqual(categories);
    for (const invalid of [[], [''], [' '], ['basic', 'basic']]) {
      expect(() => validateApprovedSubscriptionPolicy({ ...approved, assessments: { ...approved.assessments, categories: invalid } })).toThrow();
    }
  });
  it.each([
    { ...approved, retention: { ...approved.retention, graceDays: 91 } },
    { ...approved, assessments: { ...approved.assessments, categories: ['basic', 'basic'] } },
    { ...approved, refunds: { ...approved.refunds, revokeAfterRefundedCancellation: false } },
    { ...approved, ai: { conversion: 'fabricated' } },
    { ...approved, secret: 'unexpected' },
  ])('rejects malformed or conflicting policy %#', value => expect(() => validateApprovedSubscriptionPolicy(value)).toThrow());
});
describe('owner publication compiler', () => {
  it('materializes every real BRD profile through the actual publication validators with explicit owner references', () => {
    const calendarId = '60000000-0000-4000-8000-000000000001';
    for (const source of loadBrdCatalog().profiles) {
      const saved = proposal.profiles.find(profile => profile.reference === source.reference)!;
      const owner = realProfileOwner(saved), draft = saved.bundle.draft;
      const { registry, configuration } = owner;
      const compiled = materializeCatalogContract(source, saved as CatalogProfileProposal, owner);
      expect(compiled.draft.plan).toEqual(draft.plan);
      expect(compiled.draft.features).toEqual(draft.features);
      expect(compiled.includedCredits.rules.map(rule => rule.id)).toEqual(saved.bundle.includedCredits.rules.map(rule => rule.id));
      expect(saved.unresolved.length).toBeGreaterThan(0); // The saved review artifact is not silently rewritten or published.
      expect(() => materializeCatalogContract(source, saved as CatalogProfileProposal, { ...owner, registeredRoles: new Set() })).toThrow('registered roles');
      expect(() => materializeCatalogContract(source, saved as CatalogProfileProposal, { ...owner,
        registry: { ...registry, catalog: { ...registry.catalog, featureTypes: new Map() } } })).toThrow('registered');
      expect(() => materializeCatalogContract(source, { ...saved, unresolved: ['Unmapped source access'] } as CatalogProfileProposal, owner)).toThrow('source semantics');
      if (saved.bundle.includedCredits.rules.some(rule => rule.cadence.kind === 'monthly')) {
        expect(() => materializeCatalogContract(source, saved as CatalogProfileProposal, { ...owner,
          configuration: { ...configuration, subscription_credit_authoring: { ...configuration.subscription_credit_authoring, timePolicies: [] } } })).toThrow('configured calendar');
      }
    }
  });
  it('compiles separate included-start and paid-retake grants from explicit category owners', () => {
    const base = compileCatalogProfile(source, candidate(), context, config, registry);
    const assessmentSource = { ...source, cells: [source.cells[0], { ...source.cells[1], label: 'Assessments', text: '2 full assessments/year + 1 retake' }] };
    const bindings = [undefined, ...approved.assessments.categories].flatMap(assessmentCategory => [
      { actionKey: 'assessment.start', featureKey: 'capacity', mode: 'write', quota: { period: 'billing_period', countingEvent: 'assessment_start' }, ...(assessmentCategory ? { assessmentCategory } : {}) },
      { actionKey: 'assessment.retake', featureKey: 'synthetic_retake_access', mode: 'write', paymentRequired: true, ...(assessmentCategory ? { assessmentCategory } : {}) },
    ]);
    const owner = { subscription_publication: { schemaVersion: 1, requiredFeatureKeys: ['capacity', 'synthetic_retake_access'] },
      subscription_actions: { schemaVersion: 1, bindings } };
    const registered = { ...registry, catalog: { ...registry.catalog, featureTypes: new Map([...registry.catalog.featureTypes, ['synthetic_retake_access', 'boolean'] as const]) } };
    const bundle = { ...base, draft: { ...base.draft, features: [...base.draft.features,
      { key: 'synthetic_retake_access', type: 'boolean', enabled: true }] } };
    const proposal: CatalogProfileProposal = { ...candidate(), bundle, cells: assessmentSource.cells.map(cell => ({ row: cell.row, label: cell.label,
      sourceText: cell.text, disposition: cell.row === 1 ? 'mapped' : 'approved_override',
      featureKeys: cell.row === 1 ? [] : ['synthetic_retake_access', 'capacity'], evidence: cell.row === 1 ? 'Synthetic source price' : 'approvedPolicy.assessments' })) };
    const compile = (value = proposal, configuration = owner) => compileCatalogProfile(assessmentSource, value, context, configuration, registered);
    expect(compile().draft.features).toHaveLength(2);
    expect(() => compile({ ...proposal, cells: proposal.cells.map(cell => cell.row === 1 ? cell : { ...cell, featureKeys: ['capacity', 'capacity'] }) })).toThrow('duplicate');
    expect(() => compile(proposal, { ...owner, subscription_actions: { schemaVersion: 1, bindings: bindings.slice(1) } })).toThrow('exact configured');
    expect(() => compile(proposal, { ...owner, subscription_actions: { schemaVersion: 1, bindings: bindings.map(binding => ({ ...binding, paymentRequired: false })) } })).toThrow('every paid retake');
    expect(() => compile({ ...proposal, bundle: { ...bundle, draft: { ...bundle.draft, features: bundle.draft.features.map(grant => grant.type === 'boolean' ? { ...grant, enabled: false } : grant) } } })).toThrow('exclude free');
    expect(() => compile({ ...proposal, bundle: { ...bundle, draft: { ...bundle.draft, features: bundle.draft.features.map(grant => grant.type === 'numeric_limit' ? { ...grant, limit: { kind: 'finite', value: 99 } } : grant) } } })).toThrow('source quantity');
  });
  it('passes an actually complete registered bundle through existing publication owner validators', () => {
    const result = compileCatalogProfile(source, candidate(), context, config, registry);
    expect(result.draft.features[0]).toMatchObject({ key: 'capacity', limit: { kind: 'finite', value: 2 } });
    expect(result).not.toHaveProperty('publishedAt');
  });
  it('rejects known unregistered owner features with a positive control', () => {
    expect(() => compileCatalogProfile(source, candidate(), context, config, registry)).not.toThrow();
    expect(() => compileCatalogProfile(source, candidate(), context, config, { ...registry, catalog: { ...registry.catalog, featureTypes: new Map() } })).toThrow('registered');
  });
  it('rejects incomplete coverage even when bundle shape is valid', () => {
    expect(() => compileCatalogProfile(source, candidate(), context, { subscription_publication: { schemaVersion: 1, requiredFeatureKeys: ['capacity', 'absent'] } }, registry)).toThrow();
  });
  it('rejects unresolved owner requirements before certifying an otherwise complete bundle', () => {
    expect(() => compileCatalogProfile(source, { ...candidate(), unresolved: ['Missing counting owner'] }, context, config, registry)).toThrow('Missing counting owner');
  });
  it('requires exact source cells and rejects unresolved dispositions', () => {
    const input = candidate();
    expect(() => compileCatalogProfile(source, { ...input, cells: input.cells.slice(1) }, context, config, registry)).toThrow('complete');
    expect(() => compileCatalogProfile(source, { ...input, cells: input.cells.map(cell => ({ ...cell, sourceText: 'changed' })) }, context, config, registry)).toThrow('differs');
    expect(() => compileCatalogProfile(source, { ...input, cells: input.cells.map(cell => ({ ...cell, disposition: 'unresolved' })) }, context, config, registry)).toThrow('unresolved');
  });
  it('never invents a free billing interval or charges a starting-at advertised floor', () => {
    expect(() => compileCatalogProfile({ ...source, price: { ...source.price, intervalUnit: null } }, candidate(), context, config, registry)).toThrow('duration');
    expect(() => compileCatalogProfile({ ...source, price: { ...source.price, kind: 'starting_at' } }, candidate(), context, config, registry)).toThrow('negotiated');
  });
  it('rejects an inflated grant while source text and source coordinates remain unchanged', () => {
    const input = candidate();
    const changed = { ...input, bundle: { schemaVersion: 1, draft: {
      schemaVersion: 2, id: revisionId, plan, revisionNumber: 1, name: source.displayName, audiences: ['individual'], purchaseMode: 'contact_sales', prices: [],
      features: [{ key: 'capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 999 } }],
    }, includedCredits: { schemaVersion: 1, id: '50000000-0000-4000-8000-000000000001', revisionId, funding: 'included', rules: [] } } };
    expect(() => compileCatalogProfile(source, changed, context, config, registry)).toThrow('source quantity differs');
  });
  it('requires exact full-profile cardinality and refuses the real blocked proposal', () => {
    expect(() => compileCatalogRollout(loadBrdCatalog(), [], () => ({ context, configuration: config, registry }))).toThrow('complete');
    expect(() => compileCatalogRollout(loadBrdCatalog(), proposal.profiles as CatalogProfileProposal[], () => ({ context, configuration: config, registry }))).toThrow('rollout.unresolved');
  });
});
describe('unapplied stored rollout preparation', () => {
  it('covers every source cell, profile and source public price without claiming publication', () => {
    const catalog = loadBrdCatalog();
    expect(proposal.profiles).toHaveLength(catalog.profiles.length);
    for (const source of catalog.profiles) {
      const profile = proposal.profiles.find(value => value.reference === source.reference)!;
      expect(profile.cells.map(cell => [cell.row, cell.label, cell.sourceText])).toEqual(source.cells.map(cell => [cell.row, cell.label, cell.text]));
      expect(profile.unresolved.length).toBeGreaterThan(0);
      expect(profile.bundle.draft.plan.code).toMatch(/^pln_[a-f0-9]{32}$/);
      if (source.price.kind === 'fixed' && source.price.intervalUnit) expect(profile.bundle.draft.prices[0].amountMinor).toBe(source.price.amountMinor);
      else expect(profile.bundle.draft.prices).toEqual([]);
    }
    expect(new Set(proposal.profiles.map(value => value.bundle.draft.plan.id)).size).toBe(catalog.profiles.length);
    expect(proposal.status).toBe('prepared_not_applied');
  });
  it('preserves actual Hybrid UUID and immutable existing customer terms', () => {
    const hybrid = baseline.plans.find(plan => plan.code === 'hybrid')!;
    expect(validateCatalogTransition(proposal.transition, hybrid.id)).toEqual(proposal.transition);
    expect(() => validateCatalogTransition({ ...proposal.transition, retireLegacy: true }, hybrid.id)).toThrow();
    expect(() => validateCatalogTransition({ ...proposal.transition, preservePurchasedSnapshots: false }, hybrid.id)).toThrow();
    expect(() => validateCatalogTransition(proposal.transition, plan.id)).toThrow('preserved');
  });
  it('prepares six explicit assessment categories while denying free-plan assessment capacity', () => {
    for (const profile of proposal.profiles.filter(value => value.bundle.draft.features.some(feature => feature.key === 'assessment_attempts'))) {
      const bindings: readonly { actionKey: string; assessmentCategory?: string; paymentRequired?: boolean }[] = profile.proposedOwnerConfiguration.subscription_actions.bindings;
      expect(bindings.filter(binding => binding.actionKey === 'assessment.start' && binding.assessmentCategory !== undefined).map(binding => binding.assessmentCategory)).toEqual(approved.assessments.categories);
      expect(bindings.filter(binding => binding.actionKey === 'assessment.retake').every(binding => binding.paymentRequired)).toBe(true);
      const source = loadBrdCatalog().profiles.find(value => value.reference === profile.reference)!;
      if (source.price.amountMinor === 0) expect(profile.bundle.draft.features.find(feature => feature.key === 'assessment_attempts')).toMatchObject({ enabled: false, limit: { value: 0 } });
    }
  });
});

describe('canonical inactive catalog installation', () => {
  function installation() {
    const catalog = loadBrdCatalog();
    const owners = new Map(proposal.profiles.map(saved => [saved.reference, realProfileOwner(saved)]));
    const entries = proposal.profiles.map((saved, index) => ({ reference: saved.reference, expected: null as Record<string, unknown> | null,
      plan: { id: saved.bundle.draft.plan.id, plan_code: saved.bundle.draft.plan.code, product_id: proposal.productId,
        name: saved.bundle.draft.name, business_type: 'synthetic_configured_business', applicable_entities: saved.bundle.draft.audiences,
        pricing_matrix: {}, base_features: [], entity_config: owners.get(saved.reference)!.configuration, display_order: index, is_active: false as const } }));
    const hybridPlanId = '70000000-0000-4000-8000-000000000001';
    const request = { schemaVersion: 1, operationId: '70000000-0000-4000-8000-000000000002', productId: proposal.productId,
      hybridPlanId, approvalReference: 'Synthetic exact canonical installation approval', entries };
    const snapshot = { productId: proposal.productId, hybridPlanId,
      plans: [{ id: hybridPlanId, product_id: proposal.productId, plan_code: 'synthetic_retained_code', is_active: true }] as Record<string, unknown>[],
      purchasedPlanIds: new Set<string>(), publishedPlanIds: new Set<string>() };
    const actor = '70000000-0000-4000-8000-000000000003';
    const owner = (reference: string) => owners.get(reference)!;
    return { request, snapshot, actor, catalog, owner, owners };
  }
  it('prepares all 21 canonical inactive candidates with exact owner terms and no publication or activation', () => {
    const f = installation(), before = JSON.stringify({ request: f.request, snapshot: f.snapshot });
    const result = prepareCatalogInstallation(f.request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor);
    expect(result.entries).toHaveLength(f.catalog.profiles.length);
    expect(result.entries.every(entry => entry.plan.is_active === false && entry.plan.id !== result.hybridPlanId)).toBe(true);
    expect(result.actorId).toBe(f.actor);
    expect(JSON.stringify({ request: f.request, snapshot: f.snapshot })).toBe(before);
    expect(result).not.toHaveProperty('publishedRevisionId');
  });
  it('allows only an explicit full-row CAS configuration update for an inactive unused candidate', () => {
    const f = installation(), first = f.request.entries[0];
    first.expected = { ...first.plan, entity_config: {}, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' };
    f.snapshot.plans.push(structuredClone(first.expected));
    const prepare = () => prepareCatalogInstallation(f.request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor);
    expect(prepare().entries[0].expected).toEqual(first.expected);
    first.expected.updated_at = '2026-01-02T00:00:00Z';
    expect(prepare).toThrow('exact existing row');
  });
  it('refuses purchased, published, already existing, active and Hybrid plan overwrites', () => {
    for (const mode of ['purchased', 'published', 'existing', 'active', 'hybrid'] as const) {
      const f = installation(), first = f.request.entries[0];
      if (mode === 'purchased') f.snapshot.purchasedPlanIds.add(first.plan.id);
      if (mode === 'published') f.snapshot.publishedPlanIds.add(first.plan.id);
      if (mode === 'existing') f.snapshot.plans.push({ ...first.plan });
      if (mode === 'active') first.plan.is_active = true as false;
      if (mode === 'hybrid') first.plan.id = f.snapshot.hybridPlanId;
      expect(() => prepareCatalogInstallation(f.request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor)).toThrow();
    }
  });
  it('rejects missing source profiles, duplicate identities, foreign product, caller actor and guessed owner configuration', () => {
    for (const mode of ['missing', 'duplicate', 'foreign', 'actor', 'configuration'] as const) {
      const f = installation();
      let request: unknown = f.request;
      if (mode === 'missing') f.request.entries.pop();
      if (mode === 'duplicate') f.request.entries[1].plan.plan_code = f.request.entries[0].plan.plan_code;
      if (mode === 'foreign') f.request.entries[0].plan.product_id = f.snapshot.hybridPlanId;
      if (mode === 'actor') request = { ...f.request, actorId: f.actor };
      if (mode === 'configuration') f.request.entries[0].plan.entity_config = { ...f.request.entries[0].plan.entity_config,
        subscription_commerce: { ...f.request.entries[0].plan.entity_config.subscription_commerce, quoteValidityMs: 999 } };
      expect(() => prepareCatalogInstallation(request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor)).toThrow();
    }
  });
  it('preserves unrelated existing configuration and existing candidate display fields', () => {
    const f = installation(), first = f.request.entries[0];
    first.expected = { ...first.plan, entity_config: { unrelated: { preserve: true } }, created_at: null, updated_at: null };
    f.snapshot.plans.push(structuredClone(first.expected));
    expect(() => prepareCatalogInstallation(f.request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor)).toThrow('unrelated existing configuration');
    const originalOwner = f.owners.get(first.reference)!;
    const configuration = { ...originalOwner.configuration, unrelated: { preserve: true } };
    f.owners.set(first.reference, { ...originalOwner, configuration }); first.plan.entity_config = configuration;
    expect(() => prepareCatalogInstallation(f.request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor)).not.toThrow();
    first.expected.name = 'Changed unrelated display field';
    f.snapshot.plans[f.snapshot.plans.length - 1] = structuredClone(first.expected);
    expect(() => prepareCatalogInstallation(f.request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor)).toThrow('candidate fields');
  });
  it('validates exact replay receipts and propagates uncertainty without another write', async () => {
    const f = installation();
    const command = prepareCatalogInstallation(f.request, f.catalog, proposal.profiles as CatalogProfileProposal[], f.owner, f.snapshot, f.actor);
    const expected = { operationId: command.operationId, actorId: f.actor, command, planIds: command.entries.map(entry => entry.plan.id) };
    const rpc = vi.fn().mockResolvedValue(expected);
    expect(await installCanonicalCatalog({ rpc }, command)).toEqual(expected);
    expect(rpc).toHaveBeenCalledExactlyOnceWith('install_subscription_catalog_candidates', { p_command: command });
    for (const bad of [{ ...expected, actorId: command.hybridPlanId }, { ...expected, planIds: [] },
      { ...expected, command: { ...command, approvalReference: 'different' } }]) {
      rpc.mockResolvedValueOnce(bad);
      await expect(installCanonicalCatalog({ rpc }, command)).rejects.toThrow('acknowledgement');
    }
    rpc.mockRejectedValueOnce(new Error('uncertain write outcome'));
    await expect(installCanonicalCatalog({ rpc }, command)).rejects.toThrow('uncertain write outcome');
    expect(rpc).toHaveBeenCalledTimes(5);
  });
});
