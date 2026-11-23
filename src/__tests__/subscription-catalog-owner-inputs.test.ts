import { describe, expect, it } from 'vitest';
import saved from '../../../audit-evidence/local-subscription-db-audit/catalog-rollout.json';
import inputsJson from '../../config/subscriptions/owner-inputs.json';
import runtimeContracts from '../../config/subscriptions/runtime-contracts.json';
import { loadBrdCatalog } from '../lib/subscriptions/brd-catalog';
import type { SavedCatalogProfile } from '../lib/subscriptions/catalog-owner-inputs';
import { loadCatalogOwnerInputs, resolveCatalogOwnerContract, validateCatalogOwnerInputs } from '../lib/subscriptions/catalog-owner-inputs';
import { materializeCatalogContract } from '../lib/subscriptions/catalog-rollout';
import type { CreditPolicyRegistry } from '../lib/subscriptions/credit-policy';
import type { FeatureType } from '../lib/subscriptions/types';
import approvedPolicy from '../../config/subscriptions/approved-policy.json';

// Live SSO role registry (public.roles), read 2026-11-21. The registry, not this list, is the authority at publication.
const liveRoles = new Set(['admin', 'college_admin', 'college_educator', 'company_admin', 'educator', 'hr', 'learner', 'member', 'owner',
  'recruiter', 'rm_admin', 'rm_manager', 'school_admin', 'school_educator', 'super_admin', 'university_admin']);
const catalog = loadBrdCatalog();
const inputs = loadCatalogOwnerInputs();
const profiles = saved.profiles as unknown as SavedCatalogProfile[];

function registryFor(profile: SavedCatalogProfile): CreditPolicyRegistry {
  const bundle = profile.bundle as {
    draft: { plan: { productId: string }; audiences: string[]; features: { key: string; type: string }[] };
    includedCredits: { rules: { poolKey: string; featureKey: string; recipient: string; audiences: string[] }[] }
  };
  return {
    catalog: {
      productIds: new Set([bundle.draft.plan.productId]), audienceKeys: new Set(bundle.draft.audiences),
      currencies: new Map([[catalog.currency.code, catalog.currency.minorUnit]]),
      featureTypes: new Map(bundle.draft.features.map(feature => [feature.key, feature.type as FeatureType])),
      featureOptions: new Map(runtimeContracts.features.map(feature => [feature.key, new Set(feature.terms.map(term => term.value))]))
    },
    pools: new Map(bundle.includedCredits.rules.map(rule => [rule.poolKey,
    { featureKey: rule.featureKey, recipient: rule.recipient as 'subscriber' | 'organization' | 'managed_learner', audiences: new Set(rule.audiences) }])),
    timePolicyIds: new Set([inputs.monthlyTimePolicy.id]), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set(),
  };
}
function compile(reference: string, override = inputs) {
  const source = catalog.profiles.find(profile => profile.reference === reference)!;
  const profile = profiles.find(value => value.reference === reference)!;
  const resolved = resolveCatalogOwnerContract(source, profile, override, catalog.currency);
  const draft = (resolved.proposal.bundle as { draft: { plan: never; audiences: string[] } }).draft;
  return materializeCatalogContract(source, resolved.proposal, {
    context: {
      schemaVersion: 1, plan: draft.plan, audiences: draft.audiences,
      currencies: [{ code: catalog.currency.code, minorUnit: catalog.currency.minorUnit }]
    },
    configuration: resolved.configuration, registry: registryFor(profile), registeredRoles: liveRoles, monthlyTimePolicyId: resolved.monthlyTimePolicyId
  });
}

describe('approved catalog owner inputs', () => {
  it('binds approved institution trial capacity without changing other published grants or credits', () => {
    for (const [reference, capacity] of inputs.trialLearnerCapacities) {
      const prior = profiles.find(p => p.reference === reference)!;
      const source = catalog.profiles.find(p => p.reference === reference)!;
      const before = structuredClone(prior);
      const resolved = resolveCatalogOwnerContract(source, prior, inputs, catalog.currency);
      const compiled = compile(reference);
      const original = prior.bundle as typeof compiled;
      expect(capacity).toBe(25);
      expect(compiled.draft.features.find(f => f.key === 'included_learner_capacity')).toEqual({
        key: 'included_learner_capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: capacity }
      });
      expect(prior).toEqual(before);
      expect(compiled.draft.features.filter(f => f.key !== 'included_learner_capacity'))
        .toEqual(original.draft.features.filter(f => f.key !== 'included_learner_capacity'));
      expect(compiled.includedCredits).toEqual(original.includedCredits);
      expect(resolved.proposal.cells.find(c => c.featureKeys.includes('included_learner_capacity'))).toMatchObject({
        disposition: 'approved_override', evidence: 'ownerInputs.trialLearnerCapacities'
      });
    }
    for (const capacities of [{}, { ...inputsJson.trialLearnerCapacities, 'brd:7:1': 0 },
      { ...inputsJson.trialLearnerCapacities, 'brd:7:1': 1.5 },
      { ...inputsJson.trialLearnerCapacities, 'brd:6:1': 25 },
      { ...inputsJson.trialLearnerCapacities, unknown: 25 }]) {
      expect(() => compile('brd:7:1', validateCatalogOwnerInputs({ ...inputsJson, trialLearnerCapacities: capacities }))).toThrow();
    }
  });
  it('compiles every BRD profile with no unresolved owner input', () => {
    expect(profiles).toHaveLength(catalog.profiles.length);
    for (const source of catalog.profiles) expect(() => compile(source.reference)).not.toThrow();
  });
  it('makes institution Starter and Professional self-serve at the advertised floor and keeps Enterprise contact-sales', () => {
    for (const source of catalog.profiles.filter(profile => profile.price.kind === 'starting_at')) {
      const bundle = compile(source.reference);
      if (inputs.selfServeStartingAt.has(source.reference)) {
        expect(bundle.draft.purchaseMode).toBe('self_service');
        expect(bundle.draft.prices).toHaveLength(1);
        expect(bundle.draft.prices[0]).toMatchObject({ amountMinor: source.price.amountMinor, intervalUnit: source.price.intervalUnit, quantityBasis: 'subscription' });
      } else {
        expect(bundle.draft.purchaseMode).toBe('contact_sales');
        expect(bundle.draft.prices).toEqual([]);
      }
    }
    expect([...inputs.selfServeStartingAt.keys()].sort()).toEqual(['brd:7:2', 'brd:7:3', 'brd:8:2', 'brd:8:3', 'brd:9:2', 'brd:9:3']);
  });
  it('binds approved free entry: permanent Discover and Recruiter Free, 30-day trials', () => {
    for (const source of catalog.profiles.filter(profile => profile.price.amountMinor === 0)) {
      const profile = profiles.find(value => value.reference === source.reference)!;
      const { configuration } = resolveCatalogOwnerContract(source, profile, inputs, catalog.currency);
      const expected = source.section === 6 || source.section === 10 ? { schemaVersion: 1, validity: 'perpetual' } : { schemaVersion: 1, validity: 'fixed_duration', durationDays: 30 };
      expect(configuration.subscription_entry).toEqual(expected);
      expect(configuration.subscription_lifecycle).toEqual({ ...inputsJson.freeLifecycle, productId: saved.productId,
        graceAccess: 'read_only', expiredAccess: 'read_only',
        graceDurationMs: approvedPolicy.retention.graceDays * 86400000,
        readOnlyDurationMs: approvedPolicy.retention.readOnlyDays * 86400000 });
      expect(compile(source.reference).draft.purchaseMode).toBe('free');
    }
  });
  it('grants only approved manager roles commerce and lifecycle operations, and members read/consume only', () => {
    const { configuration } = resolveCatalogOwnerContract(catalog.profiles.find(p => p.reference === 'brd:10:3')!,
      profiles.find(p => p.reference === 'brd:10:3')!, inputs, catalog.currency);
    const roles = (configuration.subscription_execution as { operationRoles: Record<string, string[]> }).operationRoles;
    expect(roles.upgrade).toEqual(['owner', 'company_admin']);
    expect(roles.consume).toEqual(['owner', 'company_admin', 'recruiter', 'hr']);
    for (const operation of ['allocate', 'expire', 'payment_failed', 'suspend', 'reactivate']) expect(roles).not.toHaveProperty(operation);
    expect((configuration.subscription_commerce as { quoteValidityMs: number }).quoteValidityMs).toBe(inputsJson.quoteValidityMs);
  });
  it('places one contextual BRD section 19 badge per audience and none elsewhere', () => {
    for (const source of catalog.profiles) {
      const { configuration } = resolveCatalogOwnerContract(source, profiles.find(p => p.reference === source.reference)!, inputs, catalog.currency);
      expect((configuration.subscription_presentation as { badge: string | null }).badge).toBe(inputs.presentationBadges.get(source.reference) ?? null);
    }
    expect(inputs.presentationBadges.size).toBe(5);
  });
  it('owns recruiter and institution pools by the organization subject the application debits', () => {
    // skillpassport/functions/shared/lib/subscription-access.ts selects only organization-recipient pools for recruiter credits.
    for (const source of catalog.profiles.filter(profile => profile.section >= 7)) {
      const rules = compile(source.reference).includedCredits.rules.filter(rule => rule.recipient !== 'managed_learner');
      expect(rules.length).toBeGreaterThan(0);
      for (const rule of rules) expect(rule.recipient).toBe('organization');
    }
    for (const source of catalog.profiles.filter(profile => profile.section === 6)) {
      for (const rule of compile(source.reference).includedCredits.rules) expect(rule.recipient).toBe('subscriber');
    }
  });
  it('binds every monthly credit rule to the approved monthly time policy and refuses a different one', () => {
    let monthly = 0;
    for (const source of catalog.profiles) {
      const profile = profiles.find(p => p.reference === source.reference)!;
      const { proposal } = resolveCatalogOwnerContract(source, profile, inputs, catalog.currency);
      for (const rule of (proposal.bundle as { includedCredits: { rules: { cadence: { kind: string; timePolicyId?: string } }[] } }).includedCredits.rules) {
        if (rule.cadence.kind !== 'monthly') continue;
        monthly++;
        expect(rule.cadence.timePolicyId).toBe(inputs.monthlyTimePolicy.id);
      }
    }
    expect(monthly).toBeGreaterThan(0);
    const source = catalog.profiles.find(p => p.reference === 'brd:6:1')!;
    const profile = structuredClone(profiles.find(p => p.reference === 'brd:6:1')!);
    (profile.bundle as { includedCredits: { rules: { cadence: { timePolicyId: string } }[] } }).includedCredits.rules[0].cadence.timePolicyId = '00000000-0000-4000-8000-000000000009';
    expect(() => resolveCatalogOwnerContract(source, profile, inputs, catalog.currency)).toThrow('another time policy');
  });
  it('rejects unregistered roles, missing quote lifetime and ambiguous free terms', () => {
    const bad = (patch: Record<string, unknown>) => validateCatalogOwnerInputs({ ...inputsJson, ...patch });
    expect(() => compile('brd:8:2', bad({ audiences: { ...inputsJson.audiences, college: { subjectKind: 'organization', businessType: 'b2b', managerRoles: ['unregistered_role'], memberRoles: [] } } }))).toThrow('registered roles');
    expect(() => bad({ quoteValidityMs: 0 })).toThrow();
    expect(() => bad({ freeLifecycle: undefined })).toThrow('freeLifecycle');
    expect(() => bad({ freeLifecycle: { ...inputsJson.freeLifecycle, paymentRetryOffsetsMs: [1000] } })).toThrow('freeLifecycle');
    expect(() => bad({ freeLifecycle: { ...inputsJson.freeLifecycle, reactivationApprovalRequired: 'yes' } })).toThrow('freeLifecycle');
    expect(() => bad({ freeEntry: { ...inputsJson.freeEntry, 'brd:6:1': { validity: 'perpetual', durationDays: 30 } } })).toThrow('perpetual');
    expect(() => bad({ freeEntry: { ...inputsJson.freeEntry, 'brd:7:1': { validity: 'fixed_duration' } } })).toThrow();
    const { 'brd:10:1': _omitted, ...missingFree } = inputsJson.freeEntry;
    expect(() => compile('brd:10:1', bad({ freeEntry: missingFree }))).toThrow('exactly the free profiles');
    expect(() => compile('brd:10:5', bad({ selfServeStartingAt: { ...inputsJson.selfServeStartingAt, 'brd:6:2': { priceId: '00000000-0000-4000-8000-000000000001' } } }))).not.toThrow();
    expect(() => compile('brd:6:2', bad({ selfServeStartingAt: { ...inputsJson.selfServeStartingAt, 'brd:6:2': { priceId: '00000000-0000-4000-8000-000000000001' } } }))).toThrow('only starting-at');
  });
});
