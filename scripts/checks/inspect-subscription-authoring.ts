// Audit tool only: GET/HEAD against explicitly configured loopback owners. No RPC or mutation surface.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { readPlanAuthoringContext } from '../../src/lib/subscriptions/authoring-context';
import { readCreditAuthoringContext } from '../../src/lib/subscriptions/credit-authoring-context';
import { validatePlanIdentity } from '../../src/lib/subscriptions/catalog';
import { CatalogValidationError } from '../../src/lib/subscriptions/validation';
import { validatePlanRevisionBundle } from '../../src/lib/subscriptions/revision-bundle';
import { readPlanPublicationCompleteness } from '../../src/lib/subscriptions/publication-readiness';
import { createPlanPublicationProjection } from '../../src/lib/subscriptions/publication-projection';
import type { FeatureType } from '../../src/lib/subscriptions/types';

const root = process.cwd();
const taskRequire = createRequire(resolve(root, 'sp-dash/package.json'));
const { parse } = taskRequire('dotenv') as { parse(input: Buffer): Record<string, string> };
const settings = (app: string) => parse(readFileSync(resolve(root, app, '.dev.vars')));
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const dictionary = (value: unknown): Record<string, unknown> => {
  assert.ok(value !== null && typeof value === 'object' && !Array.isArray(value));
  return value as Record<string, unknown>;
};

function owner(app: string, tables: readonly string[]) {
  const env = settings(app);
  const origin = new URL(env.SUPABASE_URL);
  assert.equal(origin.protocol, 'http:');
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname));
  assert.ok(!origin.username && !origin.password && !origin.search && !origin.hash && origin.pathname === '/');
  assert.ok(env.SUPABASE_SERVICE_ROLE_KEY?.trim());
  async function read(path: string, method: 'GET' | 'HEAD' = 'GET') {
    assert.ok(tables.includes(path.split('?')[0]));
    const url = new URL('/rest/v1/' + path, origin);
    const response = await fetch(url, { method, redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        ...(method === 'HEAD' ? { Prefer: 'count=exact' } : {}) } });
    if (!response.ok) { await response.body?.cancel(); throw new Error('Configured owner read failed'); }
    return response;
  }
  const query = async (path: string): Promise<unknown[]> => {
    const response = await read(path);
    const value: unknown = await response.json();
    assert.ok(Array.isArray(value));
    return value;
  };
  async function inventory(path: string) {
    const result: Record<string, unknown>[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 100; page++) {
      const suffix = '&order=id.asc&limit=200' + (cursor === undefined ? '' : '&id=gt.' + encodeURIComponent(cursor));
      const rows = await query(path + suffix);
      if (!rows.length) return result;
      for (const raw of rows) {
        const row = dictionary(raw);
        assert.equal(typeof row.id, 'string');
        const id = String(row.id).toLowerCase();
        assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
        assert.ok(cursor === undefined || id > cursor);
        result.push(row); cursor = id;
      }
    }
    throw new Error('Inspection page budget exceeded');
  }
  async function count(table: string) {
    const response = await read(table + '?select=id&limit=1', 'HEAD');
    const match = /\/(\d+)$/.exec(response.headers.get('content-range') ?? '');
    assert.ok(match);
    const value = Number(match[1]); assert.ok(Number.isSafeInteger(value));
    return value;
  }
  return { env, query, inventory, count };
}

async function main() {
  assert.ok(process.argv.length === 2 || process.argv.length === 3
    && ['--validate-proposal', '--validate-installed-candidate', '--inspect-publication-completeness'].includes(process.argv[2]));
  const sso = owner('sso-worker', ['plans', 'products', 'subscription_plan_drafts']);
  const app = owner('skillpassport', ['features']);
  const productId = app.env.SKILLPASSPORT_PRODUCT_ID;
  assert.match(productId, /^[0-9a-f-]{36}$/);
  const products = await sso.query('products?select=id,code,name&id=eq.' + encodeURIComponent(productId) + '&limit=2');
  assert.equal(products.length, 1);
  assert.equal(dictionary(products[0]).code, JSON.parse(readFileSync(resolve(root, 'skillpassport/package.json'), 'utf8')).name);
  const path = 'plans?select=id,plan_code,product_id,name,is_active,applicable_entities,entity_config';
  const before = await sso.inventory(path);
  const draftsBefore = await sso.count('subscription_plan_drafts');
  const features = await app.inventory('features?select=id,feature_key,feature_type,display_name,category,value_options');
  const featureTypes = new Map(features.map(feature => [feature.feature_key, feature.feature_type]));
  assert.equal(featureTypes.size, features.length);
  if (process.argv[2]) {
    const completeness = process.argv[2] === '--inspect-publication-completeness';
    const installed = process.argv[2] !== '--validate-proposal';
    const artifact = JSON.parse(readFileSync(resolve(root, 'audit-evidence/local-subscription-db-audit/authoring-readiness.json'), 'utf8'));
    const proposal = artifact.proposal;
    assert.ok(proposal && proposal.canonicalPlanRow && proposal.bundle);
    const candidate = proposal.canonicalPlanRow;
    assert.equal(candidate.is_active, false);
    assert.equal(candidate.product_id, productId);
    if (installed) {
      const matches = before.filter(row => row.id === candidate.id || row.plan_code === candidate.plan_code);
      assert.equal(matches.length, 1);
      for (const [key, value] of Object.entries(matches[0])) assert.deepEqual(value, candidate[key]);
    } else assert.ok(!before.some(row => row.id === candidate.id || row.plan_code === candidate.plan_code));
    // Proposed-row validation only. The actual DB remains unchanged and this is not deployed acceptance.
    const proposed = { query: async (path: string): Promise<unknown[]> => {
      if (path.startsWith('products?')) return sso.query(path);
      assert.equal(path, 'plans?select=id,plan_code,product_id,applicable_entities,entity_config&id=eq.' + candidate.id + '&limit=2');
      return [{ id: candidate.id, plan_code: candidate.plan_code, product_id: candidate.product_id,
        applicable_entities: candidate.applicable_entities, entity_config: candidate.entity_config }];
    } };
    // The installed mode always reads the owner; it never substitutes a proposed row on failure.
    const context = await readCreditAuthoringContext(installed ? sso : proposed, candidate.id);
    const types = new Map<string, FeatureType>();
    const options = new Map<string, ReadonlySet<string>>();
    for (const [key, type] of featureTypes) {
      assert.equal(typeof key, 'string');
      assert.ok(type === 'boolean' || type === 'numeric_limit' || type === 'metered' || type === 'enum');
      types.set(String(key), type);
    }
    for (const feature of features) {
      if (feature.feature_type === 'enum') {
        assert.ok(Array.isArray(feature.value_options) && feature.value_options.length > 0);
        const values = feature.value_options.map((value: unknown) => {
          assert.ok(typeof value === 'string' && /^[a-z][a-z0-9_]*$/.test(value));
          return value;
        });
        assert.equal(new Set(values).size, values.length);
        options.set(String(feature.feature_key), new Set(values));
      } else assert.equal(feature.value_options, null);
    }
    const registry = {
      catalog: { productIds: new Set([productId]), audienceKeys: new Set(context.audiences),
        currencies: new Map(context.currencies.map(item => [item.code, item.minorUnit])), featureTypes: types, featureOptions: options },
      pools: new Map(context.credit.pools.map(item => [item.key, { ...item, audiences: new Set(item.audiences) }])),
      timePolicyIds: new Set(context.credit.timePolicies.map(item => item.id)),
      rolloverApprovalIds: new Set<string>(), expiryApprovalIds: new Set<string>(),
    };
    // The generic validator validates a product registry, not a canonical plan lookup.
    // Match the extra binding enforced by the real SSO staging entrypoint too.
    const validateCandidateBundle = (value: unknown) => {
      const bundle = validatePlanRevisionBundle(value, registry);
      assert.deepEqual(bundle.draft.plan, context.plan, 'Proposed revision differs from canonical candidate identity');
      return bundle;
    };
    validateCandidateBundle(proposal.bundle);
    if (completeness) {
      let failure: string | null = null;
      let projectionCompiled = false;
      try {
        const staged = await readPlanPublicationCompleteness(sso, candidate.id, proposal.bundle.draft.id, registry);
        createPlanPublicationProjection(staged.bundle, context,
          dictionary(before.find(row => row.id === candidate.id)?.entity_config), registry,
          features.map(feature => {
            const featureId = feature.id, featureKey = feature.feature_key;
            assert.ok(typeof featureId === 'string' && typeof featureKey === 'string');
            const type = types.get(featureKey);
            assert.ok(type);
            return { id: featureId, key: featureKey, type };
          }));
        projectionCompiled = true;
      }
      catch (error) { if (!(error instanceof CatalogValidationError)) throw error; failure = error.path; }
      assert.equal(hash(before), hash(await sso.inventory(path)));
      assert.equal(draftsBefore, await sso.count('subscription_plan_drafts'));
      console.log(JSON.stringify({ mode: 'read-only', completeness: failure === null ? 'passed' : 'blocked',
        failure, projectionCompiled, projectionPersisted: false, publicationPerformed: false, activationPerformed: false,
        limits: 'Completeness is not approval, application-rule readiness or an atomic publication transition.' }));
      console.log('SUBSCRIPTION_PUBLICATION_COMPLETENESS_INSPECTED');
      return;
    }
    const badFeature = structuredClone(proposal.bundle); badFeature.draft.features[0].key += '_unregistered_control';
    assert.throws(() => validatePlanRevisionBundle(badFeature, registry), CatalogValidationError);
    const badRevision = structuredClone(proposal.bundle); badRevision.includedCredits.revisionId = productId;
    assert.throws(() => validatePlanRevisionBundle(badRevision, registry), CatalogValidationError);
    const badScope = structuredClone(proposal.bundle); badScope.draft.audiences = ['unregistered_control'];
    assert.throws(() => validatePlanRevisionBundle(badScope, registry), CatalogValidationError);
    const badPlanId = structuredClone(proposal.bundle);
    assert.notEqual(productId, candidate.id);
    badPlanId.draft.plan.id = productId;
    // Positive control: shape validation alone accepts this other valid UUID.
    validatePlanRevisionBundle(badPlanId, registry);
    assert.throws(() => validateCandidateBundle(badPlanId), { code: 'ERR_ASSERTION' });
    const badPlanCode = structuredClone(proposal.bundle);
    badPlanCode.draft.plan.code = candidate.plan_code.slice(0, -1) + (candidate.plan_code.endsWith('0') ? '1' : '0');
    validatePlanRevisionBundle(badPlanCode, registry);
    assert.throws(() => validateCandidateBundle(badPlanCode), { code: 'ERR_ASSERTION' });
    assert.equal(hash(before), hash(await sso.inventory(path)));
    assert.equal(draftsBefore, await sso.count('subscription_plan_drafts'));
    console.log(JSON.stringify({ proposedRowValidatedOnly: !installed, installedCanonicalContextUsed: installed,
      currentOwnerFeatureDefinitionsUsed: true,
      negativeControls: 5, canonicalCandidateIdentityBound: true, newPlanInactive: true,
      existingPlanConfigurationUnchanged: true, draftCountUnchanged: true }));
    console.log(installed ? 'SUBSCRIPTION_AUTHORING_INSTALLED_CANDIDATE_VALIDATED' : 'SUBSCRIPTION_AUTHORING_PROPOSAL_VALIDATED');
    return;
  }
  const plans = [];
  for (const row of before.filter(plan => plan.product_id === productId)) {
    let identityValid = false;
    try { validatePlanIdentity({ id: row.id, code: row.plan_code, productId: row.product_id }); identityValid = true; }
    catch (error) { if (!(error instanceof CatalogValidationError)) throw error; }
    let commercialValid = false, creditValid = false;
    let commercialFailure: string | null = null, creditFailure: string | null = null;
    try { await readPlanAuthoringContext(sso, String(row.id)); commercialValid = true; }
    catch (error) { if (!(error instanceof CatalogValidationError)) throw error; commercialFailure = error.path; }
    try {
      const context = await readCreditAuthoringContext(sso, String(row.id));
      creditValid = context.credit.pools.every(pool => featureTypes.get(pool.featureKey) === 'metered');
      if (!creditValid) creditFailure = 'owner.poolFeatureType';
    } catch (error) { if (!(error instanceof CatalogValidationError)) throw error; creditFailure = error.path; }
    const configuration = row.entity_config !== null && typeof row.entity_config === 'object' && !Array.isArray(row.entity_config)
      ? row.entity_config as Record<string, unknown> : null;
    plans.push({ id: row.id, code: row.plan_code, name: row.name, active: row.is_active, audiences: row.applicable_entities,
      identityValid, commercialSectionPresent: configuration !== null && Object.hasOwn(configuration, 'subscription_authoring'),
      creditSectionPresent: configuration !== null && Object.hasOwn(configuration, 'subscription_credit_authoring'),
      commercialValid, creditValid, commercialFailure, creditFailure });
  }
  const after = await sso.inventory(path);
  const draftsAfter = await sso.count('subscription_plan_drafts');
  assert.equal(hash(before), hash(after), 'Plan configuration changed during inspection; no mutation attribution is inferred');
  assert.equal(draftsBefore, draftsAfter, 'Draft count changed during inspection; no mutation attribution is inferred');
  console.log(JSON.stringify({ inspectedAt: new Date().toISOString(), mode: 'read-only', product: products[0],
    summary: { plans: plans.length, activePlans: plans.filter(plan => plan.active === true).length,
      genericIdentities: plans.filter(plan => plan.identityValid).length,
      commercialSections: plans.filter(plan => plan.commercialSectionPresent).length,
      creditSections: plans.filter(plan => plan.creditSectionPresent).length,
      validCommercialContexts: plans.filter(plan => plan.commercialValid).length,
      validCreditContexts: plans.filter(plan => plan.creditValid).length,
      draftRows: draftsAfter, features: features.length },
    plans, features: features.map(feature => ({ key: feature.feature_key, type: feature.feature_type, name: feature.display_name })),
    planConfigurationFingerprint: hash(before), configurationStableDuringInspection: true,
    draftCountStableDuringInspection: true,
    limits: ['Existing production owner readers validate current rows unchanged. Invalid identity can mask later validation failures.',
      'Section presence is measured separately and does not imply valid configuration.',
      'Separate owner reads are not an atomic cross-database snapshot. No write or deployed endpoint acceptance is performed.'] }));
  console.log('SUBSCRIPTION_AUTHORING_READINESS_INSPECTED');
}
main().catch(() => { console.error('Subscription authoring inspection failed. No credential values or raw owner response were printed.'); process.exitCode = 1; });
