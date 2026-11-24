// Offline B2b preflight: runs each owner-resolved profile through the same validators used by install,
// staging and publication preparation. Read-only: no database, network or credential access.
// Usage: npx vite-node scripts/preflight-catalog-b2b.ts -- <rollout.json> <bundles.json> <features.json> [projections-out.json]
// features.json is a read-only export of the application registry: [{ id, key, type, options }].
import { readFileSync, writeFileSync } from 'node:fs';
import { createPlanAuthoringRegistry } from '../src/lib/subscriptions/authoring';
import { validatePlanAuthoringSnapshot } from '../src/lib/subscriptions/authoring-context';
import { loadBrdCatalog } from '../src/lib/subscriptions/brd-catalog';
import { loadCatalogOwnerInputs, resolveCatalogOwnerContract, type SavedCatalogProfile } from '../src/lib/subscriptions/catalog-owner-inputs';
import { validateCreditAuthoringContext } from '../src/lib/subscriptions/credit-authoring-context';
import { createPlanPublicationProjection, verifyPlanPublicationProjection } from '../src/lib/subscriptions/publication-projection';
import { validatePlanPublicationCompleteness } from '../src/lib/subscriptions/publication-readiness';
import { validatePlanRevisionBundle } from '../src/lib/subscriptions/revision-bundle';

const [rolloutPath, bundlesPath, featuresPath, projectionsPath] = process.argv.slice(2).filter(value => value !== '--');
if (!rolloutPath || !bundlesPath || !featuresPath) throw new Error('Explicit rollout, bundles and features paths are required');
const read = (path: string) => JSON.parse(readFileSync(path, 'utf8'));
const rollout = read(rolloutPath) as { productId: string; profiles: (SavedCatalogProfile & { state?: string })[] };
const resolvedBundles = new Map((read(bundlesPath).bundles as { reference: string; bundle: unknown }[]).map(item => [item.reference, item.bundle]));
const features = read(featuresPath) as { id: string; key: string; type: string; options?: string[] }[];
const catalog = loadBrdCatalog(), inputs = loadCatalogOwnerInputs(), product = rollout.productId;
const failures: string[] = [], projections: { reference: string; projection: unknown }[] = [];
for (const source of catalog.profiles) {
  try {
    const saved = rollout.profiles.find(profile => profile.reference === source.reference);
    if (!saved) throw new Error('rollout profile missing');
    const { state: _, ...profile } = saved;
    const resolved = resolveCatalogOwnerContract(source, profile as SavedCatalogProfile, inputs, catalog.currency);
    if (JSON.stringify(resolved.proposal.bundle) !== JSON.stringify(resolvedBundles.get(source.reference))) throw new Error('exported bundle differs from owner resolution');
    const draft = (resolved.proposal.bundle as { draft: { plan: { id: string; code: string }; audiences: string[] } }).draft;
    // Mirrors the inactive candidate row written by install_subscription_catalog_candidates.
    const snapshot = validatePlanAuthoringSnapshot({ id: draft.plan.id, plan_code: draft.plan.code, product_id: product,
      applicable_entities: draft.audiences, entity_config: resolved.configuration }, draft.plan.id);
    const context = validateCreditAuthoringContext(snapshot.context, snapshot.configuration);
    const registry = createPlanAuthoringRegistry(context, product, features.map(({ id: __, ...terms }) => terms));
    const bundle = validatePlanRevisionBundle(resolved.proposal.bundle, registry);
    validatePlanPublicationCompleteness(bundle, context, snapshot.configuration, registry);
    const projectionFeatures = features.map(feature => ({ id: feature.id, key: feature.key, type: registry.catalog.featureTypes.get(feature.key)! }))
      .filter(feature => feature.type);
    const projection = createPlanPublicationProjection(bundle, context, snapshot.configuration, registry, projectionFeatures);
    verifyPlanPublicationProjection(JSON.parse(JSON.stringify(projection)), bundle, context, snapshot.configuration, registry, projectionFeatures);
    projections.push({ reference: source.reference, projection });
    console.log(`PASS ${source.reference} ${draft.plan.id}`);
  } catch (error) {
    failures.push(source.reference);
    console.log(`FAIL ${source.reference} ${error instanceof Error ? `${error.name}: ${error.message}` : 'unknown'}`);
  }
}
if (failures.length) { console.log(`B2B_PREFLIGHT_FAILED ${failures.length}`); process.exitCode = 1; }
else {
  if (projectionsPath) writeFileSync(projectionsPath, `${JSON.stringify({ schemaVersion: 1, productId: product, projections }, null, 2)}\n`);
  console.log(`B2B_PREFLIGHT_PASSED ${catalog.profiles.length}`);
}
