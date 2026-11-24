// Offline validation only. Inputs are a read-only database export and the stored
// rollout identity map; no database, network, credentials or runtime defaults.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPlanAuthoringRegistry } from '../src/lib/subscriptions/authoring';
import { validatePlanAuthoringSnapshot } from '../src/lib/subscriptions/authoring-context';
import { loadBrdCatalog } from '../src/lib/subscriptions/brd-catalog';
import { loadCatalogOwnerInputs, resolveCatalogOwnerContract, type SavedCatalogProfile } from '../src/lib/subscriptions/catalog-owner-inputs';
import { validateCreditAuthoringContext } from '../src/lib/subscriptions/credit-authoring-context';
import { createPlanPublicationProjection, verifyPlanPublicationProjection } from '../src/lib/subscriptions/publication-projection';
import { validatePlanPublicationCompleteness } from '../src/lib/subscriptions/publication-readiness';
import type { FeatureType } from '../src/lib/subscriptions/types';

const [inputPath, rolloutPath, outputPath] = process.argv.slice(2).filter(value => value !== '--');
if (!inputPath || !rolloutPath || !outputPath) throw new Error('Explicit preparation paths required');
const read = (path: string) => JSON.parse(readFileSync(path, 'utf8'));
const input = read(inputPath) as { features: { id: string; key: string; type: FeatureType; options?: string[] }[];
  entries: { reference: string; plan: Record<string, unknown>; previousRevisionId: string;
    bundle: { schemaVersion: number; draft: { plan: { id: string; productId: string }; features: { key: string; type: string }[] }; includedCredits: unknown } }[] };
const rollout = read(rolloutPath) as { profiles: SavedCatalogProfile[] };
const catalog = loadBrdCatalog(), inputs = loadCatalogOwnerInputs();
if (input.entries.length !== inputs.freeEntry.size || new Set(input.entries.map(e => e.reference)).size !== inputs.freeEntry.size) {
  throw new Error('Exact unique free profile set required');
}
const entries = input.entries.map(entry => {
  const source = catalog.profiles.find(p => p.reference === entry.reference);
  const saved = rollout.profiles.find(p => p.reference === entry.reference);
  if (!source || !saved || !inputs.freeEntry.has(entry.reference)) throw new Error('Unknown free profile');
  const resolved = resolveCatalogOwnerContract(source, saved, inputs, catalog.currency);
  const capacity = inputs.trialLearnerCapacities.get(entry.reference);
  if (capacity !== undefined && entry.bundle.draft.features.filter(f => f.key === 'included_learner_capacity' && f.type === 'numeric_limit').length !== 1) {
    throw new Error('Exact current trial learner capacity feature required');
  }
  const revised = { ...entry.bundle, draft: { ...entry.bundle.draft,
    features: entry.bundle.draft.features.map(feature => capacity !== undefined && feature.key === 'included_learner_capacity'
      ? { ...feature, enabled: true, limit: { kind: 'finite', value: capacity } } : feature) } };
  const prior = entry.plan.entity_config;
  if (!prior || typeof prior !== 'object' || Array.isArray(prior)) throw new Error('Canonical configuration required');
  // Preserve every current canonical term; append only the explicitly approved policy.
  const configuration = { ...prior, subscription_lifecycle: resolved.configuration.subscription_lifecycle };
  const snapshot = validatePlanAuthoringSnapshot({ id: entry.plan.id, plan_code: entry.plan.plan_code,
    product_id: entry.plan.product_id, applicable_entities: entry.plan.applicable_entities, entity_config: configuration }, entry.bundle.draft.plan.id);
  const context = validateCreditAuthoringContext(snapshot.context, configuration);
  const registry = createPlanAuthoringRegistry(context, entry.bundle.draft.plan.productId,
    input.features.map(({ id: _, ...feature }) => feature));
  const bundle = validatePlanPublicationCompleteness(revised, context, configuration, registry);
  const definitions = input.features.filter(f => registry.catalog.featureTypes.has(f.key)).map(({ id, key, type }) => ({ id, key, type }));
  const projection = createPlanPublicationProjection(bundle, context, configuration, registry, definitions);
  verifyPlanPublicationProjection(JSON.parse(JSON.stringify(projection)), bundle, context, configuration, registry, definitions);
  return { ...entry, configuration, bundle, projection };
});
writeFileSync(outputPath, JSON.stringify({ schemaVersion: 1, entries }, null, 2) + '\n');
console.log('FREE_ENTRY_REVISED_BUNDLES_VALIDATED');
