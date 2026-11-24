// Writes the owner-resolved staging bundles for the reviewed catalog rollout. Read-only: no database or network access.
// Usage: npx vite-node scripts/export-resolved-catalog-bundles.ts -- <rollout.json> <output.json>
import { readFileSync, writeFileSync } from 'node:fs';
import { loadBrdCatalog } from '../src/lib/subscriptions/brd-catalog';
import { loadCatalogOwnerInputs, resolveCatalogOwnerContract, type SavedCatalogProfile } from '../src/lib/subscriptions/catalog-owner-inputs';

const [rolloutPath, outputPath] = process.argv.slice(2).filter(value => value !== '--');
if (!rolloutPath || !outputPath) throw new Error('Explicit rollout and output paths are required');
const rollout = JSON.parse(readFileSync(rolloutPath, 'utf8')) as { productId: string; profiles: (SavedCatalogProfile & { state?: string })[] };
const catalog = loadBrdCatalog(), inputs = loadCatalogOwnerInputs();
const saved = new Map(rollout.profiles.map(({ state: _, ...profile }) => [profile.reference, profile as SavedCatalogProfile]));
const bundles = catalog.profiles.map(source => {
  const profile = saved.get(source.reference);
  if (!profile) throw new Error(`Rollout profile missing: ${source.reference}`);
  return { reference: source.reference, bundle: resolveCatalogOwnerContract(source, profile, inputs, catalog.currency).proposal.bundle };
});
writeFileSync(outputPath, `${JSON.stringify({ schemaVersion: 1, productId: rollout.productId, bundles }, null, 2)}\n`);
console.log(`RESOLVED_CATALOG_BUNDLES_WRITTEN ${bundles.length}`);
