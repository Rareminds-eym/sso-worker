// Prepares the reviewed Hybrid catalog offer: stable identities (generated once), owner configuration,
// revision bundle and the expected application projection, checked with the production validators.
// Read-only: no database, network or credential access.
// Usage: npx vite-node scripts/prepare-hybrid-offer.ts -- <rollout.json> <features.json> <proposal.json>
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createPlanAuthoringRegistry } from '../src/lib/subscriptions/authoring';
import { validatePlanAuthoringSnapshot } from '../src/lib/subscriptions/authoring-context';
import { loadCatalogOwnerInputs } from '../src/lib/subscriptions/catalog-owner-inputs';
import { publishedPresentation } from '../src/lib/subscriptions/consumers';
import { validateCreditAuthoringContext } from '../src/lib/subscriptions/credit-authoring-context';
import { buildHybridCatalogOffer, loadHybridOffer, validateHybridIdentities } from '../src/lib/subscriptions/hybrid-offer';
import { createPlanPublicationProjection, verifyPlanPublicationProjection } from '../src/lib/subscriptions/publication-projection';
import { validatePlanPublicationCompleteness } from '../src/lib/subscriptions/publication-readiness';
import { validatePlanRevisionBundle } from '../src/lib/subscriptions/revision-bundle';
import { loadTaxPolicy } from '../src/lib/subscriptions/tax-policy';

const [rolloutPath, featuresPath, proposalPath] = process.argv.slice(2).filter(value => value !== '--');
if (!rolloutPath || !featuresPath || !proposalPath) throw new Error('Explicit rollout, features and proposal paths are required');
const rollout = JSON.parse(readFileSync(rolloutPath, 'utf8')) as { productId: string; transition: { hybridPlanId: string } };
const features = JSON.parse(readFileSync(featuresPath, 'utf8')) as { id: string; key: string; type: string; options?: string[] }[];
// Identities are immutable once reviewed: reuse a stored proposal, never regenerate it.
const stored = existsSync(proposalPath) ? JSON.parse(readFileSync(proposalPath, 'utf8')) : null;
const identities = validateHybridIdentities(stored?.identities ?? {
  targetCode: `pln_${randomBytes(16).toString('hex')}`, revisionId: randomUUID(), includedCreditsId: randomUUID(), ruleId: randomUUID() });
const inputs = loadCatalogOwnerInputs(), offer = loadHybridOffer(inputs), product = rollout.productId, planId = rollout.transition.hybridPlanId;
// Hybrid has no staged drafts, so its first catalog revision is number 1.
const { configuration, bundle } = buildHybridCatalogOffer(offer, inputs, planId, product, identities, 1);
const snapshot = validatePlanAuthoringSnapshot({ id: planId, plan_code: identities.targetCode, product_id: product, applicable_entities: [...offer.audiences], entity_config: configuration }, planId);
const context = validateCreditAuthoringContext(snapshot.context, snapshot.configuration);
const registry = createPlanAuthoringRegistry(context, product, features.map(({ id: _, ...terms }) => terms));
const validated = validatePlanRevisionBundle(bundle, registry);
validatePlanPublicationCompleteness(validated, context, snapshot.configuration, registry);
const projectionFeatures = features.map(feature => ({ id: feature.id, key: feature.key, type: registry.catalog.featureTypes.get(feature.key)! })).filter(feature => feature.type);
const projection = createPlanPublicationProjection(validated, context, snapshot.configuration, registry, projectionFeatures);
verifyPlanPublicationProjection(JSON.parse(JSON.stringify(projection)), validated, context, snapshot.configuration, registry, projectionFeatures);
const presentation = publishedPresentation(snapshot.configuration, loadTaxPolicy());
writeFileSync(proposalPath, `${JSON.stringify({ schemaVersion: 1, status: 'prepared_not_applied', productId: product, hybridPlanId: planId,
  identities, configuration, bundle, projection, presentation }, null, 2)}\n`);
console.log(`HYBRID_OFFER_PREPARED ${identities.targetCode} revision=${identities.revisionId} disabledCustomRows=${projection.entitlements.filter(row => !row.is_enabled).length}`);
