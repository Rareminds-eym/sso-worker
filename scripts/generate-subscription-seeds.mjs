// Offline generation only. Running this script never connects to a database.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const sourcePath = 'sso-worker/config/subscriptions/reset-catalog.json';
export const seedName = '20270326000000_seed_subscription_catalog.sql';
export const readJson = path => JSON.parse(readFileSync(resolve(root, path), 'utf8'));
const unique = (rows, key) => {
  assert.ok(Array.isArray(rows) && rows.length, `Missing ${key} records`);
  assert.equal(new Set(rows.map(row => row[key])).size, rows.length, `Duplicate ${key}`);
};

/** Cross-owner identities and immutable terms must agree before SQL is emitted. */
export function validateCatalog(catalog, brd, owners) {
  assert.equal(catalog.schemaVersion, 1);
  assert.deepEqual(catalog.profiles.map(p => p.reference).sort(), brd.profiles.map(p => p.reference).sort(), 'BRD coverage differs');
  assert.deepEqual([...catalog.retiredLegacyCodes].sort(), Object.keys(owners.legacyReplacements).sort(), 'Legacy transition differs');
  const { sso, application: app } = catalog;
  unique(catalog.profiles, 'planId'); unique(sso.plans, 'id'); unique(sso.plans, 'plan_code');
  unique(sso.drafts, 'id'); unique(sso.publications, 'plan_id'); unique(sso.events, 'id');
  unique(app.features, 'id'); unique(app.features, 'feature_key'); unique(app.projections, 'revision_id');
  unique(app.cacheMetadata, 'id');
  unique(sso.hybridOfferAdoptions, 'operation_id');
  assert.equal(sso.hybridOfferAdoptions.length, 1, 'Exactly one retained Hybrid adoption required');
  for (const adoption of sso.hybridOfferAdoptions) {
    const hybrid = sso.plans.find(p => p.id === catalog.hybridPlanId);
    assert.equal(adoption.product_id, catalog.productId);
    assert.equal(adoption.actor_id, adoption.command.actorId);
    assert.equal(adoption.operation_id, adoption.command.operationId);
    assert.equal(adoption.receipt.operationId, adoption.operation_id);
    assert.equal(adoption.command.hybridPlanId, catalog.hybridPlanId);
    assert.equal(adoption.command.productId, catalog.productId);
    assert.deepEqual(adoption.receipt.plan, { id: hybrid.id, code: hybrid.plan_code, productId: catalog.productId });
    assert.deepEqual(adoption.receipt.identity.command, adoption.command.identity, 'Hybrid identity evidence differs');
    assert.deepEqual(adoption.command.identity.retainedSubscriptions, [], 'Reset catalog must not contain subscriber snapshots');
    assert.deepEqual(adoption.receipt.identity.preservedSubscriptionIds, [], 'Reset catalog must not contain subscribers');
  }
  const ids = [...catalog.profiles.map(p => p.planId), catalog.hybridPlanId].sort();
  assert.deepEqual(sso.plans.map(p => p.id).sort(), ids, 'Plan coverage differs');
  assert.deepEqual(sso.publications.map(p => p.plan_id).sort(), ids, 'Publication coverage differs');
  assert.deepEqual(app.cacheMetadata.map(p => p.id).sort(), ids, 'Cache metadata coverage differs');
  assert.deepEqual(app.projections.map(p => p.revision_id).sort(), sso.drafts.map(d => d.id).sort(), 'Projection coverage differs');
  const drafts = new Map(sso.drafts.map(d => [d.id, d]));
  const features = new Map(app.features.map(f => [f.id, f]));
  for (const plan of sso.plans) {
    assert.equal(plan.product_id, catalog.productId); assert.equal(plan.is_active, true);
    assert.match(plan.plan_code, /^pln_[a-f0-9]{32}$/);
    const pub = sso.publications.find(p => p.plan_id === plan.id);
    const draft = drafts.get(pub.revision_id);
    assert.ok(draft, 'Published draft missing');
    const event = sso.events.find(e => e.plan_id === plan.id && e.revision_id === pub.revision_id);
    assert.ok(event, 'Publication event missing');
    for (const key of ['previous_revision_id', 'published_by', 'published_at']) assert.equal(pub[key], event[key], 'Publication receipt differs');
    assert.deepEqual(event.canonical_plan, { id: plan.id, code: plan.plan_code, productId: plan.product_id,
      audiences: plan.applicable_entities, configuration: plan.entity_config }, 'Canonical publication differs');
    const source = catalog.profiles.find(p => p.planId === plan.id);
    if (source) {
      const price = brd.profiles.find(p => p.reference === source.reference).price;
      if (draft.snapshot.purchaseMode === 'self_service') {
        assert.equal(draft.snapshot.prices.length, 1, 'Self-service price missing or ambiguous');
        assert.equal(draft.snapshot.prices[0].amountMinor, price.amountMinor, 'BRD price differs');
        assert.equal(draft.snapshot.prices[0].currency, brd.currency.code);
        assert.equal(draft.snapshot.prices[0].minorUnit, brd.currency.minorUnit);
        assert.equal(draft.snapshot.prices[0].intervalUnit, price.intervalUnit);
      }
      if (draft.snapshot.purchaseMode === 'contact_sales') assert.deepEqual(draft.snapshot.prices, [], 'Negotiated offer cannot carry a checkout price');
      if (price.amountMinor === 0) {
        assert.equal(draft.snapshot.purchaseMode, 'free'); assert.deepEqual(draft.snapshot.prices, []);
        assert.deepEqual(plan.entity_config.subscription_entry, { schemaVersion: 1, ...owners.freeEntry[source.reference] }, 'Free validity differs');
      }
    }
    for (const change of plan.entity_config.subscription_revision_changes ?? []) {
      assert.ok(drafts.has(change.fromRevisionId) && drafts.has(change.toRevisionId), 'Upgrade revision missing');
    }
  }
  for (const draft of sso.drafts) {
    const plan = sso.plans.find(p => p.id === draft.plan_id);
    assert.ok(plan, 'Draft plan missing');
    assert.deepEqual(draft.snapshot.plan, { id: plan.id, code: plan.plan_code, productId: catalog.productId });
    assert.equal(draft.snapshot.id, draft.id); assert.equal(draft.snapshot.revisionNumber, draft.revision_number);
    assert.equal(draft.included_credits.revisionId, draft.id);
    const projected = app.projections.find(p => p.revision_id === draft.id);
    assert.equal(projected.product_id, catalog.productId); assert.equal(projected.plan_id, plan.id);
    assert.deepEqual(projected.projection.bundle, { schemaVersion: 1, draft: draft.snapshot, includedCredits: draft.included_credits }, 'Projection bundle differs');
    const grants = draft.snapshot.features;
    assert.equal(projected.projection.entitlements.length, grants.length);
    unique(projected.projection.entitlements, 'feature_id');
    for (const row of projected.projection.entitlements) {
      const feature = features.get(row.feature_id);
      assert.ok(feature, 'Projection feature missing');
      const grant = grants.find(g => g.key === feature.feature_key);
      assert.ok(grant && grant.type === feature.feature_type, 'Feature type differs');
      assert.equal(row.plan_id, plan.id);
      const negotiated = grant.type === 'numeric_limit' && grant.limit.kind === 'contract_required';
      if (negotiated) assert.equal(draft.snapshot.purchaseMode, 'contact_sales');
      assert.equal(row.is_enabled, negotiated ? false : grant.enabled, 'Enabled grant differs');
      assert.equal(row.value_numeric, grant.type === 'numeric_limit' && grant.limit.kind === 'finite' ? grant.limit.value : null);
      assert.equal(row.value_text, grant.type === 'enum' ? grant.value : null);
      if (grant.type === 'enum' && grant.enabled) assert.ok(feature.value_options.includes(grant.value), 'Enum domain differs');
    }
  }
  for (const event of sso.events) {
    assert.ok(drafts.has(event.revision_id), 'Event draft missing');
    if (event.previous_revision_id !== null) assert.ok(drafts.has(event.previous_revision_id), 'Previous revision missing');
  }
  return catalog;
}

const literal = value => `'${JSON.stringify(value).replaceAll("'", "''")}'::jsonb`;
const selected = (alias, columns) => columns.map(c => `${alias}.${c}`).join(', ');

function records(table, rows, columns, { conflict = 'id', immutable = false, preserve = [] } = {}) {
  const payload = literal(rows);
  const source = `jsonb_populate_recordset(NULL::public.${table}, ${payload})`;
  const update = columns.filter(c => c !== conflict && !preserve.includes(c)).map(c => `${c} = EXCLUDED.${c}`).join(', ');
  return `INSERT INTO public.${table} (${columns.join(', ')})\nSELECT ${selected('seed', columns)} FROM ${source} seed\nON CONFLICT (${conflict}) ${immutable ? 'DO NOTHING' : `DO UPDATE SET ${update}`};\n`
    + (immutable ? `DO $verify$ BEGIN\n  IF EXISTS (SELECT 1 FROM ${source} expected LEFT JOIN public.${table} actual ON actual.${conflict} = expected.${conflict}\n    WHERE actual.${conflict} IS NULL OR ROW(${selected('actual', columns)}) IS DISTINCT FROM ROW(${selected('expected', columns)}))\n  THEN RAISE EXCEPTION 'Subscription seed conflicts with immutable ${table}'; END IF;\nEND $verify$;\n` : '');
}

const planColumns = ['id', 'plan_code', 'name', 'business_type', 'applicable_entities', 'pricing_matrix', 'base_features', 'entity_config', 'display_order', 'is_active', 'product_id'];
function retirement(catalog, table) {
  return `-- Retain old identities and purchased terms; hide explicitly replaced offers from new-sale catalogs.\nUPDATE public.${table} SET is_active = false\nWHERE product_id::text = ${literal(catalog.productId)} #>> '{}'\n  AND plan_code IN (SELECT jsonb_array_elements_text(${literal(catalog.retiredLegacyCodes)}));\n`;
}

export function renderSeeds(catalog) {
  const header = `-- Generated by sso-worker/scripts/generate-subscription-seeds.mjs from ${sourcePath}.\n-- RESET BASELINE ONLY. Applying this SQL to any database requires explicit target approval.\n-- Restores catalog definitions and revision evidence; never migrates subscribers or allocates credits.\nBEGIN;\n`;
  const actors = [...new Set([...catalog.sso.drafts.map(d => d.staged_by), ...catalog.sso.events.map(e => e.published_by), ...catalog.sso.hybridOfferAdoptions.map(a => a.actor_id)])];
  let sso = header + `DO $preconditions$ BEGIN\n  IF NOT EXISTS (SELECT 1 FROM public.products WHERE id::text = ${literal(catalog.productId)} #>> '{}')\n    OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(${literal(actors)}) actor WHERE NOT EXISTS (SELECT 1 FROM public.users WHERE id::text = actor))\n  THEN RAISE EXCEPTION 'Subscription seed requires the original product and publication actors from the initial environment seed'; END IF;\nEND $preconditions$;\n`;
  sso += records('plans', catalog.sso.plans, [...planColumns, 'updated_at']);
  sso += records('subscription_plan_drafts', catalog.sso.drafts, ['id', 'plan_id', 'revision_number', 'snapshot', 'included_credits', 'staged_by', 'staged_at'], { immutable: true });
  // A reset starts a new publication history. Archived receipts are source evidence,
  // not new transitions: publishing them would bypass today's policy requirements.
  // Keep dependency bundles above, and let the existing RPC create honest receipts.
  sso += `DO $publish$ DECLARE item jsonb; canonical jsonb; stored public.subscription_plan_publication_events%ROWTYPE; BEGIN\n  FOR item IN SELECT value FROM jsonb_array_elements(${literal(catalog.sso.publications)}) LOOP\n    SELECT jsonb_build_object('id', p.id, 'code', p.plan_code, 'productId', p.product_id,\n      'audiences', to_jsonb(p.applicable_entities), 'configuration', p.entity_config) INTO STRICT canonical\n    FROM public.plans p WHERE p.id = (item->>'plan_id')::uuid;\n    PERFORM public.publish_subscription_plan_revision((item->>'plan_id')::uuid, (item->>'revision_id')::uuid,\n      NULL, (item->>'published_by')::uuid, canonical);\n    SELECT * INTO STRICT stored FROM public.subscription_plan_publication_events\n      WHERE plan_id = (item->>'plan_id')::uuid AND revision_id = (item->>'revision_id')::uuid;\n    IF stored.canonical_plan IS DISTINCT FROM canonical OR stored.previous_revision_id IS NOT NULL\n      OR stored.published_by::text IS DISTINCT FROM item->>'published_by'\n    THEN RAISE EXCEPTION 'Subscription bootstrap publication differs'; END IF;\n  END LOOP;\nEND $publish$;\n`;
  sso += records('subscription_hybrid_offer_adoptions', catalog.sso.hybridOfferAdoptions,
    ['operation_id', 'product_id', 'actor_id', 'command', 'receipt', 'adopted_at'], { conflict: 'operation_id', immutable: true });
  sso += retirement(catalog, 'plans') + 'COMMIT;\n';

  const cache = catalog.sso.plans.map(plan => ({ ...plan, ...catalog.application.cacheMetadata.find(p => p.id === plan.id), auth_updated_at: plan.updated_at }));
  // Existing feature UUIDs are generated during earlier migrations. Preserve every legacy FK and
  // resolve immutable projection feature IDs by the authoritative feature key in this database.
  let app = header + records('plans_cache', cache, [...planColumns, 'plan_family', 'hierarchy_order', 'auth_updated_at']);
  app += records('features', catalog.application.features, ['id', 'feature_key', 'display_name', 'feature_type', 'category', 'description', 'value_options'], { conflict: 'feature_key', preserve: ['id'] });
  app += `DO $projections$ DECLARE item jsonb; payload jsonb; stored public.subscription_plan_projections%ROWTYPE; BEGIN\n  FOR item IN SELECT value FROM jsonb_array_elements(${literal(catalog.application.projections)}) LOOP\n    SELECT jsonb_set(item->'projection', '{entitlements}', jsonb_agg(e.value || jsonb_build_object('feature_id', f.id) ORDER BY e.ordinality)) INTO payload\n    FROM jsonb_array_elements(item#>'{projection,entitlements}') WITH ORDINALITY e(value, ordinality)\n    JOIN jsonb_to_recordset(${literal(catalog.application.features)}) original(id uuid, feature_key text) ON original.id = (e.value->>'feature_id')::uuid\n    JOIN public.features f ON f.feature_key = original.feature_key;\n    IF payload IS NULL OR jsonb_array_length(payload->'entitlements') <> jsonb_array_length(item#>'{projection,entitlements}')\n    THEN RAISE EXCEPTION 'Subscription seed feature mapping incomplete'; END IF;\n    PERFORM public.stage_subscription_plan_projection(payload, (item->>'product_id')::uuid, (item->>'staged_by')::uuid);\n    SELECT * INTO STRICT stored FROM public.subscription_plan_projections WHERE revision_id = (item->>'revision_id')::uuid;\n    IF stored.projection IS DISTINCT FROM payload OR stored.staged_by::text IS DISTINCT FROM item->>'staged_by'\n    THEN RAISE EXCEPTION 'Subscription seed projection readback differs'; END IF;\n  END LOOP;\nEND $projections$;\n`;
  // Existing quota/manifest readers use this table. Materialize only current publications,
  // from the staged, UUID-remapped payloads rather than inventing another feature matrix.
  app += `WITH current_grants AS (\n  SELECT e.* FROM jsonb_to_recordset(${literal(catalog.sso.publications)}) publication(plan_id uuid, revision_id uuid)\n  JOIN public.subscription_plan_projections p ON p.revision_id = publication.revision_id AND p.plan_id = publication.plan_id\n  CROSS JOIN LATERAL jsonb_populate_recordset(NULL::public.plan_entitlements, p.projection->'entitlements') e\n)\nINSERT INTO public.plan_entitlements(plan_id, feature_id, is_enabled, value_numeric, value_text)\nSELECT plan_id, feature_id, is_enabled, value_numeric, value_text FROM current_grants\nON CONFLICT (plan_id, feature_id) DO UPDATE SET is_enabled = EXCLUDED.is_enabled,\n  value_numeric = EXCLUDED.value_numeric, value_text = EXCLUDED.value_text;\n`;
  app += retirement(catalog, 'plans_cache') + 'COMMIT;\n';
  return { 'sso-worker': sso, skillpassport: app };
}

export function generate(check = false) {
  const catalog = validateCatalog(readJson(sourcePath), readJson('sso-worker/config/subscriptions/brd-catalog.json'), readJson('sso-worker/config/subscriptions/owner-inputs.json'));
  for (const [project, sql] of Object.entries(renderSeeds(catalog))) for (const environment of ['dev', 'production']) {
    const path = resolve(root, project, 'supabase/seed', environment, seedName);
    if (check) assert.ok(readFileSync(path, 'utf8') === sql, `Generated seed is stale: ${path}`);
    else writeFileSync(path, sql);
  }
  console.log(check ? 'SUBSCRIPTION_SEEDS_CURRENT' : 'SUBSCRIPTION_SEEDS_GENERATED');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  assert.ok(process.argv.slice(2).every(arg => arg === '--check'), 'Only --check is supported');
  generate(process.argv.includes('--check'));
}
