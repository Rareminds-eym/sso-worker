import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { root, readJson, sourcePath, seedName, renderSeeds, validateCatalog } from '../generate-subscription-seeds.mjs';

const { PGlite } = createRequire(resolve(root, 'sso-worker/package.json'))('@electric-sql/pglite');
const catalog = readJson(sourcePath);
const brd = readJson('sso-worker/config/subscriptions/brd-catalog.json');
const owners = readJson('sso-worker/config/subscriptions/owner-inputs.json');
const read = path => readFileSync(resolve(root, path), 'utf8');
const quote = value => `'${value.replaceAll("'", "''")}'`;
const seeds = renderSeeds(catalog);

function baselineTable(project, table) {
  const sql = read(`${project}/supabase/migrations/20260526000000_schema.sql`);
  const prefix = `CREATE TABLE IF NOT EXISTS "public"."${table}" (`;
  const start = sql.indexOf(prefix); assert.ok(start >= 0);
  return sql.slice(start, sql.indexOf('\n);', start) + 3);
}
async function ssoDatabase() {
  const db = new PGlite();
  await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role;
    CREATE TABLE public.products(id uuid PRIMARY KEY); CREATE TABLE public.users(id uuid PRIMARY KEY);
    ${baselineTable('sso-worker', 'plans')}
    ALTER TABLE public.plans ADD PRIMARY KEY(id), ADD UNIQUE(plan_code), ADD FOREIGN KEY(product_id) REFERENCES products(id);
    CREATE TABLE public.subscriptions(id uuid PRIMARY KEY, plan_id uuid REFERENCES plans(id), status text, plan_code text, seat_count integer,
      lifecycle_policy jsonb, product_id uuid, auto_renew boolean, lifecycle_state jsonb, plan_revision_id uuid,
      subscription_start_date timestamptz, subscription_end_date timestamptz);`);
  await db.exec(read('sso-worker/supabase/migrations/20270315010000_subscription_plan_drafts.sql'));
  await db.exec(read('sso-worker/supabase/migrations/20270317020000_subscription_plan_publications.sql'));
  for (const name of ['20270323030000_subscription_hybrid_catalog_offer.sql',
    '20270313010000_guard_hybrid_capacity_reductions.sql', '20270323040000_subscription_hybrid_capacity_guard_by_plan.sql',
    '20270324020000_subscription_free_lifecycle_policy.sql']) {
    await db.exec(read(`sso-worker/supabase/migrations/${name}`));
  }
  await db.query('INSERT INTO products VALUES($1)', [catalog.productId]);
  const actors = [...new Set(catalog.sso.drafts.map(d => d.staged_by))];
  for (const actor of actors) await db.query('INSERT INTO users VALUES($1)', [actor]);
  return db;
}
async function appDatabase() {
  const db = new PGlite();
  await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role;
    ${baselineTable('skillpassport', 'plans_cache')}
    ALTER TABLE public.plans_cache ADD PRIMARY KEY(id), ADD UNIQUE(plan_code);`);
  for (const migration of ['20261016120000_entitlement_engine.sql', '20270316010000_subscription_enum_features.sql',
    '20270317010000_subscription_plan_projections.sql', '20270323020000_subscription_sales_led_projection_terms.sql']) {
    await db.exec(read(`skillpassport/supabase/migrations/${migration}`));
  }
  return db;
}

test('all profiles and historical publication/projection bindings agree', () => {
  validateCatalog(structuredClone(catalog), brd, owners);
  for (const change of [x => x.profiles.pop(), x => x.sso.publications.pop(),
    x => { x.application.projections[0].projection.bundle.includedCredits.rules[0].quantity.value++; },
    x => { x.application.features[0].feature_type = 'unknown'; },
    x => { x.sso.hybridOfferAdoptions = []; },
    x => { x.sso.hybridOfferAdoptions[0].receipt.plan.id = randomUUID(); }]) {
    const invalid = structuredClone(catalog); change(invalid);
    assert.throws(() => validateCatalog(invalid, brd, owners));
  }
});

test('both existing reset scripts discover their environment seed after earlier seed files', () => {
  for (const project of ['sso-worker', 'skillpassport']) {
    const versions = readdirSync(resolve(root, project, 'supabase/migrations')).filter(f => /^\d+_.*\.sql$/.test(f)).map(f => f.split('_')[0]);
    assert.equal(new Set(versions).size, versions.length, `${project} has duplicate migration versions`);
    if (project === 'sso-worker') {
      const migrations = readdirSync(resolve(root, project, 'supabase/migrations')).sort();
      const commerce = migrations.indexOf('20270324000000_subscription_commerce_activation.sql');
      const freeEntry = migrations.indexOf('20270324010000_subscription_verified_free_entry.sql');
      assert.ok(commerce >= 0 && commerce < freeEntry, 'Preserve commerce activation before free-entry overrides');
    }
    const pkg = readJson(`${project}/package.json`);
    assert.match(read(`${project}/supabase/config.toml`), /\[db.seed\][\s\S]*?enabled = false/);
    for (const [environment, script] of [['dev', 'db:reset:dev'], ['production', 'db:reset:prod']]) {
      assert.equal(pkg.scripts[script], `npx supabase db reset --sql-paths "./seed/${environment}/*.sql"`);
      const names = readdirSync(resolve(root, project, 'supabase/seed', environment)).filter(f => f.endsWith('.sql')).sort();
      assert.equal(names.at(-1), seedName);
      assert.ok(read(`${project}/supabase/seed/${environment}/${seedName}`) === seeds[project], `Seed differs: ${project}/${environment}`);
    }
  }
});

test('SSO seed executes against migrated tables, restores bindings, replays exactly and preserves subscribers', async () => {
  const db = await ssoDatabase();
  try {
    const legacy = randomUUID(), subscriber = randomUUID();
    await db.query(`INSERT INTO plans(id,plan_code,name,business_type,product_id) VALUES($1,$2,'Synthetic legacy plan','b2c',$3)`, [legacy, catalog.retiredLegacyCodes[0], catalog.productId]);
    await db.query(`INSERT INTO subscriptions(id,plan_id,status) VALUES($1,$2,'active')`, [subscriber, legacy]);
    await db.exec(seeds['sso-worker']);
    const initialEvents = (await db.query('SELECT * FROM subscription_plan_publication_events ORDER BY id')).rows;
    await db.exec(seeds['sso-worker']);
    assert.deepEqual((await db.query('SELECT * FROM subscription_plan_publication_events ORDER BY id')).rows, initialEvents);
    assert.equal(initialEvents.length, catalog.sso.publications.length);
    for (const event of initialEvents) {
      assert.equal(event.previous_revision_id, null);
      assert.ok(!catalog.sso.events.some(archived => archived.id === event.id), 'Bootstrap must create its own audit receipt');
    }
    assert.equal((await db.query('SELECT count(*)::int AS count FROM plans WHERE is_active')).rows[0].count, catalog.sso.plans.length);
    assert.equal((await db.query('SELECT count(*)::int AS count FROM subscription_plan_drafts')).rows[0].count, catalog.sso.drafts.length);
    assert.equal((await db.query('SELECT count(*)::int AS count FROM subscription_plan_publications')).rows[0].count, catalog.sso.publications.length);
    assert.deepEqual((await db.query('SELECT plan_id,status FROM subscriptions WHERE id=$1', [subscriber])).rows[0], { plan_id: legacy, status: 'active' });
    const hybridSubscription = randomUUID();
    const hybrid = catalog.sso.plans.find(p => p.id === catalog.hybridPlanId);
    await db.query('INSERT INTO subscriptions(id,plan_id,plan_code,seat_count) VALUES($1,$2,$3,5)', [hybridSubscription, hybrid.id, hybrid.plan_code]);
    for (const capacity of [4, null]) await assert.rejects(db.query('UPDATE subscriptions SET seat_count=$1 WHERE id=$2', [capacity, hybridSubscription]), /Seat reductions require/);
    await db.query('UPDATE subscriptions SET seat_count=6 WHERE id=$1', [hybridSubscription]);
    const adoption = (await db.query('SELECT * FROM subscription_hybrid_offer_adoptions')).rows[0];
    assert.deepEqual(adoption.receipt, catalog.sso.hybridOfferAdoptions[0].receipt);
    const pointers = (await db.query(`SELECT p.plan_id,p.revision_id,d.snapshot,d.included_credits,e.canonical_plan FROM subscription_plan_publications p
      JOIN subscription_plan_drafts d ON d.id=p.revision_id JOIN subscription_plan_publication_events e ON e.revision_id=p.revision_id`)).rows;
    for (const pointer of pointers) {
      assert.deepEqual(pointer.snapshot, catalog.sso.drafts.find(d => d.id === pointer.revision_id).snapshot);
      assert.deepEqual(pointer.included_credits, catalog.sso.drafts.find(d => d.id === pointer.revision_id).included_credits);
      assert.deepEqual(pointer.canonical_plan.configuration, catalog.sso.plans.find(p => p.id === pointer.plan_id).entity_config);
    }
    const altered = structuredClone(catalog); altered.sso.drafts[0].snapshot.name += ' changed';
    await assert.rejects(db.exec(renderSeeds(altered)['sso-worker']), /conflicts with immutable/);
    await db.exec('ROLLBACK');
    const conflictingAdoption = structuredClone(catalog);
    conflictingAdoption.sso.hybridOfferAdoptions[0].command.approvalReference += ' changed';
    await assert.rejects(db.exec(renderSeeds(conflictingAdoption)['sso-worker']), /conflicts with immutable subscription_hybrid_offer_adoptions/);
    await db.exec('ROLLBACK');
  } finally { await db.close(); }
});

test('fresh bootstrap rejects invalid current free policy with guards enabled and rolls back', async () => {
  const db = await ssoDatabase();
  try {
    const invalid = structuredClone(catalog);
    const free = invalid.sso.publications.find(p => invalid.sso.drafts.find(d => d.id === p.revision_id).snapshot.purchaseMode === 'free');
    delete invalid.sso.plans.find(p => p.id === free.plan_id).entity_config.subscription_lifecycle;
    await assert.rejects(db.exec(renderSeeds(invalid)['sso-worker']), /Explicit free lifecycle policy required/);
    await db.exec('ROLLBACK');
    assert.equal((await db.query('SELECT count(*)::int AS count FROM plans')).rows[0].count, 0);
    assert.equal((await db.query('SELECT count(*)::int AS count FROM subscription_plan_publication_events')).rows[0].count, 0);
  } finally { await db.close(); }
});

test('SSO seed rejects missing bootstrap identities and rolls back all catalog changes', async () => {
  const db = await ssoDatabase();
  try {
    await db.exec('DELETE FROM users');
    await assert.rejects(db.exec(seeds['sso-worker']), /requires the original product and publication actors/);
    await db.exec('ROLLBACK');
    assert.equal((await db.query('SELECT count(*)::int AS count FROM plans')).rows[0].count, 0);
  } finally { await db.close(); }
});

test('application seed preserves generated feature identities and stages exact current and historical terms', async () => {
  const db = await appDatabase();
  try {
    const legacyFeature = catalog.application.features.find(f => f.feature_type === 'metered');
    const generatedId = randomUUID();
    await db.query('INSERT INTO features(id,feature_key,display_name,feature_type) VALUES($1,$2,$3,$4)',
      [generatedId, legacyFeature.feature_key, 'Synthetic legacy feature', legacyFeature.feature_type]);
    await db.exec(seeds.skillpassport);
    await db.exec(seeds.skillpassport);
    assert.equal((await db.query('SELECT id FROM features WHERE feature_key=$1', [legacyFeature.feature_key])).rows[0].id, generatedId);
    const rows = (await db.query('SELECT revision_id,projection FROM subscription_plan_projections')).rows;
    assert.equal(rows.length, catalog.application.projections.length);
    const definitions = (await db.query('SELECT id,feature_key FROM features')).rows;
    for (const row of rows) {
      const original = catalog.application.projections.find(p => p.revision_id === row.revision_id).projection;
      assert.deepEqual(row.projection.bundle, original.bundle);
      for (const grant of row.projection.entitlements) {
        const key = definitions.find(f => f.id === grant.feature_id).feature_key;
        const originalId = catalog.application.features.find(f => f.feature_key === key).id;
        assert.deepEqual({ ...grant, feature_id: originalId }, original.entitlements.find(e => e.feature_id === originalId));
      }
    }
    const cache = (await db.query('SELECT id,plan_code,entity_config FROM plans_cache WHERE is_active')).rows;
    assert.equal(cache.length, catalog.sso.plans.length);
    for (const plan of cache) assert.deepEqual(plan.entity_config, catalog.sso.plans.find(p => p.id === plan.id).entity_config);
    const grants = (await db.query('SELECT plan_id,feature_id,is_enabled,value_numeric,value_text FROM plan_entitlements')).rows;
    const expected = catalog.sso.publications.flatMap(pub => rows.find(row => row.revision_id === pub.revision_id).projection.entitlements);
    assert.equal(grants.length, expected.length, 'Only current publication grants are materialized');
    for (const grant of grants) {
      const original = expected.find(e => e.plan_id === grant.plan_id && e.feature_id === grant.feature_id);
      assert.ok(original, 'Unexpected current grant');
      assert.deepEqual(grant, { plan_id: original.plan_id, feature_id: original.feature_id, is_enabled: original.is_enabled,
        value_numeric: original.value_numeric === null ? null : String(original.value_numeric), value_text: original.value_text });
    }
  } finally { await db.close(); }
});
