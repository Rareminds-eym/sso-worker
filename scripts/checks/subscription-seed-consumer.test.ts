// Actual quota reader over seed-created PostgreSQL state. No network or environment DB access.
import assert from 'node:assert/strict';
import { test } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { getNumericLimit } from '../../../skillpassport/functions/shared/lib/entitlement-service';
import { root, readJson, sourcePath, renderSeeds } from '../generate-subscription-seeds.mjs';
const { PGlite } = createRequire(resolve(root, 'sso-worker/package.json'))('@electric-sql/pglite');
test('seeded current publication grants resolve through the actual quota reader', async () => {
const catalog=readJson(sourcePath);
const read=(path:string)=>readFileSync(resolve(root,path),'utf8');
const db=new PGlite();
const tenantId=randomUUID();
try {
  const baseline=read('skillpassport/supabase/migrations/20260526000000_schema.sql');
  const start=baseline.indexOf('CREATE TABLE IF NOT EXISTS "public"."plans_cache" (');
  await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role;
    ${baseline.slice(start,baseline.indexOf('\n);',start)+3)}
    ALTER TABLE plans_cache ADD PRIMARY KEY(id), ADD UNIQUE(plan_code);`);
  for(const migration of ['20261016120000_entitlement_engine.sql','20270316010000_subscription_enum_features.sql',
    '20270317010000_subscription_plan_projections.sql','20270323020000_subscription_sales_led_projection_terms.sql'])
    await db.exec(read('skillpassport/supabase/migrations/'+migration));
  await db.exec(renderSeeds(catalog).skillpassport);
  const free=catalog.profiles.find((p:any)=>p.reference==='brd:10:1');
  const pub=catalog.sso.publications.find((p:any)=>p.plan_id===free.planId);
  const projection=catalog.application.projections.find((p:any)=>p.revision_id===pub.revision_id);
  const definition=catalog.application.features.find((f:any)=>f.feature_key==='active_job_posts');
  const grant=projection.projection.entitlements.find((e:any)=>e.feature_id===definition.id);
  assert.equal(grant.is_enabled,true);
  const client={
    rpc:async()=>({data:[],error:null}),
    from:(table:string)=>{
      const filters:Array<[string,unknown]>=[];
      const query:any={};
      query.eq=(key:string,value:unknown)=>{filters.push([key,value]);return query;};
      for(const method of ['select','or','order','limit'])query[method]=()=>query;
      query.maybeSingle=async()=>{
        if(table==='subscription_cache')return {data:{plan_id:free.planId},error:null};
        assert.ok(['features','plan_entitlements','tenant_entitlement_overrides'].includes(table));
        const conditions=filters.map(([key],index)=>{assert.match(key,/^[a-z_]+$/);return `${key}=$${index+1}`;});
        const rows=(await db.query(`SELECT * FROM ${table} WHERE ${conditions.join(' AND ')} LIMIT 1`,filters.map(([,v])=>v))).rows;
        return {data:rows[0]??null,error:null};
      };return query;
    }
  };
  assert.deepEqual(await getNumericLimit(client as any,tenantId,'active_job_posts'),{limit:grant.value_numeric,enabled:grant.is_enabled});
  await db.query('DELETE FROM plan_entitlements WHERE plan_id=$1 AND feature_id=(SELECT id FROM features WHERE feature_key=$2)',[free.planId,definition.feature_key]);
  assert.equal(await getNumericLimit(client as any,tenantId,'active_job_posts'),null);
  console.log('CONFIRMED: actual quota reader resolves seed-derived publication grants and rejects the missing-grant control');
  console.log('CONSUMER_PROBE_CONFIRMED');
} finally {await db.close();}

}, 20000);
