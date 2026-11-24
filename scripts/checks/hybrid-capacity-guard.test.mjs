import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {PGlite} from '@electric-sql/pglite';

const migration=name=>readFileSync(new URL('../../supabase/migrations/'+name,import.meta.url),'utf8');
const legacy=migration('20270313010000_guard_hybrid_capacity_reductions.sql');
const adopted=migration('20270323040000_subscription_hybrid_capacity_guard_by_plan.sql');
const corrected=migration('20270328010000_subscription_hybrid_guard_preserve_legacy.sql');

for(const scenario of ['legacy before adoption','adopted opaque plan','unrelated plan']){
 test('Hybrid capacity protection: '+scenario,async()=>{
  const db=new PGlite();
  try{
   await db.exec('CREATE TABLE subscriptions(id uuid PRIMARY KEY,plan_id uuid,plan_code text,seat_count integer); CREATE TABLE subscription_hybrid_offer_adoptions(receipt jsonb);');
   await db.exec(legacy);
   await db.exec(adopted);
   await db.exec(corrected);
   const id=randomUUID(),plan=randomUUID();
   const protectedPlan=scenario!=='unrelated plan';
   await db.query('INSERT INTO subscriptions VALUES($1,$2,$3,5)',[id,plan,scenario==='legacy before adoption'?'hybrid':'pln_'+randomUUID().replaceAll('-','')]);
   if(scenario==='adopted opaque plan')await db.query('INSERT INTO subscription_hybrid_offer_adoptions VALUES($1::jsonb)',[JSON.stringify({plan:{id:plan}})]);
   for(const count of [4,null]){
    const change=()=>db.query('UPDATE subscriptions SET seat_count=$1 WHERE id=$2',[count,id]);
    if(protectedPlan){
     await assert.rejects(change(),error=>error.code==='23514'&&/Seat reductions require/.test(error.message));
     assert.equal((await db.query('SELECT seat_count FROM subscriptions WHERE id=$1',[id])).rows[0].seat_count,5);
    }else{
     await change();
     assert.equal((await db.query('SELECT seat_count FROM subscriptions WHERE id=$1',[id])).rows[0].seat_count,count);
     await db.query('UPDATE subscriptions SET seat_count=5 WHERE id=$1',[id]);
    }
   }
   await db.query('UPDATE subscriptions SET seat_count=5 WHERE id=$1',[id]);
   await db.query('UPDATE subscriptions SET seat_count=6 WHERE id=$1',[id]);
   assert.equal((await db.query('SELECT seat_count FROM subscriptions WHERE id=$1',[id])).rows[0].seat_count,6);
  }finally{await db.close();}
 });
}
