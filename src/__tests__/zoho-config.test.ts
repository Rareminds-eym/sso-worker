import {it,expect} from 'vitest';
import {readZohoSsoConfig,ZOHO_PROFILES} from '../lib/zoho-config';
it('uses code profiles and ignores obsolete feature variables',()=>{
 const old={ENVIRONMENT:'production',ZOHO_CANDIDATE_PROVISIONING_ENABLED:'true',ZOHO_PROJECTION_DELIVERY_ENABLED:'true'};
 expect(readZohoSsoConfig(old)).toBe(ZOHO_PROFILES.production);
 for(const ENVIRONMENT of ['production','development','qa','preview','unknown']){
  const config=readZohoSsoConfig({ENVIRONMENT});
  for(const key of ['candidateProvisioning', 'projectionDelivery'] as const)expect(config[key]).toBe(false);
 }
 expect(readZohoSsoConfig({ENVIRONMENT:'development',SUPABASE_URL:'http://127.0.0.1:54321'})).toBe(ZOHO_PROFILES.local);
});
it('preserves review-only local setup and mandatory immutable policy',()=>{
 const config=readZohoSsoConfig({ENVIRONMENT:'local-review',SUPABASE_URL:'http://127.0.0.1:54321'});
 expect(config).toBe(ZOHO_PROFILES['local-review']);expect(config.emailPolicy).toBe('forbidden');expect(config.requiresApproval).toBe(true);expect(Object.isFrozen(config)).toBe(true);
});
