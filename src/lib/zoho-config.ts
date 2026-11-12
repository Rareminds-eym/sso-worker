/** Nonsecret Zoho policy is code-owned. Only credentials and platform bindings stay external. */
export const ZOHO_SSO_DEFAULTS = Object.freeze({ dependencyTimeoutMs: 3500, deliveryTimeoutMs: 5000, recoveryBatches: 10, recoveryBudgetMs: 15000 });
const disabled=Object.freeze({emailPolicy:'forbidden' as const,requiresApproval:true as const,candidateProvisioning: false, projectionDelivery: false});
export const ZOHO_PROFILES=Object.freeze({
  production:disabled,dev:disabled,preview:disabled,'local-review':disabled,blocked:disabled,
  qa:Object.freeze({...disabled,candidateProvisioning: true, projectionDelivery: true}),
  local:Object.freeze({...disabled,candidateProvisioning: true, projectionDelivery: true}),
});
export function readZohoSsoConfig(env: {ENVIRONMENT?: unknown;SUPABASE_URL?: unknown}) {
  const name=env.ENVIRONMENT;
  if(name==='preview'||name==='local-review')return ZOHO_PROFILES[name];
  let local=false;
  try{const url=new URL(String(env.SUPABASE_URL));local=['http:','https:'].includes(url.protocol)&&['127.0.0.1','localhost','[::1]'].includes(url.hostname)&&!url.username&&!url.password&&url.pathname==='/'&&!url.search&&!url.hash;}catch{}
  if(local&&(name===undefined||name==='local'||name==='development'||name==='dev'))return ZOHO_PROFILES.local;
  return name==='production'?ZOHO_PROFILES.production:name==='qa'?ZOHO_PROFILES.qa:name==='development'||name==='dev'?ZOHO_PROFILES.dev:ZOHO_PROFILES.blocked;
}
