import { boundedDelivery } from './zoho-candidate-delivery';
import { db } from './db';
import type { Env } from '../types';

const capability = (ready: boolean) => ({ version: 1, ready, emailPolicy: 'forbidden', modules: ['Candidates'],
  checksLiveApproval: true, checksLiveApprover: true, idempotentByOperation: true,
  transactionalReceipt: true, fencesExpiredLeases: true, verifiesPostconditions: true });

/** Read-only and uncached. A producer binding alone cannot attest destination privacy. */
export async function candidateCapabilities(env: Env) {
  const unavailable = () => ({ ...capability(false), reason: 'Candidate dependencies unavailable' });
  if (env.ZOHO_CANDIDATE_PROVISIONING_ENABLED !== 'true' || env.ZOHO_PROJECTION_DELIVERY_ENABLED !== 'true' ||
      !env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY || typeof env.SYNC_QUEUE?.send !== 'function' ||
      typeof env.ZOHO_CONTROL_PLANE?.validateOperation !== 'function' ||
      typeof env.ZOHO_CONTROL_PLANE?.validateProjectionReceipt !== 'function' ||
      typeof env.ZOHO_CONTROL_PLANE?.candidateProjectionCapabilities !== 'function') return unavailable();
  try {
    const [canonical, projection] = await boundedDelivery(() => Promise.all([
      db(env).rpc<unknown>('zoho_candidate_runtime_ready'),
      env.ZOHO_CONTROL_PLANE!.candidateProjectionCapabilities!(),
    ]), 3500);
    if (canonical !== true || !projection || typeof projection !== 'object' || Array.isArray(projection)) return unavailable();
    const result = projection as Record<string, unknown>;
    if (result.version !== 1 || result.ready !== true || result.emailPolicy !== 'forbidden' ||
        result.verifiesPostconditions !== true || result.privateProfiles !== true) return unavailable();
    return capability(true);
  } catch { return unavailable(); }
}
