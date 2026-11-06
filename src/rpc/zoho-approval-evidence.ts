import { db } from '../lib/db';
import { verifyAccessToken } from '../lib/jwt';
import { PLATFORM_ORG_ID } from '../lib/constants';
import { isValidUUID } from '../lib/validate';
import type { Env } from '../types';

const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const uuid = (v: unknown): v is string => typeof v === 'string' && isValidUUID(v);
const positive = (v: unknown) => Number.isSafeInteger(v) && Number(v) > 0;
const decimal = (v: unknown) => typeof v === 'string' && /^\d{1,40}$/.test(v);
const hash = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);

/** No raw source data, passwords, sessions or notification settings are persisted. */
export function validApprovalManifest(v: unknown): v is Record<string, unknown> {
  if (!object(v) || !exact(v, ['requestId', 'connectionId', 'sourceOrgId', 'publisherOrganizationId', 'configRevision', 'items', 'reason', 'emailPolicy']) ||
      !uuid(v.requestId) || !uuid(v.connectionId) || !uuid(v.publisherOrganizationId) || !decimal(v.sourceOrgId) ||
      !positive(v.configRevision) || v.emailPolicy !== 'forbidden' || typeof v.reason !== 'string' ||
      v.reason.trim() !== v.reason || v.reason.length < 3 || v.reason.length > 500 ||
      !Array.isArray(v.items) || v.items.length < 1 || v.items.length > 50) return false;
  const ids = new Set();
  for (const item of v.items) {
    if (!object(item) || !exact(item, ['recordId', 'revision', 'sourceHash', 'module', 'externalId', 'targetId', ...(item.module === 'Candidates' ? ['candidateReviewHash'] : [])]) ||
        !uuid(item.recordId) || !positive(item.revision) || !hash(item.sourceHash) ||
        !['Candidates', 'Job_Openings'].includes(String(item.module)) || !decimal(item.externalId) ||
        !(item.targetId === null || uuid(item.targetId)) || (item.module === 'Candidates' && !hash(item.candidateReviewHash)) || ids.has(item.recordId)) return false;
    ids.add(item.recordId);
  }
  return true;
}

export async function recordApprovalEvidence(env: Env, input: unknown): Promise<{ recorded: boolean }> {
  if (!object(input) || !exact(input, ['accessToken', 'manifest']) || typeof input.accessToken !== 'string' ||
      input.accessToken.length > 16384 || !validApprovalManifest(input.manifest)) return { recorded: false };
  try {
    // Caller-supplied actor IDs and role claims are never authority. SSO verifies its own token.
    const claims = await verifyAccessToken(input.accessToken, env) as Awaited<ReturnType<typeof verifyAccessToken>> & { exp?: number; iat?: number };
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(claims.exp) || Number(claims.exp) <= now || !Number.isSafeInteger(claims.iat) || Number(claims.iat) > now + 30)
      return { recorded: false };
    if (!uuid(claims.sub) || claims.org_id !== PLATFORM_ORG_ID || claims.membership_status !== 'active' ||
        !Array.isArray(claims.roles) || !claims.roles.includes('super_admin')) return { recorded: false };
    const result = await db(env).rpc<unknown>('zoho_record_import_approval', { p_actor: claims.sub, p_manifest: input.manifest });
    return { recorded: result === true };
  } catch { return { recorded: false }; }
}

/** Also called independently by future canonical writers; coordinator checks alone are insufficient. */
export async function validateApprovalEvidence(env: Env, grant: unknown): Promise<{ allowed: boolean }> {
  if (!object(grant)) return { allowed: false };
  try {
    const encoded = JSON.stringify(grant);
    if (new TextEncoder().encode(encoded).byteLength > 131072) return { allowed: false };
    const result = await db(env).rpc<unknown>('zoho_validate_import_approval', { p_grant: grant });
    if (result !== true || typeof env.ZOHO_CONTROL_PLANE?.validateOperation !== 'function') return { allowed: false };
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const live = await Promise.race([
        env.ZOHO_CONTROL_PLANE.validateOperation(grant),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Authority unavailable')), 5000); }),
      ]);
      return { allowed: live?.allowed === true };
    } finally { if (timer !== undefined) clearTimeout(timer); }
  } catch { return { allowed: false }; }
}
