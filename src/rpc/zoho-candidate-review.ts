import { db } from '../lib/db';
import { verifyAccessToken } from '../lib/jwt';
import { PLATFORM_ORG_ID } from '../lib/constants';
import { isValidUUID } from '../lib/validate';
import type { Env } from '../types';

const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const uuid = (v: unknown) => typeof v === 'string' && isValidUUID(v);
const hash = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);

/** The source DTO is bounded and carries no credentials, notification settings or role assignments. */
export function validCandidateReviewContext(v: unknown): v is Record<string, unknown> {
  return object(v) && exact(v, ['connectionId', 'sourceOrgId', 'recordId', 'revision', 'configRevision', 'sourceHash', 'externalId', 'data', 'targetId', 'emailPolicy']) &&
    uuid(v.connectionId) && uuid(v.recordId) && (v.targetId === null || uuid(v.targetId)) &&
    Number.isSafeInteger(v.revision) && Number(v.revision) > 0 && Number.isSafeInteger(v.configRevision) && Number(v.configRevision) > 0 &&
    typeof v.sourceOrgId === 'string' && /^\d{1,40}$/.test(v.sourceOrgId) && typeof v.externalId === 'string' && /^\d{1,40}$/.test(v.externalId) &&
    hash(v.sourceHash) && v.emailPolicy === 'forbidden' && object(v.data) && exact(v.data, ['email', 'name']) &&
    typeof v.data.email === 'string' && v.data.email.length <= 320 && v.data.email === v.data.email.trim().toLowerCase() && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.data.email) &&
    typeof v.data.name === 'string' && v.data.name.length >= 2 && v.data.name.length <= 150 && v.data.name.trim() === v.data.name;
}

async function reviewedActor(env: Env, token: unknown): Promise<string | null> {
  if (typeof token !== 'string' || token.length < 1 || token.length > 16384) return null;
  const claims = await verifyAccessToken(token, env) as Awaited<ReturnType<typeof verifyAccessToken>> & { exp?: number; iat?: number };
  const now = Math.floor(Date.now() / 1000);
  if (!uuid(claims.sub) || claims.org_id !== PLATFORM_ORG_ID || claims.membership_status !== 'active' || !Array.isArray(claims.roles) ||
      !claims.roles.includes('super_admin') || !Number.isSafeInteger(claims.exp) || Number(claims.exp) <= now ||
      !Number.isSafeInteger(claims.iat) || Number(claims.iat) > now + 30) return null;
  return claims.sub;
}

/** Private service binding only. Reads canonical SSO state; never provisions, logs in or sends email. */
export async function previewCandidateReview(env: Env, input: unknown): Promise<unknown> {
  if (!object(input) || !exact(input, ['accessToken', 'context']) || !validCandidateReviewContext(input.context)) return null;
  try {
    const actor = await reviewedActor(env, input.accessToken);
    if (!actor) return null;
    return await db(env).rpc('zoho_preview_candidate_review', { p_actor: actor, p_context: input.context });
  } catch { return null; }
}

export async function verifyCandidateReview(env: Env, input: unknown): Promise<{ allowed: boolean }> {
  if (!object(input) || !exact(input, ['accessToken', 'context', 'candidateReviewHash']) || !validCandidateReviewContext(input.context) || !hash(input.candidateReviewHash))
    return { allowed: false };
  try {
    const actor = await reviewedActor(env, input.accessToken);
    if (!actor) return { allowed: false };
    const allowed = await db(env).rpc('zoho_verify_candidate_review', { p_actor: actor, p_context: input.context, p_review_hash: input.candidateReviewHash });
    return { allowed: allowed === true };
  } catch { return { allowed: false }; }
}
