import { db } from '../lib/db';
import { verifyAccessToken } from '../lib/jwt';
import { PLATFORM_ORG_ID } from '../lib/constants';
import { isValidUUID } from '../lib/validate';
import type { Env } from '../types';

const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const uuid = (v: unknown): v is string => typeof v === 'string' && isValidUUID(v);
const hash = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
export function validCandidateAdministrationContext(v: unknown): v is Record<string, unknown> {
  return object(v) && exact(v, ['action', 'sourceOrgId', 'externalId', 'targetId', 'reason', 'emailPolicy', 'acknowledgeIndependentDiscover']) &&
    ['establish_learner_context', 'erase_connector', 'release_suppression'].includes(String(v.action)) &&
    typeof v.sourceOrgId === 'string' && /^\d{1,40}$/.test(v.sourceOrgId) && typeof v.externalId === 'string' && /^\d{1,40}$/.test(v.externalId) &&
    uuid(v.targetId) && typeof v.reason === 'string' && v.reason === v.reason.trim() && v.reason.length >= 3 && v.reason.length <= 500 &&
    v.emailPolicy === 'forbidden' && v.acknowledgeIndependentDiscover === (v.action === 'establish_learner_context');
}
async function actor(env: Env, token: unknown): Promise<string | null> {
  if (typeof token !== 'string' || token.length < 1 || token.length > 16384) return null;
  const c = await verifyAccessToken(token, env) as Awaited<ReturnType<typeof verifyAccessToken>> & { exp?: number; iat?: number };
  const now = Math.floor(Date.now() / 1000);
  return uuid(c.sub) && c.org_id === PLATFORM_ORG_ID && c.membership_status === 'active' && Array.isArray(c.roles) && c.roles.includes('super_admin') &&
    Number.isSafeInteger(c.exp) && Number(c.exp) > now && Number.isSafeInteger(c.iat) && Number(c.iat) <= now + 30 ? c.sub : null;
}
/** Restricted human administration. Never accepts passwords, roles, plans, or email delivery settings. */
export async function previewCandidateAdministration(env: Env, input: unknown): Promise<unknown> {
  if (!object(input) || !exact(input, ['accessToken', 'context']) || !validCandidateAdministrationContext(input.context)) return null;
  try {
    const subject = await actor(env, input.accessToken);
    return subject ? await db(env).rpc('zoho_preview_candidate_administration', { p_actor: subject, p_context: input.context }) : null;
  } catch { return null; }
}
export async function executeCandidateAdministration(env: Env, input: unknown): Promise<unknown> {
  if (!object(input) || !exact(input, ['accessToken', 'context', 'reviewHash', 'requestId']) || !validCandidateAdministrationContext(input.context) ||
      !hash(input.reviewHash) || !uuid(input.requestId)) throw new Error('Candidate administration authority unavailable');
  const subject = await actor(env, input.accessToken).catch(() => null);
  if (!subject) throw new Error('Candidate administration authority unavailable');
  // An ambiguous database result is never translated into success/no effect. Exact retries read the durable receipt.
  return db(env).rpc('zoho_execute_candidate_administration', { p_actor: subject, p_context: input.context, p_review_hash: input.reviewHash, p_request: input.requestId });
}
export async function findCandidateAdministration(env: Env, input: unknown): Promise<unknown> {
  if (!object(input) || !exact(input, ['accessToken', 'requestId']) || !uuid(input.requestId)) return null;
  try {
    const subject = await actor(env, input.accessToken);
    return subject ? await db(env).rpc('zoho_find_candidate_administration', { p_actor: subject, p_request: input.requestId }) : null;
  } catch { return null; }
}
export async function listCandidateErasedOperations(env: Env, input: unknown): Promise<unknown> {
  if (!object(input) || !exact(input, ['accessToken', 'requestId', 'afterOperationId']) || !uuid(input.requestId) ||
      (input.afterOperationId !== null && !uuid(input.afterOperationId))) return null;
  try {
    const subject = await actor(env, input.accessToken);
    return subject ? await db(env).rpc('zoho_list_candidate_erased_operations', { p_actor: subject, p_request: input.requestId, p_after: input.afterOperationId }) : null;
  } catch { return null; }
}
/** Recovery enumerates already committed, source-scoped effects only. It never
 * authorizes a new canonical action or trusts an original actor from a client. */
export async function listPendingCandidateAdministrations(env: Env, input: unknown): Promise<unknown> {
  if (!object(input) || !exact(input, ['accessToken', 'sourceOrgId', 'before']) ||
    typeof input.sourceOrgId !== 'string' || !/^\d{1,40}$/.test(input.sourceOrgId)) return null;
  const cursor = input.before;
  if (cursor !== null && (!object(cursor) || !exact(cursor, ['createdAt', 'requestId']) || !uuid(cursor.requestId) ||
    typeof cursor.createdAt !== 'string' || cursor.createdAt.length > 64 || !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(cursor.createdAt) || !Number.isFinite(Date.parse(cursor.createdAt)))) return null;
  try {
    const subject = await actor(env, input.accessToken);
    return subject ? await db(env).rpc('zoho_list_pending_candidate_administrations', { p_actor: subject,
      p_source_org: input.sourceOrgId, p_before_at: cursor === null ? null : cursor.createdAt,
      p_before_request: cursor === null ? null : cursor.requestId }) : null;
  } catch { return null; }
}
export async function acknowledgeCandidateAdministration(env: Env, input: unknown): Promise<unknown> {
  if (!object(input) || !exact(input, ['accessToken', 'requestId']) || !uuid(input.requestId)) throw new Error('Candidate administration acknowledgement unavailable');
  const subject = await actor(env, input.accessToken).catch(() => null);
  if (!subject) throw new Error('Candidate administration acknowledgement unavailable');
  // Ambiguity is preserved: an ACK retry is idempotent and the pending list is
  // canonical, so a lost response cannot authorize another opposite action.
  return db(env).rpc('zoho_acknowledge_candidate_administration', { p_actor: subject, p_request: input.requestId });
}
