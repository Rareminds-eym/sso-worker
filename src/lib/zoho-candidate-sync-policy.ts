import { db } from './db';
import { isValidUUID } from './validate';
import type { Env } from '../types';

export async function candidateSubjectSyncPolicy(env: Env, input: unknown) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 1 ||
      !('userId' in input) || typeof input.userId !== 'string' || !isValidUUID(input.userId))
    throw new Error('Identity synchronization policy unavailable');
  const policy = await db(env).rpc<unknown>('zoho_candidate_sync_policy', { p_user: input.userId });
  if (!policy || typeof policy !== 'object' || Array.isArray(policy) || Object.keys(policy).length !== 2 ||
      !('version' in policy) || policy.version !== 1 || !('genericSyncAllowed' in policy) || typeof policy.genericSyncAllowed !== 'boolean')
    throw new Error('Identity synchronization policy unavailable');
  return { version: 1, genericSyncAllowed: policy.genericSyncAllowed };
}

export async function isImportedCandidate(env: Env, userId: string): Promise<boolean> {
  return !(await candidateSubjectSyncPolicy(env, { userId })).genericSyncAllowed;
}
