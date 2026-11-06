import { readZohoSsoConfig, ZOHO_SSO_DEFAULTS } from './zoho-config';
import { db } from './db';
import { isValidUUID } from './validate';
import type { Env } from '../types';

const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function projectionReference(input: unknown): input is { operationId: string; sourceHash: string; emailPolicy: 'forbidden' } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  const value = input as Record<string, unknown>;
  return Object.keys(value).length === 3 && typeof value.operationId === 'string' && isValidUUID(value.operationId) &&
    hash(value.sourceHash) && value.emailPolicy === 'forbidden';
}
export async function boundedDelivery<T>(work: () => Promise<T>, ms: number = ZOHO_SSO_DEFAULTS.deliveryTimeoutMs): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([Promise.resolve().then(work), new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('Projection dependency unavailable')), ms);
    })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

/** Uses the existing auth sync queue. IDs only; no email, profile or entitlement DTO. */
async function recoverCandidateDeliveryBatch(env: Env): Promise<{ published: number; reserved: number }> {
  if (!readZohoSsoConfig(env).projectionDelivery) return { published: 0, reserved: 0 };
  if (typeof env.SYNC_QUEUE?.sendBatch !== 'function' && typeof env.SYNC_QUEUE?.send !== 'function') throw new Error('Projection queue unavailable');
  const database = db(env);
  const lease = crypto.randomUUID();
  const reserved = await database.rpc<unknown>('zoho_reserve_candidate_deliveries', { p_lease: lease });
  if (!Array.isArray(reserved) || reserved.length > 10) throw new Error('Invalid projection reservation');
  for (const item of reserved) {
    if (!item || typeof item !== 'object' || item.lease !== lease ||
        !projectionReference({ operationId: item.operationId, sourceHash: item.sourceHash, emailPolicy: 'forbidden' }))
      throw new Error('Invalid projection reservation');
  }
  let published = 0;
  const events = reserved.map(item => ({ type: 'zoho.candidate.canonical_committed' as const,
    payload: { operationId: item.operationId, sourceHash: item.sourceHash, emailPolicy: 'forbidden' as const }, timestamp: new Date().toISOString() }));
  // Queue batch acceptance is all-or-unknown. On a timeout never fall back to
  // individual sends: the durable outbox will retry the same immutable references.
  let batchSent: boolean | undefined;
  if (events.length && typeof env.SYNC_QUEUE.sendBatch === 'function') {
    batchSent = false;
    try {
      await boundedDelivery(() => env.SYNC_QUEUE.sendBatch(events.map(body => ({ body }))));
      batchSent = true;
    } catch { /* Ambiguous acceptance is reconciled by the existing receipts. */ }
  }
  if (batchSent !== undefined) {
    const operations = reserved.map(item => item.operationId as string);
    const recorded = await database.rpc<unknown>('zoho_record_candidate_publications', {
      p_operations: operations, p_lease: lease, p_published: batchSent,
    });
    if (!Array.isArray(recorded) || recorded.length !== operations.length ||
        new Set(recorded.map(item => item?.operationId)).size !== operations.length ||
        recorded.some(item => !item || !operations.includes(item.operationId) || item.recorded !== true))
      throw new Error('Projection publication acknowledgement unavailable');
    return { published: batchSent ? reserved.length : 0, reserved: reserved.length };
  }
  const results = await Promise.allSettled(reserved.map(async (item, index) => {
    let sent = batchSent === true;
    if (batchSent === undefined) {
      try { await boundedDelivery(() => env.SYNC_QUEUE.send(events[index])); sent = true; }
      catch { /* Even a send timeout can publish; receipt idempotency handles duplicates. */ }
    }
    if (sent) published++;
    const recorded = await database.rpc('zoho_record_candidate_publication', { p_operation: item.operationId, p_lease: lease, p_published: sent });
    if (recorded !== true) throw new Error('Projection publication acknowledgement unavailable');
  }));
  if (results.some(result => result.status === 'rejected')) throw new Error('Projection publication recovery incomplete');
  return { published, reserved: reserved.length };
}

/** Drain a bounded backlog rather than leaving a large import at ten deliveries per cron. */
export async function recoverCandidateDeliveries(env: Env): Promise<{ published: number }> {
  const started = Date.now(); let published = 0;
  for (let batch = 0; batch < ZOHO_SSO_DEFAULTS.recoveryBatches && Date.now()-started < ZOHO_SSO_DEFAULTS.recoveryBudgetMs; batch++) {
    const result = await recoverCandidateDeliveryBatch(env);
    published += result.published;
    if (result.reserved < 10 || result.published === 0) break;
  }
  return { published };
}

/** Read authoritative current state, never accept an event-supplied identity or plan. */
export async function candidateProjectionSnapshot(env: Env, input: unknown): Promise<unknown> {
  if (!readZohoSsoConfig(env).projectionDelivery || !projectionReference(input)) return null;
  const result = await db(env).rpc<unknown>('zoho_get_candidate_projection', { p_operation: input.operationId, p_source_hash: input.sourceHash });
  if (!result || typeof result !== 'object' || Array.isArray(result)) return null;
  const snapshot = result as Record<string, unknown>;
  if (Object.keys(snapshot).length !== 5 || typeof snapshot.targetId !== 'string' || !isValidUUID(snapshot.targetId) ||
      snapshot.operationId !== input.operationId || snapshot.sourceHash !== input.sourceHash || !hash(snapshot.projectionHash) ||
      typeof snapshot.snapshot !== 'string' || new TextEncoder().encode(snapshot.snapshot).byteLength > 131072) return null;
  return result;
}

/** Read back application postconditions through an independent restricted authority. */
export async function confirmCandidateProjection(env: Env, input: unknown): Promise<unknown> {
  if (!readZohoSsoConfig(env).projectionDelivery || !input || typeof input !== 'object' || Array.isArray(input))
    throw new Error('Projection confirmation unavailable');
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== 5 || !projectionReference({ operationId: value.operationId, sourceHash: value.sourceHash, emailPolicy: value.emailPolicy }) ||
      !hash(value.projectionHash) || typeof value.projectionReceiptId !== 'string' || !isValidUUID(value.projectionReceiptId) ||
      typeof env.ZOHO_CONTROL_PLANE?.validateProjectionReceipt !== 'function') throw new Error('Projection confirmation unavailable');
  const allowed = await boundedDelivery(() => env.ZOHO_CONTROL_PLANE!.validateProjectionReceipt!(value));
  if (allowed?.allowed !== true) throw new Error('Projection postconditions unavailable');
  return db(env).rpc('zoho_confirm_candidate_projection', { p_operation: value.operationId, p_source_hash: value.sourceHash,
    p_projection_hash: value.projectionHash, p_receipt: value.projectionReceiptId });
}
