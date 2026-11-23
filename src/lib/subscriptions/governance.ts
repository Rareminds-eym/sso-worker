import type { Env } from '../../types';
import { readSubscriptionExecution, SubscriptionExecutionDenied } from './credit-execution';
import { array, choice, integer, invalid, record, text, uuid } from './validation';

const PAGE_SIZE = 50;
const object = (value: unknown, path: string) => record(value, path,
  value && typeof value === 'object' ? Object.keys(value) : []);
function timestamp(value: unknown, path: string): string {
  const result = text(value, path);
  if (!Number.isFinite(Date.parse(result)) || !/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(result)) invalid(path, 'invalid timestamp');
  return result;
}

/** Controlled, bounded audit read from immutable lifecycle evidence, without exposing raw metadata. */
export async function readSubscriptionAudit(env: Env, token: unknown, subscriptionId: unknown, productId: unknown, after: unknown) {
  const context = await readSubscriptionExecution(env, token, subscriptionId, productId, 'audit');
  if (context.access === 'suspended') throw new SubscriptionExecutionDenied();
  const cursor = after === null ? null : uuid(after, 'audit.cursor');
  const rows = array(await context.database.query<Record<string, unknown>>(
    'subscription_lifecycle_operations?select=operation_id,subscription_id,actor_id,transaction_id,kind,receipt,committed_at'
    + `&subscription_id=eq.${context.state.id}&order=operation_id.asc&limit=${PAGE_SIZE}`
    + (cursor ? `&operation_id=gt.${cursor}` : ''), undefined, 'json-array'), 'audit.rows');
  if (rows.length > PAGE_SIZE) invalid('audit.rows', 'response budget exceeded');
  let previous = cursor;
  const items = rows.map(raw => {
    const row = record(raw, 'audit.row', ['operation_id', 'subscription_id', 'actor_id', 'transaction_id', 'kind', 'receipt', 'committed_at']);
    const operationId = uuid(row.operation_id, 'audit.operationId');
    if ((previous && operationId <= previous) || row.subscription_id !== context.state.id) invalid('audit.row', 'scope or cursor differs');
    previous = operationId;
    const receipt = object(row.receipt, 'audit.receipt');
    if (receipt.operationId !== operationId) invalid('audit.receipt', 'operation differs');
    const kind = choice(row.kind, 'audit.kind', ['initialize', 'transition'] as const);
    const decision = kind === 'transition' ? object(receipt.decision, 'audit.decision') : null;
    const state = object(decision ? decision.next : receipt.state, 'audit.state');
    const subject = record(state.subject, 'audit.subject', ['kind', 'id']);
    if (state.id !== context.state.id || state.productId !== context.productId
      || subject.id !== context.subject.id || subject.kind !== context.subject.kind) invalid('audit.state', 'subject or product differs');
    const version = integer(state.version, 'audit.version', 1);
    const committedAt = timestamp(row.committed_at, 'audit.committedAt');
    const audit = decision ? object(decision.audit, 'audit.event') : null;
    const actorId = uuid(row.actor_id, 'audit.actorId');
    const fromVersion = decision ? integer(decision.expectedVersion, 'audit.fromVersion', 1) : null;
    if (decision ? version !== fromVersion! + 1 || audit!.actorId !== actorId : version !== 1) invalid('audit.event', 'actor or version differs');
    const at = audit ? integer(audit.at, 'audit.at') : Date.parse(timestamp(receipt.activatedAt, 'audit.activatedAt'));
    if (at > Date.parse(committedAt)) invalid('audit.at', 'event follows commit');
    return { operationId, actorId, operation: audit
      ? choice(audit.operation, 'audit.operation', ['upgrade', 'renew', 'downgrade', 'cancel', 'expire', 'payment_failed', 'suspend', 'reactivate'] as const)
      : 'initialize' as const,
      reason: audit ? text(audit.reason, 'audit.reason') : 'Subscription initialized', at, committedAt,
      fromVersion, toVersion: version, planId: uuid(state.planId, 'audit.planId'), revisionId: uuid(state.revisionId, 'audit.revisionId'),
      transactionId: row.transaction_id === null ? null : uuid(row.transaction_id, 'audit.transactionId') };
  });
  return { schemaVersion: 1 as const, actorId: context.actorId, productId: context.productId, subscriptionId: context.state.id,
    items, nextCursor: rows.length === PAGE_SIZE ? previous : null };
}
