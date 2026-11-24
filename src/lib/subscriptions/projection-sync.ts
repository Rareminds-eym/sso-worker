import type { DbClient } from '../db';
import { publishSyncEvent, type SyncEvent } from '../sync-queue';
import { readSubscriptionLifecycle } from './lifecycle-persistence';
import { uuid } from './validation';

type Database = Pick<DbClient, 'query' | 'queryOne' | 'rpc'>;
const inventoryPageSize = 100;

/** Include retired offers so an application can revoke stale cached availability.
 * Keyset pagination avoids silently truncating the authoritative inventory. */
export async function readPlanSyncInventory(database: Pick<DbClient, 'query'>) {
  const plans: Record<string, unknown>[] = [];
  let cursor: string | undefined;
  for (;;) {
    const page = await database.query<Record<string, unknown>>(
      `plans?order=id.asc&limit=${inventoryPageSize}${cursor ? `&id=gt.${cursor}` : ''}`,
      undefined, 'json-array',
    );
    if (!Array.isArray(page) || page.length > inventoryPageSize) throw new Error('Invalid plan sync inventory');
    for (const plan of page) {
      const id = uuid(plan.id, 'sync.planId');
      if (typeof plan.is_active !== 'boolean' || cursor !== undefined && id <= cursor) throw new Error('Invalid plan sync ordering');
      plans.push(plan); cursor = id;
    }
    if (page.length < inventoryPageSize) return plans;
  }
}

/** Publish only committed, owner-validated rows named by a verification receipt.
 * Queue payloads remain projections; they never authorize customer access. */
export async function publishCommittedSubscriptions(database: Database, queue: Queue<SyncEvent>, ctx: ExecutionContext,
  userId: string, subscriptionIds: readonly string[], event: 'subscription.created' | 'subscription.updated' = 'subscription.created') {
  const user = uuid(userId, 'sync.userId');
  const ids = subscriptionIds.map(id => uuid(id, 'sync.subscriptionId'));
  if (new Set(ids).size !== ids.length) throw new Error('Duplicate subscription sync receipt');
  if (!ids.length) return;
  const rows = await database.query<Record<string, unknown>>(
    `subscriptions?id=in.(${ids.join(',')})&user_id=eq.${user}&order=id.asc`, undefined, 'json-array',
  );
  if (!Array.isArray(rows) || rows.length !== ids.length || new Set(rows.map(row => row.id)).size !== ids.length
    || rows.some(row => !ids.includes(String(row.id)) || row.user_id !== user)) throw new Error('Subscription sync receipt differs');
  // Validate every row before publishing any part of the receipt.
  for (const row of rows) {
    const subject = row.is_organization_subscription === true
      ? { kind: 'organization' as const, id: uuid(row.organization_id, 'sync.organizationId') }
      : { kind: 'user' as const, id: user };
    const current = await readSubscriptionLifecycle(database, String(row.id), uuid(row.product_id, 'sync.productId'), subject);
    const projected = row.lifecycle_state;
    if (current.state.revisionId !== row.plan_revision_id || current.state.planId !== row.plan_id
      || current.state.status !== row.status || !projected || typeof projected !== 'object'
      || !('version' in projected) || projected.version !== current.state.version) throw new Error('Subscription sync revision differs');
  }
  for (const row of rows) publishSyncEvent(queue, ctx, event, row);
}

/** Called after an authenticated lifecycle/commerce commit; resolve the retained
 * purchasing identity from storage rather than treating the actor as its owner. */
export async function publishCommittedSubscription(database: Database, queue: Queue<SyncEvent>, ctx: ExecutionContext,
  subscriptionId: string, event: 'subscription.created' | 'subscription.updated') {
  const id = uuid(subscriptionId, 'sync.subscriptionId');
  const rows = await database.query<{ user_id: string }>(`subscriptions?select=user_id&id=eq.${id}&limit=2`, undefined, 'json-array');
  if (rows.length !== 1) throw new Error('Committed subscription missing');
  return publishCommittedSubscriptions(database, queue, ctx, rows[0].user_id, [id], event);
}
