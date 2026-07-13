export type SyncEventType =
  | 'user.created'
  | 'user.updated'
  | 'user.email_verified'
  | 'user.deleted'
  | 'organization.created'
  | 'organization.updated'
  | 'membership.created'
  | 'membership.role_changed'
  | 'membership.removed'
  | 'subscription.created'
  | 'subscription.updated'
  | 'subscription.cancelled'
  | 'subscription.expired';

export interface SyncEvent {
  type: SyncEventType;
  payload: Record<string, unknown>;
  timestamp: string;
}

export function publishSyncEvent(
  queue: Queue<SyncEvent>,
  ctx: ExecutionContext,
  type: SyncEventType,
  payload: Record<string, unknown>,
): void {
  ctx.waitUntil(
    queue.send({
      type,
      payload,
      timestamp: new Date().toISOString(),
    }).catch((err) => {
      // ponytail: Log queue errors so they're not silently swallowed
      // waitUntil doesn't propagate errors, so explicit catch is needed
      console.error(`[SYNC_QUEUE] Failed to publish ${type}:`, err);
    }),
  );
}
