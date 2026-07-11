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
    }),
  );
}
