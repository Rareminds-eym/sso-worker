export type SyncEventType =
  | 'user.created'
  | 'user.updated'
  | 'user.email_verified'
  | 'user.deleted'
  | 'organization.created'
  | 'membership.created'
  | 'membership.role_changed'
  | 'membership.removed';

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
