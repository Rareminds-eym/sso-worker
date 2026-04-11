import type { Env } from "../types";
import { db } from "./db";

export type AuditAction =
  | "signup"
  | "login"
  | "login_failed"
  | "logout"
  | "refresh"
  | "refresh_theft_detected"
  | "switch_org"
  | "invite_created"
  | "invite_accepted";

/**
 * Non-blocking audit log entry.
 * Uses ctx.waitUntil() so the write happens after the response is sent.
 * Table: audit_logs (plural, matching actual DB).
 */
export function audit(
  ctx: ExecutionContext,
  env: Env,
  action: AuditAction,
  opts: {
    user_id?: string | null;
    org_id?: string | null;
    ip_address?: string | null;
    user_agent?: string | null;
    metadata?: Record<string, unknown>;
  } = {},
): void {
  const promise = (async () => {
    try {
      const database = db(env);
      await database.mutate("audit_logs", {
        user_id: opts.user_id ?? null,
        org_id: opts.org_id ?? null,
        action,
        metadata: opts.metadata ?? {},
        ip_address: opts.ip_address ?? null,
        user_agent: opts.user_agent ?? null,
      });
    } catch (err) {
      console.error("[SSO] Audit log write failed:", err);
    }
  })();

  ctx.waitUntil(promise);
}
