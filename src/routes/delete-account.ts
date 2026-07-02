import { audit } from "../lib/audit";
import { db } from "../lib/db";
import { endpointRateLimit } from "../lib/rate-limit";
import { publishSyncEvent } from "../lib/sync-queue";
import type { Env } from "../types";

/**
 * Pure business logic for deleting account (extracted for RPC)
 */
export async function performDeleteAccount(
  env: Env,
  ctx: ExecutionContext,
  params: {
    user_id: string;
    org_id?: string;
  },
  ip?: string | null,
  ua?: string | null
): Promise<{ deleted?: boolean; error?: string; status?: number }> {
  const rateLimited = await endpointRateLimit(env, `delete-account:user:${params.user_id}`, 20, 60);
  if (rateLimited) {
    return { error: "Rate limit exceeded", status: 429 };
  }

  try {
    // Delete the user — CASCADE handles sessions, memberships, email_verifications, etc.
    const database = db(env);
    await database.delete("users", { id: `eq.${params.user_id}` });

    // Emit sync events
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'user.deleted', {
      user_id: params.user_id,
    });

    audit(ctx, env, "account_deleted", {
      user_id: params.user_id,
      org_id: params.org_id || null,
      ip_address: ip || null,
      user_agent: ua || null,
    });

    return { deleted: true };
  } catch (err) {
    console.error("[SSO] Account deletion failed:", err);
    return { error: "Failed to delete account", status: 500 };
  }
}


