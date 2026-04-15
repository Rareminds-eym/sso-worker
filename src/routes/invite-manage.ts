import type { Env, Invite, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { INVITE_TTL_MS } from "../lib/constants";

/**
 * POST /auth/invite/cancel
 * Cancel a pending invite. Only the inviter (or org owner/admin) can cancel.
 */
export async function cancelInvite(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const caller = auth!;
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");

  let body: { invite_id?: string };
  try {
    body = await req.json() as { invite_id?: string };
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.invite_id) return error("invite_id is required");

  const database = db(env);

  const invite = await database.queryOne<Invite>(
    `invites?id=eq.${encodeURIComponent(body.invite_id)}&select=*`,
  );

  if (!invite) return error("Invite not found", 404);
  if (invite.accepted) return error("Cannot cancel an accepted invite", 409);
  if (invite.org_id !== caller.org_id) {
    return error("You can only cancel invites for your active organization", 403);
  }

  // Only owner, admin, or the original inviter can cancel
  const isOwnerOrAdmin = caller.roles.includes("owner") || caller.roles.includes("admin");
  const isInviter = invite.invited_by === caller.sub;
  if (!isOwnerOrAdmin && !isInviter) {
    return error("Insufficient permissions to cancel this invite", 403);
  }

  // Delete the invite
  await database.query(
    `invites?id=eq.${encodeURIComponent(body.invite_id)}`,
    { method: "DELETE" },
  );

  audit(ctx, env, "invite_cancelled", {
    user_id: caller.sub,
    org_id: caller.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { invite_id: body.invite_id, invited_email: invite.email },
  });

  return json({ cancelled: true });
}

/**
 * POST /auth/invite/resend
 * Resend an invite by generating a new token and extending the expiry.
 */
export async function resendInvite(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const caller = auth!;
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");

  let body: { invite_id?: string };
  try {
    body = await req.json() as { invite_id?: string };
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.invite_id) return error("invite_id is required");

  const database = db(env);

  const invite = await database.queryOne<Invite>(
    `invites?id=eq.${encodeURIComponent(body.invite_id)}&select=*`,
  );

  if (!invite) return error("Invite not found", 404);
  if (invite.accepted) return error("Cannot resend an accepted invite", 409);
  if (invite.org_id !== caller.org_id) {
    return error("You can only resend invites for your active organization", 403);
  }

  if (!caller.roles.includes("owner") && !caller.roles.includes("admin")) {
    return error("Only owners and admins can resend invites", 403);
  }

  // Generate new token and extend expiry
  const newToken = crypto.randomUUID();
  const newExpiry = new Date(Date.now() + INVITE_TTL_MS).toISOString();

  await database.update(
    "invites",
    { id: `eq.${invite.id}` },
    { token: newToken, expires_at: newExpiry },
  );

  audit(ctx, env, "invite_resent", {
    user_id: caller.sub,
    org_id: caller.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { invite_id: invite.id, invited_email: invite.email },
  });

  return json({
    invite_id: invite.id,
    token: newToken,
    email: invite.email,
    expires_at: newExpiry,
  });
}
