import type { Env, Invite, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { hashToken } from "../lib/hash";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { sendEmail, inviteEmail } from "../lib/email";
import { validateRedirectUrl, resolveAppUrl } from "../lib/validate";
import { checkEmailThrottle } from "../lib/email-throttle";
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

  let body: { invite_id?: string; redirect_url?: string };
  try {
    body = await req.json() as { invite_id?: string; redirect_url?: string };
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.invite_id) return error("invite_id is required");

  const redirectErr = validateRedirectUrl(body.redirect_url, env);
  if (redirectErr) return redirectErr;

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

  const throttled = await checkEmailThrottle(env, "invite", caller.org_id);
  if (throttled) return throttled;

  // Generate new token and extend expiry
  const newToken = crypto.randomUUID();
  const newTokenHash = await hashToken(newToken);
  const newExpiry = new Date(Date.now() + INVITE_TTL_MS).toISOString();

  await database.update(
    "invites",
    { id: `eq.${invite.id}` },
    { token_hash: newTokenHash, expires_at: newExpiry },
  );

  // Fetch org name for the email template
  const org = await database.queryOne<{ name: string }>(
    `organizations?id=eq.${caller.org_id}&select=name`,
  );

  // Send invite email
  const appUrl = resolveAppUrl(body.redirect_url, env);
  const acceptUrl = `${appUrl}/invite/accept?token=${newToken}`;
  const { subject, html, text } = inviteEmail(
    caller.email,
    org?.name ?? "an organization",
    acceptUrl,
  );
  ctx.waitUntil(sendEmail(env, { to: invite.email, subject, html, text }));

  audit(ctx, env, "invite_resent", {
    user_id: caller.sub,
    org_id: caller.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { invite_id: invite.id, invited_email: invite.email },
  });

  return json({
    invite_id: invite.id,
    email: invite.email,
    expires_at: newExpiry,
  });
}
