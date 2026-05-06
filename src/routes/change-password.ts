import type { Env, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { hashPassword, verifyPassword } from "../lib/hash";
import { validatePassword } from "../lib/validate";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";

interface ChangePasswordBody {
  current_password: string;
  new_password: string;
}

interface AdminResetPasswordBody {
  user_id: string;
  new_password: string;
}

/**
 * POST /auth/change-password
 *
 * Authenticated user changes their own password.
 * Requires current password for verification.
 */
export async function changePassword(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  if (!auth) return error("Unauthorized", 401);
  let body: ChangePasswordBody;
  try {
    body = (await req.json()) as ChangePasswordBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.current_password || !body.new_password) {
    return error("current_password and new_password are required");
  }

  const passErr = validatePassword(body.new_password);
  if (passErr) return passErr;

  const database = db(env);

  // Get current user's password hash
  const users = await database.query<{ password_hash: string }>(
    `users?id=eq.${auth.sub}&select=password_hash`,
  );

  if (!users.length) {
    return error("User not found", 404);
  }

  // Verify current password
  const isValid = await verifyPassword(body.current_password, users[0].password_hash);
  if (!isValid) {
    return error("Current password is incorrect", 401);
  }

  // Hash and update new password
  const newHash = await hashPassword(body.new_password);
  await database.update(
    "users",
    { id: `eq.${auth.sub}` },
    { password_hash: newHash, updated_at: new Date().toISOString() },
  );

  // Revoke all other sessions (force re-login everywhere)
  await database.update(
    "sessions",
    { user_id: `eq.${auth.sub}`, revoked: "eq.false" },
    { revoked: true },
  );

  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  audit(ctx, env, "password_reset_completed", {
    user_id: auth.sub,
    ip_address: ip,
    user_agent: ua,
    metadata: { self_change: true },
  });

  return json({ success: true, message: "Password changed. Please log in again." });
}

/**
 * POST /auth/admin-reset-password
 *
 * Admin resets another user's password (no current password needed).
 * Requires owner or admin role.
 */
export async function adminResetPassword(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  if (!auth) return error("Unauthorized", 401);
  // Check admin/owner role
  const isAdmin = auth.roles.some(
    (r) => r === "owner" || r === "admin" || r === "school_admin" || r === "college_admin" || r === "university_admin",
  );
  if (!isAdmin) {
    return error("Forbidden: admin role required", 403);
  }

  let body: AdminResetPasswordBody;
  try {
    body = (await req.json()) as AdminResetPasswordBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.user_id || !body.new_password) {
    return error("user_id and new_password are required");
  }

  const passErr = validatePassword(body.new_password);
  if (passErr) return passErr;

  const database = db(env);

  // Verify target user exists
  const users = await database.query<{ id: string }>(
    `users?id=eq.${body.user_id}&select=id`,
  );
  if (!users.length) {
    return error("Target user not found", 404);
  }

  // Hash and update password
  const newHash = await hashPassword(body.new_password);
  await database.update(
    "users",
    { id: `eq.${body.user_id}` },
    { password_hash: newHash, updated_at: new Date().toISOString() },
  );

  // Revoke all sessions for the target user
  await database.update(
    "sessions",
    { user_id: `eq.${body.user_id}`, revoked: "eq.false" },
    { revoked: true },
  );

  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  audit(ctx, env, "password_reset_completed", {
    user_id: body.user_id,
    org_id: auth.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { admin_reset: true, reset_by: auth.sub },
  });

  return json({ success: true, message: "Password reset. User must log in again." });
}
