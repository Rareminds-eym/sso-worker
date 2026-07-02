import type { Env } from "../types";
import { db } from "../lib/db";
import { hashPassword, verifyPassword } from "../lib/hash";
import { validatePassword } from "../lib/validate";
import { audit } from "../lib/audit";
import { endpointRateLimit } from "../lib/rate-limit";

/**
 * Pure business logic for changing password (extracted for RPC)
 */
export async function performChangePassword(
  env: Env,
  ctx: ExecutionContext,
  params: {
    user_id: string;
    current_password: string;
    new_password: string;
    org_id?: string;
  },
  ip?: string | null,
  ua?: string | null
): Promise<{ success?: boolean; message?: string; error?: string; status?: number }> {
  const rl = await endpointRateLimit(env, `change-password:user:${params.user_id}`, 3, 300);
  if (rl) {
    return { error: "Rate limit exceeded", status: 429 };
  }

  if (!params.current_password || !params.new_password) {
    return { error: "current_password and new_password are required", status: 400 };
  }

  const passErr = validatePassword(params.new_password);
  if (passErr) {
    return { error: "Invalid password", status: 400 };
  }

  const database = db(env);

  // Get current user's password hash
  const users = await database.query<{ password_hash: string }>(
    `users?id=eq.${params.user_id}&select=password_hash`,
  );

  if (!users.length) {
    return { error: "User not found", status: 404 };
  }

  // Verify current password
  const isValid = await verifyPassword(params.current_password, users[0].password_hash);
  if (!isValid) {
    return { error: "Current password is incorrect", status: 401 };
  }

  // Hash and update new password
  const newHash = await hashPassword(params.new_password);
  await database.update(
    "users",
    { id: `eq.${params.user_id}` },
    { password_hash: newHash, updated_at: new Date().toISOString() },
  );

  // Revoke all other sessions (force re-login everywhere)
  await database.update(
    "sessions",
    { user_id: `eq.${params.user_id}`, revoked: "eq.false" },
    { revoked: true },
  );

  audit(ctx, env, "password_reset_completed", {
    user_id: params.user_id,
    org_id: params.org_id || null,
    ip_address: ip || null,
    user_agent: ua || null,
    metadata: { self_change: true },
  });

  return { success: true, message: "Password changed. Please log in again." };
}

/**
 * Pure business logic for admin password reset (extracted for RPC)
 */
export async function performAdminResetPassword(
  env: Env,
  ctx: ExecutionContext,
  params: {
    admin_user_id: string;
    admin_roles: string[];
    admin_org_id?: string;
    target_user_id: string;
    new_password: string;
  },
  ip?: string | null,
  ua?: string | null
): Promise<{ success?: boolean; message?: string; error?: string; status?: number }> {
  const rl = await endpointRateLimit(env, `admin-reset-password:user:${params.admin_user_id}`, 3, 300);
  if (rl) {
    return { error: "Rate limit exceeded", status: 429 };
  }

  // Check admin/owner role
  const isAdmin = params.admin_roles.some(
    (r) => r === "owner" || r === "admin" || r === "school_admin" || r === "college_admin" || r === "university_admin",
  );
  if (!isAdmin) {
    return { error: "Forbidden: admin role required", status: 403 };
  }

  if (!params.target_user_id || !params.new_password) {
    return { error: "user_id and new_password are required", status: 400 };
  }

  const passErr = validatePassword(params.new_password);
  if (passErr) {
    return { error: "Invalid password", status: 400 };
  }

  const database = db(env);

  // Verify target user exists
  const users = await database.query<{ id: string }>(
    `users?id=eq.${params.target_user_id}&select=id`,
  );
  if (!users.length) {
    return { error: "Target user not found", status: 404 };
  }

  // Hash and update password
  const newHash = await hashPassword(params.new_password);
  await database.update(
    "users",
    { id: `eq.${params.target_user_id}` },
    { password_hash: newHash, updated_at: new Date().toISOString() },
  );

  // Revoke all sessions for the target user
  await database.update(
    "sessions",
    { user_id: `eq.${params.target_user_id}`, revoked: "eq.false" },
    { revoked: true },
  );

  audit(ctx, env, "password_reset_completed", {
    user_id: params.target_user_id,
    org_id: params.admin_org_id || null,
    ip_address: ip || null,
    user_agent: ua || null,
    metadata: { admin_reset: true, reset_by: params.admin_user_id },
  });

  return { success: true, message: "Password reset. User must log in again." };
}


