import type { Env, User } from "../types";
import { db } from "../lib/db";
import { hashPassword } from "../lib/hash";
import { validateEmail, validatePassword } from "../lib/validate";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";

const RESET_TTL_MS = 1 * 60 * 60 * 1000; // 1 hour

/**
 * POST /auth/forgot-password
 * Generates a password reset token. Returns it for the caller to deliver via email.
 * Always returns 200 even if the email doesn't exist (prevents email enumeration).
 */
export async function forgotPassword(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: { email?: string };
  try {
    body = await req.json() as { email?: string };
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.email) return error("email is required");

  const emailErr = validateEmail(body.email);
  if (emailErr) return emailErr;

  const email = body.email.toLowerCase().trim();
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  const database = db(env);

  const user = await database.queryOne<User>(
    `users?email=eq.${encodeURIComponent(email)}&select=id,is_blocked`,
  );

  // Always return success to prevent email enumeration
  if (!user || user.is_blocked) {
    return json({ message: "If an account exists, a reset token has been generated." });
  }

  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + RESET_TTL_MS).toISOString();

  // Invalidate any existing unused reset tokens for this user
  await database.update(
    "password_resets",
    { user_id: `eq.${user.id}`, used: "eq.false" },
    { used: true },
  ).catch(() => { /* no existing tokens — that's fine */ });

  await database.mutate("password_resets", {
    user_id: user.id,
    token,
    expires_at: expiresAt,
  });

  audit(ctx, env, "password_reset_requested", {
    user_id: user.id,
    ip_address: ip,
    user_agent: ua,
  });

  return json({ reset_token: token, expires_at: expiresAt });
}

/**
 * POST /auth/reset-password
 * Resets the password using a valid reset token.
 * Revokes all existing sessions for the user (force re-login everywhere).
 */
export async function resetPassword(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: { token?: string; password?: string };
  try {
    body = await req.json() as { token?: string; password?: string };
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.token) return error("token is required");
  if (!body.password) return error("password is required");

  const passErr = validatePassword(body.password);
  if (passErr) return passErr;

  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  const database = db(env);

  const record = await database.queryOne<{
    id: string;
    user_id: string;
    used: boolean;
    expires_at: string;
  }>(
    `password_resets?token=eq.${encodeURIComponent(body.token)}&select=*`,
  );

  if (!record) return error("Invalid reset token", 404);
  if (record.used) return error("Token already used", 410);
  if (new Date(record.expires_at) < new Date()) return error("Token expired", 410);

  const password_hash = await hashPassword(body.password);

  // Mark token as used
  await database.update(
    "password_resets",
    { id: `eq.${record.id}` },
    { used: true },
  );

  // Update password
  await database.update(
    "users",
    { id: `eq.${record.user_id}` },
    { password_hash },
  );

  // Revoke all sessions (force re-login everywhere)
  await database.update(
    "sessions",
    { user_id: `eq.${record.user_id}` },
    { revoked: true },
  );

  audit(ctx, env, "password_reset_completed", {
    user_id: record.user_id,
    ip_address: ip,
    user_agent: ua,
  });

  return json({ reset: true });
}
