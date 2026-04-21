import type { Env, User } from "../types";
import { db } from "../lib/db";
import { hashPassword, hashToken } from "../lib/hash";
import { validateEmail, validatePassword, validateRedirectUrl, resolveAppUrl } from "../lib/validate";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { sendEmail, passwordResetEmail } from "../lib/email";
import { checkEmailThrottle } from "../lib/email-throttle";

const RESET_TTL_MS = 1 * 60 * 60 * 1000; // 1 hour

/**
 * POST /auth/forgot-password
 * Sends a password reset email if the account exists.
 * Always returns the same message to prevent email enumeration.
 */
export async function forgotPassword(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: { email?: string; redirect_url?: string };
  try {
    body = await req.json() as { email?: string; redirect_url?: string };
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.email) return error("email is required");

  const emailErr = validateEmail(body.email);
  if (emailErr) return emailErr;

  const redirectErr = validateRedirectUrl(body.redirect_url, env);
  if (redirectErr) return redirectErr;

  const email = body.email.toLowerCase().trim();
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  const database = db(env);

  // Throttle BEFORE user lookup to prevent enumeration via throttle behavior
  const throttled = await checkEmailThrottle(env, "password_reset", email);
  if (throttled) return throttled;

  const user = await database.queryOne<User>(
    `users?email=eq.${encodeURIComponent(email)}&select=id,is_blocked`,
  );

  // Always return success to prevent email enumeration
  if (!user || user.is_blocked) {
    return json({ message: "If an account exists, a reset email has been sent." });
  }

  const token = crypto.randomUUID();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + RESET_TTL_MS).toISOString();

  // Invalidate any existing unused reset tokens for this user
  await database.update(
    "password_resets",
    { user_id: `eq.${user.id}`, used: "eq.false" },
    { used: true },
  ).catch((err) => {
    console.error("[SSO] Failed to invalidate existing reset tokens:", err);
  });

  await database.mutate("password_resets", {
    user_id: user.id,
    token_hash: tokenHash,
    expires_at: expiresAt,
  });

  // Send password reset email
  const appUrl = resolveAppUrl(body.redirect_url, env);
  const resetUrl = `${appUrl}/reset-password?token=${token}`;
  const { subject, html, text } = passwordResetEmail(resetUrl);
  ctx.waitUntil(sendEmail(env, { to: email, subject, html, text }));

  audit(ctx, env, "password_reset_requested", {
    user_id: user.id,
    ip_address: ip,
    user_agent: ua,
  });

  return json({ message: "If an account exists, a reset email has been sent." });
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

  const tokenHash = await hashToken(body.token);
  const record = await database.queryOne<{
    id: string;
    user_id: string;
    used: boolean;
    expires_at: string;
  }>(
    `password_resets?token_hash=eq.${encodeURIComponent(tokenHash)}&select=*`,
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
