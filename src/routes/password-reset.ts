import { audit } from "../lib/audit";
import { db } from "../lib/db";
import { sendEmail } from "../lib/email";
import { generatePasswordResetEmailTemplate } from "../lib/email-templates";
import { checkEmailThrottle } from "../lib/email-throttle";
import { hashPassword, hashToken } from "../lib/hash";
import { endpointRateLimit } from "../lib/rate-limit";

import { resolveAppUrl, validateEmail, validatePassword, validateRedirectUrl } from "../lib/validate";
import type { Env, User } from "../types";

const RESET_TTL_MS = 1 * 60 * 60 * 1000; // 1 hour

/**
 * POST /auth/forgot-password
 * Sends a password reset email if the account exists.
 * Always returns the same message to prevent email enumeration.
 */
export async function performForgotPassword(
  env: Env,
  ctx: ExecutionContext,
  body: { email?: string; redirect_url?: string },
  ip: string,
  ua: string | null,
): Promise<{ message?: string; error?: string; status?: number }> {
  if (!body.email) return { error: "email is required", status: 400 };

  const emailErrResponse = validateEmail(body.email);
  if (emailErrResponse) return { error: await emailErrResponse.text(), status: emailErrResponse.status };

  const redirectErrResponse = validateRedirectUrl(body.redirect_url, env);
  if (redirectErrResponse) return { error: await redirectErrResponse.text(), status: redirectErrResponse.status };

  const email = body.email.toLowerCase().trim();

  const rateLimited = await endpointRateLimit(env, `forgot-password:ip:${ip}`, 3, 300);
  if (rateLimited) return { error: "Rate limit exceeded", status: 429 };

  const database = db(env);

  // Throttle BEFORE user lookup to prevent enumeration via throttle behavior
  const throttled = await checkEmailThrottle(env, "password_reset", email);
  if (throttled) return { error: "Too many requests", status: 429 };

  const user = await database.queryOne<User>(
    `users?email=eq.${encodeURIComponent(email)}&select=id,is_blocked`,
  );

  // Always return success to prevent email enumeration
  if (!user || user.is_blocked) {
    return { message: "If an account exists, a reset email has been sent." };
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

  // Send password reset email via EMAIL_SERVICE RPC
  const appUrl = resolveAppUrl(body.redirect_url, env);
  const resetUrl = `${appUrl}/reset-password?token=${token}`;

  // Generate email template locally
  const template = generatePasswordResetEmailTemplate(resetUrl);

  ctx.waitUntil(sendEmail(env, { to: email, subject: template.subject, html: template.html, text: template.text }, ctx));

  audit(ctx, env, "password_reset_requested", {
    user_id: user.id,
    ip_address: ip,
    user_agent: ua,
  });

  return { message: "If an account exists, a reset email has been sent." };
}



export async function performResetPassword(
  env: Env,
  ctx: ExecutionContext,
  body: { token?: string; password?: string },
  ip: string | null,
  ua: string | null,
): Promise<{ reset?: boolean; error?: string; status?: number }> {
  if (!body.token) {
    return { error: "token is required", status: 400 };
  }

  if (!body.password) {
    return { error: "password is required", status: 400 };
  }

  const passErrResponse = validatePassword(body.password);
  if (passErrResponse) {
    return { error: await passErrResponse.text(), status: passErrResponse.status };
  }

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

  if (!record) return { error: "Invalid reset token", status: 404 };
  if (record.used) return { error: "Token already used", status: 410 };
  if (new Date(record.expires_at) < new Date()) return { error: "Token expired", status: 410 };

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

  return { reset: true };
}


