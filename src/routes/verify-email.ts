import { audit } from "../lib/audit";
import { db } from "../lib/db";
import { generateVerificationEmailTemplate } from "../lib/email-templates";
import { checkEmailThrottle } from "../lib/email-throttle";
import { hashToken } from "../lib/hash";

import { publishSyncEvent } from "../lib/sync-queue";
import { resolveAppUrl, validateRedirectUrl } from "../lib/validate";
import type { AccessTokenPayload, Env } from "../types";

/**
 * Pure business logic for requesting verification email (extracted for RPC)
 */
export async function performRequestVerification(
  env: Env,
  ctx: ExecutionContext,
  params: {
    user_id: string;
    email: string;
    redirect_url?: string;
    org_id?: string;
  }
): Promise<{ message?: string; already_verified?: boolean; error?: string; status?: number }> {
  const database = db(env);

  // Validate redirect URL if provided
  if (params.redirect_url) {
    const redirectErr = validateRedirectUrl(params.redirect_url, env);
    if (redirectErr) {
      return { error: "Invalid redirect URL", status: 400 };
    }
  }

  const user = await database.queryOne<{ id: string; email: string; is_email_verified: boolean }>(
    `users?id=eq.${params.user_id}&select=id,email,is_email_verified`,
  );

  if (!user) return { error: "User not found", status: 404 };
  if (user.is_email_verified) return { already_verified: true };

  const throttled = await checkEmailThrottle(env, "verification", params.user_id);
  if (throttled) {
    return { error: "Too many requests. Please try again later.", status: 429 };
  }

  const token = crypto.randomUUID();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24h

  await database.mutate("email_verifications", {
    user_id: params.user_id,
    token_hash: tokenHash,
    expires_at: expiresAt,
  });

  // Send verification email
  const appUrl = resolveAppUrl(params.redirect_url, env);
  const verifyUrl = `${appUrl}/verify-email?token=${token}`;

  // Generate email template locally
  const template = generateVerificationEmailTemplate(verifyUrl);

  const emailTimeoutMs = 5_000;
  const emailPromise = env.EMAIL_SERVICE.sendEmail({
    to: user.email,
    subject: template.subject,
    html: template.html,
    text: template.text,
  });

  ctx.waitUntil(emailPromise.then(() => {
    console.log(JSON.stringify({ msg: "[SSO] Verification email delivered", email: user.email }));
  }).catch((err: Error) => {
    console.error(JSON.stringify({ msg: "[SSO] Verification email failed", error: err.message }));
  }));

  await Promise.race([
    emailPromise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("Email send timed out")), emailTimeoutMs)
    ),
  ]).catch(() => {}); // timeout is non-fatal — response already promises delivery

  audit(ctx, env, "verification_requested", {
    user_id: params.user_id,
    org_id: params.org_id || null,
  });

  return { message: "Verification email sent." };
}

/**
 * Pure business logic for verifying email (extracted for RPC)
 */
export async function performVerifyEmail(
  env: Env,
  ctx: ExecutionContext,
  params: {
    token: string;
  },
  ip?: string | null,
  ua?: string | null
): Promise<{ verified?: boolean; error?: string; status?: number }> {
  if (!params.token) return { error: "token is required", status: 400 };

  const database = db(env);

  const tokenHash = await hashToken(params.token);
  const record = await database.queryOne<{
    id: string;
    user_id: string;
    used: boolean;
    expires_at: string;
  }>(
    `email_verifications?token_hash=eq.${encodeURIComponent(tokenHash)}&select=*`,
  );

  if (!record) return { error: "Invalid verification token", status: 404 };
  if (record.used) return { error: "Token already used", status: 410 };
  if (new Date(record.expires_at) < new Date()) return { error: "Token expired", status: 410 };

  // Mark token as used and verify the user's email
  await database.update(
    "email_verifications",
    { id: `eq.${record.id}` },
    { used: true },
  );

  await database.update(
    "users",
    { id: `eq.${record.user_id}` },
    { is_email_verified: true },
  );

  publishSyncEvent(env.SYNC_QUEUE, ctx, 'user.email_verified', {
    user_id: record.user_id,
  });

  audit(ctx, env, "email_verified", {
    user_id: record.user_id,
    ip_address: ip || null,
    user_agent: ua || null,
  });

  return { verified: true };
}


