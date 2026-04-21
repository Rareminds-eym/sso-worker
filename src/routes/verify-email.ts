import type { Env, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { hashToken } from "../lib/hash";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { sendEmail, verificationEmail } from "../lib/email";
import { validateRedirectUrl, resolveAppUrl } from "../lib/validate";
import { checkEmailThrottle } from "../lib/email-throttle";

/**
 * POST /auth/request-verification — sends a verification email.
 * Requires authentication. The server sends the email directly.
 * Returns a confirmation message, or { already_verified: true } if already verified.
 */
export async function requestVerification(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const payload = auth!;
  const database = db(env);

  let body: { redirect_url?: string };
  try {
    body = await req.json() as { redirect_url?: string };
  } catch {
    body = {};
  }

  const redirectErr = validateRedirectUrl(body.redirect_url, env);
  if (redirectErr) return redirectErr;

  const user = await database.queryOne<{ id: string; email: string; is_email_verified: boolean }>(
    `users?id=eq.${payload.sub}&select=id,email,is_email_verified`,
  );

  if (!user) return error("User not found", 404);
  if (user.is_email_verified) return json({ already_verified: true });

  const throttled = await checkEmailThrottle(env, "verification", payload.sub);
  if (throttled) return throttled;

  const token = crypto.randomUUID();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24h

  await database.mutate("email_verifications", {
    user_id: payload.sub,
    token_hash: tokenHash,
    expires_at: expiresAt,
  });

  // Send verification email
  const appUrl = resolveAppUrl(body.redirect_url, env);
  const verifyUrl = `${appUrl}/verify-email?token=${token}`;
  const { subject, html, text } = verificationEmail(verifyUrl);
  ctx.waitUntil(sendEmail(env, { to: user.email, subject, html, text }));

  audit(ctx, env, "verification_requested", {
    user_id: payload.sub,
    org_id: payload.org_id,
  });

  return json({ message: "Verification email sent." });
}

/**
 * POST /auth/verify-email — verifies the email using the token.
 * No authentication required (user clicks link from email).
 */
export async function verifyEmail(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: { token?: string };
  try {
    body = await req.json() as { token?: string };
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.token) return error("token is required");

  const database = db(env);

  const tokenHash = await hashToken(body.token);
  const record = await database.queryOne<{
    id: string;
    user_id: string;
    used: boolean;
    expires_at: string;
  }>(
    `email_verifications?token_hash=eq.${encodeURIComponent(tokenHash)}&select=*`,
  );

  if (!record) return error("Invalid verification token", 404);
  if (record.used) return error("Token already used", 410);
  if (new Date(record.expires_at) < new Date()) return error("Token expired", 410);

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

  audit(ctx, env, "email_verified", {
    user_id: record.user_id,
    ip_address: req.headers.get("CF-Connecting-IP"),
    user_agent: req.headers.get("User-Agent"),
  });

  return json({ verified: true });
}
