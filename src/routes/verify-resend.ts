import { audit } from "../lib/audit";
import { db } from "../lib/db";
import { generateVerificationEmailTemplate } from "../lib/email-templates";
import { checkEmailThrottle } from "../lib/email-throttle";
import { hashToken } from "../lib/hash";
import { error, json } from "../lib/response";
import { resolveAppUrl, validateEmail } from "../lib/validate";
import type { Env } from "../types";

/**
 * POST /auth/resend-verification
 *
 * Unauthenticated endpoint keyed by email hash in KV.
 * Only works if a recent signup failed to deliver the verification email
 * (KV entry set by signup handler when email_sent === false).
 *
 * Security: always returns 200 regardless of whether KV entry exists,
 * to prevent email enumeration.
 */
export async function resendVerification(
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

  const email = body.email.toLowerCase().trim();
  const emailErr = validateEmail(email);
  if (emailErr) return emailErr;

  const emailHash = await hashToken(email);
  const stored = await env.RATE_LIMIT_KV.get(`resend:${emailHash}`);

  if (!stored) {
    // Silently succeed — don't reveal whether the email exists
    return json({ message: "If the account exists, a verification email will be sent." });
  }

  let userId: string;
  try {
    userId = (JSON.parse(stored) as { user_id: string }).user_id;
  } catch {
    return json({ message: "If the account exists, a verification email will be sent." });
  }

  const throttled = await checkEmailThrottle(env, "verification", userId);
  if (throttled) return throttled;

  const database = db(env);
  const user = await database.queryOne<{ id: string; email: string; is_email_verified: boolean }>(
    `users?id=eq.${encodeURIComponent(userId)}&select=id,email,is_email_verified`,
  );

  if (!user || user.is_email_verified) {
    return json({ message: "If the account exists, a verification email will be sent." });
  }

  const token = crypto.randomUUID();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  await database.mutate("email_verifications", {
    user_id: user.id,
    token_hash: tokenHash,
    expires_at: expiresAt,
  });

  const appUrl = resolveAppUrl(undefined, env);
  const verifyUrl = `${appUrl}/verify-email?token=${token}`;

  // Generate email template locally
  const template = generateVerificationEmailTemplate(verifyUrl);

  ctx.waitUntil(
    env.EMAIL_SERVICE.sendEmail({
      to: user.email,
      subject: template.subject,
      html: template.html,
      text: template.text
    })
      .catch((err: Error) => console.error("[SSO] Verification email background task failed:", err))
  );

  audit(ctx, env, "verification_resend", {
    user_id: user.id,
    ip_address: req.headers.get("CF-Connecting-IP"),
    user_agent: req.headers.get("User-Agent"),
  });

  return json({ message: "If the account exists, a verification email will be sent." });
}
