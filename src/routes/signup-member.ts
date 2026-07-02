import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";
import { db } from "../lib/db";
import { sendEmail } from "../lib/email";
import { generateRefreshToken, hashPassword, hashToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { endpointRateLimit } from "../lib/rate-limit";

import { generateVerificationEmailTemplate } from "../lib/email-templates";
import { publishSyncEvent } from "../lib/sync-queue";
import { resolveAppUrl, validateEmail, validatePassword, validateRedirectUrl } from "../lib/validate";
import type { Env, JwtClaims, SignupMemberBody } from "../types";

const EMAIL_SEND_TIMEOUT_MS = 5_000;

/**
 * Pure business logic for signupMember (extracted for RPC)
 */
export async function performSignupMember(
  env: Env,
  ctx: ExecutionContext,
  params: SignupMemberBody & { ip?: string; ua?: string }
): Promise<any> {
  // Implementation will reuse the logic from signupMember but return data instead of Response
  // This is a simplified version - the HTTP handler below has the full implementation
  return await signupMemberImpl(env, ctx, params);
}

async function signupMemberImpl(
  env: Env,
  ctx: ExecutionContext,
  params: SignupMemberBody & { ip?: string; ua?: string }
): Promise<any> {
  if (!params.email || !params.password || !params.role) {
    return { error: "email, password, and role are required", status: 400 };
  }

  const emailErr = validateEmail(params.email);
  if (emailErr) return { error: "Invalid email format", status: 400 };

  const passErr = validatePassword(params.password);
  if (passErr) return { error: "Invalid password format", status: 400 };

  if (params.redirect_url) {
    const redirectErr = validateRedirectUrl(params.redirect_url, env);
    if (redirectErr) return { error: "Invalid redirect URL", status: 400 };
  }

  const email = params.email.toLowerCase().trim();
  const ip = params.ip ?? "unknown";
  const ua = params.ua ?? null;

  const rateLimited = await endpointRateLimit(env, `signup:ip:${ip}`, 5, 60);
  if (rateLimited) return { error: "Rate limit exceeded", status: 429 };

  const database = db(env);

  // Idempotency check
  try {
    const existingUsers = await database.query<{ id: string; is_email_verified: boolean }>(
      `users?email=eq.${encodeURIComponent(email)}&select=id,is_email_verified`,
    );

    if (existingUsers && existingUsers.length > 0) {
      const existingUser = existingUsers[0];
      if (existingUser.is_email_verified) {
        return { error: "An account with this email already exists. Please log in.", status: 409 };
      }
      return { error: "An account with this email exists but is not verified. Please check your inbox or log in to request a new verification link.", status: 409 };
    }
  } catch (checkErr) {
    console.error("[SSO] Error checking existing user:", checkErr);
  }

  const password_hash = await hashPassword(params.password);

  // Step 1: Create user in database
  let result: { user_id: string; org_id: string | null; membership_id: string | null };
  try {
    result = await database.rpc<{
      user_id: string;
      org_id: string | null;
      membership_id: string | null;
    }>("signup_member", {
      p_email: email,
      p_password_hash: password_hash,
      p_role: params.role,
      p_org_id: params.org_id ?? null,
      p_user_metadata: params.user_metadata ?? {},
    });
  } catch (err: any) {
    if (err?.message?.includes("duplicate") || err?.message?.includes("23505")) {
      return { error: "An account with this email already exists. Please log in.", status: 409 };
    }
    if (err?.message?.includes("Invalid role")) {
      return { error: "Invalid role specified", status: 400 };
    }
    if (err?.message?.includes("Organization not found")) {
      return { error: "Organization not found", status: 404 };
    }
    return { error: err.message || "Signup failed", status: 500 };
  }

  // Step 2: Create session + sign JWT (rollback user on failure)
  try {
    // Get RBAC claims (only if user has an org membership)
    let claims: JwtClaims | null = null;
    if (result.org_id) {
      claims = await database.rpc<JwtClaims>("get_jwt_claims", {
        p_user_id: result.user_id,
        p_org_id: result.org_id,
      });
    }

    const refreshToken = generateRefreshToken();
    const refreshHash = await hashToken(refreshToken);
    const sessionId = crypto.randomUUID();

    await database.mutate("sessions", {
      id: sessionId,
      user_id: result.user_id,
      org_id: result.org_id,
      refresh_token_hash: refreshHash,
      user_agent: ua,
      ip_address: ip,
      revoked: false,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      family_id: sessionId,
      family_created_at: new Date().toISOString(),
    });

    const accessToken = await signAccessToken(
      {
        sub: result.user_id,
        email,
        org_id: result.org_id ?? "",
        roles: claims?.roles ?? [],
        products: claims?.products ?? [],
        membership_status: claims?.membership_status ?? "active",
        is_email_verified: false,
        user_metadata: params.user_metadata ?? {},
      },
      env,
    );

    // Step 3: Send verification email
    let emailSent = true;
    try {
      const verifyToken = crypto.randomUUID();
      const verifyTokenHash = await hashToken(verifyToken);
      await database.mutate("email_verifications", {
        user_id: result.user_id,
        token_hash: verifyTokenHash,
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      });
      const appUrl = resolveAppUrl(params.redirect_url, env);
      const verifyUrl = `${appUrl}/verify-email?token=${verifyToken}`;

      const template = generateVerificationEmailTemplate(verifyUrl);
      ctx.waitUntil(sendEmail(env, { to: email, subject: template.subject, html: template.html, text: template.text }, ctx));
    } catch (emailErr) {
      emailSent = false;
    }

    // Step 4: Build response
    const responseBody: Record<string, unknown> = {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: { id: result.user_id, email },
      email_sent: emailSent,
    };

    if (result.org_id) {
      responseBody.org = { id: result.org_id };
    }

    // Emit sync events
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'user.created', {
      id: result.user_id,
      email,
      user_metadata: params.user_metadata ?? {},
    });
    if (result.org_id) {
      publishSyncEvent(env.SYNC_QUEUE, ctx, 'membership.created', {
        user_id: result.user_id,
        organization_id: result.org_id,
        roles: [params.role],
        status: 'active',
      });
    }

    audit(ctx, env, "signup_member", {
      user_id: result.user_id,
      org_id: result.org_id,
      ip_address: ip,
      user_agent: ua,
      metadata: { role: params.role, email_sent: emailSent },
    });

    return responseBody;
  } catch (err) {
    // Rollback: delete the user if session/JWT creation failed
    console.error(
      JSON.stringify({
        msg: "[SSO] Signup post-creation failed, rolling back",
        user_id: result.user_id,
        org_id: result.org_id,
        error: err instanceof Error ? { message: err.message, stack: err.stack } : String(err),
      }),
    );
    try {
      await database.query(`users?id=eq.${encodeURIComponent(result.user_id)}`, { method: "DELETE" });
    } catch (rollbackErr) {
      console.error(
        JSON.stringify({
          msg: "[SSO] Rollback failed — orphan records may exist",
          user_id: result.user_id,
          org_id: result.org_id,
          error: rollbackErr instanceof Error ? { message: rollbackErr.message, stack: rollbackErr.stack } : String(rollbackErr),
        }),
      );
    }
    return { error: "Signup failed. Please try again.", status: 500 };
  }
}


