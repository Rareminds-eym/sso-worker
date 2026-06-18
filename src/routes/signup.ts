import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";
import { setAuthCookies } from "../lib/cookies";
import { db } from "../lib/db";
import { sendVerificationEmail } from "../lib/email";
import { generateRefreshToken, hashPassword, hashToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { endpointRateLimit } from "../lib/rate-limit";
import { error, json } from "../lib/response";
import { publishSyncEvent } from "../lib/sync-queue";
import { resolveAppUrl, validateEmail, validatePassword, validateRedirectUrl } from "../lib/validate";
import type { Env, JwtClaims, SignupBody } from "../types";

/**
 * POST /auth/signup
 *
 * Creates a user + organization + membership with owner role.
 * Used by institution admins creating their school/college/university.
 *
 * Atomicity guarantee:
 * - If anything other than email delivery fails after user/org creation,
 *   the user and org are rolled back (deleted) from the database.
 * - Email delivery failure is non-blocking; the response includes
 *   `email_sent: false` so the frontend can offer a resend option.
 */
export async function signup(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: SignupBody;
  try {
    body = await req.json() as SignupBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.email || !body.password || !body.org_name || !body.role) {
    return error("email, password, org_name, and role are required");
  }

  const emailErr = validateEmail(body.email);
  if (emailErr) return emailErr;

  const passErr = validatePassword(body.password);
  if (passErr) return passErr;

  const redirectErr = validateRedirectUrl(body.redirect_url, env);
  if (redirectErr) return redirectErr;

  const email = body.email.toLowerCase().trim();
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const ua = req.headers.get("User-Agent");

  const rateLimited = await endpointRateLimit(env, `signup:ip:${ip}`, 5, 60);
  if (rateLimited) return rateLimited;

  const database = db(env);

  // ─── Idempotency Check: Allow re-signup for unverified users ───
  try {
    const existingUsers = await database.query<{ id: string; is_email_verified: boolean }>(
      `users?email=eq.${encodeURIComponent(email)}&select=id,is_email_verified`,
    );

    if (existingUsers && existingUsers.length > 0) {
      const existingUser = existingUsers[0];

      // User exists and email is verified → reject
      if (existingUser.is_email_verified) {
        return error("An account with this email already exists. Please log in.", 409);
      }

      // User exists but email NOT verified
      // Prevent Account Takeover and Race Conditions by rejecting re-signup.
      // Unverified users can still log in to trigger a new verification email.
      return error("An account with this email exists but is not verified. Please check your inbox or log in to request a new verification link.", 409);
    }
  } catch (checkErr) {
    console.error("[SSO] Error checking existing user:", checkErr);
    // Continue with signup attempt - let database constraints handle duplicates
  }

  const password_hash = await hashPassword(body.password);

  const slug = body.org_name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

  // ─── Step 1: Create user + org in database ───────────────────
  let result: { user_id: string; org_id: string; slug: string };
  try {
    result = await database.rpc<{ user_id: string; org_id: string; slug: string }>(
      "signup_user",
      {
        p_email: email,
        p_password_hash: password_hash,
        p_org_name: body.org_name,
        p_org_slug: slug,
        p_role: body.role,
        p_user_metadata: body.user_metadata ?? {},
      },
    );
  } catch (err: any) {
    if (err?.message?.includes("duplicate") || err?.message?.includes("23505")) {
      return error("An account with this email already exists. Please log in.", 409);
    }
    throw err;
  }

  // ─── Step 2: Create session + sign JWT (rollback on failure) ──
  try {
    const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
      p_user_id: result.user_id,
      p_org_id: result.org_id,
    });

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
        org_id: result.org_id,
        roles: claims?.roles ?? [],
        products: claims?.products ?? [],
        membership_status: claims?.membership_status ?? "active",
        is_email_verified: false,
        user_metadata: body.user_metadata ?? {},
      },
      env,
    );

    // ─── Step 3: Send verification email (non-blocking, no rollback) ──
    let emailSent = true;
    try {
      const verifyToken = crypto.randomUUID();
      const verifyTokenHash = await hashToken(verifyToken);
      await database.mutate("email_verifications", {
        user_id: result.user_id,
        token_hash: verifyTokenHash,
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      });
      const appUrl = resolveAppUrl(body.redirect_url, env);
      const verifyUrl = `${appUrl}/verify-email?token=${verifyToken}`;
      ctx.waitUntil(
        sendVerificationEmail(env, email, verifyUrl)
          .catch(err => console.error("[SSO] Verification email background task failed:", err))
      );
    } catch (emailErr) {
      emailSent = false;
      console.error("[SSO] Verification email setup failed:", emailErr);
    }

    // ─── Step 4: Build response ──────────────────────────────────
    const response = json(
      {
        access_token: accessToken,
        user: { id: result.user_id, email },
        org: { id: result.org_id, name: body.org_name, slug: result.slug },
        email_sent: emailSent,
      },
      201,
    );

    setAuthCookies(response, accessToken, refreshToken, env);

    // Response fully built — emit sync events (safe, no rollback after this point)
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'user.created', {
      id: result.user_id,
      email,
      user_metadata: body.user_metadata ?? {},
    });
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'organization.created', {
      id: result.org_id,
      name: body.org_name,
      slug: result.slug,
      created_by: result.user_id,
    });
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'membership.created', {
      user_id: result.user_id,
      organization_id: result.org_id,
      roles: claims?.roles ?? [],
      status: 'active',
    });

    audit(ctx, env, "signup", {
      user_id: result.user_id,
      org_id: result.org_id,
      ip_address: ip,
      user_agent: ua,
      metadata: { email_sent: emailSent },
    });

    return response;
  } catch (err) {
    // ─── Rollback: delete user (cascades to membership, org if created_by) ──
    console.error(
      JSON.stringify({
        msg: "[SSO] Signup post-creation failed, rolling back",
        user_id: result.user_id,
        org_id: result.org_id,
        slug: result.slug,
        error: err instanceof Error ? { message: err.message, stack: err.stack } : String(err),
      }),
    );
    try {
      await database.query(`users?id=eq.${result.user_id}`, { method: "DELETE" });
    } catch (rollbackErr) {
      console.error(
        JSON.stringify({
          msg: "[SSO] Rollback failed — orphan records may exist",
          user_id: result.user_id,
          org_id: result.org_id,
          slug: result.slug,
          error: rollbackErr instanceof Error ? { message: rollbackErr.message, stack: rollbackErr.stack } : String(rollbackErr),
        }),
      );
    }
    return error("Signup failed. Please try again.", 500);
  }
}
