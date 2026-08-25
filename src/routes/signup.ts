import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";
import { db } from "../lib/db";
import { sendEmail } from "../lib/email";
import { generateVerificationEmailTemplate } from "../lib/email-templates";
import { checkEmailThrottle } from "../lib/email-throttle";
import { generateRefreshToken, hashPassword, hashToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { endpointRateLimit } from "../lib/rate-limit";
import { publishSyncEvent } from "../lib/sync-queue";
import { resolveAppUrl, validateEmail, validatePassword, validateRedirectUrl } from "../lib/validate";
import { resolveEffectiveRoles } from "../lib/roles";
import type { Env, JwtClaims, SignupBody } from "../types";

/**
 * performSignup - Core business logic (pure RPC, no HTTP)
 * Called by: SsoWorker.signup() RPC method, signup() HTTP handler
 */
export async function performSignup(
  env: Env,
  ctx: ExecutionContext,
  body: SignupBody,
  ip?: string,
  ua?: string | null,
): Promise<any> {

  console.log('[SSO] signup: Received request with body:', {
    email: body.email,
    hasPassword: !!body.password,
    org_name: body.org_name,
    role: body.role,
    redirect_url: body.redirect_url,
    hasUserMetadata: !!body.user_metadata
  });

  if (!body.email || !body.password) {
    console.error('[SSO] signup: Missing required fields', {
      hasEmail: !!body.email,
      hasPassword: !!body.password
    });
    return { error: "email and password are required", status: 400 };
  }

  // org_name is optional for recruiter onboarding flow
  // If not provided, it will be set during onboarding Step 1

  // role is optional, defaults to 'owner'
  const role = body.role || 'owner';
  console.log('[SSO] signup: Using role:', role);

  const emailErr = validateEmail(body.email);
  if (emailErr) {
    console.error('[SSO] signup: Email validation failed:', body.email);
    return { error: emailErr, status: 400 };
  }

  const passErr = validatePassword(body.password);
  if (passErr) {
    console.error('[SSO] signup: Password validation failed');
    return { error: passErr, status: 400 };
  }

  const redirectErr = validateRedirectUrl(body.redirect_url, env);
  if (redirectErr) {
    console.error('[SSO] signup: Redirect URL validation failed:', body.redirect_url);
    return { error: redirectErr, status: 400 };
  }

  const email = body.email.toLowerCase().trim();
  const resolvedIp = ip ?? "unknown";
  const resolvedUa = ua ?? null;

  console.log('[SSO] signup: All validations passed', { email, ip: resolvedIp, org_name: body.org_name });

  const rateLimited = await endpointRateLimit(env, `signup:ip:${resolvedIp}`, 5, 60);
  if (rateLimited) return rateLimited;

  const database = db(env);

  // ─── Idempotency Check: Allow re-signup for unverified users ───
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

  const password_hash = await hashPassword(body.password);

  // Generate slug from org_name if provided, otherwise use a temporary slug
  const slug = body.org_name
    ? body.org_name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
    : `org-${crypto.randomUUID().split('-')[0]}`;

  let result: { user_id: string; org_id: string; slug: string };
  try {
    console.log('[SSO] signup: Calling signup_user RPC with:', {
      email,
      org_name: body.org_name || null,
      slug,
      role
    });

    result = await database.rpc<{ user_id: string; org_id: string; slug: string }>(
      "signup_user",
      {
        p_email: email,
        p_password_hash: password_hash,
        p_org_name: body.org_name || null, // Allow null for recruiter onboarding
        p_org_slug: slug,
        p_role: role, // Use the role variable we set earlier
        p_user_metadata: body.user_metadata ?? {},
      },
    );

    console.log('[SSO] signup: signup_user RPC succeeded', {
      user_id: result.user_id,
      org_id: result.org_id,
      slug: result.slug
    });
  } catch (err: any) {
    console.error('[SSO] signup: signup_user RPC failed:', {
      error: err.message,
      code: err.code,
      details: err.details
    });

    if (err?.message?.includes("duplicate") || err?.message?.includes("23505")) {
      return { error: "An account with this email already exists. Please log in.", status: 409 };
    }
    throw err;
  }

  try {
    const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
      p_user_id: result.user_id,
      p_org_id: result.org_id,
    });

    const userRow = await database.queryOne<{ is_email_verified: boolean }>(
      `users?id=eq.${encodeURIComponent(result.user_id)}&select=is_email_verified`
    );
    const isEmailVerified = userRow?.is_email_verified ?? false;

    const refreshToken = generateRefreshToken();
    const refreshHash = await hashToken(refreshToken);
    const sessionId = crypto.randomUUID();

    await database.mutate("sessions", {
      id: sessionId,
      user_id: result.user_id,
      org_id: result.org_id,
      refresh_token_hash: refreshHash,
      user_agent: resolvedUa,
      ip_address: resolvedIp,
      revoked: false,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      family_id: sessionId,
      family_created_at: new Date().toISOString(),
    });

    const effectiveRoles = resolveEffectiveRoles({
      claims,
      explicitRole: role,
      fallbackRole: "learner",
    });

    const accessToken = await signAccessToken(
      {
        sub: result.user_id,
        email,
        org_id: result.org_id,
        roles: effectiveRoles,
        products: claims?.products ?? [],
        membership_status: claims?.membership_status ?? "active",
        is_email_verified: isEmailVerified,
        user_metadata: body.user_metadata ?? {},
      },
      env,
    );

    let emailSent = true;
    try {
      // Throttle verification email sending (5/hour per email)
      const throttled = await checkEmailThrottle(env, "verification", email);
      if (throttled) {
        emailSent = false;
      } else {
        const verifyToken = crypto.randomUUID();
        const verifyTokenHash = await hashToken(verifyToken);
        await database.mutate("email_verifications", {
          user_id: result.user_id,
          token_hash: verifyTokenHash,
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        });
        const appUrl = resolveAppUrl(body.redirect_url, env);
        const verifyUrl = `${appUrl}/verify-email?token=${verifyToken}`;

        const template = generateVerificationEmailTemplate(verifyUrl);
        ctx.waitUntil(sendEmail(env, { to: email, subject: template.subject, html: template.html, text: template.text }, ctx));
      }
    } catch (err) {
      console.warn('[SSO] Email verification sending failed:', err);
      emailSent = false;
    }

    // ─── Step 4: Build response ──────────────────────────────────
    // ponytail: Best-effort sync of pre-existing subscription
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'user.created', {
      id: result.user_id,
      email,
      user_metadata: {
        ...(body.user_metadata ?? {}),
        role: body.role,
      },
    });
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'organization.created', {
      id: result.org_id,
      name: body.org_name,
      slug: result.slug,
      created_by: result.user_id,
    });
    
    // Publish dependent events (membership and subscription)
    // Consumer should handle these idempotently and retry if dependencies not ready
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'membership.created', {
      user_id: result.user_id,
      organization_id: result.org_id,
      roles: claims?.roles ?? [],  // Use actual roles from DB, empty if claims failed
      status: 'active',
    });

    // ponytail: Best-effort sync of pre-existing subscription
    // Non-blocking; login re-sync path serves as backstop if this fails
    ctx.waitUntil(
      database.query<{
        id: string;
        plan_id: string;
        plan_code: string;
        plan_type: string;
        plan_amount: number;
        billing_cycle: string;
        features: string[];
        status: string;
        subscription_start_date: string;
        subscription_end_date: string | null;
        product_id: string | null;
        updated_at: string;
      }>(`subscriptions?user_id=eq.${encodeURIComponent(result.user_id)}&order=created_at.desc&limit=1`)
        .then((subscriptions) => {
          if (subscriptions && subscriptions.length > 0) {
            const sub = subscriptions[0];
            publishSyncEvent(env.SYNC_QUEUE, ctx, 'subscription.created', {
              id: sub.id,
              user_id: result.user_id,
              organization_id: null,
              plan_id: sub.plan_id,
              plan_code: sub.plan_code,
              plan_type: sub.plan_type,
              plan_amount: sub.plan_amount,
              billing_cycle: sub.billing_cycle,
              features: sub.features,
              status: sub.status,
              subscription_start_date: sub.subscription_start_date,
              subscription_end_date: sub.subscription_end_date,
              is_organization_subscription: false,
              product_id: sub.product_id,
              updated_at: sub.updated_at,
            });
          }
        })
        .catch((err) => {
          console.error(`[SSO] Failed to sync subscription for user ${result.user_id}:`, err);
        }),
    );

    audit(ctx, env, "signup", {
      user_id: result.user_id,
      org_id: result.org_id,
      ip_address: resolvedIp,
      user_agent: resolvedUa,
      metadata: { email_sent: emailSent },
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: { id: result.user_id, email },
      org: { id: result.org_id, name: body.org_name, slug: result.slug },
      email_sent: emailSent,
    };
  } catch (err) {
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
      await database.query(`users?id=eq.${encodeURIComponent(result.user_id)}`, { method: "DELETE" });
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
    throw err;
  }
}


