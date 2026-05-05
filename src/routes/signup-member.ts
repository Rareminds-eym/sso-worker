import type { Env, JwtClaims, SignupMemberBody } from "../types";
import { db } from "../lib/db";
import { hashPassword, hashToken, generateRefreshToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { setAuthCookies } from "../lib/cookies";
import { validateEmail, validatePassword, validateRedirectUrl, resolveAppUrl } from "../lib/validate";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { sendEmail, verificationEmail } from "../lib/email";
import { SESSION_TTL_MS } from "../lib/constants";

/**
 * POST /auth/signup-member
 *
 * Creates a user without creating an organization.
 * Optionally joins an existing org with the specified role.
 * Used by students, educators, recruiters who self-register.
 */
export async function signupMember(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: SignupMemberBody;
  try {
    body = (await req.json()) as SignupMemberBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.email || !body.password || !body.role) {
    return error("email, password, and role are required");
  }

  const emailErr = validateEmail(body.email);
  if (emailErr) return emailErr;

  const passErr = validatePassword(body.password);
  if (passErr) return passErr;

  const redirectErr = validateRedirectUrl(body.redirect_url, env);
  if (redirectErr) return redirectErr;

  const email = body.email.toLowerCase().trim();
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  const database = db(env);

  const password_hash = await hashPassword(body.password);

  let result: { user_id: string; org_id: string | null; membership_id: string | null };
  try {
    result = await database.rpc<{
      user_id: string;
      org_id: string | null;
      membership_id: string | null;
    }>("signup_member", {
      p_email: email,
      p_password_hash: password_hash,
      p_role: body.role,
      p_org_id: body.org_id ?? null,
    });
  } catch (err: any) {
    if (err?.message?.includes("duplicate") || err?.message?.includes("23505")) {
      return error("An account with this email already exists", 409);
    }
    if (err?.message?.includes("Invalid role")) {
      return error("Invalid role specified", 400);
    }
    if (err?.message?.includes("Organization not found")) {
      return error("Organization not found", 404);
    }
    throw err;
  }

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

  await database.mutate("sessions", {
    user_id: result.user_id,
    org_id: result.org_id,
    refresh_token_hash: refreshHash,
    user_agent: ua,
    ip_address: ip,
    revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
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
    },
    env,
  );

  const responseBody: Record<string, unknown> = {
    access_token: accessToken,
    user: { id: result.user_id, email },
  };

  if (result.org_id) {
    responseBody.org = { id: result.org_id };
  }

  const response = json(responseBody, 201);
  setAuthCookies(response, accessToken, refreshToken);

  // Send verification email
  const verifyToken = crypto.randomUUID();
  const verifyTokenHash = await hashToken(verifyToken);
  await database.mutate("email_verifications", {
    user_id: result.user_id,
    token_hash: verifyTokenHash,
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
  });
  const appUrl = resolveAppUrl(body.redirect_url, env);
  const verifyUrl = `${appUrl}/verify-email?token=${verifyToken}`;
  const { subject, html, text } = verificationEmail(verifyUrl);
  ctx.waitUntil(sendEmail(env, { to: email, subject, html, text }));

  audit(ctx, env, "signup_member", {
    user_id: result.user_id,
    org_id: result.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { role: body.role },
  });

  return response;
}
