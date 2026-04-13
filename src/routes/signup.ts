import type { Env, SignupBody, JwtClaims } from "../types";
import { db } from "../lib/db";
import { hashPassword, hashToken, generateRefreshToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { setAuthCookies } from "../lib/cookies";
import { validateEmail, validatePassword } from "../lib/validate";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";

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

  if (!body.email || !body.password || !body.org_name) {
    return error("email, password, and org_name are required");
  }

  const emailErr = validateEmail(body.email);
  if (emailErr) return emailErr;

  const passErr = validatePassword(body.password);
  if (passErr) return passErr;

  const email = body.email.toLowerCase().trim();
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  const database = db(env);

  const password_hash = await hashPassword(body.password);

  const slug = body.org_name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

  let result: { user_id: string; org_id: string; slug: string };
  try {
    result = await database.rpc<{ user_id: string; org_id: string; slug: string }>(
      "signup_user",
      {
        p_email: email,
        p_password_hash: password_hash,
        p_org_name: body.org_name,
        p_org_slug: slug,
      },
    );
  } catch (err: any) {
    if (err?.message?.includes("duplicate") || err?.message?.includes("23505")) {
      return error("An account with this email already exists", 409);
    }
    throw err;
  }

  // Get RBAC claims (owner role, no products yet)
  const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
    p_user_id: result.user_id,
    p_org_id: result.org_id,
  });

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
      org_id: result.org_id,
      roles: claims?.roles ?? [],
      products: claims?.products ?? [],
      membership_status: claims?.membership_status ?? "active",
      is_email_verified: false,
    },
    env,
  );

  const response = json(
    {
      access_token: accessToken,
      user: { id: result.user_id, email },
      org: { id: result.org_id, name: body.org_name, slug: result.slug },
    },
    201,
  );

  setAuthCookies(response, accessToken, refreshToken);

  audit(ctx, env, "signup", {
    user_id: result.user_id,
    org_id: result.org_id,
    ip_address: ip,
    user_agent: ua,
  });

  return response;
}
