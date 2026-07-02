import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";
import { db } from "../lib/db";
import { generateRefreshToken, hashToken, verifyPassword } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { checkAccountLockout, clearFailedLogins, endpointRateLimit, recordFailedLogin } from "../lib/rate-limit";
import { validateEmail } from "../lib/validate";
import type { Env, JwtClaims, LoginBody, Membership, User } from "../types";

// Pre-computed bcrypt hash (cost 12) for constant-time comparison
// when user doesn't exist. MUST match SALT_ROUNDS in hash.ts.
const DUMMY_HASH = "$2a$12$x/RiZqGfMzMQqO7MZsMmu.FS0FMCoaRaKBLGkfaOFzuBkeBMQzMFu";

export async function performLogin(
  env: Env,
  ctx: ExecutionContext,
  body: LoginBody,
  ip: string | null,
  ua: string | null,
) {
  if (!body.email || !body.password) {
    return { error: "email and password are required", status: 400 };
  }

  const emailErr = validateEmail(body.email);
  if (emailErr) {
    // emailErr is a Response, we'll return a simple object
    return { error: "Invalid email format", status: 400 };
  }

  const email = body.email.toLowerCase().trim();

  const rateLimited = await endpointRateLimit(env, `login:ip:${ip ?? "unknown"}`, 10, 60);
  if (rateLimited) {
    return { error: "Rate limit exceeded", status: 429 };
  }

  const locked = await checkAccountLockout(env, email);
  if (locked) {
    return { error: "Account locked", status: 403 };
  }

  const database = db(env);

  const user = await database.queryOne<User>(
    `users?email=eq.${encodeURIComponent(email)}&select=*`,
  );

  if (!user) {
    await verifyPassword(body.password, DUMMY_HASH);
    await recordFailedLogin(env, email);
    audit(ctx, env, "login_failed", {
      ip_address: ip,
      user_agent: ua,
      metadata: { email },
    });
    return { error: "Invalid credentials", status: 401 };
  }

  if (user.is_blocked) {
    return { error: "Account is blocked", status: 403 };
  }

  const valid = await verifyPassword(body.password, user.password_hash);
  if (!valid) {
    await recordFailedLogin(env, email);
    audit(ctx, env, "login_failed", {
      user_id: user.id,
      ip_address: ip,
      user_agent: ua,
    });
    return { error: "Invalid credentials", status: 401 };
  }

  ctx.waitUntil(clearFailedLogins(env, email));

  ctx.waitUntil(
    database.update("users", { id: `eq.${user.id}` }, { last_login_at: new Date().toISOString() })
      .catch((err) => console.warn("[SSO] Failed to update last_login_at:", err)),
  );

  const memberships = await database.query<Membership>(
    `memberships?user_id=eq.${user.id}&status=eq.active&select=*&order=created_at.asc`,
  );

  const activeMembership = memberships[0] ?? null;

  let claims: JwtClaims | null = null;
  if (activeMembership) {
    claims = await database.rpc<JwtClaims>("get_jwt_claims", {
      p_user_id: user.id,
      p_org_id: activeMembership.org_id,
    });
  }

  const refreshToken = generateRefreshToken();
  const refreshHash = await hashToken(refreshToken);
  const sessionId = crypto.randomUUID();

  await database.mutate("sessions", {
    id: sessionId,
    user_id: user.id,
    org_id: activeMembership?.org_id ?? null,
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
      sub: user.id,
      email: user.email,
      org_id: activeMembership?.org_id ?? "",
      roles: claims?.roles ?? [],
      products: claims?.products ?? [],
      membership_status: claims?.membership_status ?? "active",
      is_email_verified: user.is_email_verified,
      user_metadata: user.user_metadata ?? {},
    },
    env,
  );

  audit(ctx, env, "login", {
    user_id: user.id,
    org_id: activeMembership?.org_id ?? null,
    ip_address: ip,
    user_agent: ua,
  });

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    user: { id: user.id, email: user.email },
    active_org_id: activeMembership?.org_id ?? null,
    organizations: memberships.map((m) => ({ org_id: m.org_id })),
  };
}


