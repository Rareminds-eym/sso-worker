import type { Env, LoginBody, User, Membership } from "../types";
import { db } from "../lib/db";
import { verifyPassword, hashToken, generateRefreshToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { setAuthCookies } from "../lib/cookies";
import { validateEmail } from "../lib/validate";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { checkAccountLockout, recordFailedLogin, clearFailedLogins } from "../lib/rate-limit";
import { SESSION_TTL_MS } from "../lib/constants";

// Pre-computed bcrypt hash (cost 12) for constant-time comparison
// when user doesn't exist. MUST match SALT_ROUNDS in hash.ts.
const DUMMY_HASH = "$2a$12$x/RiZqGfMzMQqO7MZsMmu.FS0FMCoaRaKBLGkfaOFzuBkeBMQzMFu";

export async function login(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: LoginBody;
  try {
    body = await req.json() as LoginBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.email || !body.password) {
    return error("email and password are required");
  }

  const emailErr = validateEmail(body.email);
  if (emailErr) return emailErr;

  const email = body.email.toLowerCase().trim();
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");

  const locked = await checkAccountLockout(env, email);
  if (locked) return locked;

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
    return error("Invalid credentials", 401);
  }

  // Check if user is blocked
  if (user.is_blocked) {
    return error("Account is blocked", 403);
  }

  const valid = await verifyPassword(body.password, user.password_hash);
  if (!valid) {
    await recordFailedLogin(env, email);
    audit(ctx, env, "login_failed", {
      user_id: user.id,
      ip_address: ip,
      user_agent: ua,
    });
    return error("Invalid credentials", 401);
  }

  ctx.waitUntil(clearFailedLogins(env, email));

  // Update last_login_at
  ctx.waitUntil(
    database.update("users", { id: `eq.${user.id}` }, { last_login_at: new Date().toISOString() })
      .catch((err) => console.warn("[SSO] Failed to update last_login_at:", err)),
  );

  // Fetch ACTIVE memberships only, ordered deterministically
  const memberships = await database.query<Membership>(
    `memberships?user_id=eq.${user.id}&status=eq.active&select=*&order=created_at.asc`,
  );

  if (!memberships.length) {
    return error("No active organization membership found", 403);
  }

  const activeMembership = memberships[0];

  const refreshToken = generateRefreshToken();
  const refreshHash = await hashToken(refreshToken);

  await database.mutate("sessions", {
    user_id: user.id,
    org_id: activeMembership.org_id,
    refresh_token_hash: refreshHash,
    user_agent: ua,
    ip_address: ip,
    revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
  });

  const accessToken = await signAccessToken(
    {
      sub: user.id,
      email: user.email,
      org_id: activeMembership.org_id,
      role: activeMembership.role,
    },
    env,
  );

  const response = json({
    success: true,
    user: { id: user.id, email: user.email },
    active_org_id: activeMembership.org_id,
    organizations: memberships.map((m) => ({ org_id: m.org_id, role: m.role })),
  });

  setAuthCookies(response, accessToken, refreshToken);

  audit(ctx, env, "login", {
    user_id: user.id,
    org_id: activeMembership.org_id,
    ip_address: ip,
    user_agent: ua,
  });

  return response;
}
