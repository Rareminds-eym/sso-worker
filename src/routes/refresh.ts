import type { Env, Session, JwtClaims } from "../types";
import { db } from "../lib/db";
import { hashToken, generateRefreshToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { getCookie, setAuthCookies } from "../lib/cookies";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";

export async function refresh(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  // Accept refresh token from cookie (browser) OR body (server SDK)
  let incomingToken = getCookie(req, "refresh_token");

  if (!incomingToken) {
    try {
      const body = await req.json() as { refresh_token?: string };
      incomingToken = body?.refresh_token ?? null;
    } catch {
      // No body or invalid JSON — that's fine, token just stays null
    }
  }

  if (!incomingToken) {
    return error("No refresh token provided", 401);
  }

  const database = db(env);
  const tokenHash = await hashToken(incomingToken);
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");

  const session = await database.queryOne<Session>(
    `sessions?refresh_token_hash=eq.${tokenHash}&select=*`,
  );

  if (!session) {
    return error("Invalid refresh token", 401);
  }

  // Theft detection
  if (session.revoked) {
    await database.update(
      "sessions",
      { user_id: `eq.${session.user_id}` },
      { revoked: true },
    );
    audit(ctx, env, "refresh_theft_detected", {
      user_id: session.user_id,
      ip_address: ip,
      user_agent: ua,
    });
    return error("Refresh token reuse detected. All sessions revoked.", 401);
  }

  if (new Date(session.expires_at) < new Date()) {
    await database.update("sessions", { id: `eq.${session.id}` }, { revoked: true });
    return error("Session expired", 401);
  }

  // Revoke old session
  await database.update("sessions", { id: `eq.${session.id}` }, { revoked: true });

  // Create rotated session
  const newRefreshToken = generateRefreshToken();
  const newRefreshHash = await hashToken(newRefreshToken);

  await database.mutate("sessions", {
    user_id: session.user_id,
    org_id: session.org_id,
    refresh_token_hash: newRefreshHash,
    user_agent: ua,
    ip_address: ip,
    revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    rotated_from: session.id,
    last_used_at: new Date().toISOString(),
  });

  // Fetch user email + verified status + RBAC claims in parallel
  const [user, claims] = await Promise.all([
    database.queryOne<{ id: string; email: string; is_email_verified: boolean }>(
      `users?id=eq.${session.user_id}&select=id,email,is_email_verified`,
    ),
    database.rpc<JwtClaims>("get_jwt_claims", {
      p_user_id: session.user_id,
      p_org_id: session.org_id,
    }),
  ]);

  const accessToken = await signAccessToken(
    {
      sub: session.user_id,
      email: user?.email ?? "",
      org_id: session.org_id ?? "",
      roles: claims?.roles ?? [],
      products: claims?.products ?? [],
      membership_status: claims?.membership_status ?? "active",
      is_email_verified: user?.is_email_verified ?? false,
    },
    env,
  );

  const response = json({ access_token: accessToken });
  setAuthCookies(response, accessToken, newRefreshToken);

  audit(ctx, env, "refresh", {
    user_id: session.user_id,
    org_id: session.org_id,
    ip_address: ip,
    user_agent: ua,
  });

  return response;
}
