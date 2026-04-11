import type { Env, Session, Membership } from "../types";
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
  const incomingToken = getCookie(req, "refresh_token");
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

  // Create rotated session — link to old session via rotated_from
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

  // Fetch membership (active only) + user in parallel
  const [membership, user] = await Promise.all([
    database.queryOne<Membership>(
      `memberships?user_id=eq.${session.user_id}&org_id=eq.${session.org_id}&status=eq.active&select=*`,
    ),
    database.queryOne<{ id: string; email: string }>(
      `users?id=eq.${session.user_id}&select=id,email`,
    ),
  ]);

  const accessToken = await signAccessToken(
    {
      sub: session.user_id,
      email: user?.email ?? "",
      org_id: session.org_id ?? "",
      role: membership?.role ?? "member",
    },
    env,
  );

  const response = json({ success: true });
  setAuthCookies(response, accessToken, newRefreshToken);

  audit(ctx, env, "refresh", {
    user_id: session.user_id,
    org_id: session.org_id,
    ip_address: ip,
    user_agent: ua,
  });

  return response;
}
