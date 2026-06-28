import { audit } from "../lib/audit";
import { clearCookies, getCookie } from "../lib/cookies";
import { db } from "../lib/db";
import { hashToken } from "../lib/hash";
import { endpointRateLimit } from "../lib/rate-limit";
import { json } from "../lib/response";
import type { Env, Session } from "../types";

export async function logout(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  // 0. Apply rate limiting BEFORE any session mutation (Requirement 6.4).
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rateLimited = await endpointRateLimit(env, `logout:ip:${ip}`, 20, 60);
  if (rateLimited) return rateLimited;

  // Accept refresh token from cookie (browser) OR body (server SDK)
  let refreshToken = getCookie(req, "refresh_token");

  if (!refreshToken) {
    try {
      const body = await req.json() as { refresh_token?: string };
      refreshToken = body?.refresh_token ?? null;
    } catch {
      // No body — that's fine
    }
  }

  let userId: string | null = null;
  let orgId: string | null = null;

  if (refreshToken) {
    const database = db(env);
    const tokenHash = await hashToken(refreshToken);

    // Look up the session to get user_id for audit before revoking
    const session = await database.queryOne<Session>(
      `sessions?refresh_token_hash=eq.${tokenHash}&select=user_id,org_id`,
    );

    if (session) {
      userId = session.user_id;
      orgId = session.org_id;
    }

    await database.update(
      "sessions",
      { refresh_token_hash: `eq.${tokenHash}` },
      { revoked: true },
    ).catch((err) => {
      console.warn("[SSO] Session revocation failed on logout:", err);
    });
  }

  const response = json({ success: true });
  clearCookies(response, env);

  audit(ctx, env, "logout", {
    user_id: userId,
    org_id: orgId,
    ip_address: req.headers.get("CF-Connecting-IP"),
    user_agent: req.headers.get("User-Agent"),
  });

  return response;
}
