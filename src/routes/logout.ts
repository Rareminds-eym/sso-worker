import type { Env, Session } from "../types";
import { db } from "../lib/db";
import { hashToken } from "../lib/hash";
import { getCookie, clearCookies } from "../lib/cookies";
import { json } from "../lib/response";
import { audit } from "../lib/audit";

export async function logout(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
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
  clearCookies(response);

  audit(ctx, env, "logout", {
    user_id: userId,
    org_id: orgId,
    ip_address: req.headers.get("CF-Connecting-IP"),
    user_agent: req.headers.get("User-Agent"),
  });

  return response;
}
