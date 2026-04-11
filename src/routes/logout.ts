import type { Env } from "../types";
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
  const refreshToken = getCookie(req, "refresh_token");

  if (refreshToken) {
    const database = db(env);
    const tokenHash = await hashToken(refreshToken);

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
    ip_address: req.headers.get("CF-Connecting-IP"),
    user_agent: req.headers.get("User-Agent"),
  });

  return response;
}
