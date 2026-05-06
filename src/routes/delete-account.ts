import type { Env, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { clearCookies } from "../lib/cookies";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";

/**
 * POST /auth/delete-account
 *
 * Allows an authenticated user to delete their own account.
 * Used for rollback when app profile creation fails after SSO signup.
 *
 * Deletes: user, sessions, memberships (cascade), email_verifications, password_resets.
 * The `ON DELETE CASCADE` constraints handle most cleanup automatically.
 */
export async function deleteAccount(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const payload = auth!;
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  const database = db(env);

  try {
    // Delete the user — CASCADE handles sessions, memberships, email_verifications, etc.
    await database.query(`users?id=eq.${payload.sub}`, { method: "DELETE" });

    const response = json({ deleted: true });
    clearCookies(response);

    audit(ctx, env, "account_deleted", {
      user_id: payload.sub,
      ip_address: ip,
      user_agent: ua,
    });

    return response;
  } catch (err) {
    console.error("[SSO] Account deletion failed:", err);
    return error("Failed to delete account", 500);
  }
}
