import type { Env, JwtClaims, User } from "../types";
import { db } from "./db";

export interface LteEntitlementContext {
  user: User;
  claims: JwtClaims;
}

export async function requireLteEntitlement(
  env: Env,
  payload: { sub: string; org_id: string | null },
): Promise<LteEntitlementContext> {
  const database = db(env);
  const user = await database.queryOne<User>(
    `users?id=eq.${encodeURIComponent(payload.sub)}&select=*`,
  );

  if (!user) {
    throw new Error("User not found");
  }

  if (user.is_blocked) {
    throw new Error("Account is blocked");
  }

  if (!user.is_email_verified) {
    throw new Error("Email is not verified");
  }

  const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
    p_user_id: payload.sub,
    p_org_id: payload.org_id,
  });

  if (!claims) {
    throw new Error(`Failed to load user permissions for user ${payload.sub} in org ${payload.org_id}`);
  }

  if (claims.membership_status !== "active") {
    throw new Error("Active membership is required");
  }

  return { user, claims };
}
