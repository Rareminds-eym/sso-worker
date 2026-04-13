import type { Env, AccessTokenPayload } from "../types";
import { json } from "../lib/response";

/**
 * GET /auth/me — returns the authenticated user's identity from the JWT.
 * Auth is handled declaratively by the router — payload is guaranteed present.
 */
export async function me(
  _req: Request,
  _env: Env,
  _ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const payload = auth!;

  return json({
    sub: payload.sub,
    email: payload.email,
    org_id: payload.org_id,
    roles: payload.roles,
    products: payload.products,
    membership_status: payload.membership_status,
    is_email_verified: payload.is_email_verified,
  });
}
