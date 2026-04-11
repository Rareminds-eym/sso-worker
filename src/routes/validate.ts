import type { Env, AccessTokenPayload } from "../types";
import { json } from "../lib/response";

/**
 * Validate the current session.
 * Auth is handled declaratively by the router — payload is guaranteed present.
 */
export async function validate(
  _req: Request,
  _env: Env,
  _ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  return json({
    sub: auth!.sub,
    email: auth!.email,
    org_id: auth!.org_id,
    role: auth!.role,
  });
}
