import type { Env } from "../types";
import { getPublicJWK } from "../lib/jwt";
import { json } from "../lib/response";

/**
 * JWKS endpoint — serves the public key set for external JWT verification.
 * GET /.well-known/jwks.json
 */
export async function jwks(env: Env): Promise<Response> {
  const jwk = await getPublicJWK(env);

  return json(
    { keys: [jwk] },
    200,
    { "Cache-Control": "public, max-age=3600" },
  );
}
