import type { Env } from "../types";
import { getPublicJWK, exportPemAsJwk } from "../lib/jwt";
import { json } from "../lib/response";

/**
 * JWKS endpoint — serves the public key set for external JWT verification.
 * During key rotation, serves both current and previous keys.
 * GET /.well-known/jwks.json
 */
export async function jwks(env: Env): Promise<Response> {
  const keys = [await getPublicJWK(env)];

  // During rotation, also serve the previous key so tokens signed
  // with the old key remain verifiable until they expire.
  if (env.JWT_PUBLIC_KEY_PREVIOUS && env.JWT_KID_PREVIOUS) {
    try {
      const prevJwk = await exportPemAsJwk(
        env.JWT_PUBLIC_KEY_PREVIOUS,
        env.JWT_KID_PREVIOUS,
      );
      keys.push(prevJwk);
    } catch (err) {
      console.warn("[SSO] Failed to export previous JWKS key:", err);
    }
  }

  return json(
    { keys },
    200,
    { "Cache-Control": "public, max-age=3600" },
  );
}
