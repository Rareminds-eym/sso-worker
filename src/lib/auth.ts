import type { Env, AccessTokenPayload } from "../types";
import { verifyAccessToken } from "./jwt";
import { getCookie } from "./cookies";

/**
 * Extract and verify the access token from a request.
 * Checks Authorization header first, then falls back to cookie.
 * Returns the verified payload or null if unauthenticated.
 */
export async function authenticate(
  req: Request,
  env: Env,
): Promise<AccessTokenPayload | null> {
  const token = extractToken(req);
  if (!token) return null;

  try {
    return await verifyAccessToken(token, env);
  } catch {
    return null;
  }
}

/** Extract raw token string from header or cookie (no verification) */
export function extractToken(req: Request): string | null {
  const authHeader = req.headers.get("Authorization");
  if (authHeader) {
    if (!authHeader.startsWith("Bearer ")) return null;
    const token = authHeader.slice(7);
    return token || null;
  }
  return getCookie(req, "access_token");
}
