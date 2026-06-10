import { getCookie, setAuthCookies } from "../lib/cookies";
import { endpointRateLimit } from "../lib/rate-limit";
import { error, json } from "../lib/response";
import { rotateRefreshToken, type RotationContext } from "../lib/session-rotation";
import type { Env } from "../types";

/**
 * POST /auth/refresh — thin adapter over the shared rotation module.
 *
 * Reads the presented refresh token (from cookie or request body), builds a
 * RotationContext from request headers, delegates to rotateRefreshToken, and
 * translates the outcome into an HTTP Response.
 *
 * All rotation logic, theft detection, grace-window resolution, absolute
 * lifetime enforcement, and audit emission live in session-rotation.ts so the
 * HTTP route and RPC entry point (index.ts::refreshSession) cannot diverge in
 * security behavior (Requirement 4).
 */
export async function refresh(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  // 0. Apply rate limiting BEFORE any session mutation.
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rateLimited = await endpointRateLimit(env, `refresh:ip:${ip}`, 20, 60);
  if (rateLimited) return rateLimited;

  // 1. Read the presented refresh token from cookie (browser) OR body (server SDK).
  let presentedToken = getCookie(req, "refresh_token");

  if (!presentedToken) {
    try {
      const body = await req.json() as { refresh_token?: string };
      presentedToken = body?.refresh_token ?? null;
    } catch {
      // No body or invalid JSON — that's fine, token just stays null
    }
  }

  if (!presentedToken) {
    return error("No refresh token provided", 401);
  }

  // 2. Build RotationContext from CF-Connecting-IP and User-Agent headers.
  const rotationCtx: RotationContext = {
    ip: req.headers.get("CF-Connecting-IP"),
    ua: req.headers.get("User-Agent"),
  };

  // 3. Call the shared rotation module.
  const outcome = await rotateRefreshToken(env, ctx, presentedToken, rotationCtx);

  // 4. Translate RotationOutcome into HTTP Response.
  switch (outcome.kind) {
    case "rotated":
    case "overlap": {
      // Success (winner or benign overlap): return 200 with access token in
      // JSON body + X-Access-Token header, and set the refresh cookie.
      const response = json({ access_token: outcome.accessToken });
      setAuthCookies(response, outcome.accessToken, outcome.refreshToken, env);
      return response;
    }

    case "theft":
      // Token reuse detected outside grace window → 401 (sessions already revoked by module).
      return error("Refresh token reuse detected. Sessions revoked.", 401);

    case "expired_lifetime":
      // Absolute session lifetime exceeded → 401.
      return error("Session lifetime exceeded", 401);

    case "session_expired":
      // Token expired (within normal TTL) → 401.
      return error("Session expired", 401);

    case "invalid":
      // Unknown or invalid refresh token → 401.
      return error("Invalid refresh token", 401);

    default:
      // TypeScript exhaustiveness check — should never reach here.
      const _exhaustive: never = outcome;
      return error("Unknown rotation outcome", 500);
  }
}
