import type { Env } from "../types";
import { error } from "../lib/response";

/**
 * OAuth routes — placeholder for future Google/GitHub SSO.
 *
 * Flow:
 *   1. GET /auth/oauth/:provider → redirect to provider's auth URL
 *   2. GET /auth/oauth/:provider/callback → exchange code for tokens, create/link user
 *
 * These return 501 until a provider is configured.
 */

export async function oauthRedirect(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const provider = url.pathname.split("/").pop();
  return error(`OAuth provider '${provider}' is not configured yet`, 501);
}

export async function oauthCallback(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const segments = url.pathname.split("/");
  const provider = segments[segments.length - 2];
  return error(`OAuth callback for '${provider}' is not configured yet`, 501);
}
