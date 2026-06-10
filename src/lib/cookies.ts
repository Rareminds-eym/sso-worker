import { SESSION_TTL_MS } from "./constants";

// ─── Centralized Cookie Attributes ─────────────────────────────
/** Base cookie attributes for secure auth cookies. HttpOnly, Secure, Path=/. */
export const COOKIE_BASE_ATTRS = "HttpOnly; Secure; Path=/";

/** SameSite policy for refresh token (cross-site silent refresh support). */
export const COOKIE_SAMESITE = "SameSite=None";

/** Refresh token max age in seconds. */
export const REFRESH_MAX_AGE = Math.floor(SESSION_TTL_MS / 1000);

// ─── Cookie Configuration ──────────────────────────────────────
/** Configuration for refresh cookie Domain attribute. */
export interface CookieConfig {
  /** Optional registrable parent domain (e.g., ".rareminds.in"). When omitted, cookie is host-only. */
  domain?: string;
}

// ─── Cookie Builders ───────────────────────────────────────────
/**
 * Build refresh_token cookie with configurable Domain attribute.
 * @param token - The refresh token value
 * @param maxAgeSec - Max-Age in seconds
 * @param cfg - Cookie configuration (domain)
 * @returns Set-Cookie header value for refresh_token
 */
export function refreshCookie(token: string, maxAgeSec: number, cfg: CookieConfig): string {
  const domain = cfg.domain ? `; Domain=${cfg.domain}` : "";
  return `refresh_token=${token}; ${COOKIE_BASE_ATTRS}; ${COOKIE_SAMESITE}${domain}; Max-Age=${maxAgeSec}`;
}

/**
 * Build refresh_token clear cookie (Max-Age=0) with matching attributes.
 * @param cfg - Cookie configuration (domain) — must match the set cookie
 * @returns Set-Cookie header value to clear refresh_token
 */
export function clearRefreshCookie(cfg: CookieConfig): string {
  const domain = cfg.domain ? `; Domain=${cfg.domain}` : "";
  return `refresh_token=; ${COOKIE_BASE_ATTRS}; ${COOKIE_SAMESITE}${domain}; Max-Age=0`;
}

// ─── Legacy Helper (For Rollout Window) ────────────────────────
/**
 * Clear legacy access_token cookie (kept for one rollout window to evict already-set cookies).
 * TODO: Remove after rollout window (task 13.3 — approval-gated Contract phase).
 */
function clearLegacyAccessTokenCookie(): string {
  return `access_token=; ${COOKIE_BASE_ATTRS}; ${COOKIE_SAMESITE}; Max-Age=0`;
}

// ─── High-Level Response Helpers ───────────────────────────────
/**
 * Set authentication tokens on response.
 * - Sets ONLY the refresh_token cookie (no access_token cookie per Req 9.1, 9.2).
 * - Sets the X-Access-Token header for in-memory client storage.
 * - Access token is also in JSON body (handled by caller).
 * - Wires REFRESH_COOKIE_DOMAIN from env when set.
 * @param res - Response object to mutate
 * @param accessToken - Access token (sent via header, not cookie)
 * @param refreshToken - Refresh token (sent via HttpOnly cookie)
 * @param env - Environment (reads REFRESH_COOKIE_DOMAIN)
 */
export function setAuthCookies(
  res: Response,
  accessToken: string,
  refreshToken: string,
  env: { REFRESH_COOKIE_DOMAIN?: string },
): void {
  // Access token delivered via header only (in-memory on client)
  res.headers.set("X-Access-Token", accessToken);

  // Build cookie config from env
  const cfg: CookieConfig = { domain: env.REFRESH_COOKIE_DOMAIN };

  // Refresh token delivered via HttpOnly cookie with configured Domain
  res.headers.append("Set-Cookie", refreshCookie(refreshToken, REFRESH_MAX_AGE, cfg));
}

/**
 * Clear auth cookies.
 * - Clears refresh_token cookie with matching attributes (including Domain).
 * - LEGACY: Also clears access_token cookie for rollout window (task 13.3 will remove this).
 * @param res - Response object to mutate
 * @param env - Environment (reads REFRESH_COOKIE_DOMAIN) — must match the set cookies
 */
export function clearCookies(res: Response, env: { REFRESH_COOKIE_DOMAIN?: string }): void {
  // Build cookie config from env
  const cfg: CookieConfig = { domain: env.REFRESH_COOKIE_DOMAIN };

  // Clear refresh_token with matching attributes (including Domain)
  res.headers.append("Set-Cookie", clearRefreshCookie(cfg));

  // LEGACY: Clear access_token cookie (kept for rollout window to evict already-set cookies)
  // TODO: Remove after rollout window (task 13.3 — approval-gated Contract phase)
  res.headers.append("Set-Cookie", clearLegacyAccessTokenCookie());
}

/** Parse a specific cookie value from the Cookie header */
export function getCookie(req: Request, name: string): string | null {
  const header = req.headers.get("Cookie");
  if (!header) return null;

  for (const part of header.split(";")) {
    const trimmed = part.trim();
    // Exact name match: "name=" not "name_other="
    if (trimmed.startsWith(`${name}=`)) {
      const idx = trimmed.indexOf("=");
      return idx === -1 ? null : trimmed.slice(idx + 1).trim();
    }
  }
  return null;
}
