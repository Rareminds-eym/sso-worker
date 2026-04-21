import { error } from "./response";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 72; // bcrypt silently truncates at 72 bytes

/** Validate email format. Returns an error Response or null if valid. */
export function validateEmail(email: unknown): Response | null {
  if (typeof email !== "string" || !EMAIL_RE.test(email)) {
    return error("Invalid email format");
  }
  return null;
}

/**
 * Validate redirect_url against the ALLOWED_APP_URLS allowlist.
 * Returns an error Response (400) if invalid, or null if valid.
 *
 * Call this EARLY in routes — before any DB work — so invalid
 * redirect_urls are rejected with 400 instead of causing 500 crashes.
 * This also prevents enumeration vectors (e.g. in forgotPassword).
 */
export function validateRedirectUrl(redirectUrl: string | undefined, env: { ALLOWED_APP_URLS?: string }): Response | null {
  if (!redirectUrl) return null; // optional, defaults to first allowed URL

  if (!env.ALLOWED_APP_URLS) {
    return error("Server misconfiguration: ALLOWED_APP_URLS is not set", 500);
  }

  const allowed = env.ALLOWED_APP_URLS.split(",")
    .map((u) => u.trim().replace(/\/+$/, ""))
    .filter(Boolean);

  const normalized = redirectUrl.replace(/\/+$/, "");

  if (!allowed.includes(normalized)) {
    return error("redirect_url is not allowed. Must match one of the configured app URLs.", 400);
  }

  return null; // valid
}

/**
 * Resolve the app base URL for email links.
 *
 * Pattern: per-request `redirect_url` validated against an allowlist
 * (same as Supabase's `redirectTo`, Auth0's `redirect_uri`).
 *
 * 1. If `redirectUrl` is provided, validate it against ALLOWED_APP_URLS.
 * 2. If not provided, return the first URL in the allowlist as default.
 * 3. Always strips trailing slashes.
 *
 * IMPORTANT: Call validateRedirectUrl() BEFORE this function to reject
 * invalid redirect_urls with a 400 response. This function only throws
 * on server misconfiguration (missing/empty ALLOWED_APP_URLS).
 *
 * @param redirectUrl  Optional per-request redirect URL from the caller
 * @param env          Worker environment with ALLOWED_APP_URLS
 * @returns Validated base URL (no trailing slash)
 * @throws Error if ALLOWED_APP_URLS is missing or empty (server misconfiguration)
 */
export function resolveAppUrl(redirectUrl: string | undefined, env: { ALLOWED_APP_URLS?: string }): string {
  if (!env.ALLOWED_APP_URLS) {
    throw new Error("ALLOWED_APP_URLS is required for email delivery");
  }

  const allowed = env.ALLOWED_APP_URLS.split(",")
    .map((u) => u.trim().replace(/\/+$/, ""))
    .filter(Boolean);

  if (!allowed.length) {
    throw new Error("ALLOWED_APP_URLS must contain at least one URL");
  }

  // Validate each entry is a proper URL
  for (const u of allowed) {
    try { new URL(u); } catch { throw new Error(`ALLOWED_APP_URLS contains invalid URL: ${u}`); }
  }

  // No redirect_url requested — use the first allowed URL as default
  if (!redirectUrl) {
    return allowed[0];
  }

  const normalized = redirectUrl.replace(/\/+$/, "");

  // Must be an exact match of an allowed base URL (prevents open-redirect)
  if (!allowed.includes(normalized)) {
    throw new Error(
      `redirect_url "${redirectUrl}" is not in the ALLOWED_APP_URLS allowlist. ` +
      `Allowed: ${env.ALLOWED_APP_URLS}`,
    );
  }

  return normalized;
}

/** Validate password strength. Returns an error Response or null if valid. */
export function validatePassword(password: unknown): Response | null {
  if (typeof password !== "string") {
    return error("Password is required");
  }
  if (password.length < PASSWORD_MIN) {
    return error(`Password must be at least ${PASSWORD_MIN} characters`);
  }
  if (password.length > PASSWORD_MAX) {
    return error(`Password must be at most ${PASSWORD_MAX} characters`);
  }
  return null;
}
