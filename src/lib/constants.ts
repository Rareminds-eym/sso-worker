/** Session / refresh token lifetime: 30 days in milliseconds */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Access token cookie Max-Age in seconds (15 min) */
export const ACCESS_TOKEN_MAX_AGE = 900;

/** Invite expiry: 7 days in milliseconds */
export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** Supabase fetch timeout in milliseconds */
export const DB_TIMEOUT_MS = 10_000;

/** Max failed login attempts per email before lockout */
export const ACCOUNT_LOCKOUT_THRESHOLD = 10;

/** Account lockout window in seconds */
export const ACCOUNT_LOCKOUT_WINDOW = 900; // 15 minutes

/** JWT issuer claim — must match auth-core config */
export const JWT_ISSUER = "sso-api";

/** JWT audience claim — must match auth-core config */
export const JWT_AUDIENCE = "sso-client";
