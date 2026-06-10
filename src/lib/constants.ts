/** Session / refresh token lifetime: 30 days in milliseconds */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Reuse grace window (Decision A): how long after a refresh token is rotated
 * the just-superseded token may still return its already-issued replacement
 * instead of tripping theft detection. Stored as the TTL of the `grace:<hash>`
 * KV entry. 60 seconds (minimum required by Cloudflare KV).
 */
export const REUSE_GRACE_INTERVAL_SEC = 60;

/**
 * Absolute session lifetime cap (Decision C): the maximum age, measured from
 * the token family's initial-login timestamp, beyond which a refresh is refused
 * regardless of activity. 30 days in milliseconds.
 */
export const ABSOLUTE_SESSION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

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

/** Platform default org ID — users without a specific org get membership here */
export const PLATFORM_ORG_ID = "00000000-0000-0000-0000-000000000001";

/** Minimum password length — must match frontend validation */
export const PASSWORD_MIN = 10;

/** Maximum password length — bcrypt silently truncates at 72 bytes */
export const PASSWORD_MAX = 72;
