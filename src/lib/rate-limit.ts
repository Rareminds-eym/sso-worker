import type { Env } from "../types";
import { ACCOUNT_LOCKOUT_THRESHOLD, ACCOUNT_LOCKOUT_WINDOW } from "./constants";

interface RateLimitConfig {
  limit: number;
  windowSeconds: number;
}

const ROUTE_LIMITS: Record<string, RateLimitConfig> = {
  "/auth/login": { limit: 5, windowSeconds: 60 },
  "/auth/signup": { limit: 3, windowSeconds: 60 },
  "/auth/signup-member": { limit: 3, windowSeconds: 60 },
  "/auth/refresh": { limit: 10, windowSeconds: 60 },
  "/auth/invite": { limit: 5, windowSeconds: 60 },
  "/auth/invite/accept": { limit: 5, windowSeconds: 60 },
  "/auth/invite/cancel": { limit: 5, windowSeconds: 60 },
  "/auth/invite/resend": { limit: 3, windowSeconds: 60 },
  "/auth/request-verification": { limit: 3, windowSeconds: 60 },
  "/auth/verify-email": { limit: 5, windowSeconds: 60 },
  "/auth/forgot-password": { limit: 3, windowSeconds: 60 },
  "/auth/reset-password": { limit: 5, windowSeconds: 60 },
};

/**
 * KV-based fixed-window rate limiter (per-IP).
 * Returns a 429 Response if the limit is exceeded, or null if allowed.
 */
export async function rateLimit(
  req: Request,
  env: Env,
  pathname: string,
): Promise<Response | null> {
  const config = ROUTE_LIMITS[pathname];
  if (!config) return null;

  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const windowSlot = Math.floor(Date.now() / (config.windowSeconds * 1000));
  const key = `rl:${pathname}:${ip}:${windowSlot}`;

  const current = parseInt((await env.RATE_LIMIT_KV.get(key)) ?? "0", 10);

  if (current >= config.limit) {
    return rateLimitResponse(config.windowSeconds);
  }

  await env.RATE_LIMIT_KV.put(key, String(current + 1), {
    expirationTtl: config.windowSeconds * 2,
  });

  return null;
}

/**
 * Per-account lockout after repeated failed login attempts.
 * Tracks by email, not IP — prevents distributed brute-force.
 */
export async function checkAccountLockout(
  env: Env,
  email: string,
): Promise<Response | null> {
  const key = `lockout:${email}`;
  const current = parseInt((await env.RATE_LIMIT_KV.get(key)) ?? "0", 10);

  if (current >= ACCOUNT_LOCKOUT_THRESHOLD) {
    return rateLimitResponse(ACCOUNT_LOCKOUT_WINDOW);
  }

  return null;
}

/** Increment the failed login counter for an email */
export async function recordFailedLogin(env: Env, email: string): Promise<void> {
  const key = `lockout:${email}`;
  const current = parseInt((await env.RATE_LIMIT_KV.get(key)) ?? "0", 10);
  await env.RATE_LIMIT_KV.put(key, String(current + 1), {
    expirationTtl: ACCOUNT_LOCKOUT_WINDOW,
  });
}

/** Clear the failed login counter on successful login */
export async function clearFailedLogins(env: Env, email: string): Promise<void> {
  await env.RATE_LIMIT_KV.delete(`lockout:${email}`);
}

function rateLimitResponse(retryAfter: number): Response {
  return new Response(
    JSON.stringify({ error: "Too many requests. Please try again later." }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": String(retryAfter),
      },
    },
  );
}
