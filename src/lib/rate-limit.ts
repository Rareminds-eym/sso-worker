import type { Env } from "../types";
import { ACCOUNT_LOCKOUT_THRESHOLD, ACCOUNT_LOCKOUT_WINDOW } from "./constants";

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
