import type { Env } from "../types";

const THROTTLE_CONFIG = {
  verification:   { limit: 5,  windowSec: 3600, keyPrefix: "et:verify" },
  password_reset: { limit: 3,  windowSec: 3600, keyPrefix: "et:reset" },
  invite:         { limit: 10, windowSec: 3600, keyPrefix: "et:invite" },
} as const;

export type EmailType = keyof typeof THROTTLE_CONFIG;

/**
 * Check per-type email throttle using KV.
 * Returns a 429 Response if throttled, or null if allowed.
 * Uses sliding-window-by-key: one KV key per (type + identifier + time window).
 */
export async function checkEmailThrottle(
  env: Env,
  type: EmailType,
  identifier: string,
): Promise<Response | null> {
  const cfg = THROTTLE_CONFIG[type];
  const windowSlot = Math.floor(Date.now() / (cfg.windowSec * 1000));
  const key = `${cfg.keyPrefix}:${identifier}:${windowSlot}`;

  const current = parseInt((await env.RATE_LIMIT_KV.get(key)) ?? "0", 10);
  if (current >= cfg.limit) {
    return new Response(
      JSON.stringify({ error: `Too many ${type.replace("_", " ")} emails. Try again later.` }),
      { status: 429, headers: { "Content-Type": "application/json" } },
    );
  }

  await env.RATE_LIMIT_KV.put(key, String(current + 1), {
    expirationTtl: cfg.windowSec * 2,
  });
  return null; // allowed
}
