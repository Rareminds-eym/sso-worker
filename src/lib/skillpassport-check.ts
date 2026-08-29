/**
 * Helper functions for checking Skillpassport DB
 * 
 * Uses Cloudflare KV as a global cache to avoid redundant calls and prevent 522 cold-start issues.
 * Falls back to HTTPS with a strict timeout.
 */

import type { Env } from '../types';

const FETCH_TIMEOUT_MS = 5000;
const KV_TTL_SECONDS = 3600; // 1 hour

/**
 * Check if a user exists in Skillpassport database
 * 
 * Strategy: KV cache → HTTP fetch → false (trigger sync)
 * 
 * Only caches SUCCESS responses. On errors, returns false to trigger self-healing sync.
 * If user exists, sync is idempotent (no harm). If user missing, sync creates them.
 */
export async function checkUserExistsInSkillpassport(
  env: Env,
  userId: string
): Promise<boolean> {
  const kvKey = `sp-user:${userId}`;

  // 1. Fast Path: Check global KV cache
  try {
    const cached = await env.RATE_LIMIT_KV.get(kvKey);
    if (cached === 'true') {
      console.log(`[SSO KV] Cache hit: user ${userId} exists`);
      return true;
    }
  } catch (err) {
    // Graceful degradation: if KV fails, log and fall through to HTTP
    console.error(`[SSO KV] Error reading cache for ${userId}:`, err);
  }

  // 2. Slow Path: HTTP Fetch
  if (!env.SKILLPASSPORT_URL) {
    console.error('[SSO] SKILLPASSPORT_URL not configured');
    return false;
  }

  const startTime = Date.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let response: Response;

  try {
    response = await fetch(`${env.SKILLPASSPORT_URL}/api/sync/check-user`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Required by the receiver's internal-webhook gate (401 otherwise).
        ...(env.INTERNAL_WEBHOOK_SECRET
          ? { Authorization: `Bearer ${env.INTERNAL_WEBHOOK_SECRET}` }
          : {}),
      },
      body: JSON.stringify({ userId }),
      signal: controller.signal,
    });
  } catch (err) {
    const errMsg = err instanceof Error
      ? (err.name === 'AbortError' ? 'timeout' : err.message)
      : 'unknown';
    const duration = Date.now() - startTime;
    console.log(`[SSO] Skillpassport check error (${errMsg}) (${duration}ms) - will trigger sync`);
    return false;
  } finally {
    clearTimeout(timeoutId);
  }

  const duration = Date.now() - startTime;

  if (!response.ok) {
    console.log(`[SSO] Skillpassport check failed: ${response.status} (${duration}ms) - will trigger sync`);
    return false;
  }

  const result = await response.json() as { exists: boolean };
  console.log(`[SSO] User ${userId} exists: ${result.exists} (${duration}ms)`);

  // 3. Update Cache on Success
  if (result.exists) {
    try {
      await env.RATE_LIMIT_KV.put(kvKey, 'true', { expirationTtl: KV_TTL_SECONDS });
      console.log(`[SSO KV] Cached user ${userId} for ${KV_TTL_SECONDS}s`);
    } catch (err) {
      console.warn(`[SSO KV] Failed to cache user ${userId}:`, err);
    }
  }

  return result.exists;
}
