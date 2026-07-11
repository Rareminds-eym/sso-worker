/**
 * PHASE 2: Helper functions for checking Skillpassport DB
 * 
 * Uses HTTPS with caching to reduce 522 errors. Service binding not available for Pages.
 * First login may fail with 522, subsequent logins use cache and skip HTTP call.
 */

import type { Env } from '../types';

// In-memory cache for user existence checks (5 minute TTL)
const userExistsCache = new Map<string, { exists: boolean; timestamp: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Check if a user exists in Skillpassport database
 * 
 * ponytail: Only cache SUCCESS responses. On errors (522, timeout, etc), don't cache
 * and return false to trigger self-healing sync. If user exists, sync is idempotent (no harm).
 * If user missing, sync creates them (fixes the issue).
 * 
 * @param env - Worker environment with SKILLPASSPORT_URL
 * @param userId - UUID of the user to check
 * @returns true if user exists (verified), false if uncertain/error
 */
export async function checkUserExistsInSkillpassport(
  env: Env,
  userId: string
): Promise<boolean> {
  if (!env.SKILLPASSPORT_URL) {
    console.error('[SSO] SKILLPASSPORT_URL not configured');
    return false;
  }

  // Check cache first - but only for positive confirmations
  const cached = userExistsCache.get(userId);
  if (cached && cached.exists && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
    console.log(`[SSO] Cache hit: user ${userId} exists`);
    return true;
  }

  const timeout = 5000;
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    const startTime = Date.now();
    const response = await fetch(`${env.SKILLPASSPORT_URL}/api/sync/check-user`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId }),
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    const duration = Date.now() - startTime;
    
    if (!response.ok) {
      console.log(`[SSO] Skillpassport check failed: ${response.status} (${duration}ms) - will trigger sync`);
      // Don't cache errors - let sync handle it
      return false;
    }

    const result = await response.json() as { exists: boolean };
    console.log(`[SSO] User ${userId} exists: ${result.exists} (${duration}ms)`);
    
    // Only cache positive results (user exists)
    if (result.exists) {
      userExistsCache.set(userId, { exists: true, timestamp: Date.now() });
      
      // Limit cache size
      if (userExistsCache.size > 10000) {
        const oldestKey = userExistsCache.keys().next().value;
        if (oldestKey) userExistsCache.delete(oldestKey);
      }
    }
    
    return result.exists;
    
  } catch (err) {
    const errorMsg = err instanceof Error ? (err.name === 'AbortError' ? 'timeout' : err.message) : 'unknown';
    console.log(`[SSO] Skillpassport check error (${errorMsg}) - will trigger sync`);
    // Don't cache errors - return false to trigger self-healing sync
    return false;
  }
}

/**
 * Conditionally publish sync events only if user doesn't exist in Skillpassport
 * 
 * This implements the architecture diagram's "Check if user data is not there"
 * decision point before creating queue messages.
 */
export async function conditionalSyncPublish(
  env: Env,
  userId: string,
  publishFn: () => void
): Promise<void> {
  const exists = await checkUserExistsInSkillpassport(env, userId);
  
  if (!exists) {
    console.log(`[SSO] User ${userId} not in Skillpassport, publishing sync events`);
    publishFn();
  } else {
    console.log(`[SSO] User ${userId} already in Skillpassport, skipping sync`);
  }
}
