import { error } from '../lib/response';

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * In-memory rate limit store (per-worker instance)
 * 
 * Note: This is per-worker, not global. In production with multiple
 * workers, each worker has its own Map. For global rate limiting,
 * migrate to Cloudflare KV or Durable Objects.
 */
const rateLimitStore = new Map<string, RateLimitEntry>();

/**
 * Cleanup old entries every 5 minutes to prevent memory leaks
 */
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, entry] of rateLimitStore.entries()) {
    if (entry.resetAt < now) {
      rateLimitStore.delete(key);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`[rate-limit] Cleaned ${cleaned} expired entries`);
  }
}, 5 * 60 * 1000);

export interface RateLimitConfig {
  /** Maximum requests allowed in the window */
  maxRequests: number;
  /** Window duration in seconds */
  windowSeconds: number;
  /** Key prefix for this endpoint (e.g., 'login', 'signup') */
  keyPrefix: string;
}

/**
 * Rate limiting middleware using in-memory Map
 * 
 * Limits are per-IP address per-endpoint.
 * 
 * Example usage:
 * ```typescript
 * app.post('/auth/login', async (req) => {
 *   const rateLimitResponse = await rateLimit(rateLimits.login)(req);
 *   if (rateLimitResponse) return rateLimitResponse;
 *   return handleLogin(req);
 * });
 * ```
 * 
 * @param config Rate limit configuration
 * @returns Middleware function that returns Response if rate limited, null otherwise
 */
export function rateLimit(config: RateLimitConfig) {
  return async (request: Request): Promise<Response | null> => {
    // Get client IP (Cloudflare provides this for public internet requests)
    const cfIp = request.headers.get('cf-connecting-ip');
    
    // Service Bindings don't traverse the public internet, so CF-Connecting-IP is missing.
    // If it's missing (and no X-Forwarded-For fallback is present), it's an internal 
    // server-to-server request, which we should bypass rate limiting for.
    if (!cfIp && !request.headers.get('x-forwarded-for')) {
      return null;
    }

    const ip = cfIp || 
               request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
               'unknown';
    
    const key = `${config.keyPrefix}:${ip}`;
    const now = Date.now();
    const windowMs = config.windowSeconds * 1000;
    
    let entry = rateLimitStore.get(key);
    
    // Create new entry if doesn't exist or window expired
    if (!entry || entry.resetAt < now) {
      entry = {
        count: 1,
        resetAt: now + windowMs,
      };
      rateLimitStore.set(key, entry);
      return null; // Allow request
    }
    
    // Increment count
    entry.count++;
    
    // Check if limit exceeded
    if (entry.count > config.maxRequests) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      
      console.warn(`[rate-limit] ${config.keyPrefix} rate limit exceeded for IP ${ip}: ${entry.count}/${config.maxRequests}`);
      
      return new Response(
        JSON.stringify({
          error: 'Too many requests. Please try again later.',
          retryAfter,
          limit: config.maxRequests,
          window: config.windowSeconds,
        }),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': retryAfter.toString(),
            'X-RateLimit-Limit': config.maxRequests.toString(),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': entry.resetAt.toString(),
          },
        }
      );
    }
    
    // Allow request (add rate limit headers for transparency)
    return null;
  };
}

/**
 * Preset rate limit configurations for common endpoints
 * 
 * These are LENIENT limits per user requirement.
 * Adjust based on production traffic patterns.
 */
export const rateLimits = {
  /** Login: 10 requests per minute */
  login: { 
    maxRequests: 10, 
    windowSeconds: 60, 
    keyPrefix: 'login' 
  },
  
  /** Signup: 5 requests per hour */
  signup: { 
    maxRequests: 5, 
    windowSeconds: 3600, 
    keyPrefix: 'signup' 
  },
  
  /** Forgot password: 3 requests per hour */
  forgotPassword: { 
    maxRequests: 3, 
    windowSeconds: 3600, 
    keyPrefix: 'forgot' 
  },
  
  /** Reset password: 5 requests per hour */
  resetPassword: { 
    maxRequests: 5, 
    windowSeconds: 3600, 
    keyPrefix: 'reset' 
  },
  
  /** Verify email: 10 requests per hour */
  verifyEmail: { 
    maxRequests: 10, 
    windowSeconds: 3600, 
    keyPrefix: 'verify' 
  },
  
  /** Resend verification: 3 requests per hour */
  resendVerification: { 
    maxRequests: 3, 
    windowSeconds: 3600, 
    keyPrefix: 'resend' 
  },
  
  /** Refresh token: 30 requests per minute */
  refresh: { 
    maxRequests: 30, 
    windowSeconds: 60, 
    keyPrefix: 'refresh' 
  },
  
  /** Get user info (/auth/me): 60 requests per minute */
  me: { 
    maxRequests: 60, 
    windowSeconds: 60, 
    keyPrefix: 'me' 
  },
  
  /** Logout: 20 requests per minute */
  logout: { 
    maxRequests: 20, 
    windowSeconds: 60, 
    keyPrefix: 'logout' 
  },
};

/**
 * Get rate limit stats (for debugging)
 */
export function getRateLimitStats(): { totalKeys: number; entries: Array<{ key: string; count: number; resetAt: number }> } {
  const entries = Array.from(rateLimitStore.entries()).map(([key, entry]) => ({
    key,
    count: entry.count,
    resetAt: entry.resetAt,
  }));
  
  return {
    totalKeys: rateLimitStore.size,
    entries,
  };
}
