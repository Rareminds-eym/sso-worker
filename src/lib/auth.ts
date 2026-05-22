import type { Env, AccessTokenPayload } from "../types";
import { verifyAccessToken } from "./jwt";
import { getCookie } from "./cookies";

/**
 * Constant-time string comparison to prevent timing attacks.
 * Compares two strings byte-by-byte in constant time.
 */
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  // Using HMAC ensures we always compare two 32-byte buffers
  // regardless of the input string lengths, preventing length leakage
  const key = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  
  const sigA = await crypto.subtle.sign("HMAC", key, encoder.encode(a));
  const sigB = await crypto.subtle.sign("HMAC", key, encoder.encode(b));
  
  const bufA = new Uint8Array(sigA);
  const bufB = new Uint8Array(sigB);
  
  try {
    return crypto.subtle.timingSafeEqual(bufA, bufB);
  } catch {
    let result = 0;
    for (let i = 0; i < bufA.length; i++) {
      result |= bufA[i] ^ bufB[i];
    }
    return result === 0;
  }
}

/**
 * Extract and verify the access token from a request.
 * Checks Authorization header first, then falls back to cookie.
 * Returns the verified payload or null if unauthenticated.
 * 
 * @param req - The incoming request
 * @param env - Environment variables
 * @param serviceAuth - If true, only accept service secrets (reject user JWTs)
 */
export async function authenticate(
  req: Request,
  env: Env,
  serviceAuth?: boolean,
): Promise<AccessTokenPayload | null> {
  const token = extractToken(req);
  if (!token) return null;

  // Service authentication: only accept service secrets
  if (serviceAuth === true) {
    // Check if token matches SERVICE_AUTH_SECRET using constant-time comparison
    if (await timingSafeEqual(token, env.SERVICE_AUTH_SECRET)) {
      // Return service account payload
      return {
        sub: "service",
        email: "service@internal",
        org_id: "system",
        roles: ["service"],
        products: [],
        membership_status: "active",
        is_email_verified: true,
      };
    }
    
    // Service auth enabled but token doesn't match - reject immediately
    // Do NOT fall back to JWT verification
    return null;
  }

  // Standard user authentication: verify JWT
  try {
    return await verifyAccessToken(token, env);
  } catch {
    return null;
  }
}

/** Extract raw token string from header or cookie (no verification) */
export function extractToken(req: Request): string | null {
  const authHeader = req.headers.get("Authorization");
  if (authHeader) {
    if (!authHeader.startsWith("Bearer ")) return null;
    const token = authHeader.slice(7);
    return token || null;
  }
  return getCookie(req, "access_token");
}
