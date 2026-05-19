/**
 * Preservation Property Tests - SSO Internal Service Authentication
 * 
 * Feature: sso-internal-service-auth
 * Property 2: Preservation - User Authentication for Non-Sync Endpoints
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7
 * 
 * IMPORTANT: Follow observation-first methodology
 * These tests capture the baseline behavior that must be preserved after the fix
 * 
 * EXPECTED OUTCOME: Tests PASS on both unfixed and fixed code (no regressions)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT, importPKCS8 } from 'jose';
import type { Env } from '../types';

// Mock environment for testing
const mockEnv: Env = {
  SUPABASE_URL: 'https://test.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
  JWT_PRIVATE_KEY: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZwXMZz+7w2tyS
NDT3hfcZ7q+NM/0aFAo8o6+3Ck2Lg9wcd+14W0Lani09zZ+Yx4JGzvVSaJFbPWr+
THEwpbBstFsG0wN5MYayF4z0MT+/iMz+aWhm4ciA9SzupRAPjLCSjjggQVttP7GG
JUiIn7uI4sEHbj3Xy7PIfT2ooatHE/Xhpc9mOuDxrPQ2p2h0bDViy6XWL3dPVJWr
bQbnijIdGhP6cU2GJKVkn3noBQ4Uo6EbN28Zjt8S9LIboPCAi9oX+wt1gsNE+9LU
aBIIeJxGOuyL5FP397GE0X/S7vVqdYApUBU22fpqrqBnKtbGkoiLacG9QNRdG5OW
ClHSrHtRAgMBAAECggEABvXm3urmxWTVEjHWmYOJLpV7gUwSl9cDKSBcZLAM12Vs
ZiYIPDf+cGzzfZ4kzNrwUwIMwVKuTOf8g19kyuffUyZ9jfMoz7heIYsXJJljqkk4
RYayVSEAzZS72GBk2B1dg374e75VtB4LbHgc3uGDUQS56hsTpeSpAokn7M3H1hd3
VmNyq6jSZ1tkWt0Aw0/aAKogWsTqmsah2lyMmXjPJQM5xQf8jQ6jy7cWX+KlxBjJ
hxNHCwWkjHhXrPTBi4YI67a1th8u0h8slyRv78suUTpEuN89N4pKl8uWB146O9f7
J3O30k18unEs3xcprXy4/uvd1csZf/imyabWTvNT2QKBgQDXiBEmYnzlbrrtHWMi
0jEHrqsSycQHejjCLrk/p7v9TFff5GStOapsI/feZ7tQFbKwhLLMkd/leruCez4F
KpaQQASmbgZoWFu9fp3xGuV+clqrsEOxGeJw0zUDBb1+KhPL78g1p5QeEDNYjX3l
cKQ2HIQG/FBeMf/Hbm+KOidh2QKBgQC2oAI3hIDPm9tIqjUK20RlEMbNibSK9q+X
N4JfQwyR/4wyRgYavuXbTK4dQZPnHJYtfEWHKYpGlZyhA1R/pfA+2mDFMCK4POz9
M54uPUKwNYXZ+KI8UGEFn52walSWFPNP27SnWnBt8hr1Vn8Gszm/j9aTMEEERoNO
wT9tf8QCOQKBgQCjTpT4CZ3q1bjK2v53rt25nW5AISLoK4KAF5kDk1tMdKEMouhp
nIz1vVcdbGmwJ5CqURGNEWadYR5conb+wSMuD2O2mx09yN1SOnL/8co7wffTqQ3R
TfSWWmILdTj8NHOljXycsun20X2mNidTRsMVwQuEo39dr/LHMHVRPfkDGQKBgFDi
OVkhZHOO0eYzDF8MkhQ5A/PQg5fwfgB5Y1KRvaWECzHQ9a8u0Vr5cTwf6UO404K9
wYWFjmqIpOBjOy917RvJWIa9NQNoaIYUMIDGPR0R94B8sE4KQ45cDVkvHtuB1+mM
o0xjr9viGLKEZqovAuqm6CA0hPdBy7I7wL3ckpFxAoGASSuskK/jk4aFKiZZB/NK
mDRtM/CH0oRuxPgjYP33/VogStik0XQlfBuo6/jyqaJ2xPMzzDwk1vWJ05dK0mYJ
XjbVuUWcWVIQDuTKMZKh+QniwT+c8QCfh/uhIVGATAT6qPXPp5U2zPyWaNMaP9fi
8mttsTBNPjOJSfL5k3OIpj0=
-----END PRIVATE KEY-----`,
  JWT_PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmcFzGc/u8NrckjQ094X3
Ge6vjTP9GhQKPKOvtwpNi4PcHHfteFtC2p4tPc2fmMeCRs71UmiRWz1q/kxxMKWw
bLRbBtMDeTGGsheM9DE/v4jM/mloZuHIgPUs7qUQD4ywko44IEFbbT+xhiVIiJ+7
iOLBB24918uzyH09qKGrRxP14aXPZjrg8az0NqdodGw1Ysul1i93T1SVq20G54oy
HRoT+nFNhiSlZJ956AUOFKOhGzdvGY7fEvSyG6DwgIvaF/sLdYLDRPvS1GgSCHic
Rjrsi+RT9/exhNF/0u71anWAKVAVNtn6aq6gZyrWxpKIi2nBvUDUXRuTlgpR0qx7
UQIDAQAB
-----END PUBLIC KEY-----`,
  JWT_KID: 'test-key-1',
  ALLOWED_ORIGINS: 'http://localhost:3000',
  RATE_LIMIT_KV: {} as KVNamespace,
  EMAIL_SERVICE: {} as Fetcher,
  EMAIL_API_KEY: 'test-email-api-key',
  ALLOWED_APP_URLS: 'http://localhost:3000',
  SERVICE_AUTH_SECRET: 'test-service-secret-32-bytes-long-base64-encoded',
};

describe('Property 2: Preservation - User Authentication for Non-Sync Endpoints', () => {
  let validUserJWT: string;
  let expiredUserJWT: string;
  
  beforeAll(async () => {
    const privateKey = await importPKCS8(mockEnv.JWT_PRIVATE_KEY, 'RS256');
    
    // Generate a valid user JWT token
    validUserJWT = await new SignJWT({
      sub: 'test-user-123',
      email: 'test@example.com',
      org_id: 'test-org-456',
      roles: ['user'],
      products: [],
      membership_status: 'active',
      is_email_verified: true,
    })
      .setProtectedHeader({ alg: 'RS256', kid: mockEnv.JWT_KID, typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime('15m')
      .setIssuer('https://sso.rareminds.in')
      .setAudience('https://skillpassport.rareminds.in')
      .sign(privateKey);
    
    // Generate an expired JWT token
    expiredUserJWT = await new SignJWT({
      sub: 'test-user-123',
      email: 'test@example.com',
      org_id: 'test-org-456',
      roles: ['user'],
      products: [],
      membership_status: 'active',
      is_email_verified: true,
    })
      .setProtectedHeader({ alg: 'RS256', kid: mockEnv.JWT_KID, typ: 'JWT' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600) // 1 hour ago
      .setExpirationTime('-30m') // Expired 30 minutes ago
      .setIssuer('https://sso.rareminds.in')
      .setAudience('https://skillpassport.rareminds.in')
      .sign(privateKey);
  });

  /**
   * Test 1: /auth/me should accept valid user JWT tokens
   * 
   * PRESERVATION: This behavior must remain unchanged after the fix
   */
  it('should accept valid user JWT on /auth/me endpoint', async () => {
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${validUserJWT}`,
        'Origin': 'http://localhost:3000',
      },
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext);

    // User-facing endpoint should accept valid JWT
    expect(response.status).not.toBe(401);
  });

  /**
   * Test 2: User-facing endpoints should reject expired JWT tokens
   * 
   * PRESERVATION: This behavior must remain unchanged after the fix
   */
  it('should reject expired JWT on user-facing endpoints', async () => {
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${expiredUserJWT}`,
        'Origin': 'http://localhost:3000',
      },
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext);

    // Expired JWT should be rejected
    expect(response.status).toBe(401);
  });

  /**
   * Test 3: User-facing endpoints should reject invalid JWT tokens
   * 
   * PRESERVATION: This behavior must remain unchanged after the fix
   */
  it('should reject invalid JWT on user-facing endpoints', async () => {
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer invalid-jwt-token',
        'Origin': 'http://localhost:3000',
      },
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext);

    // Invalid JWT should be rejected
    expect(response.status).toBe(401);
  });

  /**
   * Test 4: User-facing endpoints should reject requests with no auth
   * 
   * PRESERVATION: This behavior must remain unchanged after the fix
   */
  it('should reject requests with no authentication on protected endpoints', async () => {
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Origin': 'http://localhost:3000',
      },
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext);

    // No auth should be rejected
    expect(response.status).toBe(401);
  });

  /**
   * Test 5: Service secrets should NOT work on user-facing endpoints
   * 
   * PRESERVATION: User-facing endpoints should only accept user JWTs, not service secrets
   */
  it('should reject service secrets on user-facing endpoints', async () => {
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${mockEnv.SERVICE_AUTH_SECRET}`,
        'Origin': 'http://localhost:3000',
      },
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext);

    // Service secret should be rejected on user-facing endpoints
    expect(response.status).toBe(401);
  });

  /**
   * Test 6: Public endpoints should work without authentication
   * 
   * PRESERVATION: Public endpoints must remain accessible
   */
  it('should allow access to public endpoints without authentication', async () => {
    const request = new Request('https://sso-api/health', {
      method: 'GET',
      headers: {
        'Origin': 'http://localhost:3000',
      },
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext);

    // Public endpoint should be accessible
    expect(response.status).toBe(200);
  });

  /**
   * Test 7: JWKS endpoint should work without authentication
   * 
   * PRESERVATION: JWKS endpoint must remain publicly accessible
   */
  it('should allow access to JWKS endpoint without authentication', async () => {
    const request = new Request('https://sso-api/.well-known/jwks.json', {
      method: 'GET',
      headers: {
        'Origin': 'http://localhost:3000',
      },
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext);

    // JWKS endpoint should be accessible
    expect(response.status).toBe(200);
    
    const body = await response.json() as { keys: unknown[] };
    expect(body).toHaveProperty('keys');
    expect(Array.isArray(body.keys)).toBe(true);
  });
});
