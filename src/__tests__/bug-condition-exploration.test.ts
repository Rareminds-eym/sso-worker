/**
 * Bug Condition Exploration Test - SSO Internal Service Authentication
 * 
 * Feature: sso-internal-service-auth
 * Property 1: Bug Condition - Sync Endpoints Accept User JWT Tokens (Security Vulnerability)
 * Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5
 * 
 * CRITICAL: This test MUST FAIL on unfixed code - failure confirms the bug exists
 * DO NOT attempt to fix the test or the code when it fails
 * 
 * This test encodes the expected behavior - it will validate the fix when it passes after implementation
 * 
 * GOAL: Surface counterexamples that demonstrate the security vulnerability exists
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

describe('Property 1: Bug Condition - Sync Endpoints Accept User JWT Tokens', () => {
  let validUserJWT: string;
  
  beforeAll(async () => {
    // Generate a valid user JWT token for testing
    const privateKey = await importPKCS8(mockEnv.JWT_PRIVATE_KEY, 'RS256');
    
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
  });

  /**
   * Test 1: User JWT should be REJECTED on /api/sync/subscription
   * 
   * EXPECTED ON UNFIXED CODE: This test FAILS (user JWT is accepted - security vulnerability)
   * EXPECTED ON FIXED CODE: This test PASSES (user JWT is rejected - bug is fixed)
   */
  it('should reject user JWT tokens on /api/sync/subscription endpoint', async () => {
    const request = new Request('https://sso-api/api/sync/subscription', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${validUserJWT}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ user_id: 'other-user-789' }),
    });

    // Import the worker to test
    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as any);

    // EXPECTED BEHAVIOR: User JWT should be rejected (401 Unauthorized)
    expect(response.status).toBe(401);
    
    const body = await response.json() as { error: string };
    expect(body.error).toContain('Unauthorized');
  });

  /**
   * Test 2: User JWT should be REJECTED on /api/sync/plans
   * 
   * EXPECTED ON UNFIXED CODE: This test FAILS (user JWT is accepted - security vulnerability)
   * EXPECTED ON FIXED CODE: This test PASSES (user JWT is rejected - bug is fixed)
   */
  it('should reject user JWT tokens on /api/sync/plans endpoint', async () => {
    const request = new Request('https://sso-api/api/sync/plans', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${validUserJWT}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as any);

    // EXPECTED BEHAVIOR: User JWT should be rejected (401 Unauthorized)
    expect(response.status).toBe(401);
    
    const body = await response.json() as { error: string };
    expect(body.error).toContain('Unauthorized');
  });

  /**
   * Test 3: User JWT should be REJECTED on /api/sync/reconcile
   * 
   * EXPECTED ON UNFIXED CODE: This test FAILS (user JWT is accepted - security vulnerability)
   * EXPECTED ON FIXED CODE: This test PASSES (user JWT is rejected - bug is fixed)
   */
  it('should reject user JWT tokens on /api/sync/reconcile endpoint', async () => {
    const request = new Request('https://sso-api/api/sync/reconcile', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${validUserJWT}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ user_ids: ['user-1', 'user-2'] }),
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as any);

    // EXPECTED BEHAVIOR: User JWT should be rejected (401 Unauthorized)
    expect(response.status).toBe(401);
    
    const body = await response.json() as { error: string };
    expect(body.error).toContain('Unauthorized');
  });

  /**
   * Test 4: Service secret should be ACCEPTED on /api/sync/subscription
   * 
   * EXPECTED ON UNFIXED CODE: This test FAILS (service secret is rejected - missing feature)
   * EXPECTED ON FIXED CODE: This test PASSES (service secret is accepted - feature implemented)
   */
  it('should accept valid service secret on /api/sync/subscription endpoint', async () => {
    const request = new Request('https://sso-api/api/sync/subscription', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${mockEnv.SERVICE_AUTH_SECRET}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ user_id: 'test-user-123' }),
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as any);

    // EXPECTED BEHAVIOR: Service secret should be accepted (200 OK)
    expect(response.status).toBe(200);
    
    const body = await response.json() as { subscription: unknown; plan: unknown };
    expect(body).toHaveProperty('subscription');
    expect(body).toHaveProperty('plan');
  });

  /**
   * Test 5: Service secret should be ACCEPTED on /api/sync/plans
   * 
   * EXPECTED ON UNFIXED CODE: This test FAILS (service secret is rejected - missing feature)
   * EXPECTED ON FIXED CODE: This test PASSES (service secret is accepted - feature implemented)
   */
  it('should accept valid service secret on /api/sync/plans endpoint', async () => {
    const request = new Request('https://sso-api/api/sync/plans', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${mockEnv.SERVICE_AUTH_SECRET}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as any);

    // EXPECTED BEHAVIOR: Service secret should be accepted (200 OK)
    expect(response.status).toBe(200);
    
    const body = await response.json() as { plans: unknown[] };
    expect(body).toHaveProperty('plans');
    expect(Array.isArray(body.plans)).toBe(true);
  });

  /**
   * Test 6: Invalid service secret should be REJECTED
   * 
   * EXPECTED ON UNFIXED CODE: This test PASSES (invalid secret is rejected)
   * EXPECTED ON FIXED CODE: This test PASSES (invalid secret is rejected)
   */
  it('should reject invalid service secret on sync endpoints', async () => {
    const request = new Request('https://sso-api/api/sync/subscription', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer wrong-secret',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ user_id: 'test-user-123' }),
    });

    const worker = await import('../index');
    const response = await worker.default.fetch(request, mockEnv, {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as any);

    // EXPECTED BEHAVIOR: Invalid secret should be rejected (401 Unauthorized)
    expect(response.status).toBe(401);
    
    const body = await response.json() as { error: string };
    expect(body.error).toContain('Unauthorized');
  });
});
