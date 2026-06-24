/**
 * Preservation Property Tests - SSO Worker RPC Architecture
 *
 * Validates that:
 * - User authentication still works on public endpoints
 * - Public endpoints remain accessible without auth
 * - JWKS endpoint works
 * - The SsoWorker export is a proper WorkerEntrypoint class
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT, importPKCS8 } from 'jose';
import { JWT_ISSUER, JWT_AUDIENCE } from '../lib/constants';
import type { Env } from '../types';
import type { ExecutionContext } from '@cloudflare/workers-types';

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
  EMAIL_SERVICE: {
    fetch: async () => new Response(),
    sendEmail: async () => ({ success: true }),
    sendOTP: async () => ({ success: true }),
    verifyOTP: async () => ({ success: true })
  } as any,
  EMAIL_API_KEY: "test_email_key",
  ALLOWED_APP_URLS: "https://skillpassport.rareminds.in",
  SYNC_QUEUE: { send: () => Promise.resolve() } as unknown as Queue<any>,
  SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
  SKILLPASSPORT: {} as any,
  INTERNAL_WEBHOOK_SECRET: "test_webhook_secret"
};

async function createWorker() {
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as any;
  const { default: SsoWorker } = await import('../index');
  return new SsoWorker(ctx, mockEnv);
}

describe('Property: Public Endpoints Work Correctly', () => {
  let validUserJWT: string;
  let expiredUserJWT: string;

  beforeAll(async () => {
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
      .setIssuer(JWT_ISSUER)
      .setAudience(JWT_AUDIENCE)
      .sign(privateKey);

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
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime('-30m')
      .setIssuer(JWT_ISSUER)
      .setAudience(JWT_AUDIENCE)
      .sign(privateKey);
  });

  it('should accept valid user JWT on /auth/me endpoint', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${validUserJWT}`,
        'Origin': 'http://localhost:3000',
      },
    });

    const response = await worker.fetch(request);
    expect(response.status).not.toBe(401);
  });

  it('should reject expired JWT on user-facing endpoints', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${expiredUserJWT}`,
        'Origin': 'http://localhost:3000',
      },
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(401);
  });

  it('should reject invalid JWT on user-facing endpoints', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer invalid-jwt-token',
        'Origin': 'http://localhost:3000',
      },
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(401);
  });

  it('should reject requests with no authentication on protected endpoints', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/auth/me', {
      method: 'GET',
      headers: { 'Origin': 'http://localhost:3000' },
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(401);
  });

  it('should allow access to public endpoints without authentication', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/health', {
      method: 'GET',
      headers: { 'Origin': 'http://localhost:3000' },
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(200);
  });

  it('should allow access to JWKS endpoint without authentication', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/.well-known/jwks.json', {
      method: 'GET',
      headers: { 'Origin': 'http://localhost:3000' },
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(200);

    const body = await response.json() as { keys: unknown[] };
    expect(body).toHaveProperty('keys');
    expect(Array.isArray(body.keys)).toBe(true);
  });
});
