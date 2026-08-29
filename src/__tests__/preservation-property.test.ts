/**
 * Preservation Property Tests - SSO Worker RPC Architecture
 *
 * Validates against the private RPC binding surface that:
 * - User authentication still works on protected RPC methods
 * - Public RPC methods (getJwks) remain accessible without auth
 * - Invalid/expired/missing credentials are rejected
 */

import { SignJWT, importPKCS8 } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthorizationCodeStore } from '../durable-objects/AuthorizationCodeStore';
import { JWT_AUDIENCE, JWT_ISSUER } from '../lib/constants';
import type { CorrelationId } from '../rpc/contracts';
import type { SyncEvent } from '../lib/sync-queue';
import type { Env } from '../types';

function createDurableObjectId(value: string): DurableObjectId {
  return {
    toString: () => value,
    equals: (other: DurableObjectId) => other.toString() === value,
  };
}

function createAuthorizationCodeNamespace(): DurableObjectNamespace<AuthorizationCodeStore> {
  const namespace = {
    newUniqueId: () => createDurableObjectId(""),
    idFromName: (name: string) => createDurableObjectId(name),
    idFromString: (id: string) => createDurableObjectId(id),
    get: (_id: DurableObjectId) => ({} as DurableObjectStub<AuthorizationCodeStore>),
    getByName: (name: string) => namespace.get(namespace.idFromName(name)),
    jurisdiction: () => namespace,
  };
  return namespace as DurableObjectNamespace<AuthorizationCodeStore>;
}

function createMockQueue<T>(): Queue<T> {
  return {
    metrics: () => Promise.resolve({ backlogCount: 0, backlogBytes: 0 } as any),
    send: () => Promise.resolve({} as any),
    sendBatch: () => Promise.resolve({} as any),
  };
}

const mockStore = new Map<string, string>();
const mockSyncQueue = createMockQueue<SyncEvent>();
const mockUnknownQueue = createMockQueue<unknown>();
const mockEmailService: Env["EMAIL_SERVICE"] = {
  fetch: async () => new Response(),
  connect: () => { throw new Error("Not implemented"); },
  sendEmail: async () => ({ success: true }),
  sendOTP: async () => ({ success: true }),
  verifyOTP: async () => ({ success: true, verified: true }),
} as Env["EMAIL_SERVICE"];

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
  JWKS_FRESHNESS_SECONDS: '300',
  ALLOWED_ORIGINS: 'http://localhost:3000',
  RATE_LIMIT_KV: {
    get: (k: string) => Promise.resolve(mockStore.get(k) ?? null),
    put: (k: string, v: string) => { mockStore.set(k, v); return Promise.resolve(); },
    delete: (k: string) => { mockStore.delete(k); return Promise.resolve(); },
    list: () => Promise.resolve({ keys: [] }),
    getWithMetadata: () => Promise.resolve({ value: null, metadata: null }),
  } as unknown as KVNamespace,
  AUTH_CODE_STORE: createAuthorizationCodeNamespace(),
  EMAIL_SERVICE: mockEmailService,
  ALLOWED_APP_URLS: "https://skillpassport.rareminds.in",
  SYNC_QUEUE: mockSyncQueue,
  LEARNER_ADMISSION_QUEUE: mockUnknownQueue,
  EMAIL_QUEUE: mockUnknownQueue,
  SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
  INTERNAL_WEBHOOK_SECRET: "test_webhook_secret"
};

let supabaseFetch: ReturnType<typeof vi.fn>;

beforeEach(() => {
  supabaseFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const restPath = url.match(/\/rest\/v1\/([^?]+)/)?.[1] ?? "";
    const method = (init?.method ?? "GET").toUpperCase();
    if (restPath.startsWith("users") && method === "GET") {
      return new Response(JSON.stringify([{
        id: "test-user-123",
        email: "test@example.com",
        is_email_verified: true,
        user_metadata: {},
        is_blocked: false,
      }]), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (restPath.startsWith("rpc/get_jwt_claims") && method === "POST") {
      return new Response(JSON.stringify({
        roles: ["user"],
        products: [],
        membership_status: "active",
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.spyOn(globalThis, "fetch").mockImplementation(supabaseFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function createWorker() {
  const ctx: ExecutionContext = { waitUntil: () => { }, passThroughOnException: () => { }, props: undefined };
  const { default: SsoWorker } = await import('../index');
  return new SsoWorker(ctx, mockEnv);
}

const correlationId = "corr_preservation_test" as CorrelationId;

describe('Property: RPC Surface Works Correctly', () => {
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

  it('should accept valid user JWT on getIdentity', async () => {
    const worker = await createWorker();
    const outcome = await worker.getIdentity({
      accessToken: validUserJWT,
      correlationId,
    });

    expect(outcome.kind).toBe("succeeded");
    if (outcome.kind === "succeeded") {
      expect(outcome.data.subject).toBe('test-user-123');
      expect(outcome.data.email).toBe('test@example.com');
    }
  });

  it('should reject expired JWT on protected RPC methods', async () => {
    const worker = await createWorker();
    const outcome = await worker.getIdentity({
      accessToken: expiredUserJWT,
      correlationId,
    });

    expect(outcome.kind).toBe("rejected");
    if (outcome.kind === "rejected") expect(outcome.code).toBe("authorization_denied");
  });

  it('should reject invalid JWT on protected RPC methods', async () => {
    const worker = await createWorker();
    const outcome = await worker.getIdentity({
      accessToken: 'invalid-jwt-token',
      correlationId,
    });

    expect(outcome.kind).toBe("rejected");
    if (outcome.kind === "rejected") expect(outcome.code).toBe("authorization_denied");
  });

  it('should reject requests with no authentication on protected RPC methods', async () => {
    const worker = await createWorker();
    const outcome = await worker.getIdentity({
      accessToken: '',
      correlationId,
    });

    expect(outcome.kind).toBe("rejected");
    if (outcome.kind === "rejected") expect(outcome.code).toBe("authorization_denied");
  });

  it('should allow access to public RPC methods without authentication', async () => {
    const worker = await createWorker();
    const outcome = await worker.getJwks({ correlationId });

    expect(outcome.kind).toBe("succeeded");
    if (outcome.kind === "succeeded") {
      expect(outcome.keys).toBeDefined();
      expect(Array.isArray(outcome.keys)).toBe(true);
      expect(outcome.keys.length).toBeGreaterThan(0);
    }
  });

  it('should expose the authoritative JWKS key with the configured kid', async () => {
    const worker = await createWorker();
    const outcome = await worker.getJwks({ correlationId });

    expect(outcome.kind).toBe("succeeded");
    if (outcome.kind === "succeeded") {
      expect(outcome.keys[0]).toMatchObject({ kid: mockEnv.JWT_KID, alg: 'RS256' });
    }
  });
});
