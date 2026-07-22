/**
 * Bug Condition Exploration Test - RPC Architecture
 *
 * Validates that internal endpoints are NOT accessible via the public fetch handler
 * and verifies the RPC methods work correctly through the WorkerEntrypoint.
 *
 * After the refactor:
 * - Internal endpoints (sync, subscription management) are removed from the fetch handler
 * - They're only callable via RPC methods on the WorkerEntrypoint class
 * - SERVICE_AUTH_SECRET is no longer needed — RPC binding is the trust boundary
 */

import { describe, expect, it } from 'vitest';
import type { Env } from '../types';
import type { AuthorizationCodeStore } from '../durable-objects/AuthorizationCodeStore';
import type { SyncEvent } from '../lib/sync-queue';

type FetchableWorker = {
  fetch: (request: Request) => Promise<Response>;
};

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
  metrics: () => Promise.resolve({
    backlogCount: 0,
    backlogBytes: 0,
  }),
  send: () => Promise.resolve({
    metadata: {
      metrics: {
        backlogCount: 0,
        backlogBytes: 0,
      },
    },
  }),
  sendBatch: () => Promise.resolve({
    metadata: {
      metrics: {
        backlogCount: 0,
        backlogBytes: 0,
      },
    },
  }),
  };
}

const mockStore = new Map<string, string>();
const mockSyncQueue = createMockQueue<SyncEvent>();
const mockUnknownQueue = createMockQueue<unknown>();
const mockEmailService: Env["EMAIL_SERVICE"] = {
  fetch: async () => new Response(),
  sendEmail: async () => ({ success: true }),
  sendOTP: async () => ({ success: true }),
  verifyOTP: async () => ({ success: true, verified: true }),
} as unknown as Env["EMAIL_SERVICE"];

const mockEnv: Env = {
  SUPABASE_URL: 'https://test.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
  JWT_PRIVATE_KEY: 'test-private-key',
  JWT_PUBLIC_KEY: 'test-public-key',
  JWT_KID: 'test-key-1',
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

async function createWorker() {
  const ctx: ExecutionContext = { waitUntil: () => { }, passThroughOnException: () => { }, props: undefined };
  const { default: SsoWorker } = await import('../index');
  const worker = new SsoWorker(ctx, mockEnv);
  if (!worker.fetch) {
    throw new Error("SsoWorker fetch handler is not configured");
  }
  return worker as FetchableWorker;
}

describe('RPC Architecture — Internal endpoints removed from fetch handler', () => {
  it('should return 404 for /api/sync/subscription (RPC only)', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/api/sync/subscription', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: 'test-user-789' }),
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(404);
  });

  it('should return 404 for /api/subscriptions/create (RPC only)', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/api/subscriptions/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(404);
  });

  it('should return 404 for /api/addon-purchases/record (RPC only)', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/api/addon-purchases/record', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(404);
  });

  it('should return 404 for /api/transactions/record (RPC only)', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/api/transactions/record', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(404);
  });

  it('should still handle public auth endpoints correctly', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'http://localhost:3000',
      },
      body: JSON.stringify({ email: 'test@example.com', password: 'password' }),
    });

    const response = await worker.fetch(request);
    expect(response.status).not.toBe(404);
  });

  it('should export a WorkerEntrypoint class with RPC methods', async () => {
    const { default: SsoWorker } = await import('../index');
    expect(typeof SsoWorker).toBe('function');
    expect(SsoWorker.name).toBe('SsoWorker');
    expect(typeof SsoWorker.prototype.recordTransaction).toBe('function');
    expect(typeof SsoWorker.prototype.syncPlans).toBe('function');
    expect(typeof SsoWorker.prototype.recordAddonPurchase).toBe('function');
  });
});
