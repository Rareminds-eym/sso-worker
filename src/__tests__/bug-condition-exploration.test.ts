/**
 * Bug Condition Exploration Test - RPC Architecture
 *
 * Validates that internal operations are NOT reachable via HTTP: the
 * SsoWorker entrypoint exposes no fetch handler of its own, so every HTTP
 * request falls through to the WorkerEntrypoint default (501 Not Implemented).
 * Internal operations are only callable via RPC methods on the entrypoint.
 */

import { describe, expect, it } from 'vitest';
import type { AuthorizationCodeStore } from '../durable-objects/AuthorizationCodeStore';
import type { SyncEvent } from '../lib/sync-queue';
import type { Env } from '../types';

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
  JWT_PRIVATE_KEY: 'test-private-key',
  JWT_PUBLIC_KEY: 'test-public-key',
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

async function createWorker() {
  const ctx: ExecutionContext = { waitUntil: () => { }, passThroughOnException: () => { }, props: undefined };
  const { default: SsoWorker } = await import('../index');
  const worker = new SsoWorker(ctx, mockEnv);
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
    expect(response.status).toBe(501);
  });

  it('should return 404 for /api/subscriptions/create (RPC only)', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/api/subscriptions/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(501);
  });

  it('should return 404 for /api/addon-purchases/record (RPC only)', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/api/addon-purchases/record', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(501);
  });

  it('should return 404 for /api/transactions/record (RPC only)', async () => {
    const worker = await createWorker();
    const request = new Request('https://sso-api/api/transactions/record', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const response = await worker.fetch(request);
    expect(response.status).toBe(501);
  });

  it('should not expose any HTTP routes on the entrypoint', async () => {
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
    expect(response.status).toBe(501);
  });

  it('should export a WorkerEntrypoint class with no own fetch handler and RPC methods', async () => {
    const { default: SsoWorker } = await import('../index');
    expect(typeof SsoWorker).toBe('function');
    expect(SsoWorker.name).toBe('SsoWorker');
    expect(Object.getOwnPropertyNames(SsoWorker.prototype)).not.toContain('fetch');
    expect(typeof SsoWorker.prototype.recordTransaction).toBe('function');
    expect(typeof SsoWorker.prototype.syncPlans).toBe('function');
    expect(typeof SsoWorker.prototype.recordAddonPurchase).toBe('function');
  });
});
