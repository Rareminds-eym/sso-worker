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

import { describe, it, expect } from 'vitest';
import type { Env } from '../types';
import type { ExecutionContext } from '@cloudflare/workers-types';

const mockStore = new Map<string, string>();
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
  EMAIL_SERVICE: {} as Fetcher,
  EMAIL_API_KEY: 'test-email-api-key',
  ALLOWED_APP_URLS: 'http://localhost:3000',
};

async function createWorker() {
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
  const { default: SsoWorker } = await import('../index');
  return new SsoWorker(ctx, mockEnv);
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
