import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SsoWorker } from '../index';
import { db } from '../lib/db';
import type { Env } from '../types';

const environment = { SUPABASE_URL: 'https://sso.example.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service-key' } as Env;
const planId = 'a0000000-0000-4000-8000-000000000001';
let transport = vi.fn<typeof fetch>();
beforeEach(() => {
  transport = vi.fn<typeof fetch>().mockImplementation(async () => new Response('[]'));
  vi.stubGlobal('fetch', transport);
});
afterEach(() => vi.unstubAllGlobals());
const worker = () => new SsoWorker({} as ExecutionContext, environment);

describe('actual SSO inventory binding through the real database HTTP client', () => {
  it('accepts an explicitly returned empty JSON array as a real empty catalog', async () => {
    await expect(worker().getSubscriptionCatalogInventory()).resolves.toEqual({ schemaVersion: 1, plans: [] });
    expect(transport).toHaveBeenCalledTimes(1);
    const url = new URL(String(transport.mock.calls[0][0]));
    expect(url.origin).toBe(environment.SUPABASE_URL);
    expect(url.pathname).toBe('/rest/v1/plans');
  });

  it('reads a real JSON plan page and a terminal empty page without mocking its subject', async () => {
    transport.mockResolvedValueOnce(new Response(JSON.stringify([{ id: planId, plan_code: 'hybrid', product_id: null,
      name: 'Hybrid', is_active: true, applicable_entities: ['college'] }])));
    const result = await worker().getSubscriptionCatalogInventory();
    expect(result.plans).toEqual([{ id: planId, code: 'hybrid', productId: null, name: 'Hybrid', isActive: true, applicableEntities: ['college'] }]);
    expect(transport).toHaveBeenCalledTimes(2);
    expect(new URL(String(transport.mock.calls[1][0])).searchParams.get('id')).toBe(`gt.${planId}`);
  });

  it.each([
    { status: 200, body: '' }, { status: 204, body: null },
    { status: 200, body: '{}' }, { status: 200, body: 'null' }, { status: 200, body: 'invalid-json' },
  ])('rejects missing or malformed HTTP evidence instead of inventing an empty catalog %j', async ({ status, body }) => {
    transport.mockImplementation(async () => new Response(body, { status }));
    await expect(worker().getSubscriptionCatalogInventory()).rejects.toThrow('DB query expected a JSON array');
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('surfaces network rejection without retrying', async () => {
    const failure = new TypeError('Synthetic unavailable transport'); transport.mockRejectedValue(failure);
    await expect(worker().getSubscriptionCatalogInventory()).rejects.toBe(failure);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('retains the pre-existing explicit DELETE minimal-response contract', async () => {
    transport.mockImplementation(async () => new Response(null, { status: 204 }));
    await expect(db(environment).query('synthetic_table?id=eq.synthetic', { method: 'DELETE' })).resolves.toEqual([]);
    expect(transport.mock.calls[0][1]?.method).toBe('DELETE');
  });
});
