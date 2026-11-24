import { afterEach, describe, expect, it, vi } from 'vitest';
import { db } from '../lib/db';

const environment = {
  SUPABASE_URL: 'https://synthetic.invalid',
  SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service-key',
} as Parameters<typeof db>[0];

afterEach(() => vi.unstubAllGlobals());

describe('database RPC response contracts', () => {
  it('accepts the explicit SQL void contract without parsing a body', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(db(environment).rpc('synthetic_reservation', {}, 'void')).resolves.toBeUndefined();
  });

  it('preserves a JSON receipt for ordinary RPCs', async () => {
    const receipt = { kind: 'synthetic_receipt', operationId: 'synthetic-operation' };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(receipt)));
    await expect(db(environment).rpc('synthetic_receipt', {})).resolves.toEqual(receipt);
  });

  it('rejects empty responses for RPCs that require JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(db(environment).rpc('synthetic_receipt', {})).rejects.toThrow();
  });

  it.each(['', '{', '{"unexpected":true}'])('rejects a non-void success response for a void RPC (%j)', async body => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body, { status: 200 })));
    await expect(db(environment).rpc('synthetic_reservation', {}, 'void')).rejects.toThrow('expected a void response');
  });

  it('preserves database rejection rather than treating it as void success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('synthetic rejection', { status: 409 })));
    await expect(db(environment).rpc('synthetic_reservation', {}, 'void')).rejects.toThrow('DB rpc failed [409]');
  });
});
