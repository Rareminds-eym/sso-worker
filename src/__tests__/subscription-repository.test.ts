import { describe, expect, it, vi } from 'vitest';
import type { DbClient } from '../lib/db';
import {
  CatalogPersistenceError, CatalogValidationError, readPlanRevision, stagePlanRevision,
  type CatalogRegistry,
} from '../lib/subscriptions';

const productId = '912d5049-e195-46e9-a319-49e3502bf7e7';
const planId = 'a0000000-0000-4000-8000-000000000041';
const revisionId = 'b0000000-0000-4000-8000-000000000001';
const actorId = 'd0000000-0000-4000-8000-000000000001';
const otherId = 'e0000000-0000-4000-8000-000000000001';
const stagedAt = '2026-11-17T10:30:00.123456+00:00';
const registry: CatalogRegistry = {
  productIds: new Set([productId]), audienceKeys: new Set(['college']),
  currencies: new Map([['INR', 2]]), featureTypes: new Map([['capacity', 'numeric_limit']]),
};
function draft() {
  return {
    schemaVersion: 1, id: revisionId,
    plan: { id: planId, code: 'pln_8f3d2c6a91b74e50b5a36d02c7e8a419', productId },
    revisionNumber: 1, name: 'Editable proposal', audiences: ['college'],
    purchaseMode: 'contact_sales', prices: [],
    features: [{ key: 'capacity', type: 'numeric_limit', enabled: true, limit: { kind: 'contract_required' } }],
  };
}
function receipt() { return { draft: draft(), stagedBy: actorId, stagedAt }; }
function rpcClient(value: unknown) {
  const rpc = vi.fn<(...args: Parameters<DbClient['rpc']>) => Promise<unknown>>().mockResolvedValue(value);
  return { rpc };
}
function readClient(value: unknown[]) {
  const query = vi.fn<(...args: Parameters<DbClient['query']>) => Promise<unknown[]>>().mockResolvedValue(value);
  return { query };
}
function stored() { return { snapshot: draft(), staged_by: actorId, staged_at: stagedAt }; }

describe('draft staging adapter', () => {
  it('uses the existing RPC client and returns a detached immutable receipt', async () => {
    const response = receipt(), client = rpcClient(response), input = draft();
    const result = await stagePlanRevision(client, input, registry, actorId);
    expect(client.rpc).toHaveBeenCalledExactlyOnceWith('stage_subscription_plan_draft', {
      p_draft: input, p_staged_by: actorId,
    });
    expect(result).toEqual(response);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.draft.features[0])).toBe(true);
    input.name = 'Changed locally'; response.draft.name = 'Changed response';
    expect(result.draft.name).toBe('Editable proposal');
    expect(result).not.toHaveProperty('publishedRevisionId');
  });

  it('accepts semantically identical JSON object key order from Postgres', async () => {
    const response = receipt();
    const reversed = Object.fromEntries(Object.entries(response.draft).reverse());
    await expect(stagePlanRevision(rpcClient({ ...response, draft: reversed }), draft(), registry, actorId))
      .resolves.toEqual(response);
  });

  it('normalizes UUIDs before staging without rewriting generic codes', async () => {
    const input = draft(); input.id = revisionId.toUpperCase();
    const client = rpcClient(receipt());
    await stagePlanRevision(client, input, registry, actorId.toUpperCase());
    expect(client.rpc.mock.calls[0][1]).toMatchObject({ p_staged_by: actorId, p_draft: { id: revisionId } });
  });

  it.each([
    { name: '' }, { revisionNumber: 0 }, { plan: { ...draft().plan, code: 'hybrid' } },
    { features: [{ key: 'unknown', type: 'boolean', enabled: true }] }, { published: true },
  ])('rejects invalid submissions before any storage call %j', async patch => {
    const client = rpcClient(receipt());
    await expect(stagePlanRevision(client, { ...draft(), ...patch }, registry, actorId)).rejects.toBeInstanceOf(CatalogValidationError);
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('rejects an invalid actor before storage', async () => {
    const client = rpcClient(receipt());
    await expect(stagePlanRevision(client, draft(), registry, 'invalid')).rejects.toThrow('actorId');
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it.each([
    { response: null, reason: 'Invalid draft staging receipt' },
    { response: [], reason: 'Invalid draft staging receipt' },
    { response: {}, reason: 'Invalid draft staging receipt' },
    { response: { ...receipt(), published: true }, reason: 'Invalid draft staging receipt' },
    { response: { ...receipt(), stagedAt: 'yesterday' }, reason: 'Invalid draft staging timestamp' },
    { response: { ...receipt(), stagedAt: null }, reason: 'Invalid draft staging timestamp' },
    { response: { ...receipt(), stagedBy: 'invalid' }, reason: 'receipt.stagedBy: expected UUID' },
    { response: { ...receipt(), draft: { ...draft(), features: [{ key: 'capacity', type: 'boolean', enabled: true }] } },
      reason: 'feature is unregistered or has a different type' },
  ])('rejects malformed or unvalidated receipts for the intended reason %j', async ({ response, reason }) => {
    await expect(stagePlanRevision(rpcClient(response), draft(), registry, actorId)).rejects.toThrow(reason);
  });

  it.each([
    { stagedBy: otherId }, { draft: { ...draft(), id: otherId } },
    { draft: { ...draft(), revisionNumber: 2 } }, { draft: { ...draft(), name: 'Different stored terms' } },
    { draft: { ...draft(), features: [] } },
  ])('rejects valid but mismatched receipts %j', async patch => {
    await expect(stagePlanRevision(rpcClient({ ...receipt(), ...patch }), draft(), registry, actorId))
      .rejects.toThrow('does not match');
  });

  it('surfaces RPC failure once without a retry or alternate write', async () => {
    const failure = new Error('RPC unavailable');
    const client = rpcClient(null); client.rpc.mockRejectedValue(failure);
    await expect(stagePlanRevision(client, draft(), registry, actorId)).rejects.toBe(failure);
    expect(client.rpc).toHaveBeenCalledTimes(1);
  });

  it.each(['2026-02-30T12:00:00Z', '2026-11-17T24:00:00Z', '2026-11-17T12:00:00', 'infinity'])
    ('rejects an invalid storage timestamp %s', async timestamp => {
      await expect(stagePlanRevision(rpcClient({ ...receipt(), stagedAt: timestamp }), draft(), registry, actorId))
        .rejects.toThrow('Invalid draft staging timestamp');
    });
});

describe('staged draft reads', () => {
  it('selects a bounded exact UUID record and validates its full stored snapshot', async () => {
    const client = readClient([stored()]);
    const result = await readPlanRevision(client, revisionId.toUpperCase(), registry);
    expect(client.query).toHaveBeenCalledExactlyOnceWith(
      `subscription_plan_drafts?select=snapshot,staged_by,staged_at&id=eq.${revisionId}&limit=2`,
    );
    expect(result).toEqual(receipt());
    expect(Object.isFrozen(result.draft.plan)).toBe(true);
  });

  it('rejects filter injection before querying', async () => {
    const client = readClient([]);
    await expect(readPlanRevision(client, `${revisionId}&or=(id.not.is.null)`, registry)).rejects.toThrow('revisionId');
    expect(client.query).not.toHaveBeenCalled();
  });

  it.each([
    { rows: [], error: 'resolve exactly once' },
    { rows: [stored(), stored()], error: 'resolve exactly once' },
    { rows: [null], error: 'Invalid stored draft' },
    { rows: [[]], error: 'Invalid stored draft' },
    { rows: [{}], error: 'Invalid draft staging timestamp' },
    { rows: [{ ...stored(), snapshot: { ...draft(), id: otherId } }], error: 'identity does not match' },
  ])('rejects absent, ambiguous, malformed or wrong-identity records %j', async ({ rows, error }) => {
      await expect(readPlanRevision(readClient(rows), revisionId, registry)).rejects.toThrow(error);
    });

  it('surfaces query failure without returning an empty plan', async () => {
    const failure = new Error('Read unavailable'), client = readClient([]);
    client.query.mockRejectedValue(failure);
    await expect(readPlanRevision(client, revisionId, registry)).rejects.toBe(failure);
    expect(client.query).toHaveBeenCalledTimes(1);
  });

  it('rejects stored configuration no longer recognized by the supplied trusted registry', async () => {
    await expect(readPlanRevision(readClient([stored()]), revisionId, { ...registry, featureTypes: new Map() }))
      .rejects.toBeInstanceOf(CatalogValidationError);
  });

  it('uses a distinct explicit missing-record error', async () => {
    await expect(readPlanRevision(readClient([]), revisionId, registry)).rejects.toBeInstanceOf(CatalogPersistenceError);
  });
});
