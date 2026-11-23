import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readCanonicalPlanInventory } from '../lib/subscriptions';
import type { Env } from '../types';
const io = vi.hoisted(() => ({ query: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => io }));
import { SsoWorker } from '../index';

const id = (value: number) => `a0000000-0000-4000-8000-${value.toString(16).padStart(12, '0')}`;
const row = (value = 1) => ({ id: id(value), plan_code: `legacy_${value}`, product_id: null,
  name: `Existing plan ${value}`, is_active: false, applicable_entities: ['college'] });
beforeEach(() => { vi.resetAllMocks(); io.query.mockResolvedValue([]); });

describe('canonical plan inventory', () => {
  it('includes existing semantic codes and inactive plans without assigning purchase meaning', async () => {
    const source = row(); io.query.mockResolvedValueOnce([source]);
    const result = await readCanonicalPlanInventory(io);
    expect(result).toEqual([{ id: id(1), code: 'legacy_1', productId: null, name: 'Existing plan 1', isActive: false, applicableEntities: ['college'] }]);
    source.applicable_entities.push('school');
    expect(result[0].applicableEntities).toEqual(['college']);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result[0])).toBe(true);
    expect(Object.isFrozen(result[0].applicableEntities)).toBe(true);
    expect(io.query.mock.calls[0][0]).toBe('plans?select=id,plan_code,product_id,name,is_active,applicable_entities&order=id.asc&limit=200');
    expect(io.query.mock.calls.every(args => args[1] === undefined && args[2] === 'json-array')).toBe(true);
    expect(io.query).toHaveBeenCalledTimes(2);
    expect(io.query.mock.calls[1][0]).toContain(`&id=gt.${id(1)}`);
  });

  it('reaches the actual worker binding method through mocked database IO', async () => {
    io.query.mockResolvedValueOnce([row()]);
    const worker = new SsoWorker({} as ExecutionContext, {} as Env);
    const result = await worker.getSubscriptionCatalogInventory();
    expect(result.schemaVersion).toBe(1);
    expect(result.plans).toHaveLength(1);
    expect(io.query).toHaveBeenCalledTimes(2);
  });

  it('advances exact UUID cursors instead of silently accepting a first-page truncation', async () => {
    io.query.mockResolvedValueOnce(Array.from({ length: 200 }, (_, index) => row(index + 1))).mockResolvedValueOnce([row(201)]);
    const result = await readCanonicalPlanInventory(io);
    expect(result).toHaveLength(201);
    expect(io.query.mock.calls[1][0]).toBe(`plans?select=id,plan_code,product_id,name,is_active,applicable_entities&order=id.asc&limit=200&id=gt.${id(200)}`);
  });

  it('continues when the server caps a page below the requested page size', async () => {
    io.query.mockResolvedValueOnce([row(1)]).mockResolvedValueOnce([row(2)]).mockResolvedValueOnce([]);
    const result = await readCanonicalPlanInventory(io);
    expect(result.map(item => item.id)).toEqual([id(1), id(2)]);
    expect(io.query).toHaveBeenCalledTimes(3);
  });

  it.each([
    { data: null, reason: 'invalid catalog page' }, { data: [null], reason: 'plain object' },
    { data: [{ ...row(), is_active: 'false' }], reason: 'expected boolean' },
    { data: [{ ...row(), product_id: 'invalid' }], reason: 'expected UUID' },
    { data: [{ ...row(), applicable_entities: ['college', 'college'] }], reason: 'duplicate entity' },
    { data: [{ ...row(), applicable_entities: new Array(1) }], reason: 'expected non-empty trimmed text' },
    { data: [row(2), row(1)], reason: 'must advance in UUID order' },
    { data: [row(), row()], reason: 'must advance in UUID order' },
    { data: [{ ...row(), secret: 'not-a-catalog-field' }], reason: 'unsupported field' },
  ])('rejects malformed or inconsistent source pages for the intended reason %j', async ({ data, reason }) => {
    io.query.mockResolvedValue(data);
    await expect(readCanonicalPlanInventory(io)).rejects.toThrow(reason);
  });

  it('preserves a real empty catalog as empty data', async () => {
    io.query.mockResolvedValue([]);
    await expect(readCanonicalPlanInventory(io)).resolves.toEqual([]);
  });

  it('surfaces a failed later page without returning a partial inventory', async () => {
    const failure = new Error('Synthetic database failure');
    io.query.mockResolvedValueOnce(Array.from({ length: 200 }, (_, index) => row(index + 1))).mockRejectedValueOnce(failure);
    await expect(readCanonicalPlanInventory(io)).rejects.toBe(failure);
    expect(io.query).toHaveBeenCalledTimes(2);
  });

  it('rejects excessive pagination rather than truncating at the resource budget', async () => {
    let next = 1;
    io.query.mockImplementation(async () => Array.from({ length: 200 }, () => row(next++)));
    await expect(readCanonicalPlanInventory(io)).rejects.toThrow('pagination budget exceeded');
    expect(io.query).toHaveBeenCalledTimes(100);
  });
});
