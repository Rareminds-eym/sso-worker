vi.mock('../lib/zoho-config',async original=>{const module=await original<typeof import('../lib/zoho-config')>();return {...module,readZohoSsoConfig:(env:Record<string,unknown>)=>({...module.readZohoSsoConfig(env),candidateProvisioning:env.ZOHO_CANDIDATE_PROVISIONING_ENABLED==='true',projectionDelivery:env.ZOHO_PROJECTION_DELIVERY_ENABLED==='true'})};});
import { beforeEach, describe, it, expect, vi } from 'vitest';
const { rpc } = vi.hoisted(() => ({ rpc: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc }) }));
import { recoverCandidateDeliveries, candidateProjectionSnapshot, confirmCandidateProjection } from '../lib/zoho-candidate-delivery';
import type { Env } from '../types';
const id = '10000000-0000-4000-8000-000000000001'; const sourceHash = 'a'.repeat(64);
const reference = { operationId: id, sourceHash, emailPolicy: 'forbidden' };
beforeEach(() => { vi.resetAllMocks(); });
describe('durable candidate delivery boundary', () => {
  it('defaults off without accessing storage or transport', async () => {
    expect(await recoverCandidateDeliveries({} as Env)).toEqual({ published: 0 });
    expect(await candidateProjectionSnapshot({} as Env, reference)).toBeNull();
    expect(rpc).not.toHaveBeenCalled();
  });
  it('publishes only immutable references on the existing queue, then records publication', async () => {
    const send = vi.fn(async () => {});
    rpc.mockImplementation(async (name, args) => name === 'zoho_reserve_candidate_deliveries' ? [{ operationId: id, sourceHash, lease: args.p_lease }] : true);
    const env = { ZOHO_PROJECTION_DELIVERY_ENABLED: 'true', SYNC_QUEUE: { send } } as unknown as Env;
    expect(await recoverCandidateDeliveries(env)).toEqual({ published: 1 });
    expect(send).toHaveBeenCalledExactlyOnceWith({ type: 'zoho.candidate.canonical_committed', payload: reference, timestamp: expect.any(String) });
    expect(rpc).toHaveBeenLastCalledWith('zoho_record_candidate_publication', { p_operation: id, p_lease: expect.any(String), p_published: true });
    expect(send.mock.invocationCallOrder[0]).toBeLessThan(rpc.mock.invocationCallOrder[1]);
  });
  it('retains a failed publication in the durable budget without marking delivery complete', async () => {
    const send = vi.fn(async () => { throw new Error('private transport body'); });
    rpc.mockImplementation(async (name, args) => name === 'zoho_reserve_candidate_deliveries' ? [{ operationId: id, sourceHash, lease: args.p_lease }] : true);
    expect(await recoverCandidateDeliveries({ ZOHO_PROJECTION_DELIVERY_ENABLED: 'true', SYNC_QUEUE: { send } } as unknown as Env)).toEqual({ published: 0 });
    expect(rpc).toHaveBeenLastCalledWith('zoho_record_candidate_publication', expect.objectContaining({ p_published: false }));
  });
  it('does not publish malformed or unfenced reservations', async () => {
    const send = vi.fn(); rpc.mockResolvedValue([{ operationId: id, sourceHash, lease: id }]);
    await expect(recoverCandidateDeliveries({ ZOHO_PROJECTION_DELIVERY_ENABLED: 'true', SYNC_QUEUE: { send } } as unknown as Env)).rejects.toThrow();
    expect(send).not.toHaveBeenCalled();
  });
  it('accepts only reference reads and bounds canonical snapshot size', async () => {
    const env = { ZOHO_PROJECTION_DELIVERY_ENABLED: 'true' } as unknown as Env;
    expect(await candidateProjectionSnapshot(env, { ...reference, planCode: 'premium' })).toBeNull();
    expect(rpc).not.toHaveBeenCalled();
    rpc.mockResolvedValue({ operationId: id, sourceHash, targetId: id, projectionHash: sourceHash, snapshot: '{"value":100.50}' });
    expect(await candidateProjectionSnapshot(env, reference)).toMatchObject({ snapshot: '{"value":100.50}' });
    rpc.mockResolvedValue({ operationId: id, sourceHash, targetId: id, projectionHash: sourceHash, snapshot: 'x'.repeat(131073) });
    expect(await candidateProjectionSnapshot(env, reference)).toBeNull();
  });
  it('requires independent application proof before the canonical confirmation transaction', async () => {
    const input = { ...reference, projectionHash: sourceHash, projectionReceiptId: id };
    await expect(confirmCandidateProjection({ ZOHO_PROJECTION_DELIVERY_ENABLED: 'true' } as unknown as Env, input)).rejects.toThrow();
    expect(rpc).not.toHaveBeenCalled();
    const validateProjectionReceipt = vi.fn(async () => ({ allowed: false }));
    const env = { ZOHO_PROJECTION_DELIVERY_ENABLED: 'true', ZOHO_CONTROL_PLANE: { validateProjectionReceipt } } as unknown as Env;
    await expect(confirmCandidateProjection(env, input)).rejects.toThrow(); expect(rpc).not.toHaveBeenCalled();
    validateProjectionReceipt.mockResolvedValue({ allowed: true }); rpc.mockResolvedValue({ state: 'completed' });
    expect(await confirmCandidateProjection(env, input)).toEqual({ state: 'completed' });
    expect(rpc).toHaveBeenCalledExactlyOnceWith('zoho_confirm_candidate_projection', { p_operation: id, p_source_hash: sourceHash, p_projection_hash: sourceHash, p_receipt: id });
  });
  it('rejects timed-out application confirmation without calling the completion RPC', async () => {
    vi.useFakeTimers();
    try {
      const env = { ZOHO_PROJECTION_DELIVERY_ENABLED: 'true', ZOHO_CONTROL_PLANE: { validateProjectionReceipt: () => new Promise(() => {}) } } as unknown as Env;
      const pending = confirmCandidateProjection(env, { ...reference, projectionHash: sourceHash, projectionReceiptId: id });
      const rejected = expect(pending).rejects.toThrow('unavailable');
      await vi.advanceTimersByTimeAsync(5000); await rejected; expect(rpc).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });
});
