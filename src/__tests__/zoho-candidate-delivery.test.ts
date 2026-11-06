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
  it('drains up to 100 immutable references in bounded ten-record reservations', async () => {
    let batches=0;
    rpc.mockImplementation(async (name,args)=>name==='zoho_reserve_candidate_deliveries'
      ? Array.from({length:10},(_,i)=>({operationId:`10000000-0000-4000-8000-${String(++batches*10+i).padStart(12,'0')}`,sourceHash,lease:args.p_lease})) : true);
    const send=vi.fn(async()=>{});
    expect(await recoverCandidateDeliveries({ZOHO_PROJECTION_DELIVERY_ENABLED:'true',SYNC_QUEUE:{send}} as unknown as Env)).toEqual({published:100});
    expect(send).toHaveBeenCalledTimes(100);
    expect(rpc.mock.calls.filter(([name])=>name==='zoho_reserve_candidate_deliveries')).toHaveLength(10);
    for(const [event] of send.mock.calls as unknown as [{payload:Record<string,unknown>}][])expect(Object.keys(event.payload).sort()).toEqual(['emailPolicy','operationId','sourceHash']);
  });
  it('stops a draining run after a wholly failed batch instead of hammering more reservations', async () => {
    rpc.mockImplementation(async(name,args)=>name==='zoho_reserve_candidate_deliveries'?Array.from({length:10},(_,i)=>({operationId:`10000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`,sourceHash,lease:args.p_lease})):true);
    const send=vi.fn(async()=>{throw new Error('unavailable');});
    expect(await recoverCandidateDeliveries({ZOHO_PROJECTION_DELIVERY_ENABLED:'true',SYNC_QUEUE:{send}} as unknown as Env)).toEqual({published:0});
    expect(rpc.mock.calls.filter(([name])=>name==='zoho_reserve_candidate_deliveries')).toHaveLength(1);
  });
  it('stops starting new delivery batches once the recovery time budget is consumed',async()=>{
    let clock=0;const now=vi.spyOn(Date,'now').mockImplementation(()=>clock);
    try{
      rpc.mockImplementation(async(name,args)=>{
        if(name==='zoho_reserve_candidate_deliveries')return Array.from({length:10},(_,i)=>({operationId:`10000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`,sourceHash,lease:args.p_lease}));
        clock+=2000;return true;
      });
      const send=vi.fn(async()=>{});
      expect(await recoverCandidateDeliveries({ZOHO_PROJECTION_DELIVERY_ENABLED:'true',SYNC_QUEUE:{send}} as unknown as Env)).toEqual({published:10});
      expect(rpc.mock.calls.filter(([name])=>name==='zoho_reserve_candidate_deliveries')).toHaveLength(1);
    }finally{now.mockRestore();}
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

describe('queue batch publication efficiency and ambiguity', () => {
  it.each([false, true])('publishes ten references with one queue call; failure=%s never sends individual fallbacks', async failed => {
    let reservations = 0;
    rpc.mockImplementation(async (name, args) => name === 'zoho_reserve_candidate_deliveries'
      ? ++reservations === 1 ? Array.from({ length: 10 }, (_, i) => ({ operationId: `10000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`, sourceHash, lease: args.p_lease })) : [] : name === 'zoho_record_candidate_publications' ? args.p_operations.map((operationId: string) => ({ operationId, recorded: true })) : true);
    const send = vi.fn(), sendBatch = vi.fn(async (_messages: { body: { payload: Record<string, unknown> } }[]) => { if (failed) throw new Error('ambiguous queue response'); });
    expect(await recoverCandidateDeliveries({ ZOHO_PROJECTION_DELIVERY_ENABLED: 'true', SYNC_QUEUE: { send, sendBatch } } as unknown as Env))
      .toEqual({ published: failed ? 0 : 10 });
    expect(sendBatch).toHaveBeenCalledTimes(1); expect(send).not.toHaveBeenCalled();
    const messages = sendBatch.mock.calls[0][0];
    expect(messages).toHaveLength(10);
    for (const { body } of messages) expect(Object.keys(body.payload).sort()).toEqual(['emailPolicy','operationId','sourceHash']);
    const acknowledgements = rpc.mock.calls.filter(([name]) => name === 'zoho_record_candidate_publications');
    expect(acknowledgements).toHaveLength(1);
    expect(acknowledgements[0][1].p_operations).toHaveLength(10);
    for (const [, args] of acknowledgements) expect(args.p_published).toBe(!failed);
  });
});

it('reduces a hundred projection publications from 210 network operations to 30', async () => {
  let sequence=0;
  rpc.mockImplementation(async(name,args)=>name==='zoho_reserve_candidate_deliveries'
    ? Array.from({length:10},()=>({operationId:`10000000-0000-4000-8000-${String(++sequence).padStart(12,'0')}`,sourceHash,lease:args.p_lease}))
    : args.p_operations.map((operationId:string)=>({operationId,recorded:true})));
  const send=vi.fn(),sendBatch=vi.fn(async (_messages:unknown[])=>{});
  expect(await recoverCandidateDeliveries({ZOHO_PROJECTION_DELIVERY_ENABLED:'true',SYNC_QUEUE:{send,sendBatch}} as unknown as Env)).toEqual({published:100});
  expect(send).not.toHaveBeenCalled();expect(sendBatch).toHaveBeenCalledTimes(10);expect(rpc).toHaveBeenCalledTimes(20);
});
it.each(['missing','duplicate','unfenced','unavailable'])('fails closed on %s publication acknowledgement without resending',async kind=>{
  rpc.mockImplementation(async(name,args)=>{
    if(name==='zoho_reserve_candidate_deliveries')return [{operationId:id,sourceHash,lease:args.p_lease}];
    if(kind==='unavailable')throw new Error('private storage error');
    if(kind==='missing')return [];
    if(kind==='duplicate')return [{operationId:id,recorded:true},{operationId:id,recorded:true}];
    return [{operationId:id,recorded:false}];
  });
  const send=vi.fn(),sendBatch=vi.fn(async(_messages:unknown[])=>{});
  await expect(recoverCandidateDeliveries({ZOHO_PROJECTION_DELIVERY_ENABLED:'true',SYNC_QUEUE:{send,sendBatch}} as unknown as Env)).rejects.toThrow();
  expect(sendBatch).toHaveBeenCalledTimes(1);expect(send).not.toHaveBeenCalled();
});
