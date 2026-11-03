import { describe, it, beforeEach, expect, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ rpc: vi.fn(), validate: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc: mocks.rpc }) }));
vi.mock('../rpc/zoho-approval-evidence', () => ({ validateApprovalEvidence: mocks.validate }));
import { candidateCapabilities, provisionCandidateCore, ZohoCandidateProvisioner } from '../rpc/zoho-candidate-provisioner';
import { verifyPassword } from '../lib/hash';
import type { Env } from '../types';
const id = '10000000-0000-4000-8000-000000000001';
const projectionCapability = { version: 1, ready: true, emailPolicy: 'forbidden', verifiesPostconditions: true, privateProfiles: true };
const enabled = { ZOHO_CANDIDATE_PROVISIONING_ENABLED: 'true', ZOHO_PROJECTION_DELIVERY_ENABLED: 'true',
  SUPABASE_URL: 'http://127.0.0.1:54321', SUPABASE_SERVICE_ROLE_KEY: 'fixture', SYNC_QUEUE: { send: vi.fn() },
  ZOHO_CONTROL_PLANE: { validateOperation: vi.fn(), validateProjectionReceipt: vi.fn(), candidateProjectionCapabilities: vi.fn() } } as unknown as Env;
beforeEach(() => { vi.resetAllMocks(); mocks.validate.mockResolvedValue({ allowed: true });
  vi.mocked(enabled.ZOHO_CONTROL_PLANE!.candidateProjectionCapabilities!).mockResolvedValue(projectionCapability);
  mocks.rpc.mockImplementation(async name => name === 'zoho_candidate_runtime_ready' ? true : { state: 'projection_pending' });
});
describe('silent canonical candidate transaction boundary', () => {
  it('defaults off before inspecting authority or storage', async () => {
    await expect(provisionCandidateCore({} as Env, { module: 'Candidates' })).rejects.toThrow('disabled');
    expect(mocks.validate).not.toHaveBeenCalled(); expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('checks independent human/live authority before the fixed transaction', async () => {
    const grant = { module: 'Candidates', operationId: id };
    expect(await provisionCandidateCore(enabled, grant)).toEqual({ state: 'projection_pending' });
    expect(mocks.validate).toHaveBeenCalledExactlyOnceWith(enabled, grant);
    expect(mocks.rpc).toHaveBeenNthCalledWith(1, 'zoho_candidate_runtime_ready');
    expect(mocks.rpc).toHaveBeenNthCalledWith(2, 'zoho_provision_candidate', { p_grant: grant });
    expect(mocks.validate.mock.invocationCallOrder[0]).toBeLessThan(mocks.rpc.mock.invocationCallOrder[0]);
  });
  it('never treats a transport failure as evidence that a transaction had no effect', async () => {
    mocks.rpc.mockImplementation(async name => { if (name === 'zoho_candidate_runtime_ready') return true; throw new Error('transport unavailable'); });
    await expect(provisionCandidateCore(enabled, { module: 'Candidates' })).rejects.toThrow('transport unavailable');
    expect(mocks.rpc).toHaveBeenCalledTimes(2);
  });
  it('denies revoked authority and job payloads before any writer', async () => {
    mocks.validate.mockResolvedValue({ allowed: false });
    await expect(provisionCandidateCore(enabled, { module: 'Candidates' })).rejects.toThrow();
    await expect(provisionCandidateCore(enabled, { module: 'Job_Openings' })).rejects.toThrow();
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('defaults readiness off and exposes no public command or mail/session method', async () => {
    const instance = new ZohoCandidateProvisioner({} as ExecutionContext, {} as Env);
    expect(await instance.capabilities()).toMatchObject({ ready: false, emailPolicy: 'forbidden' });
    expect((await instance.fetch()).status).toBe(404);
    for (const method of ['sendEmail','login','signup','createLearnerUser']) expect(method in instance).toBe(false);
  });
  it('attests the full destination contract only after independent read-only dependency probes', async () => {
    expect(await candidateCapabilities(enabled)).toEqual({ version: 1, ready: true, emailPolicy: 'forbidden', modules: ['Candidates'],
      checksLiveApproval: true, checksLiveApprover: true, idempotentByOperation: true,
      transactionalReceipt: true, fencesExpiredLeases: true, verifiesPostconditions: true });
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_candidate_runtime_ready');
    expect(enabled.ZOHO_CONTROL_PLANE!.candidateProjectionCapabilities).toHaveBeenCalledOnce();
    expect(enabled.SYNC_QUEUE.send).not.toHaveBeenCalled();
  });
  it.each([{ ZOHO_PROJECTION_DELIVERY_ENABLED: 'false' }, { SYNC_QUEUE: undefined }, { SUPABASE_SERVICE_ROLE_KEY: '' },
    { ZOHO_CONTROL_PLANE: { validateOperation() {} } }])('denies missing runtime dependency %j before writing', async patch => {
    const env = { ...enabled, ...patch } as Env;
    expect((await candidateCapabilities(env)).ready).toBe(false);
    await expect(provisionCandidateCore(env, { module: 'Candidates' })).rejects.toThrow('dependencies unavailable');
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it.each([false, null, 'true', { ready: true }])('rejects noncanonical readiness %j', async value => {
    mocks.rpc.mockResolvedValue(value);
    expect((await candidateCapabilities(enabled)).ready).toBe(false);
    await expect(provisionCandidateCore(enabled, { module: 'Candidates' })).rejects.toThrow('dependencies unavailable');
    expect(mocks.rpc.mock.calls.every(([name]) => name === 'zoho_candidate_runtime_ready')).toBe(true);
  });
  it.each([null, { ...projectionCapability, ready: false }, { ...projectionCapability, privateProfiles: false },
    { ...projectionCapability, verifiesPostconditions: false }, { ...projectionCapability, emailPolicy: 'allowed' },
    { ...projectionCapability, version: 2 }])('rejects incomplete independent projection capability %j', async value => {
    vi.mocked(enabled.ZOHO_CONTROL_PLANE!.candidateProjectionCapabilities!).mockResolvedValue(value);
    expect((await candidateCapabilities(enabled)).ready).toBe(false);
  });
  it('does not reuse a previously successful capability when a dependency becomes unavailable', async () => {
    expect((await candidateCapabilities(enabled)).ready).toBe(true);
    vi.mocked(enabled.ZOHO_CONTROL_PLANE!.candidateProjectionCapabilities!).mockRejectedValue(new Error('private deployment detail'));
    await expect(provisionCandidateCore(enabled, { module: 'Candidates' })).rejects.toThrow('Candidate dependencies unavailable');
    expect(mocks.rpc.mock.calls.every(([name]) => name === 'zoho_candidate_runtime_ready')).toBe(true);
  });
  it('bounds nonresponsive readiness and redacts the dependency error', async () => {
    vi.useFakeTimers();
    try {
      mocks.rpc.mockReturnValue(new Promise(() => {}));
      const pending = candidateCapabilities(enabled);
      await vi.advanceTimersByTimeAsync(3500);
      expect(await pending).toMatchObject({ ready: false, reason: 'Candidate dependencies unavailable' });
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });
  it('reads only a matching receipt without retrying a write', async () => {
    const instance = new ZohoCandidateProvisioner({} as ExecutionContext, {} as Env);
    mocks.rpc.mockResolvedValue({ state: 'projection_pending' });
    expect(await instance.findOperationReceipt({ operationId: id, sourceHash: 'a'.repeat(64), readOnly: true })).toEqual({ state: 'projection_pending' });
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_find_candidate_receipt', { p_operation: id, p_source_hash: 'a'.repeat(64) });
    mocks.rpc.mockClear();
    expect(await instance.findOperationReceipt({ operationId: id, sourceHash: 'a'.repeat(64), readOnly: true, retry: true })).toBeNull();
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('the disabled hash sentinel cannot authenticate as a password', async () => {
    for (const password of ['!zoho-import-no-password!', 'password', '']) expect(await verifyPassword(password, '!zoho-import-no-password!')).toBe(false);
  });
});
