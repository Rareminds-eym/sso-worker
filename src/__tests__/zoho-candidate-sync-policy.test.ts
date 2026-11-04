import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ rpc: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => mocks }));
import { candidateSubjectSyncPolicy, isImportedCandidate } from '../lib/zoho-candidate-sync-policy';
import type { Env } from '../types';
const id = '10000000-0000-4000-8000-000000000001';
beforeEach(() => vi.resetAllMocks());
describe('durable subject synchronization policy', () => {
  it('reads only canonical provenance while execution/delivery are paused', async () => {
    mocks.rpc.mockResolvedValue({ version: 1, genericSyncAllowed: false });
    expect(await isImportedCandidate({} as Env, id)).toBe(true);
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_candidate_sync_policy', { p_user: id });
  });
  it.each([null, {}, { userId: id, genericSyncAllowed: true }, { userId: 'invalid' }])('rejects unsafe subject references %j', async input => {
    await expect(candidateSubjectSyncPolicy({} as Env, input)).rejects.toThrow();
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it.each([null, true, { version: 1, genericSyncAllowed: 'true' }, { version: 1, genericSyncAllowed: true, extra: true }])('never treats unavailable/malformed provenance as ordinary identity %j', async data => {
    mocks.rpc.mockResolvedValue(data);
    await expect(isImportedCandidate({} as Env, id)).rejects.toThrow();
  });
});
