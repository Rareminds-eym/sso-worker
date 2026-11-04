import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ rpc: vi.fn(), verify: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc: mocks.rpc }) }));
vi.mock('../lib/jwt', () => ({ verifyAccessToken: mocks.verify }));
import { acknowledgeCandidateAdministration, listPendingCandidateAdministrations } from '../rpc/zoho-candidate-administration';
import { ZohoApproverAuthority } from '../rpc/zoho-approver-authority';
import type { Env } from '../types';
const actor = '10000000-0000-4000-8000-000000000001'; const requestId = '20000000-0000-4000-8000-000000000001'; const env = {} as Env;
beforeEach(() => {
  vi.resetAllMocks(); mocks.verify.mockResolvedValue({ sub: actor, org_id: '00000000-0000-0000-0000-000000000001', membership_status: 'active', roles: ['super_admin'], exp: Math.floor(Date.now()/1000)+900, iat: Math.floor(Date.now()/1000) });
});
describe('canonical administration recovery boundary', () => {
  it('lists committed pending references for the verified administrator and numeric source only', async () => {
    const result = { version: 1, items: [{ requestId }], nextCursor: null }; mocks.rpc.mockResolvedValue(result);
    expect(await listPendingCandidateAdministrations(env, { accessToken: 'signed', sourceOrgId: '1234', before: null })).toEqual(result);
    expect(mocks.rpc).toHaveBeenCalledWith('zoho_list_pending_candidate_administrations', { p_actor: actor, p_source_org: '1234', p_before_at: null, p_before_request: null });
  });
  it('keeps the exact timestamp/UUID cursor without losing database precision', async () => {
    const before = { createdAt: '2026-11-03T10:20:30.123456+00:00', requestId };
    await listPendingCandidateAdministrations(env, { accessToken: 'signed', sourceOrgId: '1234', before });
    expect(mocks.rpc).toHaveBeenCalledWith('zoho_list_pending_candidate_administrations', { p_actor: actor, p_source_org: '1234', p_before_at: before.createdAt, p_before_request: requestId });
  });
  it.each([
    { sourceOrgId: 1234, before: null }, { sourceOrgId: 'bad', before: null }, { sourceOrgId: '1234', before: undefined },
    { sourceOrgId: '1234', before: {} }, { sourceOrgId: '1234', before: { createdAt: 'bad', requestId } },
    { sourceOrgId: '1234', before: { createdAt: '2026-11-03T10:20:30Z', requestId: 'bad' } },
    { sourceOrgId: '1234', before: null, limit: 50000 }, { sourceOrgId: '1234', before: null, actorId: actor },
  ])('rejects broad or malformed enumeration %j', async input => {
    expect(await listPendingCandidateAdministrations(env, { accessToken: 'signed', ...input })).toBeNull(); expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('does not turn a lost ACK response into success', async () => {
    mocks.rpc.mockRejectedValue(new Error('Ambiguous commit'));
    await expect(acknowledgeCandidateAdministration(env, { accessToken: 'signed', requestId })).rejects.toThrow('Ambiguous commit');
    expect(mocks.rpc).toHaveBeenCalledWith('zoho_acknowledge_candidate_administration', { p_actor: actor, p_request: requestId });
  });
  it('rejects a revoked recovering administrator for list and ACK', async () => {
    mocks.verify.mockResolvedValue({ sub: actor, org_id: '00000000-0000-0000-0000-000000000001', roles: ['super_admin'], membership_status: 'inactive', exp: 9999999999, iat: 1 });
    expect(await listPendingCandidateAdministrations(env, { accessToken: 'signed', sourceOrgId: '1234', before: null })).toBeNull();
    await expect(acknowledgeCandidateAdministration(env, { accessToken: 'signed', requestId })).rejects.toThrow('unavailable'); expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('exposes only narrow private recovery methods on the existing entrypoint', () => {
    const authority = new ZohoApproverAuthority({} as any, env);
    expect(typeof authority.listPendingCandidateAdministrations).toBe('function');
    expect(typeof authority.acknowledgeCandidateAdministration).toBe('function');
    expect((authority as any).sendEmail).toBeUndefined();
  });
});
