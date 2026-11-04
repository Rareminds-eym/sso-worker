import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ rpc: vi.fn(), verify: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc: mocks.rpc }) }));
vi.mock('../lib/jwt', () => ({ verifyAccessToken: mocks.verify }));
import { executeCandidateAdministration, findCandidateAdministration, listCandidateErasedOperations, previewCandidateAdministration, validCandidateAdministrationContext } from '../rpc/zoho-candidate-administration';
import { ZohoApproverAuthority } from '../rpc/zoho-approver-authority';
import type { Env } from '../types';
const id = '10000000-0000-4000-8000-000000000001';
const env = {} as Env;
const context = (action = 'erase_connector') => ({ action, sourceOrgId: '123', externalId: '456', targetId: id,
  reason: 'Explicitly reviewed connector scope', emailPolicy: 'forbidden', acknowledgeIndependentDiscover: action === 'establish_learner_context' });
const reviewHash = 'a'.repeat(64);
beforeEach(() => {
  vi.resetAllMocks();
  mocks.verify.mockResolvedValue({ sub: id, org_id: '00000000-0000-0000-0000-000000000001', membership_status: 'active', roles: ['super_admin'],
    exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000) });
});
describe('purpose-scoped candidate administration', () => {
  it.each(['establish_learner_context', 'erase_connector', 'release_suppression'])('previews %s with verified canonical human authority', async action => {
    mocks.rpc.mockResolvedValue({ version: 1, allowed: true, reviewHash });
    const actual = await previewCandidateAdministration(env, { accessToken: 'signed', context: context(action) });
    expect(actual).toEqual({ version: 1, allowed: true, reviewHash });
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_preview_candidate_administration', { p_actor: id, p_context: context(action) });
  });
  it('rejects implicit free grants, arbitrary roles, whole-account deletion and alternate email policies', async () => {
    for (const invalid of [context('delete_account'), { ...context(), action: null }, { ...context(), sourceOrgId: 123 }, { ...context(), targetId: 'bad' },
      { ...context(), emailPolicy: 'allowed' }, { ...context(), role: 'learner' }, { ...context(), reason: '  untrimmed  ' },
      { ...context('establish_learner_context'), acknowledgeIndependentDiscover: false }, { ...context(), acknowledgeIndependentDiscover: true },
      { ...context(), reason: 'x'.repeat(501) }]) {
      expect(validCandidateAdministrationContext(invalid)).toBe(false);
      expect(await previewCandidateAdministration(env, { accessToken: 'signed', context: invalid })).toBeNull();
    }
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it.each([{ roles: ['admin'] }, { org_id: id }, { membership_status: 'inactive' }, { exp: 1 }, { sub: 'bad' }, { iat: 9999999999 }])('denies invalid human scope %j', async patch => {
    mocks.verify.mockResolvedValue({ ...(await mocks.verify()), ...patch });
    expect(await previewCandidateAdministration(env, { accessToken: 'signed', context: context() })).toBeNull();
    await expect(executeCandidateAdministration(env, { accessToken: 'signed', context: context(), reviewHash, requestId: id })).rejects.toThrow('authority unavailable');
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('executes the exact reviewed request without accepting browser actor IDs or privilege DTOs', async () => {
    const input = { accessToken: 'signed', context: context(), reviewHash, requestId: id };
    mocks.rpc.mockResolvedValue({ state: 'completed' });
    expect(await executeCandidateAdministration(env, input)).toEqual({ state: 'completed' });
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_execute_candidate_administration', { p_actor: id, p_context: context(), p_review_hash: reviewHash, p_request: id });
    mocks.rpc.mockClear();
    for (const bad of [{ ...input, actorId: id }, { ...input, reviewHash: 'bad' }, { ...input, requestId: null }, { ...input, context: { ...context(), plan: 'premium' } }])
      await expect(executeCandidateAdministration(env, bad)).rejects.toThrow('authority unavailable');
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('does not turn ambiguous execution errors into success or no-effect evidence', async () => {
    mocks.rpc.mockRejectedValue(new Error('Ambiguous transaction'));
    await expect(executeCandidateAdministration(env, { accessToken: 'signed', context: context(), reviewHash, requestId: id })).rejects.toThrow('Ambiguous transaction');
    expect(mocks.rpc).toHaveBeenCalledOnce();
  });
  it('provides authenticated receipt readback and fixed-size cursor pages without identity lookups', async () => {
    mocks.rpc.mockResolvedValue({ version: 1, state: 'completed' });
    await findCandidateAdministration(env, { accessToken: 'signed', requestId: id });
    expect(mocks.rpc).toHaveBeenLastCalledWith('zoho_find_candidate_administration', { p_actor: id, p_request: id });
    await listCandidateErasedOperations(env, { accessToken: 'signed', requestId: id, afterOperationId: null });
    expect(mocks.rpc).toHaveBeenLastCalledWith('zoho_list_candidate_erased_operations', { p_actor: id, p_request: id, p_after: null });
    mocks.rpc.mockClear();
    expect(await findCandidateAdministration(env, { accessToken: 'signed', requestId: 'bad' })).toBeNull();
    expect(await listCandidateErasedOperations(env, { accessToken: 'signed', requestId: id, afterOperationId: null, limit: 10000 })).toBeNull();
    expect(await listCandidateErasedOperations(env, { accessToken: 'signed', requestId: id, afterOperationId: 'bad' })).toBeNull();
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('keeps administration on the existing restricted authority, with no public HTTP or email interface', async () => {
    const entrypoint = new ZohoApproverAuthority({} as ExecutionContext, env);
    expect(typeof entrypoint.previewCandidateAdministration).toBe('function');
    expect(typeof entrypoint.executeCandidateAdministration).toBe('function');
    expect(typeof entrypoint.findCandidateAdministration).toBe('function');
    expect(typeof entrypoint.listCandidateErasedOperations).toBe('function');
    expect((await entrypoint.fetch(new Request('https://fixture.invalid'))).status).toBe(404);
    expect('sendEmail' in entrypoint).toBe(false);
  });
});
