import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ rpc: vi.fn(), verify: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc: mocks.rpc }) }));
vi.mock('../lib/jwt', () => ({ verifyAccessToken: mocks.verify }));
import { previewCandidateReview, verifyCandidateReview, validCandidateReviewContext } from '../rpc/zoho-candidate-review';
import { ZohoApproverAuthority } from '../rpc/zoho-approver-authority';
import type { Env } from '../types';
const id = '10000000-0000-4000-8000-000000000001';
const env = {} as Env;
const context = () => ({ connectionId: id, sourceOrgId: '123', recordId: id, revision: 1, configRevision: 1,
  sourceHash: 'a'.repeat(64), externalId: '456', data: { email: 'candidate@example.com', name: 'Candidate Example' }, targetId: null, emailPolicy: 'forbidden' });
beforeEach(() => {
  vi.resetAllMocks();
  mocks.verify.mockResolvedValue({ sub: id, org_id: '00000000-0000-0000-0000-000000000001', membership_status: 'active', roles: ['super_admin'],
    exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000) });
});
describe('canonical candidate preview and independent recheck', () => {
  it('uses a verified human subject and one fixed read/review RPC without executing a provisioning or email path', async () => {
    const snapshot = { version: 1, reviewHash: 'b'.repeat(64), decision: 'create' };
    mocks.rpc.mockResolvedValue(snapshot);
    expect(await previewCandidateReview(env, { accessToken: 'signed', context: context() })).toEqual(snapshot);
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_preview_candidate_review', { p_actor: id, p_context: context() });
    expect(mocks.verify).toHaveBeenCalledExactlyOnceWith('signed', env);
  });
  it.each(['discover_plan_version_unavailable', 'projection_versions_unavailable'])('surfaces canonical readiness blocker %s without provisioning or repairing versions', async blocker => {
    const snapshot = { version: 1, reviewHash: 'b'.repeat(64), decision: 'blocked', blockers: [blocker] };
    mocks.rpc.mockResolvedValue(snapshot);
    expect(await previewCandidateReview(env, { accessToken: 'signed', context: context() })).toEqual(snapshot);
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_preview_candidate_review', { p_actor: id, p_context: context() });
    mocks.rpc.mockClear();
    mocks.rpc.mockResolvedValue(false);
    expect(await verifyCandidateReview(env, { accessToken: 'signed', context: context(), candidateReviewHash: snapshot.reviewHash })).toEqual({ allowed: false });
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_verify_candidate_review', { p_actor: id, p_context: context(), p_review_hash: snapshot.reviewHash });
  });
  it('requires exact context and forbids payload injection, role assignments and email policies', async () => {
    for (const invalid of [{ ...context(), emailPolicy: 'allowed' }, { ...context(), actorId: id }, { ...context(), data: { ...context().data, password: 'secret' } },
      { ...context(), data: { ...context().data, email: 'MixedCase@example.com' } }, { ...context(), targetId: 'bad' }, { ...context(), revision: 0 },
      { ...context(), data: { ...context().data, name: 'x'.repeat(151) } }, { ...context(), data: { ...context().data, email: 'bad' } },
      { ...context(), sourceHash: 'bad' }, { ...context(), externalId: 'bad' }]) {
      expect(validCandidateReviewContext(invalid)).toBe(false);
      expect(await previewCandidateReview(env, { accessToken: 'signed', context: invalid })).toBeNull();
    }
    expect(mocks.rpc).not.toHaveBeenCalled();
    expect(await previewCandidateReview(env, { accessToken: 'signed', context: context(), actorId: id })).toBeNull();
  });
  it.each([{ roles: ['admin'] }, { org_id: id }, { membership_status: 'inactive' }, { exp: 1 }, { sub: 'bad' }, { iat: 9999999999 }])('denies stale or wrong human scope %j', async patch => {
    mocks.verify.mockResolvedValue({ ...(await mocks.verify()), ...patch });
    expect(await previewCandidateReview(env, { accessToken: 'signed', context: context() })).toBeNull();
    expect(await verifyCandidateReview(env, { accessToken: 'signed', context: context(), candidateReviewHash: 'b'.repeat(64) })).toEqual({ allowed: false });
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('rechecks exact source, reviewed hash and canonical subject; only explicit true is authority', async () => {
    const input = { accessToken: 'signed', context: context(), candidateReviewHash: 'b'.repeat(64) };
    for (const result of [false, null, 'true', { allowed: true }]) {
      mocks.rpc.mockResolvedValue(result);
      expect(await verifyCandidateReview(env, input)).toEqual({ allowed: false });
    }
    mocks.rpc.mockResolvedValue(true);
    expect(await verifyCandidateReview(env, input)).toEqual({ allowed: true });
    expect(mocks.rpc).toHaveBeenLastCalledWith('zoho_verify_candidate_review', { p_actor: id, p_context: context(), p_review_hash: input.candidateReviewHash });
    mocks.rpc.mockClear();
    expect(await verifyCandidateReview(env, { ...input, candidateReviewHash: 'bad' })).toEqual({ allowed: false });
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('fails closed and redacts infrastructure/token failures', async () => {
    mocks.verify.mockRejectedValue(new Error('private token'));
    expect(await previewCandidateReview(env, { accessToken: 'invalid', context: context() })).toBeNull();
    mocks.verify.mockResolvedValue({ sub: id, org_id: '00000000-0000-0000-0000-000000000001', membership_status: 'active', roles: ['super_admin'], exp: 9999999999, iat: 1 });
    mocks.rpc.mockRejectedValue(new Error('private database'));
    expect(await verifyCandidateReview(env, { accessToken: 'signed', context: context(), candidateReviewHash: 'b'.repeat(64) })).toEqual({ allowed: false });
  });
  it('exposes review only on the existing restricted entrypoint and keeps public fetch closed', async () => {
    const instance = new ZohoApproverAuthority({} as ExecutionContext, env);
    mocks.rpc.mockResolvedValue(null);
    expect(await instance.previewCandidateReview({ accessToken: 'signed', context: context() })).toBeNull();
    expect((await instance.fetch(new Request('https://fixture.invalid'))).status).toBe(404);
    for (const method of ['sendEmail', 'signup', 'login', 'createUser']) expect(method in instance).toBe(false);
  });
});
