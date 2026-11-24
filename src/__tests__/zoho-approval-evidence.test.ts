import { beforeEach, describe, it, expect, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ rpc: vi.fn(), verify: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc: mocks.rpc }) }));
vi.mock('../lib/jwt', () => ({ verifyAccessToken: mocks.verify }));
import { recordApprovalEvidence, validateApprovalEvidence, validApprovalManifest } from '../rpc/zoho-approval-evidence';
import type { Env } from '../types';
import { PLATFORM_ORG_ID } from '../lib/constants';
const env = {} as Env;
const id = '10000000-0000-4000-8000-000000000001';
const manifest = () => ({ requestId: id, connectionId: id, sourceOrgId: '123', publisherOrganizationId: id, configRevision: 1,
  items: [{ recordId: id, revision: 1, sourceHash: 'a'.repeat(64), module: 'Candidates', candidateReviewHash: 'b'.repeat(64), externalId: '123', targetId: null }], reason: 'Reviewed source', emailPolicy: 'forbidden' });
beforeEach(() => {
  vi.resetAllMocks();
  mocks.verify.mockResolvedValue({ exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000), sub: id, org_id: '00000000-0000-0000-0000-000000000001', membership_status: 'active', roles: ['super_admin'] });
  mocks.rpc.mockResolvedValue(true);
});
describe('canonical human approval evidence', () => {
  it('records a full job batch published by the reserved SkillPassport Platform organization', async () => {
    const jobManifest = { ...manifest(), publisherOrganizationId: PLATFORM_ORG_ID,
      items: Array.from({ length: 50 }, (_, index) => ({
        recordId: `20000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
        revision: 2, sourceHash: 'a'.repeat(64), module: 'Job_Openings',
        externalId: String(29510000000000000n + BigInt(index)), targetId: null,
      })) };
    expect(validApprovalManifest(jobManifest)).toBe(true);
    expect(await recordApprovalEvidence(env, { accessToken: 'signed', manifest: jobManifest })).toEqual({ recorded: true });
    expect(mocks.rpc).toHaveBeenCalledWith('zoho_record_import_approval', { p_actor: id, p_manifest: jobManifest });
  });

  it('allows the reserved platform UUID only as publisher, keeping identity and request UUID checks strict', () => {
    const valid = { ...manifest(), publisherOrganizationId: PLATFORM_ORG_ID };
    expect(validApprovalManifest(valid)).toBe(true);
    for (const value of [
      { ...valid, publisherOrganizationId: '00000000-0000-0000-0000-000000000002' },
      { ...valid, requestId: PLATFORM_ORG_ID },
      { ...valid, connectionId: PLATFORM_ORG_ID },
      { ...valid, items: [{ ...valid.items[0], recordId: PLATFORM_ORG_ID }] },
      { ...valid, items: [{ ...valid.items[0], targetId: PLATFORM_ORG_ID }] },
    ]) expect(validApprovalManifest(value)).toBe(false);
  });
  it('verifies SSO signed credentials and never trusts a caller actor', async () => {
    const input = { accessToken: 'signed', manifest: manifest() };
    expect(await recordApprovalEvidence(env, input)).toEqual({ recorded: true });
    expect(mocks.verify).toHaveBeenCalledExactlyOnceWith('signed', env);
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith('zoho_record_import_approval', { p_actor: id, p_manifest: input.manifest });
    expect(await recordApprovalEvidence(env, { ...input, actorId: id })).toEqual({ recorded: false });
  });
  it.each([{ roles: ['admin'] }, { org_id: id }, { membership_status: 'suspended' }, { sub: 'bad' }])('denies stale or wrong signed scope %j', async changes => {
    mocks.verify.mockResolvedValue({ ...(await mocks.verify()), ...changes });
    mocks.verify.mockClear();
    expect(await recordApprovalEvidence(env, { accessToken: 'signed', manifest: manifest() })).toEqual({ recorded: false });
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it('denies expired/tampered credentials before storage and redacts infrastructure failures', async () => {
    mocks.verify.mockRejectedValue(new Error('private token detail'));
    expect(await recordApprovalEvidence(env, { accessToken: 'expired', manifest: manifest() })).toEqual({ recorded: false });
    expect(mocks.rpc).not.toHaveBeenCalled();
    mocks.rpc.mockRejectedValue(new Error('private storage detail'));
    expect(await validateApprovalEvidence(env, {})).toEqual({ allowed: false });
  });
  it('rejects duplicate, unbounded, malformed, payload-bearing and email-enabled manifests', () => {
    const valid = manifest();
    expect(validApprovalManifest(valid)).toBe(true);
    for (const value of [{ ...valid, items: [] }, { ...valid, items: Array(51).fill(valid.items[0]) },
      { ...valid, items: [valid.items[0], valid.items[0]] }, { ...valid, emailPolicy: 'allowed' },
      { ...valid, items: [{ ...valid.items[0], data: { email: 'private@example.com' } }] },
      { ...valid, items: [{ ...valid.items[0], targetId: 'bad' }] },
      { ...valid, items: [{ ...valid.items[0], candidateReviewHash: undefined }] },
      { ...valid, items: [{ ...valid.items[0], candidateReviewHash: 'bad' }] }]) expect(validApprovalManifest(value)).toBe(false);
  });
  it.each([false, null, 'true', { allowed: true }])('requires explicit true from canonical storage (%j)', async value => {
    mocks.rpc.mockResolvedValue(value);
    expect(await recordApprovalEvidence(env, { accessToken: 'signed', manifest: manifest() })).toEqual({ recorded: false });
    expect(await validateApprovalEvidence(env, {})).toEqual({ allowed: false });
  });
  it('requires the independently live operation after matching canonical human evidence', async () => {
    const validateOperation = vi.fn(async () => ({ allowed: true }));
    const scoped = { ...env, ZOHO_CONTROL_PLANE: { validateOperation } };
    expect(await validateApprovalEvidence(scoped, { operationId: id })).toEqual({ allowed: true });
    expect(validateOperation).toHaveBeenCalledExactlyOnceWith({ operationId: id });
    mocks.rpc.mockResolvedValue(false);
    validateOperation.mockClear();
    expect(await validateApprovalEvidence(scoped, {})).toEqual({ allowed: false });
    expect(validateOperation).not.toHaveBeenCalled();
  });
  it.each([false, null, 'true'])('denies non-explicit live operation authority %j', async allowed => {
    const scoped = { ...env, ZOHO_CONTROL_PLANE: { validateOperation: vi.fn(async () => ({ allowed })) } } as unknown as Env;
    expect(await validateApprovalEvidence(scoped, {})).toEqual({ allowed: false });
  });
  it('fails closed on a missing, throwing or stalled live authority', async () => {
    expect(await validateApprovalEvidence(env, {})).toEqual({ allowed: false });
    const scoped = { ...env, ZOHO_CONTROL_PLANE: { validateOperation: vi.fn(async () => { throw new Error('private'); }) } };
    expect(await validateApprovalEvidence(scoped, {})).toEqual({ allowed: false });
    vi.useFakeTimers();
    try {
      scoped.ZOHO_CONTROL_PLANE.validateOperation.mockImplementation(() => new Promise(() => {}));
      const pending = validateApprovalEvidence(scoped, {});
      await vi.advanceTimersByTimeAsync(5000);
      expect(await pending).toEqual({ allowed: false });
    } finally { vi.useRealTimers(); }
  });
  it('bounds validation payloads before storage', async () => {
    expect(await validateApprovalEvidence(env, { data: 'x'.repeat(131073) })).toEqual({ allowed: false });
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
});
