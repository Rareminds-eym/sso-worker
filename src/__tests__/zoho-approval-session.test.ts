import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportSPKI, exportPKCS8, SignJWT } from 'jose';
const { rpc } = vi.hoisted(() => ({ rpc: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => ({ rpc }) }));
import { recordApprovalEvidence } from '../rpc/zoho-approval-evidence';
import type { Env } from '../types';
const id = '10000000-0000-4000-8000-000000000001';
let env: Env;
let signingKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
const manifest = { requestId: id, connectionId: id, sourceOrgId: '123', publisherOrganizationId: id, configRevision: 1,
  items: [{ recordId: id, revision: 1, sourceHash: 'a'.repeat(64), module: 'Candidates', candidateReviewHash: 'b'.repeat(64), externalId: '123', targetId: null }], reason: 'Reviewed source', emailPolicy: 'forbidden' };
beforeAll(async () => {
  const keys = await generateKeyPair('RS256', { extractable: true });
  signingKey = keys.privateKey;
  env = { JWT_PUBLIC_KEY: await exportSPKI(keys.publicKey), JWT_PRIVATE_KEY: await exportPKCS8(keys.privateKey), JWT_KID: 'fixture' } as Env;
});
beforeEach(() => { rpc.mockReset(); rpc.mockResolvedValue(true); });
async function signed(overrides: { expiry?: string | null; audience?: string; issuer?: string; type?: string; wrongKey?: boolean } = {}) {
  const key = overrides.wrongKey ? (await generateKeyPair('RS256')).privateKey : signingKey;
  const token = new SignJWT({ sub: id, org_id: '00000000-0000-0000-0000-000000000001', membership_status: 'active', roles: ['super_admin'] })
    .setProtectedHeader({ alg: 'RS256', typ: overrides.type || 'JWT' }).setIssuedAt()
    .setIssuer(overrides.issuer || 'sso-api').setAudience(overrides.audience || 'sso-client')
    ;
  if (overrides.expiry !== null) token.setExpirationTime(overrides.expiry || '15m');
  return token.sign(key);
}
describe('actual signed human credential verification', () => {
  it('accepts a valid canonical human signature before registering immutable metadata', async () => {
    expect(await recordApprovalEvidence(env, { accessToken: await signed(), manifest })).toEqual({ recorded: true });
    expect(rpc).toHaveBeenCalledExactlyOnceWith('zoho_record_import_approval', { p_actor: id, p_manifest: manifest });
  });
  it.each([{ expiry: null }, { expiry: '-1s' }, { audience: 'other-app' }, { issuer: 'attacker' }, { type: 'other' }, { wrongKey: true }])('rejects invalid credential %j before canonical storage', async overrides => {
    expect(await recordApprovalEvidence(env, { accessToken: await signed(overrides), manifest })).toEqual({ recorded: false });
    expect(rpc).not.toHaveBeenCalled();
  });
});
