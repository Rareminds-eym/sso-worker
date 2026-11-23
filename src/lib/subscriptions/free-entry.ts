import configuration from '../../../config/subscriptions/free-signup.json';
import type { DbClient } from '../db';
import { loadCatalogOwnerInputs } from './catalog-owner-inputs';
import { loadCatalogAudiences } from './catalog-audience';
import { record, text, uuid, invalid, integer } from './validation';

type Database = Pick<DbClient, 'rpc'>;
type SignupKind = 'organization' | 'member';

/** Server-owned routing configuration is checked against the existing audience/role authorities. */
export function freeSignupPolicy(value: unknown = configuration) {
  const input = record(value, 'freeSignup', ['schemaVersion', 'source', 'productCode', 'signupRoles', 'memberRoles']);
  if (input.schemaVersion !== 1) invalid('freeSignup.schemaVersion', 'unsupported version');
  text(input.source, 'freeSignup.source');
  const productCode = text(input.productCode, 'freeSignup.productCode');
  if (!/^[a-z][a-z0-9_-]*$/.test(productCode)) invalid('freeSignup.productCode', 'invalid product code');
  const owner = loadCatalogOwnerInputs(), audiences = loadCatalogAudiences(owner);
  const bindings = (raw: unknown, kind: SignupKind) => {
    const entries = record(raw, 'freeSignup.roles', raw && typeof raw === 'object' ? Object.keys(raw) : []);
    if (!Object.keys(entries).length) invalid('freeSignup.roles', 'explicit role routing required');
    return Object.fromEntries(Object.entries(entries).map(([role, value]) => {
      text(role, 'freeSignup.role');
      const binding = record(value, 'freeSignup.binding', ['audience', 'organizationType']);
      const audience = text(binding.audience, 'freeSignup.audience'), terms = owner.audiences.get(audience);
      if (!terms || !terms.managerRoles.includes(role) || terms.subjectKind !== (kind === 'member' ? 'user' : 'organization')) invalid('freeSignup.binding', 'role must manage the authoritative audience');
      const organizationType = binding.organizationType === null ? null : text(binding.organizationType, 'freeSignup.organizationType');
      if (kind === 'member' ? organizationType !== null : organizationType === null || audiences.organizationTypes.get(organizationType) !== audience) invalid('freeSignup.organizationType', 'organization type must match the catalog audience');
      return [role, { audience, organizationType }];
    }));
  };
  const signupRoles = bindings(input.signupRoles, 'organization'), memberRoles = bindings(input.memberRoles, 'member');
  const covered = new Set([...Object.values(signupRoles), ...Object.values(memberRoles)].map(binding => binding.audience));
  if (covered.size !== owner.audiences.size || [...owner.audiences.keys()].some(audience => !covered.has(audience))) invalid('freeSignup.roles', 'every owner audience requires explicit signup routing');
  return { schemaVersion: 1, productCode, signupRoles, memberRoles };
}

/** Signup and its free-entry intent share the existing owner database transaction. */
export async function signupWithFreeEntry<T>(database: Database, kind: SignupKind, signup: Record<string, unknown>): Promise<T> {
  const policy = freeSignupPolicy(), role = text(signup.p_role, 'freeSignup.role');
  const bindings = kind === 'member' ? policy.memberRoles : policy.signupRoles;
  // Other canonical roles retain their existing signup operation, without a free-entry intent.
  if (!Object.hasOwn(bindings, role)) return database.rpc<T>(kind === 'member' ? 'signup_member' : 'signup_user', signup);
  return database.rpc<T>('signup_with_subscription_entry', { p_kind: kind, p_signup: signup, p_policy: policy });
}

/** Token consumption, verified identity and free activation commit together. */
export async function verifyEmailWithFreeEntry(database: Database, tokenHash: string) {
  if (!/^[a-f0-9]{64}$/.test(tokenHash)) invalid('verification.tokenHash', 'hashed verification token required');
  const raw = await database.rpc<unknown>('verify_email_with_subscription_entry', { p_token_hash: tokenHash });
  return verificationReceipt(raw);
}

/** Called only after the gateway has verified the provider email and identity.
 * The owner rechecks the stored Google link before verifying and activating. */
export async function verifyOAuthWithFreeEntry(database: Database, userId: string, providerSubject: string, email: string) {
  const raw = await database.rpc<unknown>('verify_oauth_with_subscription_entry', {
    p_user_id: uuid(userId, 'verification.userId'),
    p_provider_subject: text(providerSubject, 'verification.providerSubject'),
    p_email: text(email, 'verification.email'),
  });
  const receipt = verificationReceipt(raw);
  if ('error' in receipt || receipt.userId !== userId) invalid('verification.receipt', 'OAuth identity acknowledgement differs');
  return receipt;
}

function verificationReceipt(raw: unknown) {
  if (raw && typeof raw === 'object' && Object.hasOwn(raw, 'error')) {
    const failure = record(raw, 'verification.failure', ['error', 'status']);
    const status = integer(failure.status, 'verification.status');
    if (status !== 404 && status !== 410) invalid('verification.status', 'unexpected owner failure');
    return { error: text(failure.error, 'verification.error'), status };
  }
  const result = record(raw, 'verification.receipt', ['verified', 'userId', 'subscriptionIds']);
  if (result.verified !== true || !Array.isArray(result.subscriptionIds)) invalid('verification.receipt', 'complete owner acknowledgement required');
  const userId = uuid(result.userId, 'verification.userId');
  const subscriptionIds = result.subscriptionIds.map(id => uuid(id, 'verification.subscriptionId'));
  if (new Set(subscriptionIds).size !== subscriptionIds.length) invalid('verification.subscriptionIds', 'duplicate subscriptions');
  return { verified: true as const, userId, subscriptionIds };
}
