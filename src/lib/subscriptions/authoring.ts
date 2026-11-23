import { errors } from 'jose';
import { PLATFORM_ORG_ID } from '../constants';
import { db } from '../db';
import { verifyAccessToken } from '../jwt';
import type { Env } from '../../types';
import { readCreditAuthoringContext, type CreditAuthoringContext } from './credit-authoring-context';
import type { CreditPolicyRegistry } from './credit-policy';
import { stagePlanRevisionBundle } from './revision-bundle';
import { CatalogValidationError, array, choice, invalid, record, text, uuid } from './validation';
import type { FeatureType } from './types';
import { recordSubscriptionCommerceEntryContract } from './commerce-persistence';

export class AuthoringForbidden extends Error {}

/** An authenticated commercial administrator records terms; activation still
 * independently verifies the purchaser, retained publication and exact contract. */
export async function registerSubscriptionCommerceEntryContract(
  env: Env, accessToken: unknown, productId: unknown, input: unknown,
) {
  try {
    const actor = await authorizeSubscriptionAdministrator(env, accessToken);
    const product = uuid(productId, 'entryContract.productId');
    const contract = record(input, 'entryContract', ['schemaVersion', 'id', 'productId', 'revisionId', 'subject',
      'audience', 'startsAt', 'endsAt', 'includedLearnerCapacity', 'sourceSubscriptionId', 'sourceEvidence']);
    if (uuid(contract.productId, 'entryContract.productId') !== product) invalid('entryContract.productId', 'owner product differs');
    const subject = record(contract.subject, 'entryContract.subject', ['kind', 'id']);
    const kind = choice(subject.kind, 'entryContract.subject.kind', ['user', 'organization']);
    const id = uuid(subject.id, 'entryContract.subject.id');
    const database = db(env);
    const products = await database.query<{ id: string }>(`products?select=id&id=eq.${product}&limit=2`, undefined, 'json-array');
    if (products.length !== 1 || products[0].id !== product) invalid('entryContract.productId', 'canonical product unavailable');
    const targets = await database.query<Record<string, unknown>>(kind === 'user'
      ? `users?select=id,is_blocked,is_email_verified&id=eq.${id}&limit=2`
      : `organizations?select=id,deleted_at&id=eq.${id}&limit=2`, undefined, 'json-array');
    if (targets.length !== 1 || targets[0].id !== id
      || (kind === 'user' ? targets[0].is_blocked !== false || targets[0].is_email_verified !== true
        : targets[0].deleted_at !== null)) invalid('entryContract.subject', 'live canonical recipient unavailable');
    const contractId = await recordSubscriptionCommerceEntryContract(database, actor, product, contract);
    return { kind: 'recorded' as const, contractId, productId: product,
      revisionId: uuid(contract.revisionId, 'entryContract.revisionId'), subject: { kind, id } };
  } catch (error) {
    if (error instanceof AuthoringForbidden) return { kind: 'forbidden' as const };
    if (error instanceof CatalogValidationError) return { kind: 'invalid' as const };
    throw error;
  }
}

/** Existing signed SSO identity and live canonical claims, never a caller-supplied actor UUID. */
export async function authorizeSubscriptionAdministrator(env: Env, accessToken: unknown): Promise<string> {
  if (typeof accessToken !== 'string' || !accessToken) throw new AuthoringForbidden();
  let claims;
  try { claims = await verifyAccessToken(accessToken, env); }
  catch (error) {
    if (error instanceof errors.JOSEError) throw new AuthoringForbidden();
    throw error;
  }
  if (!('exp' in claims) || typeof claims.exp !== 'number' || claims.exp <= Date.now() / 1000
    || claims.org_id !== PLATFORM_ORG_ID || claims.membership_status !== 'active'
    || !Array.isArray(claims.roles) || !claims.roles.includes('super_admin')) throw new AuthoringForbidden();
  let actor: string;
  try { actor = uuid(claims.sub, 'actor'); }
  catch (error) {
    if (error instanceof CatalogValidationError) throw new AuthoringForbidden();
    throw error;
  }
  const database = db(env);
  const users = await database.query<{ id: string; is_blocked: boolean }>(
    `users?select=id,is_blocked&id=eq.${actor}&limit=2`, undefined, 'json-array');
  if (users.length !== 1 || users[0].id !== actor || users[0].is_blocked !== false) throw new AuthoringForbidden();
  const live = await database.rpc<{ roles?: unknown; membership_status?: unknown }>('get_jwt_claims', { p_user_id: actor, p_org_id: PLATFORM_ORG_ID });
  if (!live || live.membership_status !== 'active' || !Array.isArray(live.roles) || !live.roles.includes('super_admin')) throw new AuthoringForbidden();
  return actor;
}

/** Private trusted-dashboard transport. App feature types must be loaded server-side, never from HTTP input. */
export async function stageOrdinaryPlanRevision(env: Env, accessToken: unknown, value: unknown, productId: unknown, featureDefinitions: unknown) {
  try {
    const actor = await authorizeSubscriptionAdministrator(env, accessToken);
    const product = uuid(productId, 'authoring.productId');
    const envelope = record(value, 'bundle', ['schemaVersion', 'draft', 'includedCredits']);
    const draft = record(envelope.draft, 'bundle.draft', ['schemaVersion', 'id', 'plan', 'revisionNumber', 'name', 'audiences', 'purchaseMode', 'prices', 'features']);
    const plan = record(draft.plan, 'bundle.draft.plan', ['id', 'code', 'productId']);
    const context = await readCreditAuthoringContext(db(env), uuid(plan.id, 'bundle.draft.plan.id'));
    if (context.plan.productId !== product || uuid(plan.productId, 'bundle.draft.plan.productId') !== product
      || plan.code !== context.plan.code) invalid('bundle.draft.plan', 'canonical plan/product identity differs');
    const registry = createPlanAuthoringRegistry(context, product, featureDefinitions);
    const receipt = await stagePlanRevisionBundle(db(env), value, registry, actor);
    return { kind: 'staged' as const, receipt };
  } catch (error) {
    if (error instanceof AuthoringForbidden) return { kind: 'forbidden' as const };
    if (error instanceof CatalogValidationError) return { kind: 'invalid' as const };
    throw error;
  }
}

/** Shared trusted owner registry parser; it never loads or fabricates commercial approvals. */
export function createPlanAuthoringRegistry(
  context: CreditAuthoringContext, product: string, featureDefinitions: unknown,
): CreditPolicyRegistry {
  if (context.plan.productId !== product) invalid('authoring.productId', 'canonical product differs');
  const featureTypes = new Map<string, FeatureType>();
  const featureOptions = new Map<string, ReadonlySet<string>>();
  for (const value of array(featureDefinitions, 'authoring.features')) {
    const feature = record(value, 'authoring.feature', ['key', 'type', 'options']);
    const key = text(feature.key, 'authoring.feature.key');
    if (featureTypes.has(key)) invalid('authoring.features', 'duplicate feature key');
    const type = choice(feature.type, 'authoring.feature.type', ['boolean', 'numeric_limit', 'metered', 'enum']);
    featureTypes.set(key, type);
    if (type === 'enum') {
      const options = array(feature.options, 'authoring.feature.options').map(option => text(option, 'authoring.feature.options'));
      if (!options.length || new Set(options).size !== options.length
        || options.some(option => !/^[a-z][a-z0-9_]*$/.test(option))) invalid('authoring.feature.options', 'expected unique explicit lower_snake_case options');
      featureOptions.set(key, new Set(options));
    } else if (Object.hasOwn(feature, 'options')) invalid('authoring.feature.options', 'options apply only to enum features');
  }
  if (context.credit.pools.some(pool => featureTypes.get(pool.featureKey) !== 'metered')) {
    invalid('authoring.pools', 'pool requires an app-owned metered feature');
  }
  return {
    catalog: { productIds: new Set([product]), audienceKeys: new Set(context.audiences),
      currencies: new Map(context.currencies.map(value => [value.code, value.minorUnit])), featureTypes, featureOptions },
    pools: new Map(context.credit.pools.map(pool => [pool.key, { ...pool, audiences: new Set(pool.audiences) }])),
    timePolicyIds: new Set(context.credit.timePolicies.map(policy => policy.id)),
    // Ordinary administration grants no rollover/expiry exceptions. These are intentional empty
    // permissions, never replacement data for a failed approval lookup.
    rolloverApprovalIds: new Set<string>(), expiryApprovalIds: new Set<string>(),
  };
}
