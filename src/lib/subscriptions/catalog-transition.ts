import { array, integer, invalid, record, text, uuid } from './validation';
import { validatePlanIdentity } from './catalog';

/** A transition changes offer eligibility only. Purchased terms never follow a
 * new offer pointer; renewals/upgrades use the ordinary quote/settlement owner. */
export interface CatalogTransitionCommand {
  schemaVersion: 1;
  operationId: string;
  productId: string;
  actorId: string;
  approvalReference: string;
  effectiveAt: number;
  hybridPlanId: string;
  expectedPlans: readonly { id: string; code: string; active: boolean }[];
  replacements: readonly { legacyPlanId: string; planId: string; revisionId: string }[];
  retainedSubscriptions: readonly { id: string; planId: string; purchasedTerms: unknown }[];
  preservation: 'retain_original_purchases_and_history';
}
export interface CatalogTransitionSnapshot {
  productId: string;
  hybridPlanId: string;
  plans: readonly { id: string; code: string; active: boolean }[];
  publications: readonly { planId: string; revisionId: string; productId: string }[];
  subscriptions: readonly { id: string; planId: string; purchasedTerms: unknown }[];
}

function canonical(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${Array.from(value, canonical).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${canonical(object[key])}`).join(',')}}`;
  }
  return invalid('transition.identity', 'exact JSON required');
}
function unique(values: readonly string[], path: string) {
  if (new Set(values).size !== values.length) invalid(path, 'duplicate identity');
}
function plans(value: unknown) {
  const rows = array(value, 'transition.expectedPlans').map(value => {
    const row = record(value, 'transition.plan', ['id', 'code', 'active']);
    if (typeof row.active !== 'boolean') invalid('transition.plan.active', 'boolean required');
    return { id: uuid(row.id, 'transition.plan.id'), code: text(row.code, 'transition.plan.code'), active: row.active };
  });
  unique(rows.map(row => row.id), 'transition.plans');
  return rows;
}
function subscriptions(value: unknown) {
  const rows = array(value, 'transition.retainedSubscriptions').map(value => {
    const row = record(value, 'transition.subscription', ['id', 'planId', 'purchasedTerms']);
    // The caller reads exact historical purchase values. Empty/fabricated terms
    // cannot be used as a preservation certificate.
    if (row.purchasedTerms === null || typeof row.purchasedTerms !== 'object' || Array.isArray(row.purchasedTerms)
      || !Object.keys(row.purchasedTerms).length) invalid('transition.purchasedTerms', 'exact owner purchase snapshot required');
    const purchasedTerms: unknown = JSON.parse(canonical(row.purchasedTerms));
    return { id: uuid(row.id, 'transition.subscription.id'), planId: uuid(row.planId, 'transition.subscription.planId'), purchasedTerms };
  });
  unique(rows.map(row => row.id), 'transition.subscriptions');
  return rows;
}
export function validateCatalogTransitionCommand(value: unknown): CatalogTransitionCommand {
  const input = record(value, 'transition', ['schemaVersion', 'operationId', 'productId', 'actorId', 'approvalReference', 'effectiveAt',
    'hybridPlanId', 'expectedPlans', 'replacements', 'retainedSubscriptions', 'preservation']);
  if (input.schemaVersion !== 1 || input.preservation !== 'retain_original_purchases_and_history') invalid('transition', 'explicit preservation contract required');
  const hybridPlanId = uuid(input.hybridPlanId, 'transition.hybridPlanId');
  const expectedPlans = plans(input.expectedPlans);
  if (expectedPlans.filter(plan => plan.id === hybridPlanId).length !== 1) invalid('transition.hybridPlanId', 'retained Hybrid must be in exact baseline');
  const replacements = array(input.replacements, 'transition.replacements').map(value => {
    const row = record(value, 'transition.replacement', ['legacyPlanId', 'planId', 'revisionId']);
    const legacyPlanId = uuid(row.legacyPlanId, 'transition.legacyPlanId'), planId = uuid(row.planId, 'transition.planId');
    if (legacyPlanId === hybridPlanId || planId === hybridPlanId || legacyPlanId === planId) invalid('transition.replacements', 'Hybrid and same-plan rewrites are prohibited');
    if (!expectedPlans.some(plan => plan.id === legacyPlanId && plan.active)
      || !expectedPlans.some(plan => plan.id === planId && plan.active)) invalid('transition.replacements', 'exact active source and target required');
    return { legacyPlanId, planId, revisionId: uuid(row.revisionId, 'transition.revisionId') };
  });
  if (!replacements.length) invalid('transition.replacements', 'explicit cohort mapping required');
  unique(replacements.map(row => row.legacyPlanId), 'transition.replacements');
  const retired = new Set(replacements.map(row => row.legacyPlanId));
  if (replacements.some(row => retired.has(row.planId))) invalid('transition.replacements', 'target cannot also retire');
  const retainedSubscriptions = subscriptions(input.retainedSubscriptions);
  if (retainedSubscriptions.some(row => !expectedPlans.some(plan => plan.id === row.planId))) invalid('transition.subscriptions', 'foreign plan in purchase cohort');
  return { schemaVersion: 1, operationId: uuid(input.operationId, 'transition.operationId'), productId: uuid(input.productId, 'transition.productId'),
    actorId: uuid(input.actorId, 'transition.actorId'), approvalReference: text(input.approvalReference, 'transition.approvalReference'),
    effectiveAt: integer(input.effectiveAt, 'transition.effectiveAt', 1), hybridPlanId, expectedPlans, replacements, retainedSubscriptions,
    preservation: 'retain_original_purchases_and_history' };
}

/** Pure preflight. The database repeats every comparison under locks before any
 * retirement. Exact replay is handled before current-state comparisons. */
export function prepareCatalogTransition(value: unknown, snapshot: CatalogTransitionSnapshot, now: number) {
  const command = validateCatalogTransitionCommand(value);
  const sorted = <T extends { id: string }>(rows: readonly T[]) => [...rows].sort((a, b) => a.id.localeCompare(b.id));
  if (snapshot.productId !== command.productId || snapshot.hybridPlanId !== command.hybridPlanId) invalid('transition.scope', 'owner product or Hybrid differs');
  if (canonical(sorted(plans(snapshot.plans))) !== canonical(sorted(command.expectedPlans))
    || canonical(sorted(subscriptions(snapshot.subscriptions))) !== canonical(sorted(command.retainedSubscriptions))) invalid('transition.baseline', 'fresh exact plan and purchase baseline required');
  for (const target of command.replacements) {
    if (snapshot.publications.filter(row => row.productId === command.productId && row.planId === target.planId
      && row.revisionId === target.revisionId).length !== 1) invalid('transition.publication', 'exact published replacement required');
  }
  if (integer(now, 'transition.now') < command.effectiveAt) invalid('transition.effectiveAt', 'not effective yet; no automatic scheduling');
  return { command, retirePlanIds: command.replacements.map(row => row.legacyPlanId),
    retainSubscriptionIds: command.retainedSubscriptions.map(row => row.id), hybridPlanId: command.hybridPlanId };
}

export interface CatalogTransitionReceipt { operationId: string; command: CatalogTransitionCommand; retiredPlanIds: string[]; preservedSubscriptionIds: string[] }
/** Only the authenticated owner may invoke this after a target-specific approval.
 * No caller in catalog preparation invokes this function. Uncertainty propagates. */
export async function commitCatalogTransition(database: { rpc(name: string, parameters: Record<string, unknown>): Promise<unknown> }, value: unknown): Promise<CatalogTransitionReceipt> {
  const command = validateCatalogTransitionCommand(value);
  const raw = record(await database.rpc('commit_subscription_catalog_transition', { p_command: command }), 'transition.receipt',
    ['operationId', 'command', 'retiredPlanIds', 'preservedSubscriptionIds']);
  const retiredPlanIds = array(raw.retiredPlanIds, 'transition.retired').map(value => uuid(value, 'transition.retired.id'));
  const preservedSubscriptionIds = array(raw.preservedSubscriptionIds, 'transition.preserved').map(value => uuid(value, 'transition.preserved.id'));
  if (raw.operationId !== command.operationId || canonical(raw.command) !== canonical(command)
    || canonical(retiredPlanIds) !== canonical(command.replacements.map(row => row.legacyPlanId))
    || canonical(preservedSubscriptionIds) !== canonical(command.retainedSubscriptions.map(row => row.id))) invalid('transition.receipt', 'owner acknowledgement differs');
  return { operationId: command.operationId, command, retiredPlanIds, preservedSubscriptionIds };
}

/** Explicit canonical-code transition. Historical purchase codes are immutable;
 * the owner supplies the retained Hybrid UUID independently of the command. */
export interface HybridIdentityTransitionCommand {
  schemaVersion: 1;
  operationId: string;
  productId: string;
  actorId: string;
  approvalReference: string;
  effectiveAt: number;
  hybridPlanId: string;
  expectedCode: string;
  targetCode: string;
  retainedSubscriptions: CatalogTransitionCommand['retainedSubscriptions'];
  preservation: 'retain_original_purchases_and_history';
}
export function validateHybridIdentityTransition(value: unknown): HybridIdentityTransitionCommand {
  const input = record(value, 'identityTransition', ['schemaVersion', 'operationId', 'productId', 'actorId', 'approvalReference',
    'effectiveAt', 'hybridPlanId', 'expectedCode', 'targetCode', 'retainedSubscriptions', 'preservation']);
  if (input.schemaVersion !== 1 || input.preservation !== 'retain_original_purchases_and_history') invalid('identityTransition', 'explicit preservation required');
  const expectedCode = text(input.expectedCode, 'identityTransition.expectedCode');
  const targetCode = text(input.targetCode, 'identityTransition.targetCode');
  if (/^pln_[0-9a-f]{32}$/.test(expectedCode) || !/^pln_[0-9a-f]{32}$/.test(targetCode)) invalid('identityTransition.code', 'only an explicit legacy to opaque code transition is permitted');
  const hybridPlanId = uuid(input.hybridPlanId, 'identityTransition.hybridPlanId');
  const retainedSubscriptions = subscriptions(input.retainedSubscriptions);
  if (retainedSubscriptions.some(row => row.planId !== hybridPlanId)) invalid('identityTransition.subscriptions', 'only the retained Hybrid purchase cohort applies');
  return { schemaVersion: 1, operationId: uuid(input.operationId, 'identityTransition.operationId'),
    productId: uuid(input.productId, 'identityTransition.productId'), actorId: uuid(input.actorId, 'identityTransition.actorId'),
    approvalReference: text(input.approvalReference, 'identityTransition.approvalReference'),
    effectiveAt: integer(input.effectiveAt, 'identityTransition.effectiveAt', 1), hybridPlanId, expectedCode, targetCode,
    retainedSubscriptions, preservation: 'retain_original_purchases_and_history' };
}
export function prepareHybridIdentityTransition(value: unknown, snapshot: CatalogTransitionSnapshot, now: number) {
  const command = validateHybridIdentityTransition(value);
  if (command.hybridPlanId !== snapshot.hybridPlanId || command.productId !== snapshot.productId) invalid('identityTransition.scope', 'trusted retained identity differs');
  const hybrid = snapshot.plans.filter(plan => plan.id === snapshot.hybridPlanId);
  if (hybrid.length !== 1 || hybrid[0].code !== command.expectedCode
    || snapshot.plans.some(plan => plan.id !== command.hybridPlanId && plan.code === command.targetCode)) invalid('identityTransition.baseline', 'exact canonical code baseline required');
  const sort = (rows: CatalogTransitionCommand['retainedSubscriptions']) => [...rows].sort((a, b) => a.id.localeCompare(b.id));
  if (canonical(sort(command.retainedSubscriptions)) !== canonical(sort(subscriptions(snapshot.subscriptions.filter(row => row.planId === snapshot.hybridPlanId))))) invalid('identityTransition.purchases', 'exact unchanged Hybrid purchase cohort required');
  if (integer(now, 'identityTransition.now') < command.effectiveAt) invalid('identityTransition.effectiveAt', 'not effective yet');
  return { command, plan: { id: command.hybridPlanId, code: command.targetCode, productId: command.productId },
    preservedSubscriptionIds: command.retainedSubscriptions.map(row => row.id) };
}
export async function commitHybridIdentityTransition(database: { rpc(name: string, parameters: Record<string, unknown>): Promise<unknown> }, value: unknown) {
  const command = validateHybridIdentityTransition(value);
  const receipt = record(await database.rpc('commit_subscription_hybrid_identity_transition', { p_command: command }),
    'identityTransition.receipt', ['operationId', 'command', 'plan', 'preservedSubscriptionIds']);
  const expected = { id: command.hybridPlanId, code: command.targetCode, productId: command.productId };
  const ids = command.retainedSubscriptions.map(row => row.id);
  if (receipt.operationId !== command.operationId || canonical(receipt.command) !== canonical(command)
    || canonical(receipt.plan) !== canonical(expected) || canonical(receipt.preservedSubscriptionIds) !== canonical(ids)) invalid('identityTransition.receipt', 'owner acknowledgement differs');
  return { operationId: command.operationId, command, plan: expected, preservedSubscriptionIds: ids };
}

export interface CatalogAvailabilityCommand {
  schemaVersion: 1;
  operationId: string;
  actorId: string;
  productId: string;
  hybridPlanId: string;
  approvalReference: string;
  effectiveAt: number;
  entries: readonly { planId: string; revisionId: string; expectedActive: false; expectedCanonical: Record<string, unknown> }[];
}
/** Implemented by the publication owner using an independent persisted
 * application-projection read and exact immutable bundle verification. HTTP
 * callers cannot supply this callback or substitute a readiness boolean. */
export type CatalogAvailabilityPublicationReader = (planId: string, revisionId: string) => Promise<{
  planId: string; revisionId: string; productId: string; canonicalPlan: unknown;
}>;
function availabilityCommand(value: unknown): CatalogAvailabilityCommand {
  const input = record(value, 'availability', ['schemaVersion', 'operationId', 'actorId', 'productId', 'hybridPlanId', 'approvalReference', 'effectiveAt', 'entries']);
  if (input.schemaVersion !== 1) invalid('availability', 'unsupported schema version');
  const productId = uuid(input.productId, 'availability.productId'), hybridPlanId = uuid(input.hybridPlanId, 'availability.hybridPlanId');
  const entries = array(input.entries, 'availability.entries').map(value => {
    const entry = record(value, 'availability.entry', ['planId', 'revisionId', 'expectedActive', 'expectedCanonical']);
    const planId = uuid(entry.planId, 'availability.planId');
    if (planId === hybridPlanId || entry.expectedActive !== false) invalid('availability.entry', 'explicit inactive non-Hybrid offer required');
    const expectedCanonical = record(entry.expectedCanonical, 'availability.canonical', ['id', 'code', 'productId', 'audiences', 'configuration']);
    const identity = validatePlanIdentity({ id: expectedCanonical.id, code: expectedCanonical.code, productId: expectedCanonical.productId });
    if (identity.id !== planId || identity.productId !== productId) invalid('availability.canonical', 'publication owner identity differs');
    const audiences = array(expectedCanonical.audiences, 'availability.canonical.audiences').map(value => text(value, 'availability.canonical.audience'));
    if (!audiences.length || new Set(audiences).size !== audiences.length) invalid('availability.canonical.audiences', 'explicit unique audiences required');
    record(expectedCanonical.configuration, 'availability.canonical.configuration', expectedCanonical.configuration
      && typeof expectedCanonical.configuration === 'object' ? Object.keys(expectedCanonical.configuration) : []);
    canonical(expectedCanonical);
    return { planId, revisionId: uuid(entry.revisionId, 'availability.revisionId'), expectedActive: false as const, expectedCanonical };
  });
  if (!entries.length) invalid('availability.entries', 'explicit verified offer set required');
  unique(entries.map(entry => entry.planId), 'availability.entries');
  unique(entries.map(entry => entry.revisionId), 'availability.entries');
  return { schemaVersion: 1, operationId: uuid(input.operationId, 'availability.operationId'), actorId: uuid(input.actorId, 'availability.actorId'),
    productId, hybridPlanId, approvalReference: text(input.approvalReference, 'availability.approvalReference'),
    effectiveAt: integer(input.effectiveAt, 'availability.effectiveAt', 1), entries };
}
export async function prepareCatalogAvailability(value: unknown, snapshot: CatalogTransitionSnapshot, actorId: string,
  readVerifiedPublication: CatalogAvailabilityPublicationReader, now: number): Promise<CatalogAvailabilityCommand> {
  const request = record(value, 'availability.request', ['schemaVersion', 'operationId', 'productId', 'hybridPlanId', 'approvalReference', 'effectiveAt', 'entries']);
  if (request.productId !== snapshot.productId || request.hybridPlanId !== snapshot.hybridPlanId) invalid('availability.scope', 'trusted product and retained identity required');
  const entries = [];
  for (const value of array(request.entries, 'availability.request.entries')) {
    const entry = record(value, 'availability.request.entry', ['planId', 'revisionId', 'expectedActive']);
    const planId = uuid(entry.planId, 'availability.planId'), revisionId = uuid(entry.revisionId, 'availability.revisionId');
    if (planId === snapshot.hybridPlanId || entry.expectedActive !== false
      || snapshot.plans.filter(row => row.id === planId && row.active === false).length !== 1
      || snapshot.publications.filter(row => row.planId === planId && row.revisionId === revisionId && row.productId === snapshot.productId).length !== 1) invalid('availability.baseline', 'exact inactive owner-published revision required');
    const proof = await readVerifiedPublication(planId, revisionId);
    if (proof.planId !== planId || proof.revisionId !== revisionId || proof.productId !== snapshot.productId) invalid('availability.projection', 'independent publication owner proof differs');
    entries.push({ planId, revisionId, expectedActive: false, expectedCanonical: proof.canonicalPlan });
  }
  const command = availabilityCommand({ ...request, actorId, entries });
  if (command.entries.some(entry => snapshot.plans.find(plan => plan.id === entry.planId)?.code !== entry.expectedCanonical.code)) invalid('availability.baseline', 'canonical code differs from trusted snapshot');
  if (integer(now, 'availability.now') < command.effectiveAt) invalid('availability.effectiveAt', 'not effective yet');
  return command;
}
export async function commitCatalogAvailability(database: { rpc(name: string, parameters: Record<string, unknown>): Promise<unknown> }, value: CatalogAvailabilityCommand) {
  const command = availabilityCommand(value);
  const receipt = record(await database.rpc('commit_subscription_catalog_availability', { p_command: command }),
    'availability.receipt', ['operationId', 'command', 'activatedPlanIds']);
  const ids = command.entries.map(entry => entry.planId);
  if (receipt.operationId !== command.operationId || canonical(receipt.command) !== canonical(command)
    || canonical(receipt.activatedPlanIds) !== canonical(ids)) invalid('availability.receipt', 'exact owner acknowledgement required');
  return { operationId: command.operationId, command, activatedPlanIds: ids };
}
