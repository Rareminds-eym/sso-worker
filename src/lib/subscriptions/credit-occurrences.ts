import { validateCreditTimePolicies, type CreditTimePolicyConfiguration } from './credit-authoring-context';
import type { CreditPolicyRegistry, CreditRollover } from './credit-policy';
import { validatePlanRevisionBundle } from './revision-bundle';
import { choice, integer, invalid, record, text, uuid } from './validation';

type CivilTime = readonly [number, number, number, number, number, number, number];
const HOUR_MS = 60 * 60 * 1000;

export interface IncludedCreditOccurrence {
  readonly schemaVersion: 1;
  readonly referenceId: string;
  readonly subscriptionId: string;
  readonly productId: string;
  readonly planId: string;
  readonly revisionId: string;
  readonly policyId: string;
  readonly ruleId: string;
  readonly featureKey: string;
  readonly poolKey: string;
  readonly audience: string;
  readonly recipient: Readonly<{ kind: 'subscriber' | 'organization' | 'managed_learner'; id: string }>;
  readonly quantity: number;
  readonly startsAt: number;
  readonly endsAt: number;
  readonly expiresAt: number;
  readonly rollover: CreditRollover;
  /** Definitions used in this calculation; persistence must compare the complete receipt on replay. */
  readonly timePolicies: readonly CreditTimePolicyConfiguration[];
}

/** Transport work budget, not a commercial credit or subscription limit. */
const REFRESH_SCAN_LIMIT = 50;

function instant(value: unknown, path: string): number {
  const result = integer(value, path);
  if (!Number.isFinite(new Date(result).getTime()) || new Date(result).getUTCFullYear() > 9998) {
    invalid(path, 'expected supported epoch milliseconds through year 9998');
  }
  return result;
}

function civilEpoch(parts: CivilTime): number {
  const date = new Date(0);
  date.setUTCFullYear(parts[0], parts[1] - 1, parts[2]);
  date.setUTCHours(parts[3], parts[4], parts[5], parts[6]);
  return date.getTime();
}

function calendar(policy: CreditTimePolicyConfiguration) {
  const formatter = new Intl.DateTimeFormat('en-US-u-ca-iso8601-nu-latn', {
    timeZone: policy.timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  });
  function civil(at: number): CivilTime {
    const parts = new Map(formatter.formatToParts(at).map(part => [part.type, part.value]));
    return [Number(parts.get('year')), Number(parts.get('month')), Number(parts.get('day')),
      Number(parts.get('hour')), Number(parts.get('minute')), Number(parts.get('second')), ((at % 1000) + 1000) % 1000];
  }
  function resolve(target: CivilTime): number {
    const wall = civilEpoch(target);
    // Enumerate zone offsets around the requested date, including full-day date-line changes.
    // Hourly probes over four days cover both sides of IANA civil-time transitions.
    const offsets = new Set<number>();
    for (let hour = -48; hour <= 48; hour++) {
      const sample = wall + hour * HOUR_MS;
      offsets.add(civilEpoch(civil(sample)) - sample);
    }
    const projections = [...offsets].map(offset => ({ at: wall - offset, wall: civilEpoch(civil(wall - offset)) }));
    const matches = projections.filter(item => item.wall === wall).map(item => item.at).sort((a, b) => a - b);
    if (matches.length === 1) return matches[0];
    if (matches.length > 1) {
      if (policy.ambiguousTime === 'reject') invalid('timePolicy.ambiguousTime', 'ambiguous local occurrence');
      return policy.ambiguousTime === 'earlier' ? matches[0] : matches[matches.length - 1];
    }
    if (policy.nonexistentTime === 'reject') invalid('timePolicy.nonexistentTime', 'nonexistent local occurrence');
    const forward = projections.filter(item => item.wall > wall).sort((a, b) => a.wall - b.wall);
    if (!forward.length) invalid('timePolicy.nonexistentTime', 'cannot resolve local occurrence');
    // shift_forward moves by the transition gap, preserving the requested position within it.
    return forward[0].at;
  }
  function month(at: number, offset: number, firstDay = false): number {
    const source = civil(at);
    const absoluteMonth = source[0] * 12 + source[1] - 1 + offset;
    const year = Math.floor(absoluteMonth / 12), month = absoluteMonth % 12 + 1;
    if (!Number.isSafeInteger(absoluteMonth) || year > 9998) invalid('occurrenceIndex', 'calendar month outside supported range');
    const end = new Date(civilEpoch([year, month + 1, 0, 0, 0, 0, 0])).getUTCDate();
    if (!firstDay && source[2] > end && policy.monthDayOverflow === 'reject') {
      invalid('timePolicy.monthDayOverflow', 'anniversary day absent from target month');
    }
    return resolve(firstDay ? [year, month, 1, 0, 0, 0, 0]
      : [year, month, Math.min(source[2], end), source[3], source[4], source[5], source[6]]);
  }
  return { month };
}

/**
 * Pure preparation, never authorization or allocation. The internal owner must load the published
 * revision, immutable calendar definitions, subscription period and eligible recipient itself.
 * No HTTP route exposes this helper. A receipt is not proof of payment, membership or permission.
 */
export async function prepareIncludedCreditOccurrence(
  bundleValue: unknown, registry: CreditPolicyRegistry, contextValue: unknown, timePoliciesValue: unknown,
): Promise<IncludedCreditOccurrence> {
  const bundle = validatePlanRevisionBundle(bundleValue, registry);
  const input = record(contextValue, 'occurrence', ['subscriptionId', 'productId', 'planId', 'revisionId', 'ruleId',
    'audience', 'recipient', 'activatedAt', 'subscriptionEndsAt', 'periodStartsAt', 'periodEndsAt', 'occurrenceIndex']);
  const subscriptionId = uuid(input.subscriptionId, 'occurrence.subscriptionId');
  const productId = uuid(input.productId, 'occurrence.productId'), planId = uuid(input.planId, 'occurrence.planId');
  const revisionId = uuid(input.revisionId, 'occurrence.revisionId'), ruleId = uuid(input.ruleId, 'occurrence.ruleId');
  if (productId !== bundle.draft.plan.productId || planId !== bundle.draft.plan.id || revisionId !== bundle.draft.id) {
    invalid('occurrence', 'subscription must bind the supplied plan, product and revision');
  }
  const rule = bundle.includedCredits.rules.find(item => item.id === ruleId);
  if (!rule) invalid('occurrence.ruleId', 'unknown included-credit rule');
  const audience = text(input.audience, 'occurrence.audience');
  if (!rule.audiences.includes(audience)) invalid('occurrence.audience', 'audience ineligible for this rule');
  const recipientValue = record(input.recipient, 'occurrence.recipient', ['kind', 'id']);
  const recipient = Object.freeze({
    kind: choice(recipientValue.kind, 'occurrence.recipient.kind', ['subscriber', 'organization', 'managed_learner']),
    id: uuid(recipientValue.id, 'occurrence.recipient.id'),
  });
  if (recipient.kind !== rule.recipient) invalid('occurrence.recipient.kind', 'recipient does not match the rule');
  if (rule.quantity.kind !== 'finite') invalid('occurrence.quantity', 'negotiated quantity must be resolved before allocation');
  const activatedAt = instant(input.activatedAt, 'occurrence.activatedAt');
  const subscriptionEndsAt = instant(input.subscriptionEndsAt, 'occurrence.subscriptionEndsAt');
  const periodStartsAt = instant(input.periodStartsAt, 'occurrence.periodStartsAt');
  const periodEndsAt = instant(input.periodEndsAt, 'occurrence.periodEndsAt');
  if (!(activatedAt <= periodStartsAt && periodStartsAt < periodEndsAt && periodEndsAt <= subscriptionEndsAt)) {
    invalid('occurrence', 'expected nonempty subscription period within the activated subscription');
  }
  const index = integer(input.occurrenceIndex, 'occurrence.occurrenceIndex');
  const definitions = validateCreditTimePolicies(timePoliciesValue);
  const used = new Map<string, CreditTimePolicyConfiguration>();
  function timePolicy(id: string): CreditTimePolicyConfiguration {
    const definition = definitions.find(item => item.id === id);
    if (!definition || !registry.timePolicyIds.has(id)) invalid('occurrence.timePolicy', 'missing registered calendar definition');
    used.set(id, definition);
    return definition;
  }
  let startsAt: number, endsAt: number, occurrenceKey: string | number;
  if (rule.cadence.kind === 'monthly') {
    const policy = timePolicy(rule.cadence.timePolicyId), dates = calendar(policy);
    const firstDay = policy.monthlyAnchor === 'calendar_month_start';
    startsAt = index === 0 ? activatedAt : dates.month(activatedAt, index, firstDay);
    endsAt = Math.min(dates.month(activatedAt, index + 1, firstDay), subscriptionEndsAt);
    occurrenceKey = index;
  } else {
    if (index !== 0) invalid('occurrence.occurrenceIndex', 'only monthly cadence accepts a nonzero index');
    if (rule.cadence.kind === 'purchase') invalid('occurrence', 'included credits cannot use purchase cadence');
    startsAt = rule.cadence.kind === 'activation' ? activatedAt : periodStartsAt;
    endsAt = rule.cadence.kind === 'activation' ? subscriptionEndsAt : periodEndsAt;
    occurrenceKey = rule.cadence.kind === 'activation' ? 'activation' : periodStartsAt;
  }
  if (startsAt >= endsAt) invalid('occurrence.occurrenceIndex', 'occurrence falls outside the subscription');
  const expiresAt = rule.expiry.kind === 'after_months'
    ? calendar(timePolicy(rule.expiry.timePolicyId)).month(startsAt, rule.expiry.months)
    : rule.expiry.kind === 'subscription_end' ? subscriptionEndsAt : endsAt;
  if (expiresAt <= startsAt) invalid('occurrence.expiry', 'expiry must follow allocation start');
  const identity = JSON.stringify([1, productId, planId, revisionId, subscriptionId, bundle.includedCredits.id,
    rule.id, recipient.kind, recipient.id, occurrenceKey]);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity));
  const referenceId = 'sc1_' + [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  return Object.freeze({ schemaVersion: 1, referenceId, subscriptionId, productId, planId, revisionId,
    policyId: bundle.includedCredits.id, ruleId, featureKey: rule.featureKey, poolKey: rule.poolKey, audience,
    recipient, quantity: rule.quantity.value, startsAt, endsAt, expiresAt, rollover: rule.rollover,
    timePolicies: Object.freeze([...used.values()].sort((a, b) => a.id.localeCompare(b.id))) });
}

/**
 * Bounded preparation of due, unexpired occurrences for one retained rule.
 * The caller must authorize the subscription/recipient; this never writes credits.
 * Cursor counts inspected occurrences, including expired ones, so a long history
 * cannot create an unbounded request or silently lose its continuation position.
 */
export async function prepareIncludedCreditRefresh(
  bundleValue: unknown, registry: CreditPolicyRegistry, contextValue: unknown, timePoliciesValue: unknown,
) {
  const input = record(contextValue, 'refresh', ['subscriptionId', 'productId', 'planId', 'revisionId', 'ruleId',
    'audience', 'recipient', 'activatedAt', 'subscriptionEndsAt', 'periodStartsAt', 'periodEndsAt', 'cursor', 'now']);
  const { cursor: cursorValue, now: nowValue, ...terms } = input;
  const cursor = integer(cursorValue, 'refresh.cursor'), now = instant(nowValue, 'refresh.now');
  const bundle = validatePlanRevisionBundle(bundleValue, registry);
  // Reuse all existing scope, recipient, calendar and quantity validation before
  // deciding whether any occurrence is currently due.
  const first = await prepareIncludedCreditOccurrence(bundle, registry, { ...terms, occurrenceIndex: 0 }, timePoliciesValue);
  const rule = bundle.includedCredits.rules.find(value => value.id === first.ruleId)!;
  if (now < instant(input.activatedAt, 'refresh.activatedAt')) invalid('refresh.now', 'refresh precedes activation');
  if (rule.cadence.kind !== 'monthly' && cursor !== 0) invalid('refresh.cursor', 'nonrecurring rule requires initial cursor');
  const definitions = validateCreditTimePolicies(timePoliciesValue);
  const cadence = rule.cadence;
  const monthlyPolicy = cadence.kind === 'monthly'
    ? definitions.find(value => value.id === cadence.timePolicyId) : undefined;
  const dates = monthlyPolicy ? calendar(monthlyPolicy) : null;
  const occurrences: IncludedCreditOccurrence[] = [];
  let index = cursor, nextCursor: number | null = null;
  for (let scanned = 0; scanned < REFRESH_SCAN_LIMIT; scanned++) {
    const startsAt = rule.cadence.kind !== 'monthly' || index === 0 ? first.startsAt
      : dates!.month(instant(input.activatedAt, 'refresh.activatedAt'), index, monthlyPolicy!.monthlyAnchor === 'calendar_month_start');
    if (startsAt > now || startsAt >= instant(input.subscriptionEndsAt, 'refresh.subscriptionEndsAt')) break;
    const occurrence = index === 0 ? first : await prepareIncludedCreditOccurrence(bundle, registry,
      { ...terms, occurrenceIndex: index }, definitions);
    if (occurrence.expiresAt > now) occurrences.push(occurrence);
    if (rule.cadence.kind !== 'monthly') break;
    index++;
    if (scanned === REFRESH_SCAN_LIMIT - 1) nextCursor = index;
  }
  return { schemaVersion: 1 as const, subscriptionId: first.subscriptionId, productId: first.productId,
    planId: first.planId, revisionId: first.revisionId, ruleId: first.ruleId, audience: first.audience,
    recipient: first.recipient, asOf: now, occurrences, nextCursor };
}
