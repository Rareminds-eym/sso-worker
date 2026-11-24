import type { DbClient } from '../db';
import { readPlanAuthoringSnapshot, type PlanAuthoringContext } from './authoring-context';
import type { CreditPoolDefinition } from './credit-policy';
import { array, choice, invalid, record, text, uuid } from './validation';

export interface CreditPoolConfiguration {
  readonly key: string;
  readonly featureKey: string;
  readonly recipient: CreditPoolDefinition['recipient'];
  readonly audiences: readonly string[];
}

/** Explicit calendar terms shared by authoring and occurrence preparation. */
export interface CreditTimePolicyConfiguration {
  readonly id: string;
  readonly timeZone: string;
  readonly monthlyAnchor: 'subscription_anniversary' | 'calendar_month_start';
  readonly monthDayOverflow: 'clamp' | 'reject';
  readonly ambiguousTime: 'earlier' | 'later' | 'reject';
  readonly nonexistentTime: 'reject' | 'shift_forward';
}

export interface CreditAuthoringContext extends PlanAuthoringContext {
  readonly credit: {
    readonly schemaVersion: 1;
    readonly pools: readonly CreditPoolConfiguration[];
    readonly timePolicies: readonly CreditTimePolicyConfiguration[];
  };
}

/** Canonical owner configuration. Neither approval records nor default credit rules are inferred. */
export async function readCreditAuthoringContext(
  client: { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> }, planId: string,
): Promise<CreditAuthoringContext> {
  const { context, configuration } = await readPlanAuthoringSnapshot(client, planId);
  return validateCreditAuthoringContext(context, configuration);
}

/** Parse credit terms from the same canonical snapshot used by publication's compare-and-set. */
export function validateCreditAuthoringContext(
  context: PlanAuthoringContext, configuration: Record<string, unknown>,
): CreditAuthoringContext {
  const settings = record(configuration.subscription_credit_authoring, 'creditAuthoring.settings', ['schemaVersion', 'pools', 'timePolicies']);
  if (settings.schemaVersion !== 1) invalid('creditAuthoring.settings.schemaVersion', 'unsupported schema version');
  const pools = array(settings.pools, 'creditAuthoring.pools').map(value => {
    const pool = record(value, 'creditAuthoring.pool', ['key', 'featureKey', 'recipient', 'audiences']);
    const audiences = array(pool.audiences, 'creditAuthoring.pool.audiences').map(value => text(value, 'creditAuthoring.pool.audiences'));
    if (!audiences.length || new Set(audiences).size !== audiences.length || audiences.some(value => !context.audiences.includes(value))) {
      invalid('creditAuthoring.pool.audiences', 'expected unique canonical plan audiences');
    }
    return Object.freeze({ key: text(pool.key, 'creditAuthoring.pool.key'), featureKey: text(pool.featureKey, 'creditAuthoring.pool.featureKey'),
      recipient: choice(pool.recipient, 'creditAuthoring.pool.recipient', ['subscriber', 'organization', 'managed_learner']),
      audiences: Object.freeze(audiences) });
  });
  if (new Set(pools.map(pool => pool.key)).size !== pools.length) invalid('creditAuthoring.pools', 'duplicate pool key');
  const timePolicies = validateCreditTimePolicies(settings.timePolicies);
  return Object.freeze({ ...context, credit: Object.freeze({ schemaVersion: 1, pools: Object.freeze(pools), timePolicies }) });
}

export function validateCreditTimePolicies(value: unknown): readonly CreditTimePolicyConfiguration[] {
  const timePolicies = array(value, 'creditAuthoring.timePolicies').map(value => {
    const policy = record(value, 'creditAuthoring.timePolicy', ['id', 'timeZone', 'monthlyAnchor', 'monthDayOverflow', 'ambiguousTime', 'nonexistentTime']);
    const timeZone = text(policy.timeZone, 'creditAuthoring.timePolicy.timeZone');
    // Reject numeric offsets: calendar policies require a named zone with explicit DST handling.
    if (!/^[A-Za-z_]+(?:\/[A-Za-z0-9_+.-]+)*$/.test(timeZone)) invalid('creditAuthoring.timePolicy.timeZone', 'expected named time zone');
    try { new Intl.DateTimeFormat('en', { timeZone }).format(0); }
    catch { invalid('creditAuthoring.timePolicy.timeZone', 'unsupported named time zone'); }
    return Object.freeze({ id: uuid(policy.id, 'creditAuthoring.timePolicy.id'), timeZone,
      monthlyAnchor: choice(policy.monthlyAnchor, 'creditAuthoring.timePolicy.monthlyAnchor', ['subscription_anniversary', 'calendar_month_start']),
      monthDayOverflow: choice(policy.monthDayOverflow, 'creditAuthoring.timePolicy.monthDayOverflow', ['clamp', 'reject']),
      ambiguousTime: choice(policy.ambiguousTime, 'creditAuthoring.timePolicy.ambiguousTime', ['earlier', 'later', 'reject']),
      nonexistentTime: choice(policy.nonexistentTime, 'creditAuthoring.timePolicy.nonexistentTime', ['reject', 'shift_forward']) });
  });
  if (new Set(timePolicies.map(policy => policy.id)).size !== timePolicies.length) invalid('creditAuthoring.timePolicies', 'duplicate time policy identity');
  return Object.freeze(timePolicies);
}
