import type { DbClient } from '../db';
import { validatePlanIdentity } from './catalog';
import type { PlanIdentity } from './types';
import { array, integer, invalid, record, text, uuid } from './validation';

export interface PlanAuthoringContext {
  readonly schemaVersion: 1;
  readonly plan: PlanIdentity;
  readonly audiences: readonly string[];
  readonly currencies: readonly { readonly code: string; readonly minorUnit: number }[];
}

/** Existing SSO plan configuration owns these terms. This grants no publication or approval. */
export async function readPlanAuthoringSnapshot(
  client: { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> },
  planId: string,
): Promise<{ context: PlanAuthoringContext; configuration: Record<string, unknown> }> {
  const id = uuid(planId, 'authoring.planId');
  const rows = await client.query(`plans?select=id,plan_code,product_id,applicable_entities,entity_config&id=eq.${id}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(rows) || rows.length !== 1) invalid('authoring.plan', 'canonical plan must resolve exactly once');
  const snapshot = validatePlanAuthoringSnapshot(rows[0], id);
  const plan = snapshot.context.plan;
  const products = await client.query(`products?select=id&id=eq.${plan.productId}&limit=2`, undefined, 'json-array');
  if (!Array.isArray(products) || products.length !== 1) invalid('authoring.product', 'canonical product must resolve exactly once');
  const product = record(products[0], 'authoring.product', ['id']);
  if (uuid(product.id, 'authoring.product.id') !== plan.productId) invalid('authoring.product', 'canonical product identity differs');
  return snapshot;
}

/** Shared parsing for live authoring and the immutable canonical snapshot saved at publication. */
export function validatePlanAuthoringSnapshot(value: unknown, planId: string): {
  context: PlanAuthoringContext; configuration: Record<string, unknown>;
} {
  const id = uuid(planId, 'authoring.planId');
  const row = record(value, 'authoring.plan', ['id', 'plan_code', 'product_id', 'applicable_entities', 'entity_config']);
  const plan = validatePlanIdentity({ id: row.id, code: row.plan_code, productId: row.product_id });
  if (plan.id !== id) invalid('authoring.plan', 'canonical identity differs from the requested plan');
  const audiences = array(row.applicable_entities, 'authoring.audiences').map(value => text(value, 'authoring.audiences'));
  if (!audiences.length || new Set(audiences).size !== audiences.length) invalid('authoring.audiences', 'expected unique explicit audiences');
  // Preserve existing entity sections. Only this reserved namespace is interpreted here.
  const config = row.entity_config;
  if (config === null || typeof config !== 'object' || Array.isArray(config)
    || Object.getPrototypeOf(config) !== Object.prototype) invalid('authoring.settings', 'expected explicit plan configuration');
  const settings = record((config as Record<string, unknown>).subscription_authoring,
    'authoring.settings', ['schemaVersion', 'currencies']);
  if (settings.schemaVersion !== 1) invalid('authoring.settings.schemaVersion', 'unsupported schema version');
  const currencies = array(settings.currencies, 'authoring.currencies').map(value => {
    const currency = record(value, 'authoring.currency', ['code', 'minorUnit']);
    const code = text(currency.code, 'authoring.currency.code');
    if (!/^[A-Z]{3}$/.test(code)) invalid('authoring.currency.code', 'expected a three-letter uppercase currency code');
    return Object.freeze({ code, minorUnit: integer(currency.minorUnit, 'authoring.currency.minorUnit') });
  });
  if (!currencies.length || new Set(currencies.map(value => value.code)).size !== currencies.length) {
    invalid('authoring.currencies', 'expected unique explicitly configured currencies');
  }
  return { context: Object.freeze({ schemaVersion: 1, plan, audiences: Object.freeze(audiences), currencies: Object.freeze(currencies) }),
    configuration: config as Record<string, unknown> };
}

/** Public context intentionally excludes raw entity configuration. */
export async function readPlanAuthoringContext(
  client: { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> },
  planId: string,
): Promise<PlanAuthoringContext> {
  return (await readPlanAuthoringSnapshot(client, planId)).context;
}
