import type { DbClient } from '../db';
import { array, invalid, record, text, uuid } from './validation';

export interface CanonicalPlanInventoryItem {
  readonly id: string;
  readonly code: string;
  readonly productId: string | null;
  readonly name: string;
  readonly isActive: boolean;
  readonly applicableEntities: readonly string[];
}

/** Inventory includes legacy and inactive rows. It does not select purchasable offers. */
export async function readCanonicalPlanInventory(
  client: { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> },
): Promise<readonly CanonicalPlanInventoryItem[]> {
  const plans: CanonicalPlanInventoryItem[] = [];
  const pageSize = 200;
  let cursor: string | undefined;
  for (let page = 0; page < 100; page++) {
    const rows = await client.query('plans?select=id,plan_code,product_id,name,is_active,applicable_entities'
      + `&order=id.asc&limit=${pageSize}` + (cursor === undefined ? '' : `&id=gt.${cursor}`), undefined, 'json-array');
    if (!Array.isArray(rows) || rows.length > pageSize) invalid('inventory.plans', 'invalid catalog page');
    for (const value of Array.from(rows)) {
      const row = record(value, 'inventory.plan', ['id', 'plan_code', 'product_id', 'name', 'is_active', 'applicable_entities']);
      const id = uuid(row.id, 'inventory.plan.id');
      if (cursor !== undefined && id <= cursor) invalid('inventory.plan.id', 'catalog pages must advance in UUID order');
      const entities = array(row.applicable_entities, 'inventory.plan.applicableEntities')
        .map(value => text(value, 'inventory.plan.applicableEntities'));
      if (new Set(entities).size !== entities.length) invalid('inventory.plan.applicableEntities', 'duplicate entity');
      if (typeof row.is_active !== 'boolean') invalid('inventory.plan.isActive', 'expected boolean');
      plans.push(Object.freeze({
        id, code: text(row.plan_code, 'inventory.plan.code'),
        productId: row.product_id === null ? null : uuid(row.product_id, 'inventory.plan.productId'),
        name: text(row.name, 'inventory.plan.name'), isActive: row.is_active,
        applicableEntities: Object.freeze(entities),
      }));
      cursor = id;
    }
    // The server may enforce a lower row cap than our requested page size.
    if (rows.length === 0) return Object.freeze(plans);
  }
  invalid('inventory.plans', 'catalog pagination budget exceeded');
}
