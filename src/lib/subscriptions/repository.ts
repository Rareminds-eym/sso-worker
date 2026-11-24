import type { DbClient } from '../db';
import { isValidUUID } from '../validate';
import { CatalogValidationError, validatePlanRevision } from './catalog';
import type { CatalogRegistry, PlanRevisionDraft } from './types';

// Instantiate the existing client's generic responses as unknown: storage is a validation boundary.
type DraftWriter = { rpc: (...args: Parameters<DbClient['rpc']>) => Promise<unknown> };
type DraftReader = { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> };

/** A staging receipt is neither a published revision nor an access decision. */
export interface StagedPlanRevision {
  readonly draft: PlanRevisionDraft;
  readonly stagedBy: string;
  readonly stagedAt: string;
}

export class CatalogPersistenceError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'CatalogPersistenceError';
  }
}

function uuid(value: unknown, path: string): string {
  if (typeof value !== 'string' || !isValidUUID(value)) {
    throw new CatalogValidationError(path, 'expected UUID');
  }
  return value.toLowerCase();
}

export function validStagingTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (!match || !Number.isFinite(Date.parse(value))) return false;
  const date = new Date(`${match[1]}T00:00:00Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === match[1]
    && Number(match[2]) < 24 && Number(match[3]) < 60 && Number(match[4]) < 60
    && (match[5] === undefined || (Number(match[5]) < 24 && Number(match[6]) < 60));
}

function receipt(value: unknown, registry: CatalogRegistry): StagedPlanRevision {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new CatalogPersistenceError('Invalid draft staging receipt');
  }
  const row = value as Record<string, unknown>;
  if (Object.keys(row).length !== 3 || !['draft', 'stagedBy', 'stagedAt'].every(key => Object.hasOwn(row, key))) {
    throw new CatalogPersistenceError('Invalid draft staging receipt');
  }
  if (!validStagingTimestamp(row.stagedAt)) {
    throw new CatalogPersistenceError('Invalid draft staging timestamp');
  }
  const draft = validatePlanRevision(row.draft, registry);
  if (draft.schemaVersion !== 1) throw new CatalogPersistenceError('Schema 2 requires bundled credit staging');
  return Object.freeze({
    draft,
    stagedBy: uuid(row.stagedBy, 'receipt.stagedBy'), stagedAt: row.stagedAt,
  });
}

/**
 * Internal service-only boundary. The caller must authorize the actor and supply trusted registries.
 * The RPC locks the existing plan, stores an immutable snapshot, and handles exact replay atomically.
 * No retry, legacy write, publication or active-plan mutation is attempted on failure.
 */
export async function stagePlanRevision(
  client: DraftWriter, value: unknown, registry: CatalogRegistry, actorId: string,
): Promise<StagedPlanRevision> {
  const draft = validatePlanRevision(value, registry);
  if (draft.schemaVersion !== 1) throw new CatalogPersistenceError('Schema 2 requires bundled credit staging');
  const stagedBy = uuid(actorId, 'actorId');
  const result = receipt(await client.rpc('stage_subscription_plan_draft', {
    p_draft: draft, p_staged_by: stagedBy,
  }), registry);
  // Validation reconstructs objects in a fixed field order; arrays remain ordered configuration.
  if (JSON.stringify(result.draft) !== JSON.stringify(draft) || result.stagedBy !== stagedBy) {
    throw new CatalogPersistenceError('Draft staging receipt does not match the request');
  }
  return result;
}

/** Read staged authoring data only; missing or invalid records are explicit failures. */
export async function readPlanRevision(
  client: DraftReader, revisionId: string, registry: CatalogRegistry,
): Promise<StagedPlanRevision> {
  const id = uuid(revisionId, 'revisionId');
  const rows = await client.query(
    `subscription_plan_drafts?select=snapshot,staged_by,staged_at&id=eq.${id}&limit=2`,
  );
  if (!Array.isArray(rows) || rows.length !== 1) {
    throw new CatalogPersistenceError('Draft revision must resolve exactly once');
  }
  const row = rows[0];
  if (row === null || typeof row !== 'object' || Array.isArray(row)) {
    throw new CatalogPersistenceError('Invalid stored draft revision');
  }
  const stored = row as Record<string, unknown>;
  const result = receipt({ draft: stored.snapshot, stagedBy: stored.staged_by, stagedAt: stored.staged_at }, registry);
  if (result.draft.id !== id) throw new CatalogPersistenceError('Stored draft identity does not match the request');
  return result;
}
