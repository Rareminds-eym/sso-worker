import type { DbClient } from '../db';
import { validatePlanRevision } from './catalog';
import { validateCreditAllocationPolicy, type CreditAllocationPolicy, type CreditPolicyRegistry } from './credit-policy';
import { CatalogPersistenceError, validStagingTimestamp } from './repository';
import type { PlanRevisionDraft } from './types';
import { invalid, record, uuid } from './validation';

/** One immutable authoring unit. This does not approve, publish or activate an offer. */
export interface PlanRevisionBundle {
  readonly schemaVersion: 1;
  readonly draft: PlanRevisionDraft;
  readonly includedCredits: CreditAllocationPolicy;
}

export interface StagedPlanRevisionBundle {
  readonly bundle: PlanRevisionBundle;
  readonly stagedBy: string;
  readonly stagedAt: string;
}

export function validatePlanRevisionBundle(value: unknown, registry: CreditPolicyRegistry): PlanRevisionBundle {
  const input = record(value, 'bundle', ['schemaVersion', 'draft', 'includedCredits']);
  if (input.schemaVersion !== 1) invalid('bundle.schemaVersion', 'unsupported schema version');
  const draft = validatePlanRevision(input.draft, registry.catalog);
  if (draft.schemaVersion !== 2) invalid('bundle.draft.schemaVersion', 'bundled terms require explicit schema 2; no automatic conversion');
  const includedCredits = validateCreditAllocationPolicy(input.includedCredits, draft, registry);
  if (includedCredits.funding !== 'included') invalid('bundle.includedCredits.funding', 'included policy required; purchased top-ups are separate offers');
  return Object.freeze({ schemaVersion: 1, draft, includedCredits });
}

function receipt(value: unknown, registry: CreditPolicyRegistry): StagedPlanRevisionBundle {
  const input = record(value, 'receipt', ['draft', 'includedCredits', 'stagedBy', 'stagedAt']);
  if (!validStagingTimestamp(input.stagedAt)) throw new CatalogPersistenceError('Invalid bundle staging timestamp');
  return Object.freeze({
    bundle: validatePlanRevisionBundle({ schemaVersion: 1, draft: input.draft, includedCredits: input.includedCredits }, registry),
    stagedBy: uuid(input.stagedBy, 'receipt.stagedBy'), stagedAt: input.stagedAt,
  });
}

/** Trusted internal caller must authorize the actor and load scoped registries before this call. */
export async function stagePlanRevisionBundle(
  client: { rpc: (...args: Parameters<DbClient['rpc']>) => Promise<unknown> },
  value: unknown, registry: CreditPolicyRegistry, actorId: string,
): Promise<StagedPlanRevisionBundle> {
  const bundle = validatePlanRevisionBundle(value, registry), stagedBy = uuid(actorId, 'actorId');
  const result = receipt(await client.rpc('stage_subscription_plan_draft', {
    p_draft: bundle.draft, p_staged_by: stagedBy, p_included_credits: bundle.includedCredits,
  }), registry);
  if (JSON.stringify(result.bundle) !== JSON.stringify(bundle) || result.stagedBy !== stagedBy) {
    throw new CatalogPersistenceError('Bundle staging receipt does not match the request');
  }
  return result;
}

export async function readPlanRevisionBundle(
  client: { query: (...args: Parameters<DbClient['query']>) => Promise<unknown[]> },
  revisionId: string, registry: CreditPolicyRegistry,
): Promise<StagedPlanRevisionBundle> {
  const id = uuid(revisionId, 'revisionId');
  const rows = await client.query(`subscription_plan_drafts?select=snapshot,included_credits,staged_by,staged_at&id=eq.${id}&limit=2`);
  if (!Array.isArray(rows) || rows.length !== 1) throw new CatalogPersistenceError('Bundled revision must resolve exactly once');
  const row = record(rows[0], 'storedBundle', ['snapshot', 'included_credits', 'staged_by', 'staged_at']);
  const result = receipt({ draft: row.snapshot, includedCredits: row.included_credits, stagedBy: row.staged_by, stagedAt: row.staged_at }, registry);
  if (result.bundle.draft.id !== id) throw new CatalogPersistenceError('Stored bundle identity does not match the request');
  return result;
}
