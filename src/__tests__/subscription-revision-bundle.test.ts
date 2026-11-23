import { describe, expect, it, vi } from 'vitest';
import {
  readPlanRevisionBundle, stagePlanRevision, stagePlanRevisionBundle, validatePlanRevisionBundle,
  type CreditPolicyRegistry,
} from '../lib/subscriptions';

const productId = '912d5049-e195-46e9-a319-49e3502bf7e7';
const planId = 'a0000000-0000-4000-8000-000000000041';
const revisionId = 'b0000000-0000-4000-8000-000000000001';
const policyId = 'c0000000-0000-4000-8000-000000000001';
const actorId = 'd0000000-0000-4000-8000-000000000001';
const ruleId = 'e0000000-0000-4000-8000-000000000001';
const otherId = 'f0000000-0000-4000-8000-000000000001';
const stagedAt = '2026-11-18T10:30:00.123456+00:00';
const registry: CreditPolicyRegistry = {
  catalog: {
    productIds: new Set([productId]), audienceKeys: new Set(['college']), currencies: new Map([['INR', 2]]),
    featureTypes: new Map([['ai_credits', 'metered'], ['capacity', 'numeric_limit']]),
  },
  pools: new Map([
    ['admin_ai', { featureKey: 'ai_credits', recipient: 'organization', audiences: new Set(['college']) }],
    ['learner_ai', { featureKey: 'ai_credits', recipient: 'managed_learner', audiences: new Set(['college']) }],
  ]), timePolicyIds: new Set([otherId]), rolloverApprovalIds: new Set(), expiryApprovalIds: new Set(),
};
function bundle() {
  return {
    schemaVersion: 1,
    draft: {
      schemaVersion: 2, id: revisionId, revisionNumber: 1,
      plan: { id: planId, code: 'pln_8f3d2c6a91b74e50b5a36d02c7e8a419', productId },
      name: 'Institution proposal', audiences: ['college'], purchaseMode: 'contact_sales', prices: [],
      features: [{ key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }],
    },
    includedCredits: {
      schemaVersion: 1, id: policyId, revisionId, funding: 'included', rules: [{
        id: ruleId, featureKey: 'ai_credits', poolKey: 'admin_ai', recipient: 'organization', audiences: ['college'],
        quantity: { kind: 'finite', value: 1000 }, cadence: { kind: 'subscription_period' },
        expiry: { kind: 'allocation_period_end' }, rollover: { kind: 'none' },
      }],
    },
  };
}
function receipt() { const value = bundle(); return { draft: value.draft, includedCredits: value.includedCredits, stagedBy: actorId, stagedAt }; }
function writer(value: unknown = receipt()) { return { rpc: vi.fn().mockResolvedValue(value) }; }
function reader(value: unknown[] = []) { return { query: vi.fn().mockResolvedValue(value) }; }
function stored() { const value = receipt(); return { snapshot: value.draft, included_credits: value.includedCredits, staged_by: actorId, staged_at: stagedAt }; }

describe('coherent authoring revision', () => {
  it('keeps quantities solely in recipient/period rules and returns deeply detached immutable terms', () => {
    const input = bundle(), result = validatePlanRevisionBundle(input, registry);
    expect(result.draft.features[0]).toEqual({ key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } });
    expect(result.includedCredits.rules[0].quantity).toEqual({ kind: 'finite', value: 1000 });
    input.includedCredits.rules[0].quantity.value = 99;
    expect(result.includedCredits.rules[0].quantity).toEqual({ kind: 'finite', value: 1000 });
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.draft.features[0].type === 'metered' && result.draft.features[0].limit)).toBe(true);
    expect(Object.isFrozen(result.includedCredits.rules[0].quantity)).toBe(true);
  });

  it('supports distinct admin and learner quantities/cadences without an aggregate feature amount', () => {
    const input = bundle();
    const second = { ...input.includedCredits.rules[0], id: otherId, poolKey: 'learner_ai', recipient: 'managed_learner',
      quantity: { kind: 'finite', value: 150 }, cadence: { kind: 'monthly', timePolicyId: otherId } };
    const result = validatePlanRevisionBundle({ ...input, includedCredits: { ...input.includedCredits, rules: [...input.includedCredits.rules, second] } }, registry);
    expect(result.includedCredits.rules.map(rule => [rule.recipient, rule.quantity, rule.cadence.kind]))
      .toEqual([['organization', { kind: 'finite', value: 1000 }, 'subscription_period'], ['managed_learner', { kind: 'finite', value: 150 }, 'monthly']]);
  });

  it.each([
    { kind: 'finite', value: 1000 }, { kind: 'unlimited' }, { kind: 'contract_required' },
    { kind: 'allocation_policy', value: 1000 }, {}, null,
  ])('rejects a second metered amount or malformed reference %j', limit => {
    const input = bundle();
    expect(() => validatePlanRevisionBundle({ ...input, draft: { ...input.draft, features: [{ ...input.draft.features[0], limit }] } }, registry)).toThrow('limit');
  });

  it.each([
    { patch: { schemaVersion: 2 }, reason: 'bundle.schemaVersion: unsupported schema version' },
    { patch: { includedCredits: null }, reason: 'creditPolicy: expected a plain object' },
    { patch: { published: true }, reason: 'bundle: unsupported field' },
    { patch: { draft: { ...bundle().draft, schemaVersion: 1,
      features: [{ ...bundle().draft.features[0], limit: { kind: 'finite', value: 1000 } }] } }, reason: 'bundled terms require explicit schema 2' },
    { patch: { includedCredits: { ...bundle().includedCredits, revisionId: otherId } }, reason: 'policy must bind the supplied revision' },
    { patch: { includedCredits: { ...bundle().includedCredits, rules: [] } }, reason: 'every enabled metered feature and audience requires included terms' },
  ])('rejects unsupported or disconnected terms %j', ({ patch, reason }) => {
    expect(() => validatePlanRevisionBundle({ ...bundle(), ...patch }, registry)).toThrow(reason);
  });

  it('rejects otherwise valid top-up terms in the included-policy position', () => {
    const input = bundle();
    const rule = { ...input.includedCredits.rules[0], cadence: { kind: 'purchase' },
      expiry: { kind: 'after_months', months: 6, timePolicyId: otherId } };
    expect(() => validatePlanRevisionBundle({ ...input, includedCredits: { ...input.includedCredits, funding: 'top_up', rules: [rule] } }, registry))
      .toThrow('included policy required');
  });

  it('allows explicit empty included terms only when no metered feature is enabled', () => {
    const input = bundle();
    const result = validatePlanRevisionBundle({ ...input, draft: { ...input.draft, features: [] }, includedCredits: { ...input.includedCredits, rules: [] } }, registry);
    expect(result.includedCredits.rules).toEqual([]);
  });
});

describe('bundled staging through the existing database client', () => {
  it('writes both snapshots in one RPC and binds the whole receipt', async () => {
    const input = bundle(), client = writer();
    const result = await stagePlanRevisionBundle(client, input, registry, actorId.toUpperCase());
    expect(client.rpc).toHaveBeenCalledExactlyOnceWith('stage_subscription_plan_draft', {
      p_draft: input.draft, p_staged_by: actorId, p_included_credits: input.includedCredits,
    });
    expect(result).toEqual({ bundle: input, stagedBy: actorId, stagedAt });
    expect(Object.isFrozen(result)).toBe(true);
    expect(result).not.toHaveProperty('publishedRevisionId');
  });

  it('accepts reordered JSON object keys from storage', async () => {
    const response = receipt();
    const includedCredits = Object.fromEntries(Object.entries(response.includedCredits).reverse());
    await expect(stagePlanRevisionBundle(writer({ ...response, includedCredits }), bundle(), registry, actorId)).resolves.toMatchObject({ stagedBy: actorId });
  });

  it.each([
    { stagedBy: otherId }, { draft: { ...bundle().draft, name: 'Different terms' } },
    { includedCredits: { ...bundle().includedCredits, id: otherId } },
    { includedCredits: { ...bundle().includedCredits, rules: [{ ...bundle().includedCredits.rules[0], quantity: { kind: 'finite', value: 999 } }] } },
  ])('rejects structurally valid changed receipt content %j', async patch => {
    await expect(stagePlanRevisionBundle(writer({ ...receipt(), ...patch }), bundle(), registry, actorId)).rejects.toThrow('does not match');
  });

  it.each([
    { response: null, reason: 'receipt: expected a plain object' },
    { response: {}, reason: 'Invalid bundle staging timestamp' },
    { response: { ...receipt(), stagedAt: '2026-02-30T12:00:00Z' }, reason: 'Invalid bundle staging timestamp' },
    { response: { ...receipt(), includedCredits: null }, reason: 'creditPolicy: expected a plain object' },
    { response: { ...receipt(), published: true }, reason: 'receipt: unsupported field' },
  ])('rejects invalid receipts for their intended reason %j', async ({ response, reason }) => {
    await expect(stagePlanRevisionBundle(writer(response), bundle(), registry, actorId)).rejects.toThrow(reason);
  });

  it('rejects invalid terms and actors before storage', async () => {
    const client = writer();
    await expect(stagePlanRevisionBundle(client, { ...bundle(), includedCredits: null }, registry, actorId)).rejects.toThrow('creditPolicy');
    await expect(stagePlanRevisionBundle(client, bundle(), registry, 'invalid')).rejects.toThrow('actorId');
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('does not allow schema 2 to bypass credit binding using the old adapter', async () => {
    const client = writer();
    await expect(stagePlanRevision(client, bundle().draft, registry.catalog, actorId)).rejects.toThrow('requires bundled credit staging');
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('surfaces write failures without retrying or substituting an unbundled write', async () => {
    const client = writer(), failure = new Error('Storage unavailable'); client.rpc.mockRejectedValue(failure);
    await expect(stagePlanRevisionBundle(client, bundle(), registry, actorId)).rejects.toBe(failure);
    expect(client.rpc).toHaveBeenCalledTimes(1);
  });

  it('reads both immutable terms from one exact bounded record', async () => {
    const client = reader([stored()]);
    const result = await readPlanRevisionBundle(client, revisionId.toUpperCase(), registry);
    expect(client.query).toHaveBeenCalledExactlyOnceWith(`subscription_plan_drafts?select=snapshot,included_credits,staged_by,staged_at&id=eq.${revisionId}&limit=2`);
    expect(result.bundle).toEqual(bundle());
  });

  it.each([
    { rows: [], reason: 'resolve exactly once' }, { rows: [stored(), stored()], reason: 'resolve exactly once' },
    { rows: [null], reason: 'plain object' }, { rows: [{ ...stored(), included_credits: null }], reason: 'creditPolicy' },
    { rows: [{ ...stored(), snapshot: { ...bundle().draft, id: otherId }, included_credits: { ...bundle().includedCredits, revisionId: otherId } }], reason: 'identity does not match' },
  ])('rejects missing, split or wrong-identity stored records %j', async ({ rows, reason }) => {
    await expect(readPlanRevisionBundle(reader(rows), revisionId, registry)).rejects.toThrow(reason);
  });

  it('rejects injection before querying and surfaces query failures', async () => {
    const client = reader();
    await expect(readPlanRevisionBundle(client, `${revisionId}&limit=9999`, registry)).rejects.toThrow('revisionId');
    expect(client.query).not.toHaveBeenCalled();
    const failure = new Error('Read unavailable'); client.query.mockRejectedValue(failure);
    await expect(readPlanRevisionBundle(client, revisionId, registry)).rejects.toBe(failure);
    expect(client.query).toHaveBeenCalledTimes(1);
  });
});
