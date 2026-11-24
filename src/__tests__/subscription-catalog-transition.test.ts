import { describe, expect, it, vi } from 'vitest';
import { commitCatalogTransition, prepareCatalogTransition, validateCatalogTransitionCommand } from '../lib/subscriptions/catalog-transition';
import type { CatalogTransitionCommand, CatalogTransitionSnapshot } from '../lib/subscriptions/catalog-transition';
import { commitCatalogAvailability, prepareCatalogAvailability, commitHybridIdentityTransition, prepareHybridIdentityTransition, validateHybridIdentityTransition } from '../lib/subscriptions/catalog-transition';

const id = (value: number) => `10000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
function fixture() {
  const command: CatalogTransitionCommand = { schemaVersion: 1, operationId: id(1), productId: id(2), actorId: id(3),
    approvalReference: 'Synthetic exact target approval', effectiveAt: 100, hybridPlanId: id(4),
    expectedPlans: [{ id: id(4), code: 'retained_owner_code', active: true }, { id: id(5), code: 'old', active: true },
      { id: id(6), code: 'pln_0123456789abcdef0123456789abcdef', active: true }],
    replacements: [{ legacyPlanId: id(5), planId: id(6), revisionId: id(7) }],
    retainedSubscriptions: [{ id: id(8), planId: id(5), purchasedTerms: { amount: '2500.00', features: ['original'],
      periodEndsAt: 500, historicalRevisionId: id(9) } }], preservation: 'retain_original_purchases_and_history' };
  const snapshot: CatalogTransitionSnapshot = { productId: command.productId, hybridPlanId: command.hybridPlanId,
    plans: command.expectedPlans, subscriptions: command.retainedSubscriptions,
    publications: [{ planId: id(6), revisionId: id(7), productId: id(2) }] };
  return { command, snapshot };
}
describe('explicit catalog offer transition', () => {
  it('prepares exact retirement while preserving original purchases and Hybrid without mutation', () => {
    const { command, snapshot } = fixture(), original = structuredClone({ command, snapshot });
    const result = prepareCatalogTransition(command, snapshot, 100);
    expect(result.retirePlanIds).toEqual([id(5)]);
    expect(result.retainSubscriptionIds).toEqual([id(8)]);
    expect(result.hybridPlanId).toBe(id(4));
    expect({ command, snapshot }).toEqual(original);
    expect(result).not.toHaveProperty('updatedSubscriptions');
  });
  it('compares exact snapshots independent of object insertion and row order', () => {
    const { command, snapshot } = fixture();
    expect(() => prepareCatalogTransition(command, { ...snapshot, plans: [...snapshot.plans].reverse() }, 100)).not.toThrow();
    expect(() => prepareCatalogTransition(command, { ...snapshot, subscriptions: [] }, 100)).toThrow('baseline');
    expect(() => prepareCatalogTransition(command, { ...snapshot, subscriptions: [{ ...snapshot.subscriptions[0],
      purchasedTerms: { amount: '2500.01', features: ['original'], periodEndsAt: 500, historicalRevisionId: id(9) } }] }, 100)).toThrow('baseline');
    expect(() => prepareCatalogTransition(command, { ...snapshot, plans: snapshot.plans.map(row => row.id === id(4)
      ? { ...row, code: 'changed' } : row) }, 100)).toThrow('baseline');
  });
  it('rejects future execution, foreign product, missing publication and duplicate pointers', () => {
    const { command, snapshot } = fixture();
    expect(() => prepareCatalogTransition(command, snapshot, 99)).toThrow('not effective');
    expect(() => prepareCatalogTransition(command, { ...snapshot, productId: id(10) }, 100)).toThrow('scope');
    expect(() => prepareCatalogTransition(command, { ...snapshot, publications: [] }, 100)).toThrow('published');
    expect(() => prepareCatalogTransition(command, { ...snapshot, publications: [...snapshot.publications, ...snapshot.publications] }, 100)).toThrow('published');
  });
  it('rejects Hybrid retirement, rewrite cycles, incomplete preservation and duplicate cohorts', () => {
    const { command } = fixture();
    for (const candidate of [
      { ...command, replacements: [{ ...command.replacements[0], legacyPlanId: command.hybridPlanId }] },
      { ...command, replacements: [{ ...command.replacements[0], planId: command.hybridPlanId }] },
      { ...command, replacements: [...command.replacements, { legacyPlanId: id(6), planId: id(5), revisionId: id(7) }] },
      { ...command, retainedSubscriptions: [...command.retainedSubscriptions, ...command.retainedSubscriptions] },
      { ...command, retainedSubscriptions: [{ ...command.retainedSubscriptions[0], purchasedTerms: {} }] },
      { ...command, preservation: 'rewrite' }, { ...command, unexpected: true },
    ]) expect(() => validateCatalogTransitionCommand(candidate)).toThrow();
  });
  it('validates exact owner receipt and propagates uncertainty without retries', async () => {
    const { command } = fixture();
    const receipt = { operationId: command.operationId, command, retiredPlanIds: [id(5)], preservedSubscriptionIds: [id(8)] };
    const rpc = vi.fn().mockResolvedValue(receipt);
    expect(await commitCatalogTransition({ rpc }, command)).toEqual(receipt);
    expect(rpc).toHaveBeenCalledExactlyOnceWith('commit_subscription_catalog_transition', { p_command: command });
    rpc.mockResolvedValueOnce({ ...receipt, preservedSubscriptionIds: [] });
    await expect(commitCatalogTransition({ rpc }, command)).rejects.toThrow('acknowledgement');
    rpc.mockRejectedValueOnce(new Error('uncertain transport'));
    await expect(commitCatalogTransition({ rpc }, command)).rejects.toThrow('uncertain transport');
    expect(rpc).toHaveBeenCalledTimes(3);
  });
});

describe('explicit retained Hybrid identity transition', () => {
  function identityFixture() {
    const { snapshot } = fixture();
    const retainedSubscriptions = [{ id: id(20), planId: snapshot.hybridPlanId,
      purchasedTerms: { planCode: 'retained_owner_code', amount: '123.00', historicalPolicy: { exact: true } } }];
    const command = { schemaVersion: 1 as const, operationId: id(21), actorId: id(3), productId: snapshot.productId,
      hybridPlanId: snapshot.hybridPlanId, expectedCode: 'retained_owner_code',
      targetCode: 'pln_abcdef0123456789abcdef0123456789', effectiveAt: 100,
      approvalReference: 'Synthetic exact identity migration approval', retainedSubscriptions,
      preservation: 'retain_original_purchases_and_history' as const };
    return { command, snapshot: { ...snapshot, subscriptions: [...snapshot.subscriptions, ...retainedSubscriptions] } };
  }
  it('prepares one canonical opaque code with unchanged UUID, purchased codes and unrelated plans', () => {
    const { command, snapshot } = identityFixture(), before = structuredClone({ command, snapshot });
    const result = prepareHybridIdentityTransition(command, snapshot, 100);
    expect(result.plan).toEqual({ id: snapshot.hybridPlanId, productId: snapshot.productId, code: command.targetCode });
    expect(result.preservedSubscriptionIds).toEqual([id(20)]);
    expect({ command, snapshot }).toEqual(before);
    expect(command.retainedSubscriptions[0].purchasedTerms.planCode).toBe(command.expectedCode);
  });
  it('rejects changed trusted UUID/product, changed historical purchases, stale code, collisions and future execution', () => {
    const { command, snapshot } = identityFixture();
    expect(() => prepareHybridIdentityTransition(command, { ...snapshot, hybridPlanId: id(5) }, 100)).toThrow('trusted');
    expect(() => prepareHybridIdentityTransition(command, { ...snapshot, productId: id(30) }, 100)).toThrow('trusted');
    expect(() => prepareHybridIdentityTransition(command, { ...snapshot, subscriptions: [] }, 100)).toThrow('purchase');
    expect(() => prepareHybridIdentityTransition({ ...command, expectedCode: 'stale' }, snapshot, 100)).toThrow('baseline');
    expect(() => prepareHybridIdentityTransition(command, { ...snapshot, plans: snapshot.plans.map(row => row.id === id(5) ? { ...row, code: command.targetCode } : row) }, 100)).toThrow('baseline');
    expect(() => prepareHybridIdentityTransition(command, snapshot, 99)).toThrow('not effective');
  });
  it('rejects client exceptions, foreign purchase identities, repeated code rotations and malformed target codes', () => {
    const { command } = identityFixture();
    for (const value of [
      { ...command, targetCode: 'hybrid' }, { ...command, targetCode: command.targetCode.toUpperCase() },
      { ...command, expectedCode: command.targetCode }, { ...command, legacyCompatibility: true },
      { ...command, retainedSubscriptions: [{ ...command.retainedSubscriptions[0], planId: id(5) }] },
    ]) expect(() => validateHybridIdentityTransition(value)).toThrow();
  });
  it('uses exactly one owner operation, validates the full receipt and preserves uncertain outcomes', async () => {
    const { command } = identityFixture();
    const expected = { operationId: command.operationId, command,
      plan: { id: command.hybridPlanId, productId: command.productId, code: command.targetCode }, preservedSubscriptionIds: [id(20)] };
    const rpc = vi.fn().mockResolvedValue(expected);
    expect(await commitHybridIdentityTransition({ rpc }, command)).toEqual(expected);
    expect(rpc).toHaveBeenCalledExactlyOnceWith('commit_subscription_hybrid_identity_transition', { p_command: command });
    for (const bad of [{ ...expected, plan: { ...expected.plan, id: id(5) } }, { ...expected, preservedSubscriptionIds: [] },
      { ...expected, command: { ...command, expectedCode: 'changed' } }]) {
      rpc.mockResolvedValueOnce(bad);
      await expect(commitHybridIdentityTransition({ rpc }, command)).rejects.toThrow('acknowledgement');
    }
    rpc.mockRejectedValueOnce(new Error('uncertain owner transport'));
    await expect(commitHybridIdentityTransition({ rpc }, command)).rejects.toThrow('uncertain owner transport');
    expect(rpc).toHaveBeenCalledTimes(5);
  });
});

describe('explicit published offer availability', () => {
  async function availabilityFixture() {
    const { snapshot } = fixture();
    const request = { schemaVersion: 1, operationId: id(40), productId: snapshot.productId,
      hybridPlanId: snapshot.hybridPlanId, approvalReference: 'Synthetic exact offer activation approval', effectiveAt: 100,
      entries: [{ planId: id(6), revisionId: id(7), expectedActive: false }] };
    const inactive = { ...snapshot, plans: snapshot.plans.map(plan => plan.id === id(6) ? { ...plan, active: false } : plan) };
    const canonicalPlan = { id: id(6), code: inactive.plans.find(plan => plan.id === id(6))!.code,
      productId: snapshot.productId, audiences: ['synthetic'], configuration: { synthetic: true } };
    const proof = { planId: id(6), revisionId: id(7), productId: snapshot.productId, canonicalPlan };
    const reader = vi.fn().mockResolvedValue(proof);
    return { request, snapshot: inactive, canonicalPlan, proof, reader };
  }
  it('requires an independent owner verification call before preparing exact availability', async () => {
    const f = await availabilityFixture(), before = structuredClone(f.snapshot);
    const command = await prepareCatalogAvailability(f.request, f.snapshot, id(3), f.reader, 100);
    expect(f.reader).toHaveBeenCalledExactlyOnceWith(id(6), id(7));
    expect(command.entries[0].expectedCanonical).toEqual(f.canonicalPlan);
    expect(command.actorId).toBe(id(3));
    expect(f.snapshot).toEqual(before);
  });
  it('rejects missing/currently changed pointers, active offers and retained Hybrid', async () => {
    for (const mode of ['pointer', 'active', 'hybrid', 'scope'] as const) {
      const f = await availabilityFixture();
      if (mode === 'pointer') f.snapshot.publications = [];
      if (mode === 'active') f.snapshot.plans = f.snapshot.plans.map(plan => ({ ...plan, active: true }));
      if (mode === 'hybrid') f.request.entries[0].planId = f.snapshot.hybridPlanId;
      if (mode === 'scope') f.request.productId = id(99);
      await expect(prepareCatalogAvailability(f.request, f.snapshot, id(3), f.reader, 100)).rejects.toThrow();
      expect(f.reader).not.toHaveBeenCalled();
    }
  });
  it('rejects client readiness flags, client proof objects and caller-supplied actors', async () => {
    for (const extra of [{ projectionVerified: true }, { expectedCanonical: {} }, { readiness: 'ready' }]) {
      const f = await availabilityFixture();
      const request = { ...f.request, entries: [{ ...f.request.entries[0], ...extra }] };
      await expect(prepareCatalogAvailability(request, f.snapshot, id(3), f.reader, 100)).rejects.toThrow();
      expect(f.reader).not.toHaveBeenCalled();
    }
    const f = await availabilityFixture();
    await expect(prepareCatalogAvailability({ ...f.request, actorId: id(3) }, f.snapshot, id(3), f.reader, 100)).rejects.toThrow();
  });
  it('rejects foreign or malformed owner proofs, duplicate offers and future execution', async () => {
    const f = await availabilityFixture();
    for (const proof of [{ ...f.proof, productId: id(99) }, { ...f.proof, revisionId: id(99) },
      { ...f.proof, canonicalPlan: { ...f.canonicalPlan, code: 'legacy' } },
      { ...f.proof, canonicalPlan: { ...f.canonicalPlan, audiences: [] } },
      { ...f.proof, canonicalPlan: { ...f.canonicalPlan, configuration: [] } }]) {
      f.reader.mockResolvedValueOnce(proof);
      await expect(prepareCatalogAvailability(f.request, f.snapshot, id(3), f.reader, 100)).rejects.toThrow();
    }
    await expect(prepareCatalogAvailability({ ...f.request, entries: [...f.request.entries, ...f.request.entries] }, f.snapshot, id(3), f.reader, 100)).rejects.toThrow('duplicate');
    await expect(prepareCatalogAvailability(f.request, f.snapshot, id(3), f.reader, 99)).rejects.toThrow('not effective');
  });
  it('propagates unavailable owner verification and validates immutable attributable receipts without retries', async () => {
    const f = await availabilityFixture();
    f.reader.mockRejectedValueOnce(new Error('Independent projection unavailable'));
    await expect(prepareCatalogAvailability(f.request, f.snapshot, id(3), f.reader, 100)).rejects.toThrow('Independent projection unavailable');
    const command = await prepareCatalogAvailability(f.request, f.snapshot, id(3), f.reader, 100);
    const expected = { operationId: command.operationId, command, activatedPlanIds: [id(6)] };
    const rpc = vi.fn().mockResolvedValue(expected);
    expect(await commitCatalogAvailability({ rpc }, command)).toEqual(expected);
    expect(rpc).toHaveBeenCalledExactlyOnceWith('commit_subscription_catalog_availability', { p_command: command });
    rpc.mockResolvedValueOnce({ ...expected, command: { ...command, actorId: id(99) } });
    await expect(commitCatalogAvailability({ rpc }, command)).rejects.toThrow('acknowledgement');
    rpc.mockResolvedValueOnce({ ...expected, activatedPlanIds: [] });
    await expect(commitCatalogAvailability({ rpc }, command)).rejects.toThrow('acknowledgement');
    rpc.mockRejectedValueOnce(new Error('Uncertain availability outcome'));
    await expect(commitCatalogAvailability({ rpc }, command)).rejects.toThrow('Uncertain availability outcome');
    expect(rpc).toHaveBeenCalledTimes(4);
  });
});
