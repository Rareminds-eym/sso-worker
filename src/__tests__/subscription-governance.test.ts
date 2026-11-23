import { beforeEach, describe, expect, it, vi } from 'vitest';
const io = vi.hoisted(() => ({ read: vi.fn(), query: vi.fn() }));
vi.mock('../lib/subscriptions/credit-execution', () => ({ readSubscriptionExecution: io.read, SubscriptionExecutionDenied: class extends Error {} }));
import { readSubscriptionAudit } from '../lib/subscriptions/governance';
import type { Env } from '../types';
const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const state = () => ({ id: id(1), productId: id(2), subject: { kind: 'user', id: id(3) }, planId: id(4), revisionId: id(5), version: 2 });
const saved = () => ({ operation_id: id(6), subscription_id: id(1), actor_id: id(3), transaction_id: id(7), kind: 'transition',
  receipt: { operationId: id(6), decision: { expectedVersion: 1, next: state(), audit: { operation: 'renew', actorId: id(3), reason: 'Synthetic renewal', at: 2000 } } },
  committed_at: new Date(3000).toISOString() });
beforeEach(() => {
  vi.resetAllMocks();
  io.read.mockResolvedValue({ database: { query: io.query }, actorId: id(3), productId: id(2), state: state(), subject: state().subject, access: 'full' });
  io.query.mockResolvedValue([saved()]);
});
describe('controlled subscription audit', () => {
  it('requires live audit authority and emits bounded selected metadata rather than raw receipts', async () => {
    const result = await readSubscriptionAudit({} as Env, 'synthetic-token', id(1), id(2), null);
    expect(io.read).toHaveBeenCalledWith({}, 'synthetic-token', id(1), id(2), 'audit');
    expect(result.items).toEqual([{ operationId: id(6), actorId: id(3), transactionId: id(7), operation: 'renew', reason: 'Synthetic renewal',
      at: 2000, committedAt: new Date(3000).toISOString(), fromVersion: 1, toVersion: 2, planId: id(4), revisionId: id(5) }]);
    expect(io.query.mock.calls[0][0]).toContain(`subscription_id=eq.${id(1)}`);
    expect(io.query.mock.calls[0][0]).toContain('limit=50');
    expect(result.nextCursor).toBeNull();
  });
  it('reads initialization while rejecting raw extra-row metadata', async () => {
    const row = { ...saved(), kind: 'initialize', transaction_id: null,
      receipt: { operationId: id(6), state: { ...state(), version: 1 }, activatedAt: new Date(1000).toISOString() } };
    io.query.mockResolvedValue([row]);
    expect((await readSubscriptionAudit({} as Env, 'token', id(1), id(2), null)).items[0]).toMatchObject({ operation: 'initialize', fromVersion: null, toVersion: 1, at: 1000 });
    io.query.mockResolvedValue([{ ...row, privateMetadata: 'must not leak' }]);
    await expect(readSubscriptionAudit({} as Env, 'token', id(1), id(2), null)).rejects.toThrow();
  });
  it.each(['subject', 'product', 'subscription', 'actor', 'version', 'operation', 'timestamp', 'cursor', 'duplicate', 'over-budget'])('rejects altered %s evidence', async defect => {
    const row = saved();
    if (defect === 'subject') row.receipt.decision.next.subject.id = id(20);
    if (defect === 'product') row.receipt.decision.next.productId = id(20);
    if (defect === 'subscription') row.subscription_id = id(20);
    if (defect === 'actor') row.receipt.decision.audit.actorId = id(20);
    if (defect === 'version') row.receipt.decision.next.version = 4;
    if (defect === 'operation') row.receipt.decision.audit.operation = 'invented';
    if (defect === 'timestamp') row.receipt.decision.audit.at = 4000;
    io.query.mockResolvedValue(defect === 'duplicate' ? [row, row] : defect === 'over-budget' ? Array(51).fill(row) : [row]);
    await expect(readSubscriptionAudit({} as Env, 'token', id(1), id(2), defect === 'cursor' ? id(6) : null)).rejects.toThrow();
  });
  it('preserves read-only access but denies suspended reads and owner outages', async () => {
    const context = await io.read(); io.read.mockResolvedValue({ ...context, access: 'read_only' });
    expect((await readSubscriptionAudit({} as Env, 'token', id(1), id(2), null)).items).toHaveLength(1);
    io.read.mockResolvedValue({ ...context, access: 'suspended' });
    await expect(readSubscriptionAudit({} as Env, 'token', id(1), id(2), null)).rejects.toThrow();
    io.read.mockRejectedValue(new Error('Owner unavailable'));
    await expect(readSubscriptionAudit({} as Env, 'token', id(1), id(2), null)).rejects.toThrow('Owner unavailable');
  });
});
