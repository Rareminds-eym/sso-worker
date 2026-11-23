import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Env, QueueMessage } from '../../types';

const mocks = vi.hoisted(() => ({ query: vi.fn(), queryOne: vi.fn(), mutate: vi.fn(), capture: vi.fn() }));
vi.mock('../../lib/db', () => ({ db: () => mocks }));
vi.mock('../../lib/subscriptions/commerce-persistence', () => ({ recordSubscriptionCommerceCapture: mocks.capture }));
vi.mock('../bulk-import-adapters', () => ({
  BULK_CREATE_MESSAGE_TYPES: {}, BULK_PARSE_MESSAGE_TYPES: [],
  learnerBulkImport: { parseMessageType: 'test.parse', createMessageType: 'test.create', itemKey: 'items' },
  handleCreateFacultyBatch: vi.fn(), handleCreateLearnerBatch: vi.fn(),
  handleParseCsvQueue: vi.fn(), handleParseFacultyCsvQueue: vi.fn(),
}));
import { routeQueueMessage } from '../queue-router';

const orderId = 'order_Synthetic1';
const envelope = () => ({ event_id: 'a'.repeat(64), event_type: 'payment.captured',
  payload: { payment: { entity: { order_id: orderId } } },
  verification: { kind: 'razorpay_hmac_sha256', bodySha256: 'a'.repeat(64), receivedAt: 1000 },
  capture: { orderId, paymentId: 'pay_Synthetic1', capturedAt: 900, paymentCreatedAt: 800,
    amountMinor: 9900, currency: 'INR' } });
const message = () => ({ ack: vi.fn(), retry: vi.fn() }) as unknown as QueueMessage<ReturnType<typeof envelope>>;

describe('canonical subscription capture queue ownership', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.query.mockResolvedValue([{ provider_order_id: orderId }]);
    mocks.capture.mockResolvedValue({ eventId: 'a'.repeat(64) });
    mocks.queryOne.mockResolvedValue(null);
  });
  it('persists the full verified envelope before acknowledgement and avoids legacy fulfillment', async () => {
    const body = envelope(), msg = message();
    mocks.capture.mockImplementation(async () => { expect(msg.ack).not.toHaveBeenCalled(); });
    await routeQueueMessage({} as Env, msg, body);
    expect(mocks.capture).toHaveBeenCalledWith(mocks, body);
    expect(msg.ack).toHaveBeenCalledOnce();
    expect(mocks.mutate).not.toHaveBeenCalled();
    expect(mocks.queryOne).not.toHaveBeenCalled();
  });
  it('replays through the immutable capture owner even if a legacy event exists', async () => {
    mocks.queryOne.mockResolvedValue({ status: 'completed' });
    await routeQueueMessage({} as Env, message(), envelope());
    expect(mocks.capture).toHaveBeenCalledOnce();
    expect(mocks.queryOne).not.toHaveBeenCalled();
  });
  it('never forwards canonical order.paid to legacy fulfillment or invents capture evidence', async () => {
    const msg = message();
    await routeQueueMessage({} as Env, msg, { event_id: 'b'.repeat(64), event_type: 'order.paid',
      payload: { order: { entity: { id: orderId } } } });
    expect(msg.ack).toHaveBeenCalledOnce();
    expect(mocks.capture).not.toHaveBeenCalled();
    expect(mocks.mutate).not.toHaveBeenCalled();
  });
  it('does not acknowledge failed or conflicting capture persistence', async () => {
    mocks.capture.mockRejectedValue(new Error('conflicting capture'));
    const msg = message();
    await expect(routeQueueMessage({} as Env, msg, envelope())).rejects.toThrow('conflicting capture');
    expect(msg.ack).not.toHaveBeenCalled();
    expect(mocks.mutate).not.toHaveBeenCalled();
  });
  it.each([undefined, 'bad/order'])('rejects malformed order identity %s', async order => {
    const body = envelope();
    body.payload.payment.entity.order_id = order as string;
    const msg = message();
    await expect(routeQueueMessage({} as Env, msg, body)).rejects.toThrow('order identity');
    expect(msg.ack).not.toHaveBeenCalled();
    expect(mocks.capture).not.toHaveBeenCalled();
  });
  it.each([[{ provider_order_id: orderId }, { provider_order_id: orderId }],
    [{ provider_order_id: 'order_Foreign' }], null])('rejects ambiguous owner lookup', async rows => {
    mocks.query.mockResolvedValue(rows);
    const msg = message();
    await expect(routeQueueMessage({} as Env, msg, envelope())).rejects.toThrow('quote identity');
    expect(msg.ack).not.toHaveBeenCalled();
  });
  it('surfaces lookup failure without substituting legacy handling', async () => {
    mocks.query.mockRejectedValue(new Error('owner unavailable'));
    const msg = message();
    await expect(routeQueueMessage({} as Env, msg, envelope())).rejects.toThrow('owner unavailable');
    expect(mocks.mutate).not.toHaveBeenCalled();
    expect(msg.ack).not.toHaveBeenCalled();
  });
  it('preserves legacy handling only after the provider confirms noncanonical order ownership', async () => {
    mocks.query.mockResolvedValue([]);
    const body = envelope(), msg = message();
    const getOrder = vi.fn().mockResolvedValue({ id: orderId, notes: { type: 'subscription' } });
    await routeQueueMessage({ PAYMENT_WORKER: { getOrder } } as unknown as Env, msg, body);
    expect(getOrder).toHaveBeenCalledWith(orderId);
    expect(mocks.capture).not.toHaveBeenCalled();
    expect(mocks.mutate).toHaveBeenCalledWith('events', expect.objectContaining({ payload: body.payload, status: 'received' }));
    expect(msg.ack).toHaveBeenCalledOnce();
  });
  it('holds a capture that races the canonical create-order acknowledgement', async () => {
    mocks.query.mockResolvedValue([]);
    const getOrder = vi.fn().mockResolvedValue({ id: orderId, notes: { subscription_quote_id: 'synthetic-quote' } });
    const msg = message();
    await expect(routeQueueMessage({ PAYMENT_WORKER: { getOrder } } as unknown as Env, msg, envelope()))
      .rejects.toThrow('awaiting retained quote');
    expect(msg.ack).not.toHaveBeenCalled();
    expect(mocks.mutate).not.toHaveBeenCalled();
  });
  it('does not substitute legacy processing when the payment owner is missing', async () => {
    mocks.query.mockResolvedValue([]);
    const msg = message();
    await expect(routeQueueMessage({} as Env, msg, envelope())).rejects.toThrow('order owner unavailable');
    expect(msg.ack).not.toHaveBeenCalled();
    expect(mocks.mutate).not.toHaveBeenCalled();
  });
  it.each([{ id: 'order_Foreign', notes: {} }, { id: orderId, notes: null }])('rejects invalid provider classification', async order => {
    mocks.query.mockResolvedValue([]);
    const getOrder = vi.fn().mockResolvedValue(order), msg = message();
    await expect(routeQueueMessage({ PAYMENT_WORKER: { getOrder } } as unknown as Env, msg, envelope()))
      .rejects.toThrow('classification unavailable');
    expect(msg.ack).not.toHaveBeenCalled();
    expect(mocks.mutate).not.toHaveBeenCalled();
  });
});
