import { beforeEach, expect, it, vi } from 'vitest';
import type { DbClient } from '../lib/db';
import { fulfillSubscriptionPayment, readSubscriptionPayment, type SubscriptionPaymentInput } from '../lib/subscription-payment';
const database: DbClient = { query: vi.fn(), queryOne: vi.fn(), rpc: vi.fn(), mutate: vi.fn(), update: vi.fn(), bulkInsert: vi.fn() };
const input: SubscriptionPaymentInput = { user_id: 'buyer', plan_id: 'plan', razorpay_order_id: 'order', razorpay_payment_id: 'pay', amount: 4999,
  currency: 'INR', billing_cycle: 'yearly', full_name: 'Synthetic Buyer', email: 'buyer@example.invalid' };
const subscription = { id: 'sub', user_id: 'buyer', organization_id: null, plan_id: 'later_plan', razorpay_payment_id: 'later_payment', status: 'active' };
const transaction = { id: 'tx', user_id: 'buyer', organization_id: null, subscription_id: 'sub', razorpay_order_id: 'order', razorpay_payment_id: 'pay',
  amount: '4999.00', currency: 'INR', status: 'completed', transaction_type: 'subscription', metadata: { plan: { id: 'plan', code: 'starter' } } };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(database.query).mockResolvedValue([transaction]);
  vi.mocked(database.queryOne).mockResolvedValue(subscription);
  vi.mocked(database.rpc).mockResolvedValue({ subscription, transaction_id: 'tx', already_fulfilled: false, is_upgrade: false });
});
it('delegates activation and payment evidence to one atomic database RPC', async () => {
  await expect(fulfillSubscriptionPayment(database, input)).resolves.toMatchObject({ transaction_id: 'tx' });
  expect(database.rpc).toHaveBeenCalledExactlyOnceWith('fulfill_subscription_payment', { p_input: input });
  expect(database.mutate).not.toHaveBeenCalled(); expect(database.update).not.toHaveBeenCalled();
});
it('uses bounded durable transaction history after an upgrade overwrites the subscription payment id', async () => {
  await expect(readSubscriptionPayment(database, input)).resolves.toMatchObject({ already_fulfilled: true, subscription: { plan_id: 'later_plan' } });
  expect(database.query).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('razorpay_payment_id=eq.pay&limit=2'));
});
it('accepts the original catalog code recorded with that payment', async () => {
  await expect(readSubscriptionPayment(database, { ...input, plan_id: 'starter' })).resolves.toMatchObject({ already_fulfilled: true });
});
it.each([{ user_id: 'other' }, { plan_id: 'other' }, { organization_id: 'other' }, { amount: 1 }, { currency: 'USD' }, { razorpay_order_id: 'other' }])('rejects mismatched durable payment terms (%j)', async change => {
  await expect(readSubscriptionPayment(database, { ...input, ...change })).rejects.toThrow('identity or terms mismatch');
});
it('does not turn an unavailable ledger into a new activation', async () => {
  vi.mocked(database.query).mockRejectedValue(new Error('Unavailable'));
  await expect(readSubscriptionPayment(database, input)).rejects.toThrow('Unavailable'); expect(database.rpc).not.toHaveBeenCalled();
});
it('requires reconciliation for duplicate payment evidence', async () => {
  vi.mocked(database.query).mockResolvedValue([transaction, transaction]);
  await expect(readSubscriptionPayment(database, input)).rejects.toThrow('reconciliation');
});
it('rejects a subscription owned by another buyer', async () => {
  vi.mocked(database.queryOne).mockResolvedValue({ ...subscription, user_id: 'another' });
  await expect(readSubscriptionPayment(database, input)).rejects.toThrow('subscription mismatch');
});
it('returns no fulfillment for a new payment, without manufacturing success', async () => {
  vi.mocked(database.query).mockResolvedValue([]);
  await expect(readSubscriptionPayment(database, input)).resolves.toBeNull();
});
it('does not accept success-shaped malformed activation results', async () => {
  vi.mocked(database.rpc).mockResolvedValue({ success: true });
  await expect(fulfillSubscriptionPayment(database, input)).rejects.toThrow('Invalid subscription fulfillment');
});
it('does not forward database row details containing payment proof', async () => {
  vi.mocked(database.rpc).mockRejectedValue(new Error('Row constraint details: synthetic-private-signature'));
  await expect(fulfillSubscriptionPayment(database, input)).rejects.toThrow('Unable to confirm subscription payment fulfillment');
  try { await fulfillSubscriptionPayment(database, input); } catch (error) {
    expect(String(error)).not.toContain('synthetic-private-signature');
  }
});
