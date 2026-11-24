import type { DbClient } from './db';

export interface SubscriptionPaymentInput {
  user_id: string;
  plan_id: string;
  organization_id?: string;
  organization_type?: string;
  razorpay_order_id: string;
  razorpay_payment_id: string;
  razorpay_signature?: string;
  amount: number;
  currency: string;
  billing_cycle: 'monthly' | 'yearly';
  full_name: string;
  email: string;
  seat_count?: number;
  payment_method?: string;
}
export interface SubscriptionPaymentResult {
  subscription: Record<string, unknown>;
  transaction_id: string;
  already_fulfilled: boolean;
  is_upgrade: boolean;
  receipt_url?: string | null;
}

export type SubscriptionPaymentReference = Pick<SubscriptionPaymentInput,
  'user_id' | 'plan_id' | 'organization_id' | 'razorpay_order_id' | 'razorpay_payment_id' | 'amount' | 'currency'>;

/** Bounded, payment-specific history lookup; never scan a buyer's history. */
export async function readSubscriptionPayment(database: DbClient, input: SubscriptionPaymentReference): Promise<SubscriptionPaymentResult | null> {
  if (!input.razorpay_payment_id?.trim() || !input.razorpay_order_id?.trim() || !input.user_id || !input.plan_id) throw new Error('Invalid payment reference');
  const rows = await database.query<Record<string, unknown>>(
    `transactions?razorpay_payment_id=eq.${encodeURIComponent(input.razorpay_payment_id)}&limit=2`);
  if (!rows.length) return null;
  if (rows.length !== 1) throw new Error('Payment requires transaction reconciliation');
  const tx = rows[0];
  const metadata = tx.metadata as { plan?: { id?: string; code?: string } } | null;
  if (tx.status !== 'completed' || !['subscription', 'upgrade'].includes(String(tx.transaction_type))
    || tx.user_id !== input.user_id || tx.razorpay_order_id !== input.razorpay_order_id
    || (tx.organization_id ?? null) !== (input.organization_id ?? null)
    || Number(tx.amount) !== input.amount || tx.currency !== input.currency
    || ![metadata?.plan?.id, metadata?.plan?.code].includes(input.plan_id)
    || typeof tx.subscription_id !== 'string') throw new Error('Payment fulfillment identity or terms mismatch');
  const subscription = await database.queryOne<Record<string, unknown>>(
    `subscriptions?id=eq.${encodeURIComponent(tx.subscription_id)}&limit=1`);
  if (!subscription || subscription.user_id !== input.user_id
    || (subscription.organization_id ?? null) !== (input.organization_id ?? null)
    || typeof tx.id !== 'string') throw new Error('Payment fulfillment subscription mismatch');
  return { subscription, transaction_id: tx.id, already_fulfilled: true,
    is_upgrade: tx.transaction_type === 'upgrade', receipt_url: typeof tx.receipt_url === 'string' ? tx.receipt_url : null };
}

/** One database transaction owns activation and durable payment evidence. */
export async function fulfillSubscriptionPayment(database: DbClient, input: SubscriptionPaymentInput): Promise<SubscriptionPaymentResult> {
  if (!input.user_id || !input.plan_id || !input.razorpay_order_id?.trim() || !input.razorpay_payment_id?.trim()
    || !Number.isSafeInteger(Math.round(input.amount * 100)) || !Number.isFinite(input.amount) || input.amount <= 0
    || input.currency !== 'INR' || !['monthly', 'yearly'].includes(input.billing_cycle)) {
    throw new Error('Invalid verified subscription payment');
  }
  let result: SubscriptionPaymentResult;
  try {
    result = await database.rpc<SubscriptionPaymentResult>('fulfill_subscription_payment', { p_input: input });
  } catch {
    // Database constraint details can contain the inserted signature. Keep
    // the failure explicit without forwarding provider proof into logs/API errors.
    throw new Error('Unable to confirm subscription payment fulfillment');
  }
  if (!result || !result.subscription || typeof result.subscription.id !== 'string'
    || typeof result.transaction_id !== 'string' || typeof result.already_fulfilled !== 'boolean'
    || typeof result.is_upgrade !== 'boolean' || result.subscription.user_id !== input.user_id
    || !['active','pending','paused','cancelled','expired','grace_period'].includes(String(result.subscription.status))) {
    throw new Error('Invalid subscription fulfillment response');
  }
  return result;
}
