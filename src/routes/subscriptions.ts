import type { Env, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { json, error } from "../lib/response";
import { addMonths, parseDurationMonths } from "../lib/date";
import { endpointRateLimit } from "../lib/rate-limit";

interface CreateSubscriptionBody {
  user_id: string;
  plan_id: string;
  plan_code: string;
  plan_type: string;
  plan_amount: number;
  billing_cycle: string;
  features: unknown[];
  full_name: string;
  email: string;
  phone?: string;
  razorpay_order_id?: string;
  razorpay_payment_id?: string;
  organization_id?: string;
  organization_type?: string;
  seat_count?: number;
  is_organization_subscription?: boolean;
  is_bulk_purchase?: boolean;
  purchased_by?: string;
}

interface UpdateStatusBody {
  status: string;
  cancellation_reason?: string;
  cancellation_feedback?: string;
  cancelled_by?: string;
  paused_until?: string;
  receipt_url?: string;
}

interface RecordTransactionBody {
  subscription_id?: string;
  user_id: string;
  razorpay_order_id?: string;
  razorpay_payment_id?: string;
  razorpay_signature?: string;
  amount: number;
  currency?: string;
  status: string;
  transaction_type?: string;
  payment_method?: string;
  organization_id?: string;
  organization_type?: string;
  seat_count?: number;
  is_bulk_purchase?: boolean;
  receipt?: string;
  receipt_url?: string;
  notes?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

// ─── Plans (public) ───────────────────────────────────────────

export async function listPlans(
  _req: Request,
  env: Env,
): Promise<Response> {
  const database = db(env);
  const plans = await database.query(
    "plans?is_active=eq.true&order=display_order.asc",
  );
  return json(plans);
}

export async function getPlanByCode(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const code = url.pathname.split("/").pop();
  if (!code) return error("Plan code required", 400);

  const database = db(env);
  const plan = await database.queryOne(
    `plans?plan_code=eq.${encodeURIComponent(code)}&is_active=eq.true`,
  );
  if (!plan) return error("Plan not found", 404);
  return json(plan);
}

// ─── Subscriptions ────────────────────────────────────────────

async function createSubscription(
  req: Request,
  env: Env,
  _ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  let body: CreateSubscriptionBody;
  try {
    body = (await req.json()) as CreateSubscriptionBody;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.user_id || !body.plan_id || !body.plan_code || !body.email) {
    return error("user_id, plan_id, plan_code, and email are required", 400);
  }

  const billingCycle = body.billing_cycle || "lifetime";
  const now = new Date();
  const endDate = addMonths(now, parseDurationMonths(billingCycle));

  const database = db(env);
  const subscription = await database.mutate("subscriptions", {
    user_id: body.user_id,
    plan_id: body.plan_id,
    plan_code: body.plan_code,
    plan_type: body.plan_type || body.plan_code,
    plan_amount: body.plan_amount || 0,
    billing_cycle: billingCycle,
    features: body.features || [],
    full_name: body.full_name || "",
    email: body.email,
    phone: body.phone || null,
    status: "active",
    auto_renew: billingCycle !== "lifetime",
    subscription_start_date: now.toISOString(),
    subscription_end_date: billingCycle === "lifetime" ? null : endDate.toISOString(),
    razorpay_order_id: body.razorpay_order_id || null,
    razorpay_payment_id: body.razorpay_payment_id || null,
    organization_id: body.organization_id || null,
    organization_type: body.organization_type || null,
    seat_count: body.seat_count || 1,
    is_organization_subscription: body.is_organization_subscription || false,
    is_bulk_purchase: body.is_bulk_purchase || false,
    purchased_by: body.purchased_by || null,
  });

  return json(subscription, 201);
}

async function createFreemiumSubscription(
  req: Request,
  env: Env,
): Promise<Response> {
  let body: { user_id: string; email: string; full_name?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.user_id || !body.email) {
    return error("user_id and email are required", 400);
  }

  const database = db(env);

  // Find the freemium plan
  const freemiumPlan = await database.queryOne(
    "plans?plan_code=eq.freemium&is_active=eq.true",
  );
  if (!freemiumPlan) {
    return error("Freemium plan not found", 500);
  }

  // Check for existing active subscription
  const existing = await database.queryOne(
    `subscriptions?user_id=eq.${body.user_id}&status=in.(active,pending)`,
  );
  if (existing) {
    return json(existing, 200);
  }

  const subscription = await database.mutate("subscriptions", {
    user_id: body.user_id,
    plan_id: freemiumPlan.id,
    plan_code: "freemium",
    plan_type: "Freemium",
    plan_amount: 0,
    billing_cycle: "lifetime",
    features: freemiumPlan.base_features || [],
    full_name: body.full_name || "",
    email: body.email,
    status: "active",
    auto_renew: false,
    subscription_start_date: new Date().toISOString(),
    subscription_end_date: null,
  });

  return json(subscription, 201);
}

async function getUserSubscription(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const userId = url.pathname.split("/").pop();
  if (!userId) return error("User ID required", 400);

  const database = db(env);
  const subscription = await database.queryOne(
    `subscriptions?user_id=eq.${encodeURIComponent(userId)}&status=in.(active,pending)&order=created_at.desc`,
  );

  if (!subscription) {
    return json({ subscription: null });
  }

  // Enrich with plan data
  const plan = await database.queryOne(
    `plans?id=eq.${subscription.plan_id}`,
  );

  return json({ subscription, plan });
}

async function getOrgSubscription(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const orgId = url.pathname.split("/").pop();
  if (!orgId) return error("Organization ID required", 400);

  const database = db(env);
  const subscriptions = await database.query(
    `subscriptions?organization_id=eq.${encodeURIComponent(orgId)}&is_organization_subscription=eq.true&status=in.(active,pending)&order=created_at.desc`,
  );

  return json({ subscriptions });
}

async function updateSubscriptionStatus(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const parts = url.pathname.split("/");
  const subId = parts[parts.length - 2]; // /api/subscriptions/:id/status
  if (!subId) return error("Subscription ID required", 400);

  let body: UpdateStatusBody;
  try {
    body = (await req.json()) as UpdateStatusBody;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.status) {
    return error("status is required", 400);
  }

  const database = db(env);
  const updateData: Record<string, unknown> = {
    status: body.status,
    updated_at: new Date().toISOString(),
  };

  if (body.cancellation_reason) updateData.cancellation_reason = body.cancellation_reason;
  if (body.cancellation_feedback) updateData.cancellation_feedback = body.cancellation_feedback;
  if (body.cancelled_by) updateData.cancelled_by = body.cancelled_by;
  if (body.paused_until) updateData.paused_until = body.paused_until;
  if (body.receipt_url) updateData.receipt_url = body.receipt_url;

  if (body.status === "paused") {
    updateData.paused_at = new Date().toISOString();
  }

  await database.update(
    "subscriptions",
    { id: `eq.${subId}` },
    updateData,
  );

  const updated = await database.queryOne(
    `subscriptions?id=eq.${subId}`,
  );

  return json(updated);
}

async function cancelSubscription(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const parts = url.pathname.split("/");
  const subId = parts[parts.length - 2]; // /api/subscriptions/:id/cancel
  if (!subId) return error("Subscription ID required", 400);

  let body: { reason?: string; feedback?: string; cancelled_by?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    body = {};
  }

  const database = db(env);
  await database.update(
    "subscriptions",
    { id: `eq.${subId}` },
    {
      status: "cancelled",
      cancellation_reason: body.reason || null,
      cancellation_feedback: body.feedback || null,
      cancelled_by: body.cancelled_by || "user",
      updated_at: new Date().toISOString(),
    },
  );

  const updated = await database.queryOne(
    `subscriptions?id=eq.${subId}`,
  );

  return json(updated);
}

async function updateSubscriptionField(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const parts = url.pathname.split("/");
  const subId = parts[parts.length - 2]; // /api/subscriptions/:id/update
  if (!subId) return error("Subscription ID required", 400);

  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return error("Invalid JSON body", 400);
  }

  // Allowlist of updatable fields
  const allowed = new Set([
    "plan_id", "plan_code", "plan_type", "plan_amount", "billing_cycle",
    "features", "razorpay_order_id", "razorpay_payment_id",
    "subscription_start_date", "subscription_end_date", "auto_renew",
    "receipt_url", "seat_count", "metadata",
  ]);

  const updateData: Record<string, unknown> = { updated_at: new Date().toISOString() };
  for (const [key, value] of Object.entries(body)) {
    if (allowed.has(key)) updateData[key] = value;
  }

  const database = db(env);
  await database.update("subscriptions", { id: `eq.${subId}` }, updateData);

  const updated = await database.queryOne(`subscriptions?id=eq.${subId}`);
  return json(updated);
}

// ─── Transactions ─────────────────────────────────────────────

async function recordTransaction(
  req: Request,
  env: Env,
): Promise<Response> {
  let body: RecordTransactionBody;
  try {
    body = (await req.json()) as RecordTransactionBody;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.user_id || body.amount === undefined || !body.status) {
    return error("user_id, amount, and status are required", 400);
  }

  const database = db(env);
  const transaction = await database.mutate("transactions", {
    subscription_id: body.subscription_id || null,
    user_id: body.user_id,
    razorpay_order_id: body.razorpay_order_id || null,
    razorpay_payment_id: body.razorpay_payment_id || null,
    razorpay_signature: body.razorpay_signature || null,
    amount: body.amount,
    currency: body.currency || "INR",
    status: body.status,
    transaction_type: body.transaction_type || "subscription",
    payment_method: body.payment_method || null,
    organization_id: body.organization_id || null,
    organization_type: body.organization_type || null,
    seat_count: body.seat_count || 1,
    is_bulk_purchase: body.is_bulk_purchase || false,
    receipt: body.receipt || null,
    receipt_url: body.receipt_url || null,
    notes: body.notes || {},
    metadata: body.metadata || {},
  });

  return json(transaction, 201);
}

async function getUserTransactions(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const userId = url.searchParams.get("user_id");
  const subscriptionId = url.searchParams.get("subscription_id");

  if (!userId) {
    return error("user_id query param is required", 400);
  }

  const database = db(env);

  let query = `transactions?user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc`;
  if (subscriptionId) {
    query += `&subscription_id=eq.${encodeURIComponent(subscriptionId)}`;
  }

  const transactions = await database.query(query);
  return json({ transactions: transactions || [] });
}

// ─── Events (webhook store) ───────────────────────────────────

export async function processWebhookEvent(
  req: Request,
  env: Env,
): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rateLimited = await endpointRateLimit(env, `webhook:ip:${ip}`, 60, 60);
  if (rateLimited) return rateLimited;

  let body: { event_id: string; event_type: string; payload: unknown; user_id?: string; subscription_id?: string; razorpay_payment_id?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.event_id || !body.event_type || !body.payload) {
    return error("event_id, event_type, and payload are required", 400);
  }

  const database = db(env);

  // Idempotency check
  const existing = await database.queryOne(
    `events?event_id=eq.${encodeURIComponent(body.event_id)}`,
  );
  if (existing) {
    return json({ status: "skipped", message: "Event already processed", event: existing }, 200);
  }

  const event = await database.mutate("events", {
    event_id: body.event_id,
    event_type: body.event_type,
    status: "received",
    payload: body.payload,
    user_id: body.user_id || null,
    subscription_id: body.subscription_id || null,
    razorpay_payment_id: body.razorpay_payment_id || null,
  });

  return json(event, 201);
}

// ─── Sync endpoints (for shadow tables) ───────────────────────

async function syncSubscription(
  req: Request,
  env: Env,
): Promise<Response> {
  let body: { user_id: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.user_id) return error("user_id is required", 400);

  const database = db(env);
  const subscription = await database.queryOne(
    `subscriptions?user_id=eq.${encodeURIComponent(body.user_id)}&status=in.(active,pending)&order=created_at.desc`,
  );

  if (!subscription) {
    return json({ subscription: null, plan: null });
  }

  const plan = await database.queryOne(
    `plans?id=eq.${subscription.plan_id}`,
  );

  return json({ subscription, plan });
}

async function syncPlans(
  _req: Request,
  env: Env,
): Promise<Response> {
  const database = db(env);
  const plans = await database.query(
    "plans?is_active=eq.true&order=display_order.asc",
  );
  return json({ plans });
}

async function syncReconcile(
  req: Request,
  env: Env,
): Promise<Response> {
  let body: { user_ids: string[] };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.user_ids || !Array.isArray(body.user_ids)) {
    return error("user_ids array is required", 400);
  }

  const database = db(env);
  const userIdList = body.user_ids.map((id) => encodeURIComponent(id)).join(",");
  const subscriptions = await database.query(
    `subscriptions?user_id=in.(${userIdList})&status=in.(active,pending)&order=created_at.desc`,
  );

  return json({ subscriptions });
}


