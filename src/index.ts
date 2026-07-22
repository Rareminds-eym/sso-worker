import { WorkerEntrypoint } from "cloudflare:workers";
import { audit } from "./lib/audit";
import { INVITE_TTL_MS, SESSION_TTL_MS } from "./lib/constants";
import { addMonths, parseDurationMonths } from "./lib/date";
import { db } from "./lib/db";
import { inviteEmail, sendEmail } from "./lib/email";
import { checkEmailThrottle } from "./lib/email-throttle";
import { generateRefreshToken, hashPassword, hashToken } from "./lib/hash";
import { exportPemAsJwk, getPublicJWK, signAccessToken, verifyAccessToken } from "./lib/jwt";
import { signLteAccessToken } from "./lib/app-token";
import { endpointRateLimit } from "./lib/rate-limit";
import { mintAccessToken, rotateRefreshToken } from "./lib/session-rotation";
import { publishSyncEvent } from "./lib/sync-queue";
import {
  assertAllowedRedirectUri,
  assertTargetApp,
  createAuthorizationCode,
  getAuthorizationCodeStub,
  hashAuthorizationValue,
} from "./lib/authorization-code";
import { requireLteEntitlement } from "./lib/lte-entitlement";
import { getLteSubscriptionSnapshot } from "./lib/subscription-snapshot";
import { resolveAppUrl, validateEmail, validatePassword, validateRedirectUrl } from "./lib/validate";
import { fetchWithTimeout } from "./lib/fetch-timeout";
import { getBatch, type BatchMetadata } from "./lib/batch-kv";
import { handleQueueBatch } from "./queue/queue-router";
import type {
  AccessTokenPayload,
  Env,
  Invite,
  JwtClaims,
  Membership,
  MessageBatch,
  Organization,
  Session,
  SignupMemberBody,
} from "./types";
import type {
  ExchangeAuthorizationCodeRequest,
  ExchangeAuthorizationCodeResponse,
  GenerateAuthorizationCodeRequest,
  GenerateAuthorizationCodeResponse,
} from "./types/sso-code";

export { AuthorizationCodeStore } from "./durable-objects/AuthorizationCodeStore";

import { performQueueUserSync } from "./routes/user-sync";
import { performCreateOrganization, performUpdateOrganization, performUpdateOrganizationDetails } from "./routes/organization";
import { performCreateLearnerUser, performQueueBulkLearnerUpload } from "./routes/learner-admission";
import { performCreateMember, performCreateMembership, performUpdateMembershipStatus, performAssignMembershipRole } from "./routes/membership";

// ─── WorkerEntrypoint ─────────────────────────────────────────
export class SsoWorker extends WorkerEntrypoint<Env> {
  // ── Scheduled (cron) ──────────────────────────────────────────
  async scheduled(_event: ScheduledEvent): Promise<void> {
    const database = db(this.env);

    // Clean up expired or revoked tokens (verifications, password resets, etc.)
    const deletedTokens = await database.rpc<number>("cleanup_expired_tokens");
    console.log(`[SSO] Cleaned up ${deletedTokens} expired token rows`);

    // Clean up expired sessions to prevent unbounded database growth
    const deletedSessions = await database.rpc<number>("cleanup_expired_sessions");
    console.log(`[SSO] Cleaned up ${deletedSessions} expired session rows`);

    try {
      const result = await database.rpc<{ count: number }[]>("expire_old_subscriptions");
      const expired = Array.isArray(result) ? result[0]?.count ?? 0 : 0;
      if (expired > 0) console.log(`[SSO] Expired ${expired} subscription(s)`);
    } catch (err: unknown) {
      const errMessage = err instanceof Error ? err.message : String(err);
      console.error(`[SSO] Failed to expire subscriptions: ${errMessage}`);
    }

    try {
      const pendingEvents = await database.query<Record<string, unknown>>(
        "events?status=eq.received&order=created_at.asc&limit=10"
      );
      if (pendingEvents && pendingEvents.length > 0) {
        for (const event of pendingEvents) {
          const eventId = event.id as string;
          const eventType = event.event_type as string;
          const eventPublicId = event.event_id as string;
          const eventRetryCount = event.retry_count as number | null;

          await database.update("events", { id: `eq.${encodeURIComponent(eventId)}` }, { status: "processing" });
          try {
            if (eventType === 'payment.captured' || eventType === 'order.paid') {
              if (!this.env.SKILLPASSPORT_URL || !this.env.INTERNAL_WEBHOOK_SECRET) {
                throw new Error("SKILLPASSPORT URL or INTERNAL_WEBHOOK_SECRET not configured. Cannot dispatch webhook.");
              }

              const targetUrl = `${this.env.SKILLPASSPORT_URL}/api/internal/webhooks/payment`;
              const dispatchResponse = await fetchWithTimeout(targetUrl, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${this.env.INTERNAL_WEBHOOK_SECRET}`,
                  'X-Webhook-Event': eventType
                },
                body: JSON.stringify(event.payload)
              }, 10000); // 10 second timeout for webhook dispatch

              if (!dispatchResponse.ok) {
                const resBody = await dispatchResponse.text();
                throw new Error(`Fulfillment failed with status ${dispatchResponse.status}: ${resBody}`);
              }
            }

            // Mark as completed since fulfillment succeeded (or event type was ignored)
            await database.update("events", { id: `eq.${encodeURIComponent(eventId)}` }, {
              status: "completed",
              processed_at: new Date().toISOString()
            });
            console.log(`[SSO] Processed webhook event ${eventPublicId} of type ${eventType}`);
          } catch (processErr: unknown) {
            const processErrMessage = processErr instanceof Error ? processErr.message : String(processErr);
            await database.update("events", { id: `eq.${encodeURIComponent(eventId)}` }, {
              status: "failed",
              error_message: processErrMessage || "Unknown error",
              retry_count: (eventRetryCount || 0) + 1
            });
          }
        }
      }
    } catch (err: unknown) {
      const errMessage = err instanceof Error ? err.message : String(err);
      console.error(`[SSO] Failed to process webhook events: ${errMessage}`);
    }
  }

  // ══════════════════════════════════════════════════════════════
  // RPC METHODS — callable via service binding only
  // ══════════════════════════════════════════════════════════════

  // ── Subscription Management ─────────────────────────────────

  // ── Queue Handler (Asynchronous Events) ─────────────────────
  async queue(batch: MessageBatch): Promise<void> {
    if (batch.messages.length === 0) {
      console.log('[SSO] Empty batch received, skipping');
      return;
    }

    try {
      await handleQueueBatch(this.env, batch);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      console.error('[SSO] Queue batch processing failed:', errorMsg);
      // Re-throw to trigger batch-level retry by Cloudflare Queues
      throw err;
    }
  }


  async queueUserSync(userId: string): Promise<{ queued: boolean; reason: string }> {
    return performQueueUserSync(this.env, userId);
  }

  // ══════════════════════════════════════════════════════════════
  // RPC METHODS — callable via service binding only
  // ══════════════════════════════════════════════════════════════

  // ── Subscription Management ─────────────────────────────────

  async createSubscription(data: {
    user_id: string;
    plan_id: string;
    plan_code: string;
    plan_type: string;
    plan_amount: number;
    billing_cycle: string;
    features: unknown[];
    full_name: string;
    email: string;
    razorpay_order_id?: string;
    razorpay_payment_id?: string;
    organization_id?: string;
    organization_type?: string;
    seat_count?: number;
    is_organization_subscription?: boolean;
    is_bulk_purchase?: boolean;
    purchased_by?: string;
  }): Promise<Record<string, unknown>> {
    if (!data.user_id || !data.plan_id || !data.plan_code || !data.email) {
      throw new Error("user_id, plan_id, plan_code, and email are required");
    }

    const billingCycle = data.billing_cycle || "lifetime";
    const now = new Date();
    const endDate = addMonths(now, parseDurationMonths(billingCycle));

    const database = db(this.env);
    const subscription = await database.mutate("subscriptions", {
      user_id: data.user_id,
      plan_id: data.plan_id,
      plan_code: data.plan_code,
      plan_type: data.plan_type || data.plan_code,
      plan_amount: data.plan_amount || 0,
      billing_cycle: billingCycle,
      features: data.features || [],
      full_name: data.full_name || "",
      email: data.email,
      status: "active",
      auto_renew: billingCycle !== "lifetime",
      subscription_start_date: now.toISOString(),
      subscription_end_date: billingCycle === "lifetime" ? null : endDate.toISOString(),
      razorpay_order_id: data.razorpay_order_id || null,
      razorpay_payment_id: data.razorpay_payment_id || null,
      organization_id: data.organization_id || null,
      organization_type: data.organization_type || null,
      seat_count: data.seat_count || 1,
      is_organization_subscription: data.is_organization_subscription || false,
      is_bulk_purchase: data.is_bulk_purchase || false,
      purchased_by: data.purchased_by || null,
    });

    publishSyncEvent(this.env.SYNC_QUEUE, this.ctx, 'subscription.created', {
      id: (subscription as { id: string }).id,
      user_id: data.user_id,
      organization_id: data.organization_id || null,
      plan_id: data.plan_id,
      plan_code: data.plan_code,
      plan_type: data.plan_type || data.plan_code,
      plan_amount: data.plan_amount || 0,
      billing_cycle: billingCycle,
      features: data.features || [],
      status: 'active',
      subscription_start_date: now.toISOString(),
      subscription_end_date: billingCycle === 'lifetime' ? null : endDate.toISOString(),
      is_organization_subscription: data.is_organization_subscription || false,
      product_id: null,
      updated_at: now.toISOString(),
    });

    return subscription as Record<string, unknown>;
  }

  async createFreemiumSubscription(data: {
    user_id: string;
    email: string;
    full_name?: string;
  }): Promise<Record<string, unknown>> {
    if (!data.user_id || !data.email) {
      throw new Error("user_id and email are required");
    }

    const database = db(this.env);

    const freemiumPlan = await database.queryOne(
      "plans?plan_code=eq.freemium&is_active=eq.true",
    );
    if (!freemiumPlan) {
      throw new Error("Freemium plan not found");
    }

    const existing = await database.queryOne(
      `subscriptions?user_id=eq.${encodeURIComponent(data.user_id)}&status=in.(active,pending)`,
    );
    if (existing) {
      return existing as Record<string, unknown>;
    }

    const subscription = await database.mutate("subscriptions", {
      user_id: data.user_id,
      plan_id: freemiumPlan.id,
      plan_code: "freemium",
      plan_type: "Freemium",
      plan_amount: 0,
      billing_cycle: "lifetime",
      features: freemiumPlan.base_features || [],
      full_name: data.full_name || "",
      email: data.email,
      status: "active",
      auto_renew: false,
      subscription_start_date: new Date().toISOString(),
      subscription_end_date: null,
    });

    publishSyncEvent(this.env.SYNC_QUEUE, this.ctx, 'subscription.created', {
      id: (subscription as { id: string }).id,
      user_id: data.user_id,
      organization_id: null,
      plan_id: freemiumPlan.id,
      plan_code: 'freemium',
      plan_type: 'Freemium',
      plan_amount: 0,
      billing_cycle: 'lifetime',
      features: freemiumPlan.base_features || [],
      status: 'active',
      subscription_start_date: new Date().toISOString(),
      subscription_end_date: null,
      is_organization_subscription: false,
      product_id: null,
      updated_at: new Date().toISOString(),
    });

    return subscription as Record<string, unknown>;
  }

  /**
   * Admin-create a member user (e.g. a school admin adding a teacher).
   *
   * Creates an SSO user with a temporary password, joins them to the given org
   * with an ACTIVE membership, and assigns the supplied role. No subscription is
   * created — members get access through their organization's subscription/seats.
   *
   * Callable only via the SSO_SERVICE binding (the binding is the trust boundary).
   *
   * @returns { user_id, org_id, membership_id } from the signup_member RPC.
   * @throws if email/password/role/org_id are missing, the role is invalid, or
   *   the email already exists (duplicate).
   */
  async createMember(data: {
    email: string;
    password: string;
    role: string;
    org_id: string;
  }): Promise<{ user_id: string; org_id: string; membership_id: string }> {
    return performCreateMember(this.env, data);
  }

  async getUserSubscription(userId: string): Promise<{
    subscription: Record<string, unknown> | null;
    plan: Record<string, unknown> | null;
  }> {
    if (!userId) throw new Error("User ID required");

    const database = db(this.env);
    const subscription = await database.queryOne(
      `subscriptions?user_id=eq.${encodeURIComponent(userId)}&status=in.(active,pending)&order=created_at.desc`,
    );

    if (!subscription) {
      return { subscription: null, plan: null };
    }

    const plan = await database.queryOne(
      `plans?id=eq.${encodeURIComponent(subscription.plan_id)}`,
    );

    return { subscription: subscription as Record<string, unknown>, plan: plan as Record<string, unknown> };
  }

  async getOrgSubscription(orgId: string): Promise<{
    subscriptions: Record<string, unknown>[];
  }> {
    if (!orgId) throw new Error("Organization ID required");

    const database = db(this.env);
    const subscriptions = await database.query(
      `subscriptions?organization_id=eq.${encodeURIComponent(orgId)}&is_organization_subscription=eq.true&status=in.(active,pending)&order=created_at.desc`,
    );

    return { subscriptions: (subscriptions || []) as Record<string, unknown>[] };
  }

  async updateSubscriptionStatus(subscriptionId: string, data: {
    status: string;
    cancellation_reason?: string;
    cancellation_feedback?: string;
    cancelled_by?: string;
    paused_until?: string;
    receipt_url?: string;
  }): Promise<Record<string, unknown>> {
    if (!subscriptionId) throw new Error("Subscription ID required");
    if (!data.status) throw new Error("status is required");

    const database = db(this.env);
    const updateData: Record<string, unknown> = {
      status: data.status,
      updated_at: new Date().toISOString(),
    };

    if (data.cancellation_reason) updateData.cancellation_reason = data.cancellation_reason;
    if (data.cancellation_feedback) updateData.cancellation_feedback = data.cancellation_feedback;
    if (data.cancelled_by) updateData.cancelled_by = data.cancelled_by;
    if (data.paused_until) updateData.paused_until = data.paused_until;
    if (data.receipt_url) updateData.receipt_url = data.receipt_url;

    if (data.status === "paused") {
      updateData.paused_at = new Date().toISOString();
    }

    await database.update(
      "subscriptions",
      { id: `eq.${encodeURIComponent(subscriptionId)}` },
      updateData,
    );

    const updated = await database.queryOne(
      `subscriptions?id=eq.${encodeURIComponent(subscriptionId)}`,
    );

    return updated as Record<string, unknown>;
  }

  /**
   * Fetch subscription data for sales dashboard
   * @param searchParams Record of query parameters
   */
  async getSalesSubscriptions(searchParamsStr: string): Promise<any> {
    const { performGetSalesSubscriptions } = await import("./routes/sales-subscriptions");
    const result = await performGetSalesSubscriptions(this.env, new URLSearchParams(searchParamsStr));
    if ('error' in result && result.error) {
      throw new Error(result.error);
    }
    return result;
  }

  /**
   * Get filter metadata for sales dashboard (distinct values from DB)
   */
  async getSalesFilterMeta(): Promise<{
    planTypes: string[];
    statuses: string[];
    clientTypes: string[];
  }> {
    const database = db(this.env);
    const [planTypeRows, statusRows, roleRows] = await Promise.all([
      database.query<{ plan_type: string }>("subscriptions?select=plan_type"),
      database.query<{ status: string }>("subscriptions?select=status"),
      database.query<{ name: string }>("roles?select=name"),
    ]);
    return {
      planTypes: [...new Set(planTypeRows.map(r => r.plan_type))].sort(),
      statuses: [...new Set(statusRows.map(r => r.status))].sort(),
      clientTypes: roleRows.map(r => r.name).sort(),
    };
  }

  async cancelSubscription(subscriptionId: string, data?: {
    reason?: string;
    feedback?: string;
    cancelled_by?: string;
  }): Promise<Record<string, unknown>> {
    if (!subscriptionId) throw new Error("Subscription ID required");

    const database = db(this.env);
    await database.update(
      "subscriptions",
      { id: `eq.${encodeURIComponent(subscriptionId)}` },
      {
        status: "cancelled",
        cancellation_reason: data?.reason || null,
        cancellation_feedback: data?.feedback || null,
        cancelled_by: data?.cancelled_by || "user",
        updated_at: new Date().toISOString(),
      },
    );

    const updated = await database.queryOne(
      `subscriptions?id=eq.${encodeURIComponent(subscriptionId)}`,
    );

    return updated as Record<string, unknown>;
  }

  async updateSubscriptionField(
    subscriptionId: string,
    data: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    if (!subscriptionId) throw new Error("Subscription ID required");

    const allowed = new Set([
      "plan_id", "plan_code", "plan_type", "plan_amount", "billing_cycle",
      "features", "razorpay_order_id", "razorpay_payment_id",
      "subscription_start_date", "subscription_end_date", "auto_renew",
      "receipt_url", "seat_count", "metadata",
    ]);

    const updateData: Record<string, unknown> = { updated_at: new Date().toISOString() };
    for (const [key, value] of Object.entries(data)) {
      if (allowed.has(key)) updateData[key] = value;
    }

    const database = db(this.env);
    await database.update("subscriptions", { id: `eq.${encodeURIComponent(subscriptionId)}` }, updateData);

    const updated = await database.queryOne(`subscriptions?id=eq.${encodeURIComponent(subscriptionId)}`);
    return updated as Record<string, unknown>;
  }

  // ── Transactions ──────────────────────────────────────────────

  async recordTransaction(data: {
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
    failure_reason?: string;
    product_id?: string;
    organization_id?: string;
    organization_type?: string;
    seat_count?: number;
    is_bulk_purchase?: boolean;
    receipt?: string;
    receipt_url?: string;
    notes?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    if (!data.user_id || data.amount === undefined || !data.status) {
      throw new Error("user_id, amount, and status are required");
    }

    const database = db(this.env);

    let productId = data.product_id;
    if (!productId && data.subscription_id) {
      const subRow = await database.queryOne<{ product_id: string | null; plan_id: string | null }>(
        `subscriptions?id=eq.${encodeURIComponent(data.subscription_id)}&select=product_id,plan_id`,
      );
      productId = subRow?.product_id ?? undefined;
      if (!productId && subRow?.plan_id) {
        const plan = await database.queryOne<{ product_id: string | null }>(
          `plans?id=eq.${encodeURIComponent(subRow.plan_id)}&select=product_id`,
        );
        productId = plan?.product_id ?? undefined;
      }
    }

    const transaction = await database.mutate("transactions", {
      subscription_id: data.subscription_id || null,
      user_id: data.user_id,
      razorpay_order_id: data.razorpay_order_id || null,
      razorpay_payment_id: data.razorpay_payment_id || null,
      razorpay_signature: data.razorpay_signature || null,
      amount: data.amount,
      currency: data.currency || "INR",
      status: data.status,
      transaction_type: data.transaction_type || "subscription",
      payment_method: data.payment_method || null,
      failure_reason: data.failure_reason || null,
      product_id: productId || null,
      organization_id: data.organization_id || null,
      organization_type: data.organization_type || null,
      seat_count: data.seat_count || 1,
      is_bulk_purchase: data.is_bulk_purchase || false,
      receipt: data.receipt || null,
      receipt_url: data.receipt_url || null,
      notes: data.notes || {},
      metadata: data.metadata || {},
    });

    return transaction as Record<string, unknown>;
  }

  async getUserTransactions(userId: string, subscriptionId?: string): Promise<Record<string, unknown>[]> {
    if (!userId) throw new Error("user_id is required");

    const database = db(this.env);
    let query = `transactions?user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc`;
    if (subscriptionId) {
      query += `&subscription_id=eq.${encodeURIComponent(subscriptionId)}`;
    }

    const transactions = await database.query(query);
    return (transactions || []) as Record<string, unknown>[];
  }

  // ── Sync Operations ───────────────────────────────────────────

  async syncSubscription(userId: string): Promise<{
    subscription: Record<string, unknown> | null;
    plan: Record<string, unknown> | null;
  }> {
    if (!userId) throw new Error("user_id is required");

    const database = db(this.env);
    const subscription = await database.queryOne(
      `subscriptions?user_id=eq.${encodeURIComponent(userId)}&status=in.(active,pending)&order=created_at.desc`,
    );

    if (!subscription) {
      return { subscription: null, plan: null };
    }

    const plan = await database.queryOne(
      `plans?id=eq.${encodeURIComponent(subscription.plan_id)}`,
    );

    return { subscription: subscription as Record<string, unknown>, plan: plan as Record<string, unknown> };
  }

  async syncPlans(): Promise<{ plans: Record<string, unknown>[] }> {
    const database = db(this.env);
    const plans = await database.query(
      "plans?is_active=eq.true&order=display_order.asc",
    );
    return { plans: (plans || []) as Record<string, unknown>[] };
  }

  /**
   * List the canonical authorization roles (single source of truth).
   *
   * Mirrors {@link syncPlans}: read-only pull of `public.roles` used by the
   * skillpassport app DB to keep its read-only `roles` shadow in sync
   * (`functions/lib/sync-shadow.ts` → `syncRolesShadow`). Called by the
   * skillpassport scheduled reconcile and on-demand cache-miss refresh.
   *
   * The shadow is NOT an authorization source — Cloudflare Functions enforce
   * authz from the verified JWT; this list only mirrors role metadata for the
   * app-side type generator (task 18) and reference data (task 17).
   *
   * @returns `{ roles }` — each role's `id`, `name`, and `description`.
   */
  async listRoles(): Promise<{
    roles: { id: string; name: string; description: string | null }[];
  }> {
    const database = db(this.env);
    const roles = await database.query<{ id: string; name: string; description: string | null }>(
      "roles?select=id,name,description&order=name.asc",
    );
    return { roles: (roles || []) as { id: string; name: string; description: string | null }[] };
  }

  async syncReconcile(userIds: string[]): Promise<{ subscriptions: Record<string, unknown>[] }> {
    if (!userIds || !Array.isArray(userIds)) {
      throw new Error("user_ids array is required");
    }

    const database = db(this.env);
    const userIdList = userIds.map((id) => encodeURIComponent(id)).join(",");
    const subscriptions = await database.query(
      `subscriptions?user_id=in.(${userIdList})&status=in.(active,pending)&order=created_at.desc`,
    );

    return { subscriptions: (subscriptions || []) as Record<string, unknown>[] };
  }

  // ── Addon / Bundle Purchase Recording ─────────────────────────

  async recordAddonPurchase(data: {
    user_id: string;
    feature_key: string;
    billing_period: string;
    price_at_purchase: number;
    razorpay_order_id?: string;
    razorpay_payment_id?: string;
    razorpay_signature?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<Record<string, unknown>> {
    if (!data.user_id || !data.feature_key || !data.billing_period || data.price_at_purchase === undefined) {
      throw new Error("user_id, feature_key, billing_period, and price_at_purchase are required");
    }

    const database = db(this.env);
    const addon = await database.queryOne(
      `addon_catalog?feature_key=eq.${encodeURIComponent(data.feature_key)}`,
    );

    if (!addon) {
      throw new Error(`Addon not found for feature_key: ${data.feature_key}`);
    }

    const now = new Date();
    const endDate = data.billing_period === "annual"
      ? addMonths(now, 12)
      : addMonths(now, 1);

    const purchase = await database.mutate("addon_purchases", {
      user_id: data.user_id,
      product_id: addon?.product_id || null,
      feature_key: data.feature_key,
      billing_period: data.billing_period,
      price_at_purchase: data.price_at_purchase,
      razorpay_order_id: data.razorpay_order_id || null,
      razorpay_payment_id: data.razorpay_payment_id || null,
      razorpay_signature: data.razorpay_signature || null,
      status: "active",
      start_date: data.start_date || now.toISOString(),
      end_date: data.end_date || endDate.toISOString(),
    });

    return purchase as Record<string, unknown>;
  }

  async recordBundlePurchase(data: {
    user_id: string;
    bundle_id: string;
    billing_period: string;
    price_at_purchase: number;
    discount_applied?: number;
    razorpay_order_id?: string;
    razorpay_payment_id?: string;
    razorpay_signature?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<Record<string, unknown>> {
    if (!data.user_id || !data.bundle_id || !data.billing_period || data.price_at_purchase === undefined) {
      throw new Error("user_id, bundle_id, billing_period, and price_at_purchase are required");
    }

    const database = db(this.env);
    const bundle = await database.queryOne(
      `bundles?id=eq.${encodeURIComponent(data.bundle_id)}`,
    );

    if (!bundle) {
      throw new Error("Bundle not found");
    }

    const now = new Date();
    const endDate = data.billing_period === "annual"
      ? addMonths(now, 12)
      : addMonths(now, 1);

    const purchase = await database.mutate("bundle_purchases", {
      user_id: data.user_id,
      product_id: bundle.product_id || null,
      bundle_id: data.bundle_id,
      billing_period: data.billing_period,
      price_at_purchase: data.price_at_purchase,
      discount_applied: data.discount_applied || bundle.discount_percentage || 0,
      razorpay_order_id: data.razorpay_order_id || null,
      razorpay_payment_id: data.razorpay_payment_id || null,
      razorpay_signature: data.razorpay_signature || null,
      status: "active",
      start_date: data.start_date || now.toISOString(),
      end_date: data.end_date || endDate.toISOString(),
    });

    return purchase as Record<string, unknown>;
  }

  // ── Membership Sync ─────────────────────────────────────────

  async getUserMemberships(userId: string): Promise<{
    memberships: { id: string; org_id: string; role: string; status: string }[];
  }> {
    if (!userId) throw new Error("userId is required");
    const database = db(this.env);

    const rows = await database.query<{
      id: string;
      org_id: string;
      status: string;
      membership_roles?: { roles?: { name: string } }[];
    }>(`memberships?user_id=eq.${encodeURIComponent(userId)}&select=id,org_id,status,membership_roles(roles(name))`);

    return {
      memberships: (rows || []).map((r) => {
        const mrole = r.membership_roles?.[0]?.roles;
        return {
          id: r.id,
          org_id: r.org_id,
          status: r.status,
          role: mrole?.name || "member",
        };
      }),
    };
  }

  // ── User Lookup ──────────────────────────────────────────────

  /**
   * Look up a user by their email address.
   * Queries the SSO database's `users` table.
   * Returns user info or null if not found.
   */
  async getUserByEmail(email: string): Promise<{ id: string; email: string; is_email_verified: boolean } | null> {
    if (!email) throw new Error("email is required");
    const database = db(this.env);
    const normalized = email.toLowerCase().trim();

    const users = await database.query<{ id: string; email: string; is_email_verified: boolean }>(
      `users?email=eq.${encodeURIComponent(normalized)}&select=id,email,is_email_verified`,
    );

    return users && users.length > 0 ? users[0] : null;
  }

  // ── Membership RPC Methods ────────────────────────────────────

  async createMembership(data: {
    user_id: string;
    org_id: string;
    status: string;
  }): Promise<{ id: string; status: string }> {
    return performCreateMembership(this.env, data);
  }

  async updateMembershipStatus(data: {
    membership_id: string;
    status: string;
  }): Promise<{ success: boolean }> {
    return performUpdateMembershipStatus(this.env, data);
  }

  async assignMembershipRole(data: {
    membership_id: string;
    role_id: string;
  }): Promise<{ success: boolean }> {
    return performAssignMembershipRole(this.env, data);
  }

  // ── Organization RPC Methods ──────────────────────────────────

  async createOrganization(data: {
    name: string;
    slug: string;
    created_by: string;
    metadata?: Record<string, unknown>;
  }): Promise<{ success: boolean; org_id?: string; error?: string }> {
    return performCreateOrganization(this.env, data);
  }

  async updateOrganization(data: {
    id: string;
    name: string;
  }): Promise<{ success: boolean }> {
    return performUpdateOrganization(this.env, data);
  }

  async updateOrganizationDetails(data: {
    id: string;
    metadata: Record<string, unknown>;
  }): Promise<{ success: boolean; error?: string }> {
    return performUpdateOrganizationDetails(this.env, data);
  }

  // ── Learner Admission RPC Methods ─────────────────────────────

  async createLearnerUser(data: {
    email: string;
    name: string;
    organization_id: string;
    contact_number?: string;
    enrollment_number?: string;
    program_id?: string;
    metadata?: Record<string, unknown>;
  }): Promise<{ success: boolean; user_id?: string; temp_password?: string; error?: string; sync_warning?: string }> {
    return performCreateLearnerUser(this.env, data);
  }

  async queueBulkLearnerUpload(data: {
    csv_data: string;
    organization_id: string;
    admin_id: string;
  }): Promise<{ success: boolean; batch_id?: string; error?: string }> {
    return performQueueBulkLearnerUpload(this.env, data);
  }

  async getBulkUploadStatus(batchId: string): Promise<BatchMetadata | null> {
    if (!batchId) {
      throw new Error('batchId is required');
    }
    try {
      const result = await getBatch(this.env, batchId);
      return result;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[SSO] getBulkUploadStatus error for ${batchId}:`, msg);
      return null;
    }
  }

  // ── Auth RPC Methods ──────────────────────────────────────────

  async getJWKS(): Promise<{ keys: Record<string, unknown>[] }> {
    const keys = [await getPublicJWK(this.env)];
    if (this.env.JWT_PUBLIC_KEY_PREVIOUS && this.env.JWT_KID_PREVIOUS) {
      try {
        const prevJwk = await exportPemAsJwk(this.env.JWT_PUBLIC_KEY_PREVIOUS, this.env.JWT_KID_PREVIOUS);
        keys.push(prevJwk);
      } catch (err) {
        console.warn("[SSO] Failed to export previous JWKS key:", err);
      }
    }
    return { keys };
  }

  /**
   * Signup RPC - creates user, org, membership
   * Called by skillpassport via RPC
   */
  async signup(params: {
    email: string;
    password: string;
    org_name: string;
    role: string;
    redirect_url?: string;
    ip?: string;
    ua?: string;
  }): Promise<any> {
    const { performSignup } = await import("./routes/signup");

    try {
      const result = await performSignup(
        this.env,
        this.ctx,
        params,
        params.ip,
        params.ua
      );

      if (result.error) {
        return { success: false, error: result.error, status: result.status ?? 400 };
      }

      return {
        success: true,
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        user: result.user,
        org: result.org,
        email_sent: result.email_sent
      };
    } catch (err: unknown) {
      const errMessage = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        error: errMessage || 'Signup failed',
        status: 500
      };
    }
  }

  /**
   * Request verification email RPC
   * Called by skillpassport via RPC
   */
  async requestVerification(params: {
    user_id: string;
    email: string;
    redirect_url?: string;
    org_id?: string;
  }): Promise<{ message?: string; already_verified?: boolean }> {
    const { performRequestVerification } = await import('./routes/verify-email');
    const result = await performRequestVerification(
      this.env,
      this.ctx,
      params
    );

    if (result.error) {
      throw new Error(result.error);
    }

    return result;
  }

  /**
   * Verify email RPC
   * Called by skillpassport via RPC
   */
  async verifyEmail(params: {
    token: string;
    ip?: string;
    ua?: string;
  }): Promise<{ success: false; error: string } | { success: true; verified?: boolean }> {
    const { performVerifyEmail } = await import('./routes/verify-email');
    const result = await performVerifyEmail(
      this.env,
      this.ctx,
      { token: params.token },
      params.ip || null,
      params.ua || null
    );

    if (result.error) {
      return { success: false, error: result.error };
    }

    return { success: true, verified: result.verified };
  }

  /**
   * Delete account RPC
   * Called by skillpassport via RPC
   */
  async deleteAccount(params: {
    user_id: string;
    org_id?: string;
    ip?: string;
    ua?: string;
  }): Promise<{ success: true; deleted?: boolean }> {
    const { performDeleteAccount } = await import('./routes/delete-account');
    const result = await performDeleteAccount(
      this.env,
      this.ctx,
      {
        user_id: params.user_id,
        org_id: params.org_id,
      },
      params.ip || null,
      params.ua || null
    );

    if (result.error) {
      throw new Error(result.error);
    }

    return { success: true, deleted: result.deleted };
  }

  /**
   * Change password RPC
   * Called by skillpassport via RPC
   */
  async changePassword(params: {
    user_id: string;
    current_password: string;
    new_password: string;
    org_id?: string;
    ip?: string;
    ua?: string;
  }): Promise<{ success: true; message?: string }> {
    const { performChangePassword } = await import('./routes/change-password');
    const result = await performChangePassword(
      this.env,
      this.ctx,
      {
        user_id: params.user_id,
        current_password: params.current_password,
        new_password: params.new_password,
        org_id: params.org_id,
      },
      params.ip || null,
      params.ua || null
    );

    if (result.error) {
      throw new Error(result.error);
    }

    return { success: true, message: result.message };
  }

  /**
   * Admin reset password RPC
   * Called by skillpassport via RPC
   */
  async adminResetPassword(params: {
    admin_user_id: string;
    admin_roles: string[];
    admin_org_id?: string;
    target_user_id: string;
    new_password: string;
    ip?: string;
    ua?: string;
  }): Promise<{ success: true; message?: string }> {
    const { performAdminResetPassword } = await import('./routes/change-password');
    const result = await performAdminResetPassword(
      this.env,
      this.ctx,
      {
        admin_user_id: params.admin_user_id,
        admin_roles: params.admin_roles,
        admin_org_id: params.admin_org_id,
        target_user_id: params.target_user_id,
        new_password: params.new_password,
      },
      params.ip || null,
      params.ua || null
    );

    if (result.error) {
      throw new Error(result.error);
    }

    return { success: true, message: result.message };
  }

  /**
   * Signup member RPC
   * Called by skillpassport via RPC
   */
  async signupMember(params: SignupMemberBody & { ip?: string; ua?: string }): Promise<any> {
    const { performSignupMember } = await import('./routes/signup-member');
    const result = await performSignupMember(this.env, this.ctx, params);

    if (result.error) {
      return { success: false, error: result.error, status: result.status };
    }

    return { success: true, ...result };
  }

  /**
   * Log in user via true RPC.
   *
   * @param params Object containing email, password, ip, ua
   * @returns Successful login payload or throws error
   */
  async login(params: { email?: string; password?: string; ip?: string; ua?: string }): Promise<any> {
    const { performLogin } = await import("./routes/login");
    const result = await performLogin(
      this.env,
      this.ctx,
      { email: params.email ?? "", password: params.password ?? "" },
      params.ip ?? null,
      params.ua ?? null
    );

    // If error exists, return failure response
    if (result.error) {
      return { success: false, error: result.error, status: result.status ?? 401 };
    }

    // Return success response with all login data
    return {
      success: true,
      access_token: result.access_token,
      refresh_token: result.refresh_token,
      user: result.user,
      active_org_id: result.active_org_id,
      organizations: result.organizations
    };
  }

  /**
   * RPC entry point for refresh-token rotation, callable via service binding.
   *
   * Thin adapter over the shared rotation module
   * (`lib/session-rotation.ts::rotateRefreshToken`). Accepts the presented
   * refresh token plus optional IP/UA context, delegates rotation logic to the
   * shared module, then translates the `RotationOutcome` into the RPC return
   * shape `{ access_token, refresh_token }` or throws errors.
   *
   * The behavioral contract (what succeeds, what fails) is now identical to the
   * `POST /auth/refresh` HTTP route because both call the same shared module
   * (Requirement 4.2, Property 7).
   *
   * @param refreshToken The opaque refresh token presented by the caller.
   * @param ip Optional client IP address forwarded from auth-core.
   * @param ua Optional User-Agent forwarded from auth-core.
   * @returns `{ access_token, refresh_token }` on successful rotation or
   *   benign overlap.
   * @throws Error on invalid, revoked (theft), lifetime-exceeded, or
   *   session-expired outcomes, preserving the existing failure contract so
   *   auth-core's consumers continue to work.
   */
  async refreshSession(refreshToken: string, ip?: string, ua?: string): Promise<{ access_token: string, refresh_token: string }> {
    if (!refreshToken) throw new Error("No refresh token provided");

    // Build rotation context from ip/ua arguments (Requirement 4.3, task 4.3).
    const rotationCtx = { ip: ip ?? null, ua: ua ?? null };

    // Delegate to the shared rotation module (Requirement 4.1).
    const outcome = await rotateRefreshToken(this.env, this.ctx, refreshToken, rotationCtx);

    // Translate RotationOutcome into RPC return shape or throw (Requirement 4.3).
    switch (outcome.kind) {
      case "rotated":
      case "overlap":
        // Success outcomes: return the pair. Both "rotated" and "overlap" produce
        // a valid access+refresh token pair; the RPC caller does not distinguish.
        return {
          access_token: outcome.accessToken,
          refresh_token: outcome.refreshToken,
        };

      case "theft":
        // Family-scoped revocation already performed by rotateRefreshToken.
        // Throw the same error message as the old inline logic so auth-core
        // consumers see consistent behavior.
        throw new Error("Refresh token reuse detected. All sessions revoked.");

      case "blocked":
        // Account blocked.
        throw new Error("Account is blocked");

      case "expired_lifetime":
        // Absolute session lifetime exceeded (Requirement 5.2).
        throw new Error("Session expired");

      case "session_expired":
        // Per-token TTL expiry.
        throw new Error("Session expired");

      case "invalid":
        // Missing session row, unresolvable token, or user deleted mid-rotation.
        throw new Error("Invalid refresh token");

      default: {
        // Compile-time guard: if RotationOutcome ever gains a new "kind", this
        // line fails to typecheck until it's handled explicitly above.
        const _exhaustive: never = outcome;
        throw new Error("Invalid refresh token");
      }
    }
  }

  async validateSession(refreshToken: string): Promise<{ valid: boolean; roles: string[] }> {
    if (!refreshToken) return { valid: false, roles: [] };

    const database = db(this.env);
    const tokenHash = await hashToken(refreshToken);

    const session = await database.queryOne<{ user_id: string; org_id: string | null; expires_at: string }>(
      `sessions?refresh_token_hash=eq.${encodeURIComponent(tokenHash)}&revoked=eq.false&select=user_id,org_id,expires_at`
    );

    if (!session) {
      return { valid: false, roles: [] };
    }

    if (new Date(session.expires_at) < new Date()) {
      return { valid: false, roles: [] };
    }

    const user = await database.queryOne<{ is_blocked: boolean }>(
      `users?id=eq.${encodeURIComponent(session.user_id)}&select=is_blocked`
    );

    if (!user || user.is_blocked) {
      return { valid: false, roles: [] };
    }

    const claims = await database.rpc<{ roles: string[] }>("get_jwt_claims", {
      p_user_id: session.user_id,
      p_org_id: session.org_id,
    });

    return { valid: true, roles: claims?.roles ?? [] };
  }

  async authenticateSharedSession(
    refreshToken: string,
    targetApp: string,
    _ip?: string,
    _ua?: string,
  ): Promise<{ success: boolean; access_token?: string; refresh_token?: string; error?: string }> {
    if (!refreshToken) {
      return { success: false, error: "No refresh token provided" };
    }

    const database = db(this.env);
    let activeToken = refreshToken;
    const tokenHash = await hashToken(activeToken);

    let session = await database.queryOne<Session>(
      `sessions?refresh_token_hash=eq.${encodeURIComponent(tokenHash)}&select=id,user_id,org_id,expires_at,revoked,family_id`,
    );

    // If no direct session or session is revoked, check if token was rotated within KV grace window
    if ((!session || session.revoked) && this.env.RATE_LIMIT_KV) {
      try {
        const replacementToken = await this.env.RATE_LIMIT_KV.get(`grace:${tokenHash}`);
        if (replacementToken) {
          const replacementHash = await hashToken(replacementToken);
          const activeSession = await database.queryOne<Session>(
            `sessions?refresh_token_hash=eq.${encodeURIComponent(replacementHash)}&revoked=eq.false&select=id,user_id,org_id,expires_at,revoked,family_id`,
          );
          if (activeSession) {
            session = activeSession;
            activeToken = replacementToken;
          }
        }
      } catch (kvErr) {
        console.warn("[SSO] KV grace resolution failed:", kvErr);
      }
    }

    // Fallback: If session was marked revoked, resolve latest unrevoked session in family
    if (session?.revoked && session.family_id) {
      const activeSession = await database.queryOne<Session>(
        `sessions?family_id=eq.${encodeURIComponent(session.family_id)}&revoked=eq.false&order=created_at.desc&limit=1&select=id,user_id,org_id,expires_at,revoked,family_id`,
      );
      if (activeSession) {
        session = activeSession;
      }
    }

    if (!session || session.revoked) {
      console.log("[SSO] Shared session is invalid or revoked for app:", targetApp);
      return { success: false, error: "Invalid or revoked session" };
    }

    if (new Date(session.expires_at) < new Date()) {
      return { success: false, error: "Session expired" };
    }

    const result = await mintAccessToken(database, this.env, session.user_id, session.org_id);

    if (result === "blocked") return { success: false, error: "Account is blocked" };
    if (result === "not_found") return { success: false, error: "User not found" };
    if (!result || typeof result !== "object") {
      return { success: false, error: "Failed to mint access token" };
    }

    const payload = await verifyAccessToken(result.token, this.env);
    if (!payload.products.includes(targetApp) && targetApp !== "sso") {
      return { success: false, error: `Access denied for product: ${targetApp}` };
    }

    // Always include user_metadata so app clients can normalize a stable user shape.
    return {
      success: true,
      access_token: result.token,
      refresh_token: activeToken,
    };
  }

  async getMe(accessToken: string): Promise<Record<string, unknown>> {
    if (!accessToken) throw new Error("No access token provided");
    let payload: AccessTokenPayload;
    try {
      payload = await verifyAccessToken(accessToken, this.env);
    } catch {
      throw new Error("Invalid or expired access token");
    }
    return {
      sub: payload.sub,
      email: payload.email,
      org_id: payload.org_id,
      roles: payload.roles,
      products: payload.products,
      membership_status: payload.membership_status,
      is_email_verified: payload.is_email_verified,
      user_metadata: payload.user_metadata ?? {},
    };
  }

  async generateAuthorizationCode(
    params: GenerateAuthorizationCodeRequest,
  ): Promise<GenerateAuthorizationCodeResponse> {
    if (!params.accessToken) {
      throw new Error("No access token provided");
    }

    assertTargetApp(params.targetApp);
    assertAllowedRedirectUri(params.redirectUri, this.env);

    let payload: AccessTokenPayload;
    try {
      payload = await verifyAccessToken(params.accessToken, this.env);
    } catch {
      throw new Error("Invalid or expired access token");
    }

    await requireLteEntitlement(this.env, payload);

    const generated = await createAuthorizationCode(params.redirectUri);
    const stub = getAuthorizationCodeStub(this.env, generated.codeHash);
    const now = Date.now();

    try {
      await stub.store({
        codeHash: generated.codeHash,
        stateHash: generated.stateHash,
        userId: payload.sub,
        orgId: payload.org_id,
        targetApp: "lte",
        redirectUri: params.redirectUri,
        expiresAt: Date.parse(generated.expiresAt),
        createdAt: now,
      });
    } catch (err) {
      throw new Error(`Failed to store authorization code: ${err instanceof Error ? err.message : String(err)}`);
    }

    audit(this.ctx, this.env, "authorization_code.generated", {
      user_id: payload.sub,
      org_id: payload.org_id,
      ip_address: params.ip,
      user_agent: params.ua,
      metadata: { target_app: "lte", redirect_uri: params.redirectUri },
    });

    return {
      code: generated.code,
      state: generated.state,
      redirectUrl: generated.redirectUrl,
      codeExpiresAt: generated.expiresAt,
    };
  }

  async exchangeAuthorizationCode(
    params: ExchangeAuthorizationCodeRequest,
  ): Promise<ExchangeAuthorizationCodeResponse> {
    if (!params.code || !params.state) {
      throw new Error("Authorization code and state are required");
    }

    assertTargetApp(params.targetApp);
    assertAllowedRedirectUri(params.redirectUri, this.env);

    const [codeHash, stateHash] = await Promise.all([
      hashAuthorizationValue(params.code),
      hashAuthorizationValue(params.state),
    ]);
    const stub = getAuthorizationCodeStub(this.env, codeHash);
    let consumeResult;
    try {
      consumeResult = await stub.consume({
        codeHash,
        stateHash,
        redirectUri: params.redirectUri,
        now: Date.now(),
      });
    } catch (err) {
      throw new Error(`Failed to consume authorization code: ${err instanceof Error ? err.message : String(err)}`);
    }

    if (!consumeResult.success) {
      const reason = consumeResult.reason || "unknown";
      audit(this.ctx, this.env, "authorization_code.exchange_failed", {
        ip_address: params.ip,
        user_agent: params.ua,
        metadata: { target_app: "lte", reason },
      });
      throw new Error(`Authorization code exchange failed: ${reason}`);
    }

    const record = consumeResult.record;
    if (record.targetApp !== "lte") {
      throw new Error("Authorization code target app mismatch");
    }

    const entitlement = await requireLteEntitlement(this.env, {
      sub: record.userId,
      org_id: record.orgId,
    });
    if (!entitlement) {
      throw new Error("Failed to resolve LTE entitlement");
    }

    const refreshToken = generateRefreshToken();
    const refreshHash = await hashToken(refreshToken);
    const sessionId = crypto.randomUUID();
    const now = new Date().toISOString();

    await db(this.env).mutate("sessions", {
      id: sessionId,
      user_id: record.userId,
      org_id: record.orgId,
      refresh_token_hash: refreshHash,
      user_agent: params.ua,
      ip_address: params.ip,
      revoked: false,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      family_id: sessionId,
      family_created_at: now,
      device_info: { app: "lte" },
    });

    const claims: JwtClaims = entitlement.claims;
    const lteProducts = claims.products.includes("lte") ? claims.products : [...claims.products, "lte"];
    const accessToken = await signLteAccessToken(
      {
        sub: record.userId,
        email: entitlement.user.email,
        org_id: record.orgId,
        roles: claims.roles,
        products: lteProducts,
        membership_status: claims.membership_status,
        is_email_verified: entitlement.user.is_email_verified,
        user_metadata: entitlement.user.user_metadata ?? {},
      },
      this.env,
    );

    let subscription = null;
    try {
      subscription = await getLteSubscriptionSnapshot(this.env, record.userId);
    } catch (err) {
      console.warn("[SSO] Failed to fetch LTE subscription snapshot:", err);
    }

    audit(this.ctx, this.env, "authorization_code.exchanged", {
      user_id: record.userId,
      org_id: record.orgId,
      ip_address: params.ip,
      user_agent: params.ua,
      metadata: { target_app: "lte", session_id: sessionId },
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: {
        sub: record.userId,
        email: entitlement.user.email,
        org_id: record.orgId,
        roles: claims.roles,
        products: lteProducts,
        membership_status: claims.membership_status,
        is_email_verified: entitlement.user.is_email_verified,
        user_metadata: entitlement.user.user_metadata ?? {},
      },
      subscription,
      expires_in: 900,
    };
  }

  async listOrgs(accessToken: string): Promise<any> {
    if (!accessToken) throw new Error("No access token provided");

    let payload: AccessTokenPayload;
    try {
      payload = await verifyAccessToken(accessToken, this.env);
    } catch {
      throw new Error("Invalid or expired access token");
    }

    const database = db(this.env);

    // Only active memberships
    const memberships = await database.query<Membership>(
      `memberships?user_id=eq.${encodeURIComponent(payload.sub)}&status=eq.active&select=*&order=created_at.asc`,
    );

    const orgIds = memberships.map((m) => m.org_id);
    const orgs = orgIds.length
      ? await database.query<Organization>(
        `organizations?id=in.(${orgIds.map(id => encodeURIComponent(id)).join(",")})&select=*`,
      )
      : [];

    const orgMap = new Map(orgs.map((o) => [o.id, o]));

    // Fetch roles for each membership via join table
    const membershipIds = memberships.map((m) => m.id);
    const roleRows = membershipIds.length
      ? await database.query<{ membership_id: string; role_id: { name: string } | null }>(
        `membership_roles?membership_id=in.(${membershipIds.map(id => encodeURIComponent(id)).join(",")})&select=membership_id,role_id(name)`,
      )
      : [];

    // PostgREST returns nested objects for FK selects — flatten
    const roleMap = new Map<string, string[]>();
    for (const row of roleRows) {
      if (!row.role_id) continue;

      const mid = row.membership_id;
      let roles = roleMap.get(mid);
      if (!roles) {
        roles = [];
        roleMap.set(mid, roles);
      }
      roles.push(row.role_id.name);
    }

    return {
      organizations: memberships.map((m) => ({
        org_id: m.org_id,
        roles: roleMap.get(m.id) ?? [],
        name: orgMap.get(m.org_id)?.name ?? null,
        slug: orgMap.get(m.org_id)?.slug ?? null,
        is_active: m.org_id === payload.org_id,
      })),
    };
  }

  async switchOrg(params: { access_token?: string; org_id?: string; ip?: string; ua?: string }): Promise<{ access_token: string; org_id: string; roles: string[]; refresh_token?: string }> {
    if (!params.access_token || !params.org_id) {
      throw new Error("access_token and org_id are required");
    }

    let payload: AccessTokenPayload;
    try {
      payload = await verifyAccessToken(params.access_token, this.env);
    } catch {
      throw new Error("Invalid or expired access token");
    }

    const database = db(this.env);
    const rateLimited = await endpointRateLimit(this.env, `switch-org:user:${payload.sub}`, 30, 60);
    if (rateLimited) throw new Error("Rate limit exceeded");

    // Verify ACTIVE membership in target org and check if user is blocked
    const [membership, user] = await Promise.all([
      database.queryOne<Membership>(
        `memberships?user_id=eq.${encodeURIComponent(payload.sub)}&org_id=eq.${encodeURIComponent(params.org_id)}&status=eq.active&select=*`,
      ),
      database.queryOne<{ is_blocked: boolean }>(
        `users?id=eq.${encodeURIComponent(payload.sub)}&select=is_blocked`,
      )
    ]);

    if (user?.is_blocked) {
      throw new Error("Account is blocked");
    }

    if (!membership) {
      throw new Error("You are not an active member of this organization");
    }

    // Revoke old session and create new one
    const familyId = crypto.randomUUID();
    const familyCreatedAt = new Date().toISOString();

    // Get RBAC claims for the target org
    const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
      p_user_id: payload.sub,
      p_org_id: params.org_id,
    });

    if (!claims) {
      throw new Error("Failed to resolve membership claims");
    }

    const refreshToken = generateRefreshToken();
    const refreshHash = await hashToken(refreshToken);
    const sessionId = crypto.randomUUID();

    await database.mutate("sessions", {
      id: sessionId,
      user_id: payload.sub,
      org_id: params.org_id,
      refresh_token_hash: refreshHash,
      user_agent: params.ua,
      ip_address: params.ip,
      revoked: false,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      family_id: familyId,
      family_created_at: familyCreatedAt,
    });

    const accessToken = await signAccessToken(
      {
        sub: payload.sub,
        email: payload.email,
        org_id: params.org_id,
        roles: claims.roles,
        products: claims.products,
        membership_status: claims.membership_status,
        is_email_verified: payload.is_email_verified,
        user_metadata: payload.user_metadata ?? {},
      },
      this.env,
    );

    audit(this.ctx, this.env, "switch_org", {
      user_id: payload.sub,
      org_id: params.org_id,
      ip_address: params.ip,
      user_agent: params.ua,
      metadata: { from_org: payload.org_id, to_org: params.org_id },
    });

    return {
      access_token: accessToken,
      org_id: params.org_id,
      roles: claims.roles,
      refresh_token: refreshToken,
    };
  }

  async forgotPassword(
    params: { email?: string; redirect_url?: string },
    ip?: string,
    ua?: string,
  ): Promise<{ success: boolean; message?: string; error?: string }> {
    const { performForgotPassword } = await import("./routes/password-reset");
    const result = await performForgotPassword(
      this.env,
      this.ctx,
      { email: params.email, redirect_url: params.redirect_url },
      ip ?? "unknown",
      ua ?? null
    );

    if (result.error) {
      return { success: false, error: result.error };
    }

    const message =
      result.message ?? "If an account exists, a reset email has been sent.";

    return { success: true, message };
  }

  async resetPassword(params: { token?: string; password?: string }, ip?: string, ua?: string): Promise<{ success: false; error: string } | { success: true; reset: boolean }> {
    const { performResetPassword } = await import("./routes/password-reset");
    const result = await performResetPassword(
      this.env,
      this.ctx,
      { token: params.token, password: params.password },
      ip ?? null,
      ua ?? null
    );

    if (result.error) {
      return { success: false, error: result.error };
    }

    const reset = result.reset ?? true;

    return { success: true, reset };
  }

  async listAddonCatalog(params?: { category?: string; role?: string; product?: string }): Promise<any> {
    const { performListAddonCatalog } = await import("./routes/addon-catalog");
    return performListAddonCatalog(this.env, params);
  }

  async getAddonByFeatureKey(featureKey: string): Promise<any> {
    const { performGetAddonByFeatureKey } = await import("./routes/addon-catalog");
    const result = await performGetAddonByFeatureKey(this.env, featureKey);

    if (result.error) {
      throw new Error(result.error);
    }

    return result;
  }

  async listBundles(params?: { role?: string }): Promise<any> {
    const { performListBundles } = await import("./routes/addon-catalog");
    return performListBundles(this.env, params);
  }

  async logoutSession(refreshToken: string, ip?: string, ua?: string): Promise<{ success: boolean }> {
    if (!refreshToken) return { success: true };

    const database = db(this.env);
    const tokenHash = await hashToken(refreshToken);

    const session = await database.queryOne<Session>(
      `sessions?refresh_token_hash=eq.${encodeURIComponent(tokenHash)}&select=user_id,org_id,family_id`,
    );

    if (session) {
      // Global SSO logout: revoke all sessions for this user across all apps
      // WARNING: this revokes every active session for the user, not only the presented refresh token.
      await database.update(
        "sessions",
        { user_id: `eq.${encodeURIComponent(session.user_id)}` },
        { revoked: true },
      ).catch((err) => {
        console.warn("[SSO] User sessions revocation failed on logout:", err);
      });

      audit(this.ctx, this.env, "logout", {
        user_id: session.user_id,
        org_id: session.org_id,
        ip_address: ip || null,
        user_agent: ua || null,
        metadata: { global_logout: true, family_id: session.family_id },
      });
    }

    return { success: true };
  }

  // ── Invite Management RPC Methods ─────────────────────────────

  /**
   * Create an invite for a user to join an organization.
   * Sends an invite email with a token that expires in 7 days.
   */
  async createInvite(params: {
    email: string;
    org_id: string;
    role: string[];
    redirect_url?: string;
    caller: AccessTokenPayload;
    ip?: string;
    ua?: string;
  }): Promise<{ invite_id: string; email: string; expires_at: string }> {
    if (!params.email || !params.org_id || !params.role || !params.caller) {
      throw new Error("email, org_id, role, and caller are required");
    }

    const emailErr = validateEmail(params.email);
    if (emailErr) throw new Error(await emailErr.text());

    const redirectErr = validateRedirectUrl(params.redirect_url, this.env);
    if (redirectErr) throw new Error(await redirectErr.text());

    const database = db(this.env);
    const inviteEmailAddress = params.email.toLowerCase().trim();

    // Check for existing pending invite
    const existing = await database.queryOne<{ id: string }>(
      `invites?email=eq.${encodeURIComponent(inviteEmailAddress)}&org_id=eq.${encodeURIComponent(params.org_id)}&accepted=eq.false&select=id`,
    );
    if (existing) {
      throw new Error("An invite for this email already exists");
    }

    const throttled = await checkEmailThrottle(this.env, "invite", params.org_id);
    if (throttled) throw new Error("Too many invite requests. Please try again later.");

    const inviteToken = crypto.randomUUID();
    const inviteTokenHash = await hashToken(inviteToken);
    const invite = await database.mutate<Invite>("invites", {
      email: inviteEmailAddress,
      org_id: params.org_id,
      role: params.role,
      token_hash: inviteTokenHash,
      invited_by: params.caller.sub,
      expires_at: new Date(Date.now() + INVITE_TTL_MS).toISOString(),
      accepted: false,
    });

    // Fetch org name for the email template
    const org = await database.queryOne<{ name: string }>(
      `organizations?id=eq.${encodeURIComponent(params.org_id)}&select=name`,
    );

    // Send invite email
    const appUrl = resolveAppUrl(params.redirect_url, this.env);
    const acceptUrl = `${appUrl}/invite/accept?token=${inviteToken}`;
    const { subject, html, text } = inviteEmail(
      params.caller.email,
      org?.name ?? "an organization",
      acceptUrl,
    );
    this.ctx.waitUntil(sendEmail(this.env, { to: inviteEmailAddress, subject, html, text }, this.ctx));

    audit(this.ctx, this.env, "invite_created", {
      user_id: params.caller.sub,
      org_id: params.org_id,
      ip_address: params.ip,
      user_agent: params.ua,
      metadata: { invited_email: inviteEmailAddress, roles: params.role },
    });

    return {
      invite_id: invite.id,
      email: inviteEmailAddress,
      expires_at: invite.expires_at || "",
    };
  }

  /**
   * Accept an invite by token. Creates user if needed and adds them to the organization.
   */
  async acceptInvite(params: {
    token: string;
    password?: string;
    ip?: string;
    ua?: string;
  }): Promise<{ access_token: string; user: { id: string; email: string }; org_id: string }> {
    if (!params.token) {
      throw new Error("token is required");
    }

    const database = db(this.env);
    const tokenHash = await hashToken(params.token);
    const invite = await database.queryOne<Invite>(
      `invites?token_hash=eq.${encodeURIComponent(tokenHash)}&select=*`,
    );

    if (!invite) throw new Error("Invalid invite token");
    if (invite.accepted) throw new Error("Invite has already been accepted");
    if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
      throw new Error("Invite has expired");
    }

    let user = await database.queryOne<{ id: string; email: string; is_email_verified: boolean; user_metadata: Record<string, unknown> | null }>(
      `users?email=eq.${encodeURIComponent(invite.email)}&select=*`,
    );

    let isNewUser = false;
    if (!user) {
      isNewUser = true;
      if (!params.password) {
        throw new Error("password is required for new users");
      }

      const passErr = validatePassword(params.password);
      if (passErr) throw new Error(await passErr.text());

      const password_hash = await hashPassword(params.password);
      user = await database.mutate("users", {
        email: invite.email,
        password_hash,
        is_email_verified: false,
      });

      if (!user) {
        throw new Error("Failed to create user");
      }
    }

    const existingMembership = await database.queryOne<{ id: string; status: string }>(
      `memberships?user_id=eq.${encodeURIComponent(user.id)}&org_id=eq.${encodeURIComponent(invite.org_id)}&select=id,status`,
    );

    let membershipId: string;

    if (existingMembership) {
      membershipId = existingMembership.id;
      // Reactivate if deactivated
      if (existingMembership.status !== "active") {
        await database.update(
          "memberships",
          { id: `eq.${encodeURIComponent(existingMembership.id)}` },
          { status: "active" },
        );
      }
    } else {
      const newMembership = await database.mutate("memberships", {
        user_id: user.id,
        org_id: invite.org_id,
        status: "active",
      });
      membershipId = newMembership.id;
    }

    // Assign roles from invite via join table
    const inviteRoles = invite.role?.length ? invite.role : ["member"];
    const roleRows = await database.query<{ id: string; name: string }>(
      `roles?name=in.(${inviteRoles.map(r => encodeURIComponent(r)).join(",")})&select=id,name`,
    );

    for (const role of roleRows) {
      try {
        await database.mutate("membership_roles", {
          membership_id: membershipId,
          role_id: role.id,
        });
      } catch (err: unknown) {
        // Ignore duplicate — role already assigned
        const errMessage = err instanceof Error ? err.message : String(err);
        const isDuplicate = errMessage.includes("23505") || errMessage.includes("duplicate");
        if (!isDuplicate) {
          throw err;
        }
      }
    }

    // Mark invite as accepted
    await database.update("invites", { id: `eq.${encodeURIComponent(invite.id)}` }, {
      accepted: true,
      accepted_at: new Date().toISOString(),
    });

    // Get RBAC claims for the new membership
    const claims = await database.rpc<{ roles: string[]; products: string[]; membership_status: string }>("get_jwt_claims", {
      p_user_id: user.id,
      p_org_id: invite.org_id,
    });

    const refreshToken = generateRefreshToken();
    const refreshHash = await hashToken(refreshToken);
    const sessionId = crypto.randomUUID();

    await database.mutate("sessions", {
      id: sessionId,
      user_id: user.id,
      org_id: invite.org_id,
      refresh_token_hash: refreshHash,
      user_agent: params.ua,
      ip_address: params.ip,
      revoked: false,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      family_id: sessionId,
      family_created_at: new Date().toISOString(),
    });

    const accessToken = await signAccessToken(
      {
        sub: user.id,
        email: user.email,
        org_id: invite.org_id,
        roles: claims?.roles ?? inviteRoles,
        products: claims?.products ?? [],
        membership_status: (claims?.membership_status ?? "active") as "active" | "inactive" | "suspended" | "expired",
        is_email_verified: user.is_email_verified,
        // user_metadata is nullable at the DB level; default to an empty object
        user_metadata: user.user_metadata !== null ? user.user_metadata : {},
      },
      this.env,
    );

    // Emit sync events (non-blocking, post-response)
    if (isNewUser) {
      publishSyncEvent(this.env.SYNC_QUEUE, this.ctx, 'user.created', {
        id: user.id,
        email: user.email,
        user_metadata: {},
      });
    }
    if (existingMembership && existingMembership.status !== 'active') {
      publishSyncEvent(this.env.SYNC_QUEUE, this.ctx, 'membership.role_changed', {
        user_id: user.id,
        organization_id: invite.org_id,
        roles: inviteRoles,
        status: 'active',
      });
    } else if (!existingMembership) {
      publishSyncEvent(this.env.SYNC_QUEUE, this.ctx, 'membership.created', {
        user_id: user.id,
        organization_id: invite.org_id,
        roles: inviteRoles,
        status: 'active',
      });
    }

    audit(this.ctx, this.env, "invite_accepted", {
      user_id: user.id,
      org_id: invite.org_id,
      ip_address: params.ip,
      user_agent: params.ua,
      metadata: { invite_id: invite.id },
    });

    return {
      access_token: accessToken,
      user: { id: user.id, email: user.email },
      org_id: invite.org_id,
    };
  }

  /**
   * Cancel a pending invite. Only the inviter (or org owner/admin) can cancel.
   */
  async cancelInvite(params: {
    invite_id: string;
    caller: AccessTokenPayload;
    ip?: string;
    ua?: string;
  }): Promise<{ cancelled: boolean }> {
    if (!params.invite_id || !params.caller) {
      throw new Error("invite_id and caller are required");
    }

    const database = db(this.env);
    const invite = await database.queryOne<Invite>(
      `invites?id=eq.${encodeURIComponent(params.invite_id)}&select=*`,
    );

    if (!invite) throw new Error("Invite not found");
    if (invite.accepted) throw new Error("Cannot cancel an accepted invite");
    if (invite.org_id !== params.caller.org_id) {
      throw new Error("You can only cancel invites for your active organization");
    }

    // Only owner, admin, or the original inviter can cancel
    const isOwnerOrAdmin = params.caller.roles.includes("owner") || params.caller.roles.includes("admin");
    const isInviter = invite.invited_by === params.caller.sub;
    if (!isOwnerOrAdmin && !isInviter) {
      throw new Error("Insufficient permissions to cancel this invite");
    }

    // Delete the invite
    await database.query(
      `invites?id=eq.${encodeURIComponent(params.invite_id)}`,
      { method: "DELETE" },
    );

    audit(this.ctx, this.env, "invite_cancelled", {
      user_id: params.caller.sub,
      org_id: params.caller.org_id,
      ip_address: params.ip,
      user_agent: params.ua,
      metadata: { invite_id: params.invite_id, invited_email: invite.email },
    });

    return { cancelled: true };
  }

  /**
   * Resend an invite by generating a new token and extending the expiry.
   */
  async resendInvite(params: {
    invite_id: string;
    redirect_url?: string;
    caller: AccessTokenPayload;
    ip?: string;
    ua?: string;
  }): Promise<{ invite_id: string; email: string; expires_at: string }> {
    if (!params.invite_id || !params.caller) {
      throw new Error("invite_id and caller are required");
    }

    const redirectErr = validateRedirectUrl(params.redirect_url, this.env);
    if (redirectErr) throw new Error(await redirectErr.text());

    const database = db(this.env);
    const invite = await database.queryOne<Invite>(
      `invites?id=eq.${encodeURIComponent(params.invite_id)}&select=*`,
    );

    if (!invite) throw new Error("Invite not found");
    if (invite.accepted) throw new Error("Cannot resend an accepted invite");
    if (invite.org_id !== params.caller.org_id) {
      throw new Error("You can only resend invites for your active organization");
    }

    if (!params.caller.roles.includes("owner") && !params.caller.roles.includes("admin")) {
      throw new Error("Only owners and admins can resend invites");
    }

    const throttled = await checkEmailThrottle(this.env, "invite", params.caller.org_id);
    if (throttled) throw new Error("Too many invite requests. Please try again later.");

    // Generate new token and extend expiry
    const newToken = crypto.randomUUID();
    const newTokenHash = await hashToken(newToken);
    const newExpiry = new Date(Date.now() + INVITE_TTL_MS).toISOString();
    await database.update(
      "invites",
      { id: `eq.${encodeURIComponent(invite.id)}` },
      { token_hash: newTokenHash, expires_at: newExpiry },
    );

    // Fetch org name for the email template
    const org = await database.queryOne<{ name: string }>(
      `organizations?id=eq.${encodeURIComponent(params.caller.org_id)}&select=name`,
    );

    // Send invite email
    const appUrl = resolveAppUrl(params.redirect_url, this.env);
    const acceptUrl = `${appUrl}/invite/accept?token=${newToken}`;
    const { subject, html, text } = inviteEmail(
      params.caller.email,
      org?.name ?? "an organization",
      acceptUrl,
    );
    this.ctx.waitUntil(sendEmail(this.env, { to: invite.email, subject, html, text }, this.ctx));

    audit(this.ctx, this.env, "invite_resent", {
      user_id: params.caller.sub,
      org_id: params.caller.org_id,
      ip_address: params.ip,
      user_agent: params.ua,
      metadata: { invite_id: invite.id, invited_email: invite.email },
    });

    return {
      invite_id: invite.id,
      email: invite.email,
      expires_at: newExpiry,
    };
  }
}

export default SsoWorker;
