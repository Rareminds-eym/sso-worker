import { WorkerEntrypoint } from "cloudflare:workers";
import { audit } from "./lib/audit";
import { authenticate } from "./lib/auth";
import { addMonths, parseDurationMonths } from "./lib/date";
import { db } from "./lib/db";
import { hashPassword, hashToken } from "./lib/hash";
import { exportPemAsJwk, getPublicJWK, verifyAccessToken } from "./lib/jwt";
import { error, json } from "./lib/response";
import { rotateRefreshToken } from "./lib/session-rotation";
import {
  getAddonByFeatureKey,
  listAddonCatalog,
  listBundles,
} from "./routes/addon-catalog";
import { adminResetPassword, changePassword } from "./routes/change-password";
import { deleteAccount } from "./routes/delete-account";
import { acceptInvite, createInvite } from "./routes/invite";
import { cancelInvite, resendInvite } from "./routes/invite-manage";
import { jwks } from "./routes/jwks";
import { login } from "./routes/login";
import { logout } from "./routes/logout";
import { me } from "./routes/me";
import { oauthCallback, oauthRedirect } from "./routes/oauth";
import { listOrgs } from "./routes/orgs";
import { forgotPassword, resetPassword } from "./routes/password-reset";
import { refresh } from "./routes/refresh";
import { signup } from "./routes/signup";
import { signupMember } from "./routes/signup-member";
import {
  getPlanByCode,
  listPlans,
} from "./routes/subscriptions";
import { switchOrg } from "./routes/switch-org";
import { requestVerification, verifyEmail } from "./routes/verify-email";
import type { AccessTokenPayload, Env, RouteConfig, Session } from "./types";

/** Max request body size: 10 KB */
const MAX_BODY_SIZE = 10_240;

// ─── Public Route Table ───────────────────────────────────────
const routes: Record<string, Record<string, RouteConfig>> = {
  POST: {
    "/auth/signup": { handler: signup },
    "/auth/signup-member": { handler: signupMember },
    "/auth/login": { handler: login },
    "/auth/refresh": { handler: refresh },
    "/auth/logout": { handler: logout },
    "/auth/switch-org": { handler: switchOrg, auth: true },
    "/auth/invite": { handler: createInvite, auth: true },
    "/auth/invite/accept": { handler: acceptInvite },
    "/auth/invite/cancel": { handler: cancelInvite, auth: true },
    "/auth/invite/resend": { handler: resendInvite, auth: true },
    "/auth/request-verification": { handler: requestVerification, auth: true },
    "/auth/verify-email": { handler: verifyEmail },
    "/auth/forgot-password": { handler: forgotPassword },
    "/auth/reset-password": { handler: resetPassword },
    "/auth/change-password": { handler: changePassword, auth: true },
    "/auth/admin-reset-password": { handler: adminResetPassword, auth: true },
    "/auth/delete-account": { handler: deleteAccount, auth: true },
  },
  GET: {
    "/auth/me": { handler: me, auth: true },
    "/auth/orgs": { handler: listOrgs, auth: true },
    "/auth/oauth/google": { handler: oauthRedirect },
    "/auth/oauth/github": { handler: oauthRedirect },
    "/auth/oauth/google/callback": { handler: oauthCallback },
    "/auth/oauth/github/callback": { handler: oauthCallback },
    "/.well-known/jwks.json": { handler: (_req, env) => jwks(env) },
    "/health": { handler: () => Promise.resolve(json({ status: "ok" })) },
    "/api/plans": { handler: listPlans },
    "/api/addon-catalog": { handler: listAddonCatalog },
    "/api/addon-catalog/:featureKey": { handler: getAddonByFeatureKey },
    "/api/bundles": { handler: listBundles },
  },
};

// ─── CORS ──────────────────────────────────────────────────────
function originMatchesPattern(origin: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.includes("*.")) {
    const wildcardSuffix = pattern.replace("*.", "");
    try {
      const originUrl = new URL(origin);
      const patternUrl = new URL(wildcardSuffix);
      return (
        originUrl.protocol === patternUrl.protocol &&
        (originUrl.hostname === patternUrl.hostname ||
          originUrl.hostname.endsWith("." + patternUrl.hostname))
      );
    } catch {
      return false;
    }
  }
  return origin === pattern;
}

function corsHeaders(req: Request, env: Env): Record<string, string> {
  const origin = req.headers.get("Origin") ?? "";
  const allowed = env.ALLOWED_ORIGINS.split(",").map((o) => o.trim());
  const isAllowed = allowed.some((pattern) => originMatchesPattern(origin, pattern));

  if (!isAllowed) return {};

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Request-ID",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Expose-Headers": "X-Access-Token, X-Request-ID",
    "Access-Control-Max-Age": "86400",
  };
}

function withCors(response: Response, cors: Record<string, string>): Response {
  const res = new Response(response.body, response);
  for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
  return res;
}

function validateOrigin(req: Request, env: Env): boolean {
  // For read-only methods (GET, OPTIONS), allow missing Origin (simple CORS requests)
  if (req.method === "GET" || req.method === "OPTIONS") return true;

  // For state-changing methods (POST, PUT, DELETE, PATCH), require Origin header
  const origin = req.headers.get("Origin");
  if (!origin) return false; // Missing Origin on state-changing request → reject

  // Origin present: validate against allowlist
  const allowed = env.ALLOWED_ORIGINS.split(",").map((o) => o.trim());
  return allowed.some((pattern) => originMatchesPattern(origin, pattern));
}

// ─── WorkerEntrypoint ─────────────────────────────────────────
export class SsoWorker extends WorkerEntrypoint<Env> {
  // ── Scheduled (cron) ──────────────────────────────────────────
  async scheduled(_event: ScheduledEvent): Promise<void> {
    const database = db(this.env);
    const deleted = await database.rpc<number>("cleanup_expired_tokens");
    console.log(`[SSO] Cleaned up ${deleted} expired token rows`);

    try {
      const result = await database.rpc<{ count: number }[]>("expire_old_subscriptions");
      const expired = Array.isArray(result) ? result[0]?.count ?? 0 : 0;
      if (expired > 0) console.log(`[SSO] Expired ${expired} subscription(s)`);
    } catch (err: any) {
      console.error(`[SSO] Failed to expire subscriptions: ${err?.message}`);
    }

    try {
      const pendingEvents = await database.query<Record<string, any>>(
        "events?status=eq.received&order=created_at.asc&limit=10"
      );
      if (pendingEvents && pendingEvents.length > 0) {
        for (const event of pendingEvents) {
          await database.update("events", { id: `eq.${event.id}` }, { status: "processing" });
          try {
            if (event.event_type === 'payment.captured' || event.event_type === 'order.paid') {
              if (!this.env.SKILLPASSPORT_URL || !this.env.INTERNAL_WEBHOOK_SECRET) {
                throw new Error("SKILLPASSPORT_URL or INTERNAL_WEBHOOK_SECRET not configured. Cannot dispatch webhook.");
              }

              const targetUrl = `${this.env.SKILLPASSPORT_URL}/api/internal/webhooks/payment`;
              const dispatchResponse = await fetch(targetUrl, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${this.env.INTERNAL_WEBHOOK_SECRET}`,
                  'X-Webhook-Event': event.event_type
                },
                body: JSON.stringify(event.payload)
              });

              if (!dispatchResponse.ok) {
                const resBody = await dispatchResponse.text();
                throw new Error(`Fulfillment failed with status ${dispatchResponse.status}: ${resBody}`);
              }
            }

            // Mark as completed since fulfillment succeeded (or event type was ignored)
            await database.update("events", { id: `eq.${event.id}` }, { 
              status: "completed",
              processed_at: new Date().toISOString()
            });
            console.log(`[SSO] Processed webhook event ${event.event_id} of type ${event.event_type}`);
          } catch (processErr: any) {
            await database.update("events", { id: `eq.${event.id}` }, { 
              status: "failed",
              error_message: processErr?.message || "Unknown error",
              retry_count: (event.retry_count || 0) + 1
            });
          }
        }
      }
    } catch (err: any) {
      console.error(`[SSO] Failed to process webhook events: ${err?.message}`);
    }
  }

  // ── Fetch handler (public routes only) ────────────────────────
  async fetch(req: Request): Promise<Response> {
    const env = this.env;
    const ctx = this.ctx;
    const cors = corsHeaders(req, env);
    const requestId = crypto.randomUUID();

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(req.url);
    const { pathname } = url;
    const method = req.method;
    const start = Date.now();

    if (!validateOrigin(req, env)) {
      return withCors(error("Origin not allowed", 403), cors);
    }

    const contentLength = parseInt(req.headers.get("Content-Length") ?? "0", 10);
    if (contentLength > MAX_BODY_SIZE) {
      return withCors(error("Request body too large", 413), cors);
    }

    // Route matching
    let config = routes[method]?.[pathname];

    if (!config) {
      const methodRoutes = routes[method];
      if (methodRoutes) {
        if (method === "GET" && pathname.startsWith("/api/plans/")) {
          config = { handler: getPlanByCode };
        } else if (method === "GET" && pathname.startsWith("/api/addon-catalog/")) {
          config = { handler: getAddonByFeatureKey };
        }
      }
    }

    if (!config) {
      return withCors(error("Not found", 404), cors);
    }

    try {
      let authPayload: AccessTokenPayload | undefined;
      if (config.auth) {
        authPayload = await authenticate(req, env) ?? undefined;
        if (!authPayload) {
          return withCors(error("Unauthorized", 401), cors);
        }
      }

      const response = await config.handler(req, env, ctx, authPayload);
      const res = withCors(response, cors);
      res.headers.set("X-Request-ID", requestId);

      console.log(
        JSON.stringify({
          rid: requestId,
          method,
          path: pathname,
          status: res.status,
          ms: Date.now() - start,
        }),
      );

      return res;
    } catch (err: any) {
      console.error(
        JSON.stringify({
          rid: requestId,
          method,
          path: pathname,
          error: err?.message ?? "unknown",
          stack: err?.stack,
          ms: Date.now() - start,
        }),
      );
      const errResponse = withCors(error(err?.message ?? "Internal server error", 500), cors);
      errResponse.headers.set("X-Request-ID", requestId);
      return errResponse;
    }
  }

  // ══════════════════════════════════════════════════════════════
  // RPC METHODS — callable via service binding only
  // ══════════════════════════════════════════════════════════════

  // ── Subscription Management ─────────────────────────────────

  // ── Queue Handler (Asynchronous Events) ─────────────────────
  async queue(batch: any): Promise<void> {
    const database = db(this.env);

    for (const message of batch.messages) {
      try {
        const body = message.body;
        if (!body.event_id || !body.event_type || !body.payload) {
          console.warn("[SSO] Skipping invalid queue message", body);
          message.ack();
          continue;
        }

        // Intercept Reverse Sync Events
        if (body.event_type === 'user_metadata.updated' && body.user_id) {
          const { first_name, last_name } = body.payload;
          
          if (first_name !== undefined || last_name !== undefined) {
            try {
              // Note: using db(this.env) which wraps Postgres REST. 
              const user = await database.queryOne(`users?id=eq.${body.user_id}&select=user_metadata`);
              const currentMetadata = (user as any)?.user_metadata || {};
              
              const newMetadata = { ...currentMetadata };
              if (first_name !== undefined) newMetadata.first_name = first_name;
              if (last_name !== undefined) newMetadata.last_name = last_name;
              
              await database.update('users', { id: `eq.${body.user_id}` }, { user_metadata: newMetadata });
              console.log(`[SSO] Bidirectional sync complete: updated user_metadata for user ${body.user_id}`);
              
              // Broadcast to all forward consumers (e.g. App 1, App 2) so they stay in sync
              if (this.env.SYNC_QUEUE) {
                const userObj = await database.queryOne<{ id: string, email: string }>(`users?id=eq.${body.user_id}&select=id,email`);
                if (userObj) {
                  await this.env.SYNC_QUEUE.send({
                    type: 'user.updated',
                    payload: { 
                      id: userObj.id, 
                      email: userObj.email, 
                      user_metadata: newMetadata 
                    },
                    timestamp: new Date().toISOString()
                  });
                }
              } else {
                console.warn(`[SSO] SYNC_QUEUE not bound, cannot broadcast user.updated for ${body.user_id}`);
              }
            } catch (updateErr) {
              console.error(`[SSO] Failed to update user_metadata for ${body.user_id}:`, updateErr);
              message.retry();
              continue;
            }
          }
          
          message.ack();
          continue;
        }

        // Idempotency check
        const existing = await database.queryOne(
          `events?event_id=eq.${encodeURIComponent(body.event_id)}`,
        );
        if (existing) {
          console.log(`[SSO] Event ${body.event_id} already processed`);
          message.ack();
          continue;
        }

        await database.mutate("events", {
          event_id: body.event_id,
          event_type: body.event_type,
          status: "received",
          payload: body.payload,
          user_id: body.user_id || null,
          subscription_id: body.subscription_id || null,
          razorpay_payment_id: body.razorpay_payment_id || null,
        });

        message.ack();
      } catch (err) {
        console.error("[SSO] Failed to process queue message:", err);
        message.retry();
      }
    }
  }

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
    phone?: string;
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
      phone: data.phone || null,
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
      `subscriptions?user_id=eq.${data.user_id}&status=in.(active,pending)`,
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
    if (!data.email || !data.password || !data.role || !data.org_id) {
      throw new Error("email, password, role, and org_id are required");
    }

    const email = data.email.toLowerCase().trim();
    const password_hash = await hashPassword(data.password);
    const database = db(this.env);

    let result: { user_id: string; org_id: string; membership_id: string };
    try {
      result = await database.rpc<{ user_id: string; org_id: string; membership_id: string }>(
        "signup_member",
        {
          p_email: email,
          p_password_hash: password_hash,
          p_role: data.role,
          p_org_id: data.org_id,
        },
      );
    } catch (err: any) {
      if (err?.message?.includes("duplicate") || err?.message?.includes("23505")) {
        throw new Error(`A user with email ${email} already exists`);
      }
      throw err;
    }

    // Admin-created members are trusted — auto-verify their email so they can log
    // in immediately without an email-verification step.
    await database.update("users", { id: `eq.${result.user_id}` }, { is_email_verified: true });

    // Emit sync events — await directly (RPC method, no ctx.waitUntil)
    try {
      await this.env.SYNC_QUEUE.send({
        type: 'user.created',
        payload: { id: result.user_id, email },
        timestamp: new Date().toISOString(),
      });
      await this.env.SYNC_QUEUE.send({
        type: 'membership.created',
        payload: {
          user_id: result.user_id,
          organization_id: data.org_id,
          roles: [data.role],
          status: 'active',
        },
        timestamp: new Date().toISOString(),
      });
    } catch (e) {
      console.error('[SSO] Failed to emit sync events:', e);
    }

    return result;
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
      `plans?id=eq.${subscription.plan_id}`,
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
      { id: `eq.${subscriptionId}` },
      updateData,
    );

    const updated = await database.queryOne(
      `subscriptions?id=eq.${subscriptionId}`,
    );

    return updated as Record<string, unknown>;
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
      { id: `eq.${subscriptionId}` },
      {
        status: "cancelled",
        cancellation_reason: data?.reason || null,
        cancellation_feedback: data?.feedback || null,
        cancelled_by: data?.cancelled_by || "user",
        updated_at: new Date().toISOString(),
      },
    );

    const updated = await database.queryOne(
      `subscriptions?id=eq.${subscriptionId}`,
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
    await database.update("subscriptions", { id: `eq.${subscriptionId}` }, updateData);

    const updated = await database.queryOne(`subscriptions?id=eq.${subscriptionId}`);
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
      const sub = await database.queryOne(
        `subscriptions?id=eq.${data.subscription_id}&select=product_id,plan_id`,
      );
      const subRow = sub as any;
      productId = subRow?.product_id || null;
      if (!productId && subRow?.plan_id) {
        const plan = await database.queryOne(
          `plans?id=eq.${subRow.plan_id}&select=product_id`,
        );
        productId = (plan as any)?.product_id || null;
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
      `plans?id=eq.${subscription.plan_id}`,
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
    memberships: { org_id: string; role: string; status: string }[];
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
          org_id: r.org_id,
          status: r.status,
          role: mrole?.name || "member",
        };
      }),
    };
  }

  // ── Auth RPC Methods ──────────────────────────────────────────

  async getJWKS(): Promise<{ keys: any[] }> {
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

      case "expired_lifetime":
        // Absolute session lifetime exceeded (Requirement 5.2).
        throw new Error("Session expired");

      case "session_expired":
        // Per-token TTL expiry.
        throw new Error("Session expired");

      case "invalid":
      default:
        // Unknown or missing refresh token.
        throw new Error("Invalid refresh token");
    }
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
    };
  }

  async logoutSession(refreshToken: string, ip?: string, ua?: string): Promise<{ success: boolean }> {
    if (!refreshToken) return { success: true };

    const database = db(this.env);
    const tokenHash = await hashToken(refreshToken);

    const session = await database.queryOne<Session>(
      `sessions?refresh_token_hash=eq.${tokenHash}&select=user_id,org_id`,
    );

    if (session) {
      await database.update(
        "sessions",
        { refresh_token_hash: `eq.${tokenHash}` },
        { revoked: true },
      ).catch((err) => {
        console.warn("[SSO] Session revocation failed on logout:", err);
      });

      audit(this.ctx, this.env, "logout", {
        user_id: session.user_id,
        org_id: session.org_id,
        ip_address: ip || null,
        user_agent: ua || null,
      });
    }

    return { success: true };
  }
}

export default SsoWorker;
