import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env, RouteConfig, AccessTokenPayload, Session, JwtClaims } from "./types";
import { signup } from "./routes/signup";
import { signupMember } from "./routes/signup-member";
import { login } from "./routes/login";
import { refresh } from "./routes/refresh";
import { logout } from "./routes/logout";
import { me } from "./routes/me";
import { switchOrg } from "./routes/switch-org";
import { createInvite, acceptInvite } from "./routes/invite";
import { listOrgs } from "./routes/orgs";
import { jwks } from "./routes/jwks";
import { requestVerification, verifyEmail } from "./routes/verify-email";
import { forgotPassword, resetPassword } from "./routes/password-reset";
import { cancelInvite, resendInvite } from "./routes/invite-manage";
import { oauthRedirect, oauthCallback } from "./routes/oauth";
import { changePassword, adminResetPassword } from "./routes/change-password";
import { deleteAccount } from "./routes/delete-account";
import {
  listPlans, getPlanByCode,
  processWebhookEvent,
} from "./routes/subscriptions";
import {
  listAddonCatalog, getAddonByFeatureKey,
  listBundles,
} from "./routes/addon-catalog";
import { createMembership, updateMembershipStatus, assignMembershipRole } from "./handlers/memberships";
import { rateLimit, rateLimits } from "./middleware/rateLimit";
import { authenticate } from "./lib/auth";
import { json, error } from "./lib/response";
import { db } from "./lib/db";
import { addMonths, parseDurationMonths } from "./lib/date";
import { signAccessToken, verifyAccessToken, getPublicJWK, exportPemAsJwk } from "./lib/jwt";
import { hashToken, generateRefreshToken } from "./lib/hash";
import { audit } from "./lib/audit";
import { SESSION_TTL_MS } from "./lib/constants";

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
    // Subscription management — all require SERVICE_AUTH_SECRET
    // These endpoints are only callable by the skillpassport backend via
    // Cloudflare Service Binding + SERVICE_AUTH_SECRET. User JWTs are rejected.
    "/api/subscriptions/create": { handler: createSubscription, serviceAuth: true },
    "/api/subscriptions/create-freemium": { handler: createFreemiumSubscription, serviceAuth: true },
    "/api/transactions/record": { handler: recordTransaction, serviceAuth: true },
    "/api/events/webhook": { handler: processWebhookEvent },
    // Addon & bundle purchase recording (service-auth only)
    "/api/addon-purchases/record": { handler: recordAddonPurchase, serviceAuth: true },
    "/api/bundle-purchases/record": { handler: recordBundlePurchase, serviceAuth: true },
    // Sync endpoints (called by skillpassport workers)
    "/api/sync/subscription": { handler: syncSubscription, serviceAuth: true },
    "/api/sync/plans": { handler: syncPlans, serviceAuth: true },
    "/api/sync/reconcile": { handler: syncReconcile, serviceAuth: true },
    // Membership management (called by skillpassport for invitation acceptance)
    "/api/memberships/create": { handler: createMembership, serviceAuth: true },
    "/api/memberships/assign-role": { handler: assignMembershipRole, serviceAuth: true },
  },
  PUT: {
    "/api/subscriptions/cancel": { handler: cancelSubscription, serviceAuth: true },
    "/api/subscriptions/status": { handler: updateSubscriptionStatus, serviceAuth: true },
    "/api/subscriptions/update": { handler: updateSubscriptionField, serviceAuth: true },
    // Membership status updates
    "/api/memberships/update-status": { handler: updateMembershipStatus, serviceAuth: true },
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
    // Plans (public)
    "/api/plans": { handler: listPlans },
    // Addon catalog & bundles (public)
    "/api/addon-catalog": { handler: listAddonCatalog },
    "/api/bundles": { handler: listBundles },
    // Transactions
    "/api/transactions/user": { handler: getUserTransactions, serviceAuth: true },
    "/api/addon-catalog/:featureKey": { handler: getAddonByFeatureKey },
    "/api/bundles":           { handler: listBundles },
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
  if (req.method === "GET" || req.method === "OPTIONS") return true;

  const origin = req.headers.get("Origin");
  if (!origin) return true;

  const allowed = env.ALLOWED_ORIGINS.split(",").map((o) => o.trim());
  return allowed.some((pattern) => originMatchesPattern(origin, pattern));
}

// ─── WorkerEntrypoint ─────────────────────────────────────────
export default class SsoWorker extends WorkerEntrypoint<Env> {
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

    // Rate limiting (skip health check and JWKS endpoint)
    if (pathname !== "/health" && pathname !== "/.well-known/jwks.json") {
      let rateLimitConfig: ReturnType<typeof rateLimit> | null = null;

      // Map routes to rate limit configs
      switch (pathname) {
        case "/auth/login":
          rateLimitConfig = rateLimit(rateLimits.login);
          break;
        case "/auth/signup":
        case "/auth/signup-member":
          rateLimitConfig = rateLimit(rateLimits.signup);
          break;
        case "/auth/forgot-password":
          rateLimitConfig = rateLimit(rateLimits.forgotPassword);
          break;
        case "/auth/reset-password":
          rateLimitConfig = rateLimit(rateLimits.resetPassword);
          break;
        case "/auth/verify-email":
          rateLimitConfig = rateLimit(rateLimits.verifyEmail);
          break;
        case "/auth/request-verification":
          rateLimitConfig = rateLimit(rateLimits.resendVerification);
          break;
        case "/auth/refresh":
          rateLimitConfig = rateLimit(rateLimits.refresh);
          break;
        case "/auth/me":
          rateLimitConfig = rateLimit(rateLimits.me);
          break;
        case "/auth/logout":
          rateLimitConfig = rateLimit(rateLimits.logout);
          break;
      }

      if (rateLimitConfig) {
        const rateLimited = await rateLimitConfig(req);
        if (rateLimited) return withCors(rateLimited, cors);
      }
    }

    // Route matching — exact first, then pattern-based
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
      const errResponse = withCors(error("Internal server error", 500), cors);
      errResponse.headers.set("X-Request-ID", requestId);
      return errResponse;
    }
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

  async refreshSession(refreshToken: string, ip?: string, ua?: string): Promise<{ access_token: string, refresh_token: string }> {
    if (!refreshToken) throw new Error("No refresh token provided");

    const database = db(this.env);
    const tokenHash = await hashToken(refreshToken);

    const session = await database.queryOne<Session>(
      `sessions?refresh_token_hash=eq.${tokenHash}&select=*`,
    );

    if (!session) throw new Error("Invalid refresh token");

    if (session.revoked) {
      await database.update("sessions", { user_id: `eq.${session.user_id}` }, { revoked: true });
      audit(this.ctx, this.env, "refresh_theft_detected", {
        user_id: session.user_id,
        ip_address: ip || null,
        user_agent: ua || null,
      });
      throw new Error("Refresh token reuse detected. All sessions revoked.");
    }

    if (new Date(session.expires_at) < new Date()) {
      await database.update("sessions", { id: `eq.${session.id}` }, { revoked: true });
      throw new Error("Session expired");
    }

    await database.update("sessions", { id: `eq.${session.id}` }, { revoked: true });

    const newRefreshToken = generateRefreshToken();
    const newRefreshHash = await hashToken(newRefreshToken);

    await database.mutate("sessions", {
      user_id: session.user_id,
      org_id: session.org_id,
      refresh_token_hash: newRefreshHash,
      user_agent: ua || null,
      ip_address: ip || null,
      revoked: false,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      rotated_from: session.id,
      last_used_at: new Date().toISOString(),
    });

    const [user, claims] = await Promise.all([
      database.queryOne<{ id: string; email: string; is_email_verified: boolean }>(
        `users?id=eq.${session.user_id}&select=id,email,is_email_verified`,
      ),
      database.rpc<JwtClaims>("get_jwt_claims", {
        p_user_id: session.user_id,
        p_org_id: session.org_id,
      }),
    ]);

    const accessToken = await signAccessToken(
      {
        sub: session.user_id,
        email: user?.email ?? "",
        org_id: session.org_id ?? "",
        roles: claims?.roles ?? [],
        products: claims?.products ?? [],
        membership_status: claims?.membership_status ?? "active",
        is_email_verified: user?.is_email_verified ?? false,
      },
      this.env,
    );

    audit(this.ctx, this.env, "refresh", {
      user_id: session.user_id,
      org_id: session.org_id,
      ip_address: ip || null,
      user_agent: ua || null,
    });

    return { access_token: accessToken, refresh_token: newRefreshToken };
  }

  async getMe(accessToken: string): Promise<Record<string, unknown>> {
    if (!accessToken) throw new Error("No access token provided");
    const payload = await verifyAccessToken(accessToken, this.env);
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


