/**
 * Addon Catalog & Bundle API routes
 *
 * Serves the canonical addon_catalog, bundles, and purchase recording
 * endpoints from the Auth DB.
 *
 * Public endpoints: listAddonCatalog, getAddonByFeatureKey, listBundles
 * Service-auth endpoints: recordAddonPurchase, recordBundlePurchase
 */

import type { Env } from "../types";
import { db } from "../lib/db";
import { json, error } from "../lib/response";
import { addMonths } from "../lib/date";

// ─── Public: Addon Catalog ────────────────────────────────────────

/**
 * GET /api/addon-catalog
 * Returns all active addons, optionally filtered by category or role.
 *
 * Query params:
 *   ?category=learning       — filter by category
 *   ?role=educator            — filter by target_roles containing this role
 *   ?product=skillpassport    — filter by product code (default: all)
 */
export async function listAddonCatalog(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const category = url.searchParams.get("category");
  const role = url.searchParams.get("role");
  const product = url.searchParams.get("product");

  const database = db(env);

  // Build query — Supabase PostgREST filter syntax
  let query = "addon_catalog?is_active=eq.true&order=display_order.asc";

  if (category) {
    query += `&category=eq.${encodeURIComponent(category)}`;
  }

  if (role) {
    // PostgREST array contains operator
    query += `&target_roles=cs.{${encodeURIComponent(role)}}`;
  }

  if (product) {
    // Join through product_id — need to resolve product code to id first
    // For simplicity, use a select with inner join via PostgREST
    query += `&product_id=eq.${encodeURIComponent(product)}`;
  }

  const addons = await database.query(query);
  return json({ addons: addons || [] });
}

/**
 * GET /api/addon-catalog/:featureKey
 * Returns a single addon by its feature_key.
 */
export async function getAddonByFeatureKey(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const featureKey = url.pathname.split("/").pop();
  if (!featureKey) return error("Feature key required", 400);

  const database = db(env);
  const addon = await database.queryOne(
    `addon_catalog?feature_key=eq.${encodeURIComponent(featureKey)}&is_active=eq.true`,
  );

  if (!addon) return error("Addon not found", 404);
  return json(addon);
}

// ─── Public: Bundles ──────────────────────────────────────────────

/**
 * GET /api/bundles
 * Returns all active bundles with their feature_keys.
 *
 * Query params:
 *   ?role=educator    — filter by target_roles
 */
export async function listBundles(
  req: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(req.url);
  const role = url.searchParams.get("role");

  const database = db(env);

  let query = "bundles?is_active=eq.true&order=display_order.asc";
  if (role) {
    query += `&target_roles=cs.{${encodeURIComponent(role)}}`;
  }

  const bundles = await database.query(query);

  // Enrich each bundle with its feature_keys
  const enriched = await Promise.all(
    (bundles || []).map(async (bundle: Record<string, unknown>) => {
      const features = await database.query(
        `bundle_features?bundle_id=eq.${bundle.id}&select=feature_key`,
      );
      return {
        ...bundle,
        feature_keys: (features || []).map(
          (f: Record<string, unknown>) => f.feature_key,
        ),
      };
    }),
  );

  return json({ bundles: enriched });
}

// ─── Service-Auth: Purchase Recording ─────────────────────────────

interface RecordAddonPurchaseBody {
  user_id: string;
  feature_key: string;
  billing_period: string;
  price_at_purchase: number;
  razorpay_order_id?: string;
  razorpay_payment_id?: string;
  razorpay_signature?: string;
  start_date?: string;
  end_date?: string;
}

/**
 * POST /api/addon-purchases/record
 * Records a successful addon purchase in the Auth DB.
 * Called by skillpassport verify-addon-payment handler via service binding.
 */
async function recordAddonPurchase(
  req: Request,
  env: Env,
): Promise<Response> {
  let body: RecordAddonPurchaseBody;
  try {
    body = (await req.json()) as RecordAddonPurchaseBody;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.user_id || !body.feature_key || !body.billing_period || body.price_at_purchase === undefined) {
    return error("user_id, feature_key, billing_period, and price_at_purchase are required", 400);
  }

  const database = db(env);

  // Resolve product_id from addon_catalog
  const addon = await database.queryOne(
    `addon_catalog?feature_key=eq.${encodeURIComponent(body.feature_key)}`,
  );

  if (!addon) {
    return error(`Addon not found for feature_key: ${body.feature_key}`, 404);
  }

  const now = new Date();
  const endDate = body.billing_period === "annual"
    ? addMonths(now, 12)
    : addMonths(now, 1);

  const purchase = await database.mutate("addon_purchases", {
    user_id: body.user_id,
    product_id: addon?.product_id || null,
    feature_key: body.feature_key,
    billing_period: body.billing_period,
    price_at_purchase: body.price_at_purchase,
    razorpay_order_id: body.razorpay_order_id || null,
    razorpay_payment_id: body.razorpay_payment_id || null,
    razorpay_signature: body.razorpay_signature || null,
    status: "active",
    start_date: body.start_date || now.toISOString(),
    end_date: body.end_date || endDate.toISOString(),
  });

  return json(purchase, 201);
}

interface RecordBundlePurchaseBody {
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
}

/**
 * POST /api/bundle-purchases/record
 * Records a successful bundle purchase in the Auth DB.
 * Called by skillpassport verify-bundle-payment handler via service binding.
 */
async function recordBundlePurchase(
  req: Request,
  env: Env,
): Promise<Response> {
  let body: RecordBundlePurchaseBody;
  try {
    body = (await req.json()) as RecordBundlePurchaseBody;
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body.user_id || !body.bundle_id || !body.billing_period || body.price_at_purchase === undefined) {
    return error("user_id, bundle_id, billing_period, and price_at_purchase are required", 400);
  }

  const database = db(env);

  // Resolve product_id from bundle
  const bundle = await database.queryOne(
    `bundles?id=eq.${encodeURIComponent(body.bundle_id)}`,
  );

  if (!bundle) {
    return error("Bundle not found", 404);
  }

  const now = new Date();
  const endDate = body.billing_period === "annual"
    ? addMonths(now, 12)
    : addMonths(now, 1);

  const purchase = await database.mutate("bundle_purchases", {
    user_id: body.user_id,
    product_id: bundle.product_id || null,
    bundle_id: body.bundle_id,
    billing_period: body.billing_period,
    price_at_purchase: body.price_at_purchase,
    discount_applied: body.discount_applied || bundle.discount_percentage || 0,
    razorpay_order_id: body.razorpay_order_id || null,
    razorpay_payment_id: body.razorpay_payment_id || null,
    razorpay_signature: body.razorpay_signature || null,
    status: "active",
    start_date: body.start_date || now.toISOString(),
    end_date: body.end_date || endDate.toISOString(),
  });

  return json(purchase, 201);
}
