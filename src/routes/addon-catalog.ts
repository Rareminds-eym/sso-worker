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


// ─── Pure Business Logic (for RPC) ────────────────────────────────

/**
 * Pure business logic for listing addon catalog (extracted for RPC)
 */
export async function performListAddonCatalog(
  env: Env,
  params?: {
    category?: string;
    role?: string;
    product?: string;
  }
): Promise<{ addons: any[] }> {
  const database = db(env);

  // Build query — Supabase PostgREST filter syntax
  let query = "addon_catalog?is_active=eq.true&order=display_order.asc";

  if (params?.category) {
    query += `&category=eq.${encodeURIComponent(params.category)}`;
  }

  if (params?.role) {
    // PostgREST array contains operator
    query += `&target_roles=cs.{${encodeURIComponent(params.role)}}`;
  }

  if (params?.product) {
    // Join through product_id — need to resolve product code to id first
    // For simplicity, use a select with inner join via PostgREST
    query += `&product_id=eq.${encodeURIComponent(params.product)}`;
  }

  const addons = await database.query(query);
  return { addons: addons || [] };
}

/**
 * Pure business logic for getting addon by feature key (extracted for RPC)
 */
export async function performGetAddonByFeatureKey(
  env: Env,
  featureKey: string
): Promise<any> {
  if (!featureKey) {
    return { error: "Feature key required", status: 400 };
  }

  const database = db(env);
  const addon = await database.queryOne(
    `addon_catalog?feature_key=eq.${encodeURIComponent(featureKey)}&is_active=eq.true`,
  );

  if (!addon) {
    return { error: "Addon not found", status: 404 };
  }
  
  return addon;
}

/**
 * Pure business logic for listing bundles (extracted for RPC)
 */
export async function performListBundles(
  env: Env,
  params?: {
    role?: string;
  }
): Promise<{ bundles: any[] }> {
  const database = db(env);

  let query = "bundles?is_active=eq.true&order=display_order.asc";
  if (params?.role) {
    query += `&target_roles=cs.{${encodeURIComponent(params.role)}}`;
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

  return { bundles: enriched };
}

// HTTP handlers removed - all access via RPC methods in index.ts:
// - listAddonCatalog() → env.SSO_SERVICE.listAddonCatalog()
// - getAddonByFeatureKey() → env.SSO_SERVICE.getAddonByFeatureKey()
// - listBundles() → env.SSO_SERVICE.listBundles()
// - recordAddonPurchase() → env.SSO_SERVICE.recordAddonPurchase()
// - recordBundlePurchase() → env.SSO_SERVICE.recordBundlePurchase()

