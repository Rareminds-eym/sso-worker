/**
 * Addon Catalog & Bundle API routes
 *
 * Serves the canonical addon_catalog, bundles, and purchase recording
 * endpoints from the Auth DB.
 *
 * Public endpoints: listAddonCatalog, getAddonByFeatureKey, listBundles
 * Service-auth endpoints: recordAddonPurchase, recordBundlePurchase
 */

import type { Env } from '../types';
import { db } from '../lib/db';

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
  },
): Promise<{ addons: any[] }> {
  const database = db(env);

  const addons = await database.rpc<any[]>('addon_catalog_payload', {
    p_category: params?.category || null,
    p_role: params?.role || null,
    p_product_id: params?.product || null,
  });
  return { addons: addons || [] };
}

/**
 * Pure business logic for getting addon by feature key (extracted for RPC)
 */
export async function performGetAddonByFeatureKey(
  env: Env,
  featureKey: string,
): Promise<any> {
  if (!featureKey) {
    return { error: 'Feature key required', status: 400 };
  }

  const database = db(env);
  let addon = await database.queryOne(
    `addon_catalog?feature_key=eq.${encodeURIComponent(featureKey)}&is_active=eq.true`,
  );

  if (!addon)
    addon = await database.queryOne(
      `addon_catalog?target_feature_key=eq.${encodeURIComponent(featureKey)}&is_active=eq.true&order=fulfilment_quantity.asc,display_order.asc&limit=1`,
    );

  if (!addon) {
    return { error: 'Addon not found', status: 404 };
  }

  const billingOptions = await database.rpc('addon_checkout_options', {
    p_addon_id: (addon as { id: string }).id,
  });
  return {
    ...(addon as Record<string, unknown>),
    billing_options: billingOptions || [],
  };
}

/**
 * Pure business logic for listing bundles (extracted for RPC)
 */
export async function performListBundles(
  env: Env,
  params?: {
    role?: string;
  },
): Promise<{ bundles: any[] }> {
  const database = db(env);

  let query = 'bundles?is_active=eq.true&order=display_order.asc';
  if (params?.role) {
    query += `&target_roles=cs.{${encodeURIComponent(params.role)}}`;
  }

  const bundles = await database.query<Record<string, unknown>>(query);

  // Enrich each bundle with its feature_keys
  const enriched = await Promise.all(
    (bundles || []).map(async (bundle: Record<string, unknown>) => {
      const features = await database.query<{ feature_key: unknown }>(
        `bundle_features?bundle_id=eq.${encodeURIComponent(String(bundle.id))}&select=feature_key`,
      );
      return {
        ...bundle,
        feature_keys: (features || []).map((f) => f.feature_key),
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
