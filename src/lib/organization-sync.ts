/**
 * Organization Sync Helpers
 * Ensures organizations exist in SSO DB before creating memberships
 */

import { db } from './db';
import type { Env } from '../types';

/**
 * Ensure organization exists in SSO DB
 * Fetches from Skillpassport if missing
 */
export async function ensureOrganizationExists(
  env: Env,
  organizationId: string
): Promise<{ id: string } | null> {
  const database = db(env);
  
  // Check if org exists in SSO DB
  let org = await database.queryOne<{ id: string }>(
    `organizations?id=eq.${encodeURIComponent(organizationId)}&select=id`
  );
  
  if (org) {
    return org;
  }
  
  // Org doesn't exist, sync from Skillpassport
  console.log(`[SSO] Organization ${organizationId} not in SSO DB, syncing from Skillpassport`);
  
  if (!env.SKILLPASSPORT_URL || !env.INTERNAL_WEBHOOK_SECRET) {
    console.error('[SSO] Cannot sync org: SKILLPASSPORT_URL or INTERNAL_WEBHOOK_SECRET not configured');
    return null;
  }
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${env.SKILLPASSPORT_URL}/api/organizations/${organizationId}`, {
      headers: {
        'Authorization': `Bearer ${env.INTERNAL_WEBHOOK_SECRET}`
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    
    if (!response.ok) {
      console.error(`[SSO] Failed to fetch org from Skillpassport: ${response.status}`);
      return null;
    }
    
    const orgData = await response.json() as {
      name: string;
      slug?: string;
      metadata?: Record<string, unknown>;
    };
    
    // Create org in SSO DB
    org = await database.mutate<{ id: string }>("organizations", {
      id: organizationId,
      name: orgData.name,
      slug: orgData.slug || `org-${organizationId.slice(0, 8)}`,
      metadata: orgData.metadata || {}
    });
    
    console.log(`[SSO] Created organization ${organizationId} in SSO DB`);
    return org;
    
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.error(`[SSO] Error syncing org from Skillpassport:`, errorMsg);
    return null;
  }
}
