/**
 * Organization Sync Helpers
 * Ensures organizations exist in SSO DB before creating memberships
 */

import { db } from './db';
import type { Env } from '../types';

/**
 * Ensure organization exists in SSO DB (race-safe)
 * Fetches from Skillpassport if missing, handles concurrent inserts gracefully
 * 
 * ponytail: upsert pattern — check, fetch, insert-or-ignore, re-check
 * Concurrent requests may both fetch but only one insert succeeds; both get valid result
 */
export async function ensureOrganizationExists(
  env: Env,
  organizationId: string
): Promise<{ id: string } | null> {
  const database = db(env);
  
  // Step 1: Check if org exists
  let org = await database.queryOne<{ id: string }>(
    `organizations?id=eq.${encodeURIComponent(organizationId)}&select=id`
  );
  
  if (org) {
    return org;
  }
  
  // Step 2: Org missing, fetch from Skillpassport
  console.log(`[SSO] Organization ${organizationId} not in SSO DB, syncing from Skillpassport`);
  
  if (!env.SKILLPASSPORT_URL || !env.INTERNAL_WEBHOOK_SECRET) {
    console.error('[SSO] Cannot sync org: SKILLPASSPORT_URL or INTERNAL_WEBHOOK_SECRET not configured');
    return null;
  }
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);
  
  let orgData: { name: string; slug?: string; metadata?: Record<string, unknown> };
  
  try {
    const response = await fetch(
      `${env.SKILLPASSPORT_URL}/api/organizations/${encodeURIComponent(organizationId)}`,
      {
        headers: {
          'Authorization': `Bearer ${env.INTERNAL_WEBHOOK_SECRET}`
        },
        signal: controller.signal,
      }
    );
    
    if (!response.ok) {
      console.error(`[SSO] Failed to fetch org from Skillpassport: ${response.status}`);
      return null;
    }
    
    orgData = await response.json();
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      console.error(`[SSO] Timeout fetching organization ${organizationId} from Skillpassport`);
    } else {
      const errorMsg = error instanceof Error ? error.message : String(error);
      console.error(`[SSO] Error syncing org from Skillpassport:`, errorMsg);
    }
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
  
  // Step 3: Insert with conflict handling
  try {
    org = await database.mutate<{ id: string }>("organizations", {
      id: organizationId,
      name: orgData.name,
      slug: orgData.slug || `org-${organizationId.slice(0, 8)}`,
      metadata: orgData.metadata || {}
    });
    
    console.log(`[SSO] Created organization ${organizationId} in SSO DB`);
    return org;
  } catch (insertError) {
    // Duplicate key error means concurrent request won the race — re-check
    const errorMsg = insertError instanceof Error ? insertError.message : String(insertError);
    if (errorMsg.includes('duplicate') || errorMsg.includes('23505') || errorMsg.includes('already exists')) {
      console.log(`[SSO] Org ${organizationId} inserted by concurrent request, re-fetching`);
      
      // Step 4: Re-check (org now exists)
      org = await database.queryOne<{ id: string }>(
        `organizations?id=eq.${encodeURIComponent(organizationId)}&select=id`
      );
      
      return org;
    }
    
    // Other DB error
    console.error(`[SSO] Failed to insert org ${organizationId}:`, errorMsg);
    throw insertError;
  }
}
