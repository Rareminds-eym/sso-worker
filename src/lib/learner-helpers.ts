/**
 * Learner/User Creation Helpers
 * Used for bulk learner admission flow
 */

import type { DbClient } from './db';

export interface LearnerUserData {
  email: string;
  name: string;
  organization_id: string;
  contact_number?: string;
  enrollment_number?: string;
  program_id?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateLearnerResult {
  success: boolean;
  user_id?: string;
  temp_password?: string;
  error?: string;
}

/**
 * Generate temporary password for learner
 * Uses Web Crypto API for secure random password generation
 */
export function generateTempPassword(length: number = 12): string {
  // Generate random bytes using Web Crypto API (Cloudflare Workers compatible)
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  
  // Convert to base64url and slice to desired length
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return base64.slice(0, length);
}

/**
 * Split full name into first and last name
 */
export function splitName(fullName: string): { first_name: string; last_name: string } {
  const parts = fullName.trim().split(' ');
  return {
    first_name: parts[0] || '',
    last_name: parts.slice(1).join(' ') || ''
  };
}

/**
 * Validate learner data before creating user
 */
export function validateLearnerData(data: LearnerUserData): { valid: boolean; error?: string } {
  if (!data.email || !data.email.includes('@')) {
    return { valid: false, error: 'Invalid email address' };
  }
  
  if (!data.name || data.name.trim().length < 2) {
    return { valid: false, error: 'Name must be at least 2 characters' };
  }
  
  if (!data.organization_id) {
    return { valid: false, error: 'Organization ID is required' };
  }
  
  return { valid: true };
}

/**
 * Check if user already exists by email
 */
export async function checkUserExists(
  database: DbClient,
  email: string
): Promise<boolean> {
  const users = await database.query<{ id: string }>(
    `users?email=eq.${encodeURIComponent(email)}&select=id`
  );
  return users.length > 0;
}

/**
 * Get or create learner role
 */
export async function getLearnerRole(database: DbClient): Promise<string | null> {
  const roles = await database.query<{ id: string }>(
    `roles?name=eq.learner&select=id`
  );
  
  if (roles.length > 0) {
    return roles[0].id;
  }
  
  // Role doesn't exist, return null (caller should handle)
  return null;
}
