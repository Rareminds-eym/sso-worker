/**
 * Shared RPC Types for Service Binding Callers
 * 
 * These types are used by sp-dash-2 when calling sso-api via service binding.
 * Import these in your calling worker to get full type safety.
 * 
 * @example
 * import type { AccessTokenPayload } from "../../workers/sso-worker/src/types/rpc";
 * 
 * const payload = await env.SSO_SERVICE.verifyToken(token);
 */

// ─── Core Auth Types ───────────────────────────────────────────

export interface AccessTokenPayload {
  sub: string;              // user_id
  email: string;
  org_id: string;
  roles: string[];
  products: string[];
  membership_status: MembershipStatus;
  is_email_verified: boolean;
}

export type MembershipStatus = "active" | "inactive" | "suspended" | "expired";

// ─── User Types ────────────────────────────────────────────────

export interface UserProfile {
  id: string;
  email: string;
  is_email_verified: boolean;
  is_blocked: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface UserListResult {
  users: UserProfile[];
  total: number;
}

// ─── Organization Types ────────────────────────────────────────

export interface OrganizationProfile {
  id: string;
  name: string;
  slug: string;
  created_by: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface OrganizationListResult {
  organizations: OrganizationProfile[];
  total: number;
}


export interface OrganizationMember {
  user_id: string;
  email: string;
  roles: string[];
  status: MembershipStatus;
  joined_at: string;
}

export interface OrganizationStats {
  total_members: number;
  active_members: number;
  pending_invites: number;
  has_active_subscription: boolean;
}

// ─── Membership Types ──────────────────────────────────────────

export interface UserMembership {
  org_id: string;
  org_name: string;
  org_slug: string;
  roles: string[];
  status: MembershipStatus;
  joined_at: string;
}

// ─── Session Types ─────────────────────────────────────────────

export interface SessionInfo {
  id: string;
  created_at: string;
  last_used_at: string | null;
  user_agent: string | null;
  ip_address: string | null;
  expires_at: string;
}

// ─── Invite Types ──────────────────────────────────────────────

export interface InviteInfo {
  id: string;
  email: string;
  role: string[];
  invited_by: string | null;
  created_at: string | null;
  expires_at: string | null;
  accepted: boolean;
}

// ─── Analytics Types ───────────────────────────────────────────

export interface UserActivity {
  login_count: number;
  last_login: string | null;
  active_sessions: number;
}

// ─── Response Types ────────────────────────────────────────────

export interface SuccessResponse {
  success: boolean;
  error?: string;
}

export interface TokenResponse {
  access_token?: string;
  error?: string;
}

export interface RevokeSessionsResponse {
  success: boolean;
  revoked_count?: number;
  error?: string;
}
