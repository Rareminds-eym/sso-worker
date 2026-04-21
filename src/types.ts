// ─── Environment ───────────────────────────────────────────────
export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  JWT_PRIVATE_KEY: string;
  JWT_PUBLIC_KEY: string;
  JWT_KID: string;
  /** Previous public key PEM for key rotation (optional). Set during rotation window. */
  JWT_PUBLIC_KEY_PREVIOUS?: string;
  /** Previous key ID (optional). Set during rotation window. */
  JWT_KID_PREVIOUS?: string;
  ALLOWED_ORIGINS: string;
  RATE_LIMIT_KV: KVNamespace;
  /** Service binding to the email-worker for sending emails. */
  EMAIL_SERVICE: Fetcher;
  /** API key for authenticating with the email-worker. */
  EMAIL_API_KEY: string;
  /** Comma-separated allowlist of base URLs for email links, e.g. "https://skillpassport.rareminds.in,https://courses.rareminds.in". */
  ALLOWED_APP_URLS: string;
}

// ─── Route Configuration ───────────────────────────────────────
export interface RouteConfig {
  handler: RouteHandler;
  auth?: boolean;
}

export type RouteHandler = (
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
) => Promise<Response>;

// ─── JWT Payload (aligned with auth-core AuthUser) ─────────────
export interface AccessTokenPayload {
  sub: string;
  email: string;
  org_id: string;
  roles: string[];
  products: string[];
  membership_status: MembershipStatus;
  is_email_verified: boolean;
}

// ─── JWT Claims from get_jwt_claims() RPC ──────────────────────
export interface JwtClaims {
  roles: string[];
  products: string[];
  membership_status: MembershipStatus;
}

// ─── Database Models (aligned to actual Supabase schema) ───────
export interface User {
  id: string;
  email: string;
  password_hash: string;
  is_email_verified: boolean;
  is_blocked: boolean;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  created_by: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export type MembershipStatus = "active" | "inactive" | "suspended" | "expired";

export interface Membership {
  id: string;
  user_id: string;
  org_id: string;
  status: MembershipStatus;
  created_at: string;
}

export interface Role {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
}

export interface MembershipRole {
  id: string;
  membership_id: string;
  role_id: string;
  created_at: string;
}

export interface Product {
  id: string;
  code: string;
  name: string;
  description: string | null;
  created_at: string;
}

export interface OrganizationProduct {
  id: string;
  org_id: string;
  product_id: string;
  active: boolean;
  created_at: string;
}

export interface MembershipProduct {
  id: string;
  membership_id: string;
  product_id: string;
  created_at: string;
}

export interface Session {
  id: string;
  user_id: string;
  org_id: string | null;
  refresh_token_hash: string;
  user_agent: string | null;
  ip_address: string | null;
  revoked: boolean;
  expires_at: string;
  created_at: string;
  rotated_from: string | null;
  last_used_at: string | null;
  device_info: Record<string, unknown> | null;
}

export interface Invite {
  id: string;
  email: string;
  org_id: string;
  role: string[];
  token_hash: string | null;
  invited_by: string | null;
  expires_at: string | null;
  accepted: boolean;
  accepted_at: string | null;
  created_at: string | null;
}

// ─── Request Bodies ────────────────────────────────────────────
export interface SignupBody {
  email: string;
  password: string;
  org_name: string;
  redirect_url?: string;
}

export interface LoginBody {
  email: string;
  password: string;
}

export interface SwitchOrgBody {
  org_id: string;
}

export interface InviteBody {
  email: string;
  org_id: string;
  role: string[];
  redirect_url?: string;
}

export interface AcceptInviteBody {
  token: string;
  password?: string;
}
