// ─── Environment ───────────────────────────────────────────────
export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  JWT_PRIVATE_KEY: string;
  JWT_PUBLIC_KEY: string;
  JWT_KID: string;
  ALLOWED_ORIGINS: string;
  RATE_LIMIT_KV: KVNamespace;
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

export interface Membership {
  id: string;
  user_id: string;
  org_id: string;
  role: "owner" | "admin" | "member";
  status: "active" | string;
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
  role: string | null;
  token: string | null;
  invited_by: string | null;
  expires_at: string | null;
  accepted: boolean;
  accepted_at: string | null;
  created_at: string | null;
}

// ─── JWT Payload ───────────────────────────────────────────────
export interface AccessTokenPayload {
  sub: string;
  email: string;
  org_id: string;
  role: string;
}

// ─── Request Bodies ────────────────────────────────────────────
export interface SignupBody {
  email: string;
  password: string;
  org_name: string;
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
  role: string;
}

export interface AcceptInviteBody {
  token: string;
  password?: string;
}
