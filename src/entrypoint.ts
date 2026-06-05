/**
 * SSO RPC Entrypoint
 * 
 * Service binding interface for internal sp-dash-2 operations.
 * All methods are called server-to-server — NO auth/rate-limiting here.
 * Callers (sp-dash-2) are responsible for authentication and authorization.
 */

import { WorkerEntrypoint } from "cloudflare:workers";
import type { 
  Env, 
  AccessTokenPayload, 
  MembershipStatus,
  User,
  Organization,
  Membership,
  Session,
  Invite,
  JwtClaims,
} from "./types";
import { db } from "./lib/db";
import { verifyAccessToken, signAccessToken } from "./lib/jwt";
import { audit } from "./lib/audit";
import { verifyPassword, hashToken, generateRefreshToken } from "./lib/hash";
import { validateEmail } from "./lib/validate";
import { checkAccountLockout, recordFailedLogin, clearFailedLogins } from "./lib/rate-limit";
import { SESSION_TTL_MS } from "./lib/constants";

export class SSOEntrypoint extends WorkerEntrypoint<Env> {
  // ══════════════════════════════════════════════════════════════
  // GROUP 1: Token & Auth
  // ══════════════════════════════════════════════════════════════

  /**
   * Login via RPC.
   */
  async login(params: { email: string; password: string; ip?: string; ua?: string }): Promise<{
    access_token?: string;
    refresh_token?: string;
    user?: { id: string; email: string };
    active_org_id?: string | null;
    organizations?: Array<{ org_id: string }>;
    error?: string;
    status?: number;
  }> {
    console.log("[RPC] Login called via RPC for:", params.email);
    try {
      if (!params.email || !params.password) {
        return { error: "email and password are required", status: 400 };
      }

      const emailErr = validateEmail(params.email);
      if (emailErr) {
        return { error: "Invalid email format", status: 400 };
      }

      const email = params.email.toLowerCase().trim();
      const { ip, ua } = params;

      const lockedResponse = await checkAccountLockout(this.env, email);
      if (lockedResponse) {
        return { error: "Too many requests. Please try again later.", status: 429 };
      }

      const database = db(this.env);
      const user = await database.queryOne<User>(
        `users?email=eq.${encodeURIComponent(email)}&select=*`,
      );

      const DUMMY_HASH = "$2a$12$x/RiZqGfMzMQqO7MZsMmu.FS0FMCoaRaKBLGkfaOFzuBkeBMQzMFu";

      if (!user) {
        await verifyPassword(params.password, DUMMY_HASH);
        await recordFailedLogin(this.env, email);
        audit(this.ctx, this.env, "login_failed", {
          ip_address: ip ?? null,
          user_agent: ua ?? null,
          metadata: { email, source: "rpc" },
        });
        return { error: "Invalid credentials", status: 401 };
      }

      if (user.is_blocked) {
        return { error: "Account is blocked", status: 403 };
      }

      const valid = await verifyPassword(params.password, user.password_hash);
      if (!valid) {
        await recordFailedLogin(this.env, email);
        audit(this.ctx, this.env, "login_failed", {
          user_id: user.id,
          ip_address: ip ?? null,
          user_agent: ua ?? null,
          metadata: { source: "rpc" },
        });
        return { error: "Invalid credentials", status: 401 };
      }

      this.ctx.waitUntil(clearFailedLogins(this.env, email));

      this.ctx.waitUntil(
        database.update("users", { id: `eq.${user.id}` }, { last_login_at: new Date().toISOString() })
          .catch((err) => console.warn("[SSO] Failed to update last_login_at:", err)),
      );

      const memberships = await database.query<Membership>(
        `memberships?user_id=eq.${user.id}&status=eq.active&select=*&order=created_at.asc`,
      );

      const activeMembership = memberships[0] ?? null;

      let claims: JwtClaims | null = null;
      if (activeMembership) {
        claims = await database.rpc<JwtClaims>("get_jwt_claims", {
          p_user_id: user.id,
          p_org_id: activeMembership.org_id,
        });
      }

      const refreshToken = generateRefreshToken();
      const refreshHash = await hashToken(refreshToken);

      await database.mutate("sessions", {
        user_id: user.id,
        org_id: activeMembership?.org_id ?? null,
        refresh_token_hash: refreshHash,
        user_agent: ua ?? null,
        ip_address: ip ?? null,
        revoked: false,
        expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      });

      const accessToken = await signAccessToken(
        {
          sub: user.id,
          email: user.email,
          org_id: activeMembership?.org_id ?? "",
          roles: claims?.roles ?? [],
          products: claims?.products ?? [],
          membership_status: claims?.membership_status ?? "active",
          is_email_verified: user.is_email_verified,
        },
        this.env,
      );

      audit(this.ctx, this.env, "login", {
        user_id: user.id,
        org_id: activeMembership?.org_id ?? null,
        ip_address: ip ?? null,
        user_agent: ua ?? null,
        metadata: { source: "rpc" },
      });

      return {
        access_token: accessToken,
        refresh_token: refreshToken,
        user: { id: user.id, email: user.email },
        active_org_id: activeMembership?.org_id ?? null,
        organizations: memberships.map((m) => ({ org_id: m.org_id })),
      };
    } catch (err: any) {
      console.error("[RPC] login failed:", err);
      return { error: err?.message ?? "Login failed", status: 500 };
    }
  }

  /**
   * Refresh session via RPC.
   */
  async refresh(params: { refresh_token: string; ip?: string; ua?: string }): Promise<{
    access_token?: string;
    refresh_token?: string;
    error?: string;
    status?: number;
  }> {
    try {
      if (!params.refresh_token) {
        return { error: "No refresh token provided", status: 401 };
      }

      const database = db(this.env);
      const tokenHash = await hashToken(params.refresh_token);
      const { ip, ua } = params;

      const session = await database.queryOne<Session>(
        `sessions?refresh_token_hash=eq.${tokenHash}&select=*`,
      );

      if (!session) {
        return { error: "Invalid refresh token", status: 401 };
      }

      if (session.revoked) {
        await database.update(
          "sessions",
          { user_id: `eq.${session.user_id}` },
          { revoked: true },
        );
        audit(this.ctx, this.env, "refresh_theft_detected", {
          user_id: session.user_id,
          ip_address: ip ?? null,
          user_agent: ua ?? null,
          metadata: { source: "rpc" },
        });
        return { error: "Refresh token reuse detected. All sessions revoked.", status: 401 };
      }

      if (new Date(session.expires_at) < new Date()) {
        await database.update("sessions", { id: `eq.${session.id}` }, { revoked: true });
        return { error: "Session expired", status: 401 };
      }

      await database.update("sessions", { id: `eq.${session.id}` }, { revoked: true });

      const newRefreshToken = generateRefreshToken();
      const newRefreshHash = await hashToken(newRefreshToken);

      await database.mutate("sessions", {
        user_id: session.user_id,
        org_id: session.org_id,
        refresh_token_hash: newRefreshHash,
        user_agent: ua ?? null,
        ip_address: ip ?? null,
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
        ip_address: ip ?? null,
        user_agent: ua ?? null,
        metadata: { source: "rpc" },
      });

      return {
        access_token: accessToken,
        refresh_token: newRefreshToken,
      };
    } catch (err: any) {
      console.error("[RPC] refresh failed:", err);
      return { error: err?.message ?? "Refresh failed", status: 500 };
    }
  }

  /**
   * Logout via RPC.
   */
  async logout(params: { refresh_token: string; ip?: string; ua?: string }): Promise<{
    success: boolean;
    error?: string;
  }> {
    console.log("[RPC] Logout called via RPC!");
    try {
      if (!params.refresh_token) {
        return { success: false, error: "refresh_token is required" };
      }

      const database = db(this.env);
      const tokenHash = await hashToken(params.refresh_token);
      const { ip, ua } = params;

      const session = await database.queryOne<Session>(
        `sessions?refresh_token_hash=eq.${tokenHash}&select=user_id,org_id`,
      );

      let userId: string | null = null;
      let orgId: string | null = null;

      if (session) {
        userId = session.user_id;
        orgId = session.org_id;
      }

      await database.update(
        "sessions",
        { refresh_token_hash: `eq.${tokenHash}` },
        { revoked: true },
      ).catch((err) => {
        console.warn("[SSO] Session revocation failed on RPC logout:", err);
      });

      audit(this.ctx, this.env, "logout", {
        user_id: userId,
        org_id: orgId,
        ip_address: ip ?? null,
        user_agent: ua ?? null,
        metadata: { source: "rpc" },
      });

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] logout failed:", err);
      return { success: false, error: err?.message ?? "Logout failed" };
    }
  }

  /**
   * Verify JWT without HTTP context.
   * Used by middleware to verify tokens via RPC.
   */
  async verifyToken(token: string): Promise<AccessTokenPayload | null> {
    console.log("[RPC] Verifying token via RPC!");
    try {
      if (!token || typeof token !== "string") return null;
      return await verifyAccessToken(token, this.env);
    } catch (err) {
      console.error("[RPC] verifyToken failed:", err);
      return null;
    }
  }

  /**
   * Issue a new access token for a user (admin action).
   * ⚠️ Security: Should only be called by trusted admin operations.
   */
  async issueAccessToken(
    userId: string, 
    orgId: string
  ): Promise<{ access_token: string } | { error: string }> {
    try {
      if (!userId || typeof userId !== "string") {
        return { error: "userId is required" };
      }

      if (!orgId || typeof orgId !== "string") {
        return { error: "orgId is required" };
      }

      const database = db(this.env);

      // Verify user exists
      const user = await database.queryOne<{ id: string; email: string; is_email_verified: boolean }>(
        `users?id=eq.${encodeURIComponent(userId)}&select=id,email,is_email_verified`,
      );
      if (!user) {
        return { error: "User not found" };
      }

      // Get JWT claims
      const claims = await database.rpc<{ roles: string[]; products: string[]; membership_status: MembershipStatus }>(
        "get_jwt_claims",
        { p_user_id: userId, p_org_id: orgId },
      );

      const accessToken = await signAccessToken(
        {
          sub: userId,
          email: user.email,
          org_id: orgId,
          roles: claims?.roles ?? [],
          products: claims?.products ?? [],
          membership_status: claims?.membership_status ?? "active",
          is_email_verified: user.is_email_verified,
        },
        this.env,
      );

      // Audit log this admin action
      audit(this.ctx, this.env, "admin_issue_token", {
        user_id: userId,
        org_id: orgId,
        metadata: { reason: "RPC admin action" },
      });

      return { access_token: accessToken };
    } catch (err: any) {
      console.error("[RPC] issueAccessToken failed:", err);
      return { error: err?.message ?? "Failed to issue token" };
    }
  }


  // ══════════════════════════════════════════════════════════════
  // GROUP 2: User Management
  // ══════════════════════════════════════════════════════════════

  /**
   * Get user profile by ID.
   * Returns null if user not found.
   */
  async getUser(userId: string): Promise<{
    id: string;
    email: string;
    is_email_verified: boolean;
    is_blocked: boolean;
    last_login_at: string | null;
    created_at: string;
  } | null> {
    try {
      if (!userId || typeof userId !== "string") return null;

      const database = db(this.env);
      const user = await database.queryOne<User>(
        `users?id=eq.${encodeURIComponent(userId)}&select=id,email,is_email_verified,is_blocked,last_login_at,created_at`,
      );

      return user ? {
        id: user.id,
        email: user.email,
        is_email_verified: user.is_email_verified,
        is_blocked: user.is_blocked,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
      } : null;
    } catch (err) {
      console.error("[RPC] getUser failed:", err);
      return null;
    }
  }

  /**
   * List users with optional filters (paginated).
   */
  async listUsers(params?: {
    search?: string;
    is_blocked?: boolean;
    is_email_verified?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<{
    users: Array<{
      id: string;
      email: string;
      is_email_verified: boolean;
      is_blocked: boolean;
      last_login_at: string | null;
      created_at: string;
    }>;
    total: number;
  }> {
    try {
      const database = db(this.env);
      let query = "users?select=id,email,is_email_verified,is_blocked,last_login_at,created_at";

      // Apply filters
      if (params?.search) {
        query += `&email=ilike.*${encodeURIComponent(params.search)}*`;
      }
      if (params?.is_blocked !== undefined) {
        query += `&is_blocked=eq.${params.is_blocked}`;
      }
      if (params?.is_email_verified !== undefined) {
        query += `&is_email_verified=eq.${params.is_email_verified}`;
      }

      // Pagination
      const limit = params?.limit ?? 50;
      const offset = params?.offset ?? 0;
      query += `&limit=${limit}&offset=${offset}&order=created_at.desc`;

      const users = await database.query<User>(query);

      // Get total count (without pagination)
      let countQuery = "users?select=count";
      if (params?.search) {
        countQuery += `&email=ilike.*${encodeURIComponent(params.search)}*`;
      }
      if (params?.is_blocked !== undefined) {
        countQuery += `&is_blocked=eq.${params.is_blocked}`;
      }
      if (params?.is_email_verified !== undefined) {
        countQuery += `&is_email_verified=eq.${params.is_email_verified}`;
      }
      
      const countResult = await database.query<{ count: number }>(countQuery);
      const total = countResult[0]?.count ?? users.length;

      return {
        users: users.map(u => ({
          id: u.id,
          email: u.email,
          is_email_verified: u.is_email_verified,
          is_blocked: u.is_blocked,
          last_login_at: u.last_login_at,
          created_at: u.created_at,
        })),
        total,
      };
    } catch (err) {
      console.error("[RPC] listUsers failed:", err);
      return { users: [], total: 0 };
    }
  }


  /**
   * Block or unblock a user account (admin action).
   * Revokes all sessions if blocking.
   */
  async setUserBlockStatus(
    userId: string, 
    blocked: boolean
  ): Promise<{ success: boolean; error?: string }> {
    try {
      if (!userId || typeof userId !== "string") {
        return { success: false, error: "userId is required" };
      }
      if (typeof blocked !== "boolean") {
        return { success: false, error: "blocked must be boolean" };
      }

      const database = db(this.env);

      // Verify user exists
      const user = await database.queryOne<{ id: string }>(
        `users?id=eq.${encodeURIComponent(userId)}&select=id`,
      );
      if (!user) {
        return { success: false, error: "User not found" };
      }

      // Update block status
      await database.update(
        "users",
        { id: `eq.${userId}` },
        { is_blocked: blocked, updated_at: new Date().toISOString() },
      );

      // If blocking, revoke all sessions
      if (blocked) {
        await database.update(
          "sessions",
          { user_id: `eq.${userId}`, revoked: "eq.false" },
          { revoked: true },
        );
      }

      // Audit log
      audit(this.ctx, this.env, blocked ? "user_blocked" : "user_unblocked", {
        user_id: userId,
        metadata: { action: "RPC admin action" },
      });

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] setUserBlockStatus failed:", err);
      return { success: false, error: err?.message ?? "Failed to update block status" };
    }
  }

  /**
   * Verify user's email (admin override).
   */
  async adminVerifyEmail(userId: string): Promise<{ success: boolean; error?: string }> {
    try {
      if (!userId || typeof userId !== "string") {
        return { success: false, error: "userId is required" };
      }


      const database = db(this.env);

      // Verify user exists
      const user = await database.queryOne<{ id: string; is_email_verified: boolean }>(
        `users?id=eq.${encodeURIComponent(userId)}&select=id,is_email_verified`,
      );
      if (!user) {
        return { success: false, error: "User not found" };
      }

      if (user.is_email_verified) {
        return { success: true }; // Already verified
      }

      // Update verification status
      await database.update(
        "users",
        { id: `eq.${userId}` },
        { is_email_verified: true, updated_at: new Date().toISOString() },
      );

      // Audit log
      audit(this.ctx, this.env, "admin_verify_email", {
        user_id: userId,
        metadata: { action: "RPC admin action" },
      });

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] adminVerifyEmail failed:", err);
      return { success: false, error: err?.message ?? "Failed to verify email" };
    }
  }

  // ══════════════════════════════════════════════════════════════
  // GROUP 3: Organization
  // ══════════════════════════════════════════════════════════════

  /**
   * Get organization details.
   * Returns null if not found.
   */
  async getOrganization(orgId: string): Promise<{
    id: string;
    name: string;
    slug: string;
    created_by: string | null;
    metadata: Record<string, unknown>;
    created_at: string;
  } | null> {
    try {
      if (!orgId || typeof orgId !== "string") return null;

      const database = db(this.env);
      const org = await database.queryOne<Organization>(
        `organizations?id=eq.${encodeURIComponent(orgId)}&select=*`,
      );

      return org;
    } catch (err) {
      console.error("[RPC] getOrganization failed:", err);
      return null;
    }
  }


  /**
   * List organizations with filters.
   */
  async listOrganizations(params?: {
    search?: string;
    created_by?: string;
    limit?: number;
    offset?: number;
  }): Promise<{
    organizations: Array<{
      id: string;
      name: string;
      slug: string;
      created_by: string | null;
      metadata: Record<string, unknown>;
      created_at: string;
    }>;
    total: number;
  }> {
    try {
      const database = db(this.env);
      let query = "organizations?select=*";

      if (params?.search) {
        query += `&name=ilike.*${encodeURIComponent(params.search)}*`;
      }
      if (params?.created_by) {
        query += `&created_by=eq.${encodeURIComponent(params.created_by)}`;
      }

      const limit = params?.limit ?? 50;
      const offset = params?.offset ?? 0;
      query += `&limit=${limit}&offset=${offset}&order=created_at.desc`;

      const orgs = await database.query<Organization>(query);

      // Get total count
      let countQuery = "organizations?select=count";
      if (params?.search) {
        countQuery += `&name=ilike.*${encodeURIComponent(params.search)}*`;
      }
      if (params?.created_by) {
        countQuery += `&created_by=eq.${encodeURIComponent(params.created_by)}`;
      }

      const countResult = await database.query<{ count: number }>(countQuery);
      const total = countResult[0]?.count ?? orgs.length;

      return { organizations: orgs, total };
    } catch (err) {
      console.error("[RPC] listOrganizations failed:", err);
      return { organizations: [], total: 0 };
    }
  }


  /**
   * Get organization members with roles.
   */
  async getOrganizationMembers(orgId: string): Promise<{
    members: Array<{
      user_id: string;
      email: string;
      roles: string[];
      status: MembershipStatus;
      joined_at: string;
    }>;
  }> {
    try {
      if (!orgId || typeof orgId !== "string") {
        return { members: [] };
      }

      const database = db(this.env);

      // Get memberships for this org
      const memberships = await database.query<Membership>(
        `memberships?org_id=eq.${encodeURIComponent(orgId)}&select=*&order=created_at.asc`,
      );

      if (!memberships.length) {
        return { members: [] };
      }

      // Get user details
      const userIds = memberships.map(m => m.user_id);
      const users = await database.query<{ id: string; email: string }>(
        `users?id=in.(${userIds.join(",")})&select=id,email`,
      );
      const userMap = new Map(users.map(u => [u.id, u]));

      // Get roles for each membership
      const membershipIds = memberships.map(m => m.id);
      const roleRows = membershipIds.length
        ? await database.query<{ membership_id: string; role_id: any }>(
            `membership_roles?membership_id=in.(${membershipIds.join(",")})&select=membership_id,role_id(name)`,
          )
        : [];

      // Build role map
      const roleMap = new Map<string, string[]>();
      for (const row of roleRows) {
        const mid = row.membership_id;
        const roleName = (row.role_id as any)?.name ?? (row as any).name;
        if (!roleMap.has(mid)) roleMap.set(mid, []);
        if (roleName) roleMap.get(mid)!.push(roleName);
      }

      return {
        members: memberships.map(m => ({
          user_id: m.user_id,
          email: userMap.get(m.user_id)?.email ?? "",
          roles: roleMap.get(m.id) ?? [],
          status: m.status,
          joined_at: m.created_at,
        })),
      };
    } catch (err) {
      console.error("[RPC] getOrganizationMembers failed:", err);
      return { members: [] };
    }
  }


  /**
   * Update organization metadata.
   */
  async updateOrganization(
    orgId: string,
    data: {
      name?: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<{ success: boolean; error?: string }> {
    try {
      if (!orgId || typeof orgId !== "string") {
        return { success: false, error: "orgId is required" };
      }
      if (!data || typeof data !== "object") {
        return { success: false, error: "data object is required" };
      }

      const database = db(this.env);

      // Verify org exists
      const org = await database.queryOne<{ id: string }>(
        `organizations?id=eq.${encodeURIComponent(orgId)}&select=id`,
      );
      if (!org) {
        return { success: false, error: "Organization not found" };
      }

      // Build update data
      const updateData: Record<string, unknown> = {};
      if (data.name !== undefined) updateData.name = data.name;
      if (data.metadata !== undefined) updateData.metadata = data.metadata;

      if (Object.keys(updateData).length === 0) {
        return { success: false, error: "No fields to update" };
      }

      await database.update("organizations", { id: `eq.${orgId}` }, updateData);

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] updateOrganization failed:", err);
      return { success: false, error: err?.message ?? "Failed to update organization" };
    }
  }

  /**
   * Get organization stats.
   */
  async getOrganizationStats(orgId: string): Promise<{
    total_members: number;
    active_members: number;
    pending_invites: number;
    has_active_subscription: boolean;
  }> {
    try {
      if (!orgId || typeof orgId !== "string") {
        return { total_members: 0, active_members: 0, pending_invites: 0, has_active_subscription: false };
      }

      const database = db(this.env);


      // Get membership counts
      const memberships = await database.query<Membership>(
        `memberships?org_id=eq.${encodeURIComponent(orgId)}&select=status`,
      );
      const totalMembers = memberships.length;
      const activeMembers = memberships.filter(m => m.status === "active").length;

      // Get pending invites
      const invites = await database.query<Invite>(
        `invites?org_id=eq.${encodeURIComponent(orgId)}&accepted=eq.false&select=id`,
      );
      const pendingInvites = invites.length;

      // Check for active subscription
      const subscriptions = await database.query(
        `subscriptions?organization_id=eq.${encodeURIComponent(orgId)}&is_organization_subscription=eq.true&status=eq.active&select=id`,
      );
      const hasActiveSubscription = subscriptions.length > 0;

      return {
        total_members: totalMembers,
        active_members: activeMembers,
        pending_invites: pendingInvites,
        has_active_subscription: hasActiveSubscription,
      };
    } catch (err) {
      console.error("[RPC] getOrganizationStats failed:", err);
      return { total_members: 0, active_members: 0, pending_invites: 0, has_active_subscription: false };
    }
  }

  // ══════════════════════════════════════════════════════════════
  // GROUP 4: Membership
  // ══════════════════════════════════════════════════════════════

  /**
   * Get user's memberships across all orgs.
   */
  async getUserMemberships(userId: string): Promise<{
    memberships: Array<{
      org_id: string;
      org_name: string;
      org_slug: string;
      roles: string[];
      status: MembershipStatus;
      joined_at: string;
    }>;
  }> {
    try {
      if (!userId || typeof userId !== "string") {
        return { memberships: [] };
      }

      const database = db(this.env);


      // Get memberships
      const memberships = await database.query<Membership>(
        `memberships?user_id=eq.${encodeURIComponent(userId)}&select=*&order=created_at.asc`,
      );

      if (!memberships.length) {
        return { memberships: [] };
      }

      // Get organization details
      const orgIds = memberships.map(m => m.org_id);
      const orgs = await database.query<Organization>(
        `organizations?id=in.(${orgIds.join(",")})&select=id,name,slug`,
      );
      const orgMap = new Map(orgs.map(o => [o.id, o]));

      // Get roles for each membership
      const membershipIds = memberships.map(m => m.id);
      const roleRows = membershipIds.length
        ? await database.query<{ membership_id: string; role_id: any }>(
            `membership_roles?membership_id=in.(${membershipIds.join(",")})&select=membership_id,role_id(name)`,
          )
        : [];

      const roleMap = new Map<string, string[]>();
      for (const row of roleRows) {
        const mid = row.membership_id;
        const roleName = (row.role_id as any)?.name ?? (row as any).name;
        if (!roleMap.has(mid)) roleMap.set(mid, []);
        if (roleName) roleMap.get(mid)!.push(roleName);
      }

      return {
        memberships: memberships.map(m => {
          const org = orgMap.get(m.org_id);
          return {
            org_id: m.org_id,
            org_name: org?.name ?? "",
            org_slug: org?.slug ?? "",
            roles: roleMap.get(m.id) ?? [],
            status: m.status,
            joined_at: m.created_at,
          };
        }),
      };
    } catch (err) {
      console.error("[RPC] getUserMemberships failed:", err);
      return { memberships: [] };
    }
  }

  /**
   * Update membership status (activate, suspend, expire).
   */
  async updateMembershipStatus(
    membershipId: string,
    status: MembershipStatus
  ): Promise<{ success: boolean; error?: string }> {
    try {
      if (!membershipId || typeof membershipId !== "string") {
        return { success: false, error: "membershipId is required" };
      }

      if (!status || !["active", "inactive", "suspended", "expired"].includes(status)) {
        return { success: false, error: "Invalid status. Must be: active, inactive, suspended, or expired" };
      }

      const database = db(this.env);

      // Verify membership exists
      const membership = await database.queryOne<{ id: string }>(
        `memberships?id=eq.${encodeURIComponent(membershipId)}&select=id`,
      );
      if (!membership) {
        return { success: false, error: "Membership not found" };
      }

      await database.update(
        "memberships",
        { id: `eq.${membershipId}` },
        { status },
      );

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] updateMembershipStatus failed:", err);
      return { success: false, error: err?.message ?? "Failed to update membership status" };
    }
  }

  /**
   * Assign/revoke roles for a membership.
   * Replaces existing roles with the provided list.
   */
  async updateMembershipRoles(
    membershipId: string,
    roles: string[]
  ): Promise<{ success: boolean; error?: string }> {
    try {
      if (!membershipId || typeof membershipId !== "string") {
        return { success: false, error: "membershipId is required" };
      }
      if (!Array.isArray(roles)) {
        return { success: false, error: "roles must be an array" };
      }

      const database = db(this.env);

      // Verify membership exists
      const membership = await database.queryOne<{ id: string }>(
        `memberships?id=eq.${encodeURIComponent(membershipId)}&select=id`,
      );
      if (!membership) {
        return { success: false, error: "Membership not found" };
      }

      // Get role IDs
      const roleRows = await database.query<{ id: string; name: string }>(
        `roles?name=in.(${roles.join(",")})&select=id,name`,
      );

      if (roleRows.length !== roles.length) {
        const foundRoles = roleRows.map(r => r.name);
        const missing = roles.filter(r => !foundRoles.includes(r));
        return { success: false, error: `Invalid roles: ${missing.join(", ")}` };
      }


      // Delete existing roles
      await database.query(
        `membership_roles?membership_id=eq.${encodeURIComponent(membershipId)}`,
        { method: "DELETE" },
      ).catch(() => {
        // Ignore errors if no existing roles
      });

      // Insert new roles
      for (const roleRow of roleRows) {
        try {
          await database.mutate("membership_roles", {
            membership_id: membershipId,
            role_id: roleRow.id,
          });
        } catch (err: any) {
          // Ignore duplicates
          if (!err?.message?.includes("23505") && !err?.message?.includes("duplicate")) {
            throw err;
          }
        }
      }

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] updateMembershipRoles failed:", err);
      return { success: false, error: err?.message ?? "Failed to update membership roles" };
    }
  }

  // ══════════════════════════════════════════════════════════════
  // GROUP 5: Sessions
  // ══════════════════════════════════════════════════════════════

  /**
   * List active sessions for a user.
   */
  async getUserSessions(userId: string): Promise<{
    sessions: Array<{
      id: string;
      created_at: string;
      last_used_at: string | null;
      user_agent: string | null;
      ip_address: string | null;
      expires_at: string;
    }>;
  }> {
    try {
      if (!userId || typeof userId !== "string") {
        return { sessions: [] };
      }

      const database = db(this.env);
      const sessions = await database.query<Session>(
        `sessions?user_id=eq.${encodeURIComponent(userId)}&revoked=eq.false&select=id,created_at,last_used_at,user_agent,ip_address,expires_at&order=created_at.desc`,
      );

      return {
        sessions: sessions.map(s => ({
          id: s.id,
          created_at: s.created_at,
          last_used_at: s.last_used_at,
          user_agent: s.user_agent,
          ip_address: s.ip_address,
          expires_at: s.expires_at,
        })),
      };
    } catch (err) {
      console.error("[RPC] getUserSessions failed:", err);
      return { sessions: [] };
    }
  }

  /**
   * Revoke a specific session.
   */
  async revokeSession(sessionId: string): Promise<{ success: boolean; error?: string }> {
    try {
      if (!sessionId || typeof sessionId !== "string") {
        return { success: false, error: "sessionId is required" };
      }

      const database = db(this.env);

      // Verify session exists
      const session = await database.queryOne<{ id: string }>(
        `sessions?id=eq.${encodeURIComponent(sessionId)}&select=id`,
      );
      if (!session) {
        return { success: false, error: "Session not found" };
      }

      await database.update(
        "sessions",
        { id: `eq.${sessionId}` },
        { revoked: true },
      );

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] revokeSession failed:", err);
      return { success: false, error: err?.message ?? "Failed to revoke session" };
    }
  }

  /**
   * Revoke all sessions for a user (admin action).
   */
  async revokeAllUserSessions(userId: string): Promise<{
    success: boolean;
    revoked_count?: number;
    error?: string;
  }> {
    try {
      if (!userId || typeof userId !== "string") {
        return { success: false, error: "userId is required" };
      }

      const database = db(this.env);

      // Get count of active sessions before revoking
      const activeSessions = await database.query<{ id: string }>(
        `sessions?user_id=eq.${encodeURIComponent(userId)}&revoked=eq.false&select=id`,
      );
      const count = activeSessions.length;

      if (count > 0) {
        await database.update(
          "sessions",
          { user_id: `eq.${userId}`, revoked: "eq.false" },
          { revoked: true },
        );
      }

      // Audit log
      audit(this.ctx, this.env, "admin_revoke_all_sessions", {
        user_id: userId,
        metadata: { revoked_count: count, action: "RPC admin action" },
      });

      return { success: true, revoked_count: count };
    } catch (err: any) {
      console.error("[RPC] revokeAllUserSessions failed:", err);
      return { success: false, error: err?.message ?? "Failed to revoke sessions" };
    }
  }

  // ══════════════════════════════════════════════════════════════
  // GROUP 6: Invites
  // ══════════════════════════════════════════════════════════════

  /**
   * List pending invites for an organization.
   */
  async getOrganizationInvites(orgId: string): Promise<{
    invites: Array<{
      id: string;
      email: string;
      role: string[];
      invited_by: string | null;
      created_at: string | null;
      expires_at: string | null;
      accepted: boolean;
    }>;
  }> {
    try {
      if (!orgId || typeof orgId !== "string") {
        return { invites: [] };
      }

      const database = db(this.env);
      const invites = await database.query<Invite>(
        `invites?org_id=eq.${encodeURIComponent(orgId)}&select=*&order=created_at.desc`,
      );

      return {
        invites: invites.map(i => ({
          id: i.id,
          email: i.email,
          role: i.role ?? [],
          invited_by: i.invited_by,
          created_at: i.created_at,
          expires_at: i.expires_at,
          accepted: i.accepted,
        })),
      };
    } catch (err) {
      console.error("[RPC] getOrganizationInvites failed:", err);
      return { invites: [] };
    }
  }

  /**
   * Cancel invite by ID (admin action).
   */
  async adminCancelInvite(inviteId: string): Promise<{ success: boolean; error?: string }> {
    try {
      if (!inviteId || typeof inviteId !== "string") {
        return { success: false, error: "inviteId is required" };
      }

      const database = db(this.env);

      // Verify invite exists and get details for audit
      const invite = await database.queryOne<{ id: string; email: string; org_id: string }>(
        `invites?id=eq.${encodeURIComponent(inviteId)}&select=id,email,org_id`,
      );
      if (!invite) {
        return { success: false, error: "Invite not found" };
      }


      // Delete the invite
      await database.query(
        `invites?id=eq.${encodeURIComponent(inviteId)}`,
        { method: "DELETE" },
      );

      // Audit log
      audit(this.ctx, this.env, "admin_cancel_invite", {
        org_id: invite.org_id,
        metadata: { invite_id: inviteId, email: invite.email, action: "RPC admin action" },
      });

      return { success: true };
    } catch (err: any) {
      console.error("[RPC] adminCancelInvite failed:", err);
      return { success: false, error: err?.message ?? "Failed to cancel invite" };
    }
  }

  // ══════════════════════════════════════════════════════════════
  // GROUP 7: Analytics
  // ══════════════════════════════════════════════════════════════

  /**
   * Get user activity summary.
   */
  async getUserActivity(
    userId: string,
    params?: { days?: number }
  ): Promise<{
    login_count: number;
    last_login: string | null;
    active_sessions: number;
  }> {
    try {
      if (!userId || typeof userId !== "string") {
        return { login_count: 0, last_login: null, active_sessions: 0 };
      }

      const database = db(this.env);

      // Get user's last login
      const user = await database.queryOne<{ last_login_at: string | null }>(
        `users?id=eq.${encodeURIComponent(userId)}&select=last_login_at`,
      );

      // Get active sessions count
      const sessions = await database.query<{ id: string }>(
        `sessions?user_id=eq.${encodeURIComponent(userId)}&revoked=eq.false&select=id`,
      );

      // For login_count, we'd need an audit log or sessions table history
      // For now, use active sessions as a proxy
      const loginCount = sessions.length;

      return {
        login_count: loginCount,
        last_login: user?.last_login_at ?? null,
        active_sessions: sessions.length,
      };
    } catch (err) {
      console.error("[RPC] getUserActivity failed:", err);
      return { login_count: 0, last_login: null, active_sessions: 0 };
    }
  }
}
