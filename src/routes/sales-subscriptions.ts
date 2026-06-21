import type { Env, SalesUser, SalesSubscription } from "../types";
import { db } from "../lib/db";
import { json, error } from "../lib/response";

/**
 * GET /api/sales/subscriptions — fetch subscription data for sales dashboard
 * Query params: page, limit, planType, status, startDate, endDate
 */
export async function getSalesSubscriptions(
  req: Request,
  env: Env,
): Promise<Response> {

  const url = new URL(req.url);
  const searchParams = url.searchParams;

  // Parse pagination params
  const rawPage = Number(searchParams.get("page") ?? "1");
  const rawLimit = Number(searchParams.get("limit") ?? "20");
  const page = Number.isInteger(rawPage) && rawPage > 0 ? rawPage : 1;
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 20;
  const offset = (page - 1) * limit;

  // Parse and validate filter params
  const planType = searchParams.get("planType")?.trim() || null;
  const status = searchParams.get("status")?.trim() || null;
  const startDate = searchParams.get("startDate")?.trim() || null;
  const endDate = searchParams.get("endDate")?.trim() || null;

  // Validate date format (ISO 8601)
  const isValidISODate = (dateStr: string): boolean => /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}.*)?Z?$/.test(dateStr);
  if (startDate && !isValidISODate(startDate)) return error("Invalid startDate format, use ISO 8601", 400);
  if (endDate && !isValidISODate(endDate)) return error("Invalid endDate format, use ISO 8601", 400);

  try {
    const database = db(env);

    // Build subscription query with filters
    let subsQuery = "subscriptions?select=user_id,id,plan_type,status";

    const filters = [];
    if (planType) filters.push(`plan_type=eq.${encodeURIComponent(planType)}`);
    if (status) filters.push(`status=eq.${encodeURIComponent(status)}`);
    if (startDate) filters.push(`subscription_start_date=gte.${encodeURIComponent(startDate)}`);
    if (endDate) filters.push(`subscription_end_date=lte.${encodeURIComponent(endDate)}`);

    if (filters.length > 0) {
      subsQuery += "&" + filters.join("&");
    }

    // Get subscription user IDs (for filtering users)
    const subscriptions = await database.query<{ user_id: string }>(subsQuery);

    if (!subscriptions || subscriptions.length === 0) {
      return json({
        data: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
      });
    }

    const subscriptionUserIds = [...new Set(subscriptions.map(s => s.user_id))];

    // Paginate user IDs
    const paginatedUserIds = subscriptionUserIds.slice(offset, offset + limit);
    const total = subscriptionUserIds.length;

    if (total === 0) {
      return json({
        data: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
      });
    }

    // Fetch full users data using `in` operator
    if (paginatedUserIds.length === 0) {
      return json({
        data: [],
        pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
      });
    }
    const userIdList = paginatedUserIds.map(id => encodeURIComponent(id)).join(",");
    const users = await database.query<SalesUser>(`users?select=*&id=in.(${userIdList})`);

    // Fetch subscriptions for these users using `in` operator
    const subsUserIdList = paginatedUserIds.map(id => encodeURIComponent(id)).join(",");
    const subsDetailsQuery = `subscriptions?select=*&user_id=in.(${subsUserIdList})`;

    const subsDetails = await database.query<SalesSubscription>(subsDetailsQuery);

    // Create subscription map
    const subscriptionsByUserId: Record<string, SalesSubscription[]> = {};
    subsDetails.forEach(sub => {
      if (!subscriptionsByUserId[sub.user_id]) {
        subscriptionsByUserId[sub.user_id] = [];
      }
      subscriptionsByUserId[sub.user_id].push(sub);
    });

    // Helper to select best subscription
    const selectSubscription = (subs: SalesSubscription[]): SalesSubscription | null => {
      if (!subs || subs.length === 0) return null;
      return subs.sort((a, b) => {
        if (a.status === "active" && b.status !== "active") return -1;
        if (a.status !== "active" && b.status === "active") return 1;
        return new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime();
      })[0];
    };

    // Batch fetch user roles through memberships (avoid N+1 query problem)
    const userRoles: Record<string, string> = {};

    // Set default role for all users
    users.forEach(user => {
      userRoles[user.id] = "member";
    });

    try {
      // Batch fetch all memberships for all users
      const userIds = users.map(u => encodeURIComponent(u.id)).join(',');
      if (userIds) {
        const allMemberships = await database.query<{ user_id: string; id: string }>(
          `memberships?select=user_id,id&user_id=in.(${userIds})`
        );

        if (allMemberships.length > 0) {
          // Batch fetch all roles for all memberships
          const membershipIds = allMemberships.map(m => encodeURIComponent(m.id)).join(',');
          const allRoles = await database.query<{ membership_id: string; roles: { name: string } }>(
            `membership_roles?select=membership_id,roles(name)&membership_id=in.(${membershipIds})`
          );

          // Map roles back to users in memory using O(n) lookup with Map
          const membershipsByUserId = new Map(allMemberships.map(m => [m.user_id, m]));
          const rolesByMembershipId = new Map(allRoles.map(r => [r.membership_id, r]));

          users.forEach(user => {
            const membership = membershipsByUserId.get(user.id);
            const role = membership ? rolesByMembershipId.get(membership.id) : null;
            userRoles[user.id] = role?.roles.name || "member";
          });
        }
      }
    } catch (err) {
      // If role fetch fails, keep default "member" role for all users
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error("Error fetching user roles:", errorMessage);
    }

    // Combine users with subscriptions - exclude rm_admin role
    const clients = users
      .filter(user => subscriptionsByUserId[user.id] && userRoles[user.id] !== "rm_admin")
      .map(user => {
        const subscription = selectSubscription(subscriptionsByUserId[user.id]);
        return {
          id: user.id,
          email: user.email,
          fullName: user.full_name || user.email,
          phone: subscription?.phone || "-",
          role: userRoles[user.id] || "member",
          subscriptionId: subscription?.id || null,
          planType: subscription?.plan_type || null,
          planAmount: subscription?.plan_amount || null,
          billingCycle: subscription?.billing_cycle || null,
          subscriptionStatus: subscription?.status || null,
          startDate: subscription?.subscription_start_date || null,
          endDate: subscription?.subscription_end_date || null,
        };
      });

    return json({
      data: clients,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error("Sales subscriptions error:", errorMessage);
    return error("Internal server error", 500);
  }
}
