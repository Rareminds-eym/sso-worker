import type { Env } from "../types";
import { db } from "../lib/db";
import { json, error } from "../lib/response";

/**
 * GET /api/sales/subscriptions — fetch subscription data for sales dashboard
 * Query params: page, limit, planType, status, startDate, endDate, search
 */
export async function getSalesSubscriptions(
  req: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {

  const url = new URL(req.url);
  const searchParams = url.searchParams;

  // Parse pagination params
  const rawPage = Number(searchParams.get("page") ?? "1");
  const rawLimit = Number(searchParams.get("limit") ?? "20");
  const page = Number.isInteger(rawPage) && rawPage > 0 ? rawPage : 1;
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 20;
  const offset = (page - 1) * limit;

  // Parse filter params
  const planType = searchParams.get("planType");
  const status = searchParams.get("status");
  const startDate = searchParams.get("startDate");
  const endDate = searchParams.get("endDate");
  const search = searchParams.get("search");

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
    const userIdFilter = subscriptionUserIds.map(id => `id=eq.${encodeURIComponent(id)}`).join(",");

    // Count total users
    let countQuery = `users?select=id,email&${userIdFilter}`;
    const excludedDomains = [
      "rareminds.",
    ];

    // Add domain exclusions
    excludedDomains.forEach(domain => {
      countQuery += `&email=not.like.%${encodeURIComponent(domain)}%`;
    });

    if (search) {
      countQuery += `&email=like.%${encodeURIComponent(search)}%`;
    }

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
    const userIdList = paginatedUserIds.map(id => encodeURIComponent(id)).join(",");
    const users = await database.query<any>(`users?select=*&id=in.(${userIdList})`);

    // Fetch subscriptions for these users using `in` operator
    const subsUserIdList = paginatedUserIds.map(id => encodeURIComponent(id)).join(",");
    let subsDetailsQuery = `subscriptions?select=*&user_id=in.(${subsUserIdList})`;

    if (planType) subsDetailsQuery += `&plan_type=eq.${encodeURIComponent(planType)}`;
    if (status) subsDetailsQuery += `&status=eq.${encodeURIComponent(status)}`;

    const subsDetails = await database.query<any>(subsDetailsQuery);

    // Create subscription map
    const subscriptionsByUserId: Record<string, any[]> = {};
    subsDetails.forEach(sub => {
      if (!subscriptionsByUserId[sub.user_id]) {
        subscriptionsByUserId[sub.user_id] = [];
      }
      subscriptionsByUserId[sub.user_id].push(sub);
    });

    // Helper to select best subscription
    const selectSubscription = (subs: any[]) => {
      if (!subs || subs.length === 0) return null;
      return subs.sort((a, b) => {
        if (a.status === "active" && b.status !== "active") return -1;
        if (a.status !== "active" && b.status === "active") return 1;
        return new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime();
      })[0];
    };

    // Fetch user roles for each user through memberships
    const userRoles: Record<string, string> = {};
    for (const user of users) {
      try {
        // First get memberships for this user
        const memberships = await database.query<{ id: string }>(
          `memberships?select=id&user_id=eq.${encodeURIComponent(user.id)}&limit=1`
        );

        if (memberships.length > 0) {
          // Then get roles for that membership
          const roles = await database.query<{ name: string }>(
            `membership_roles?select=roles(name)&membership_id=eq.${encodeURIComponent(memberships[0].id)}&limit=1`
          );

          if (roles.length > 0 && (roles[0] as any).roles?.name) {
            userRoles[user.id] = (roles[0] as any).roles.name;
          } else {
            userRoles[user.id] = "member";
          }
        } else {
          userRoles[user.id] = "member";
        }
      } catch (err) {
        userRoles[user.id] = "member";
      }
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
    console.error("Sales subscriptions error:", err);
    return error("Internal server error", 500);
  }
}
