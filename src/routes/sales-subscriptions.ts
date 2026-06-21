import type { Env, SalesSubscription } from "../types";
import { db } from "../lib/db";
import { json, error } from "../lib/response";

/**
 * GET /api/sales/subscriptions — fetch subscription data for sales dashboard
 * Query params: page, limit, planType, status, startDate, endDate, clientType, search
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
  const clientType = searchParams.get("clientType")?.trim() || null;
  const search = searchParams.get("search")?.trim() || null;

  // Validate date format (ISO 8601)
  const isValidISODate = (dateStr: string): boolean => {
    try {
      const d = new Date(dateStr);
      return !isNaN(d.getTime());
    } catch {
      return false;
    }
  };
  if (startDate && !isValidISODate(startDate)) return error("Invalid startDate format, use ISO 8601", 400);
  if (endDate && !isValidISODate(endDate)) return error("Invalid endDate format, use ISO 8601", 400);

  try {
    const database = db(env);

    // Step 1: Build subscription query with subscription-level filters
    let subsQuery = "subscriptions?select=*&order=created_at.desc";

    const subsFilters = [];
    if (planType) subsFilters.push(`plan_type=eq.${encodeURIComponent(planType)}`);
    if (status) subsFilters.push(`status=eq.${encodeURIComponent(status)}`);
    if (startDate) subsFilters.push(`subscription_start_date=gte.${encodeURIComponent(startDate)}`);
    if (endDate) subsFilters.push(`subscription_end_date=lte.${encodeURIComponent(endDate)}`);

    if (subsFilters.length > 0) {
      subsQuery += "&" + subsFilters.join("&");
    }

    // Fetch all subscriptions matching subscription-level filters
    let allSubscriptions: SalesSubscription[];
    try {
      allSubscriptions = await database.query<SalesSubscription>(subsQuery);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error("Error fetching subscriptions:", errorMessage);
      return error("Failed to fetch subscription data", 500);
    }

    if (!allSubscriptions || allSubscriptions.length === 0) {
      return json({
        data: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
      });
    }

    // Step 2: Parse clientType filter
    const clientTypeList = clientType ? clientType.split(',').map(t => t.trim()) : [];

    // Step 3: Build role map for users (needed for clientType filtering)
    const userIds = [...new Set(allSubscriptions.map(s => s.user_id))];
    const userRoles: Record<string, string> = {};

    // Set default role for all users
    userIds.forEach(userId => {
      userRoles[userId] = "member";
    });

    // Fetch and map user roles
    try {
      const encodedUserIds = userIds.map(id => encodeURIComponent(id)).join(',');
      if (encodedUserIds) {
        const allMemberships = await database.query<{ user_id: string; id: string }>(
          `memberships?select=user_id,id&user_id=in.(${encodedUserIds})`
        );

        if (allMemberships.length > 0) {
          const membershipIds = allMemberships.map(m => encodeURIComponent(m.id)).join(',');
          const allRoles = await database.query<{ membership_id: string; roles: { name: string } }>(
            `membership_roles?select=membership_id,roles(name)&membership_id=in.(${membershipIds})`
          );

          const membershipsByUserId = new Map(allMemberships.map(m => [m.user_id, m]));
          const rolesByMembershipId = new Map(allRoles.map(r => [r.membership_id, r]));

          userIds.forEach(userId => {
            const membership = membershipsByUserId.get(userId);
            const role = membership ? rolesByMembershipId.get(membership.id) : null;
            userRoles[userId] = role?.roles.name || "member";
          });
        }
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error("Error fetching user roles:", errorMessage);
    }

    // Step 4: Apply client-level filters (search + clientType) in memory
    const filteredSubscriptions = allSubscriptions.filter(subscription => {
      // Filter by clientType if specified (requires role lookup)
      if (clientTypeList.length > 0) {
        const userRole = userRoles[subscription.user_id] || "member";
        if (!clientTypeList.includes(userRole)) {
          return false;
        }
      }

      // Filter by search (email or subscription full_name from SSO database)
      // Note: Name search on actual SkillPassport names happens in sp-dash-2 API after enrichment
      if (search) {
        const searchLower = search.toLowerCase();
        const matchesEmail = subscription.email?.toLowerCase().includes(searchLower) || false;
        const matchesName = subscription.full_name?.toLowerCase().includes(searchLower) || false;
        if (!matchesEmail && !matchesName) {
          return false;
        }
      }

      // Exclude rm_admin users
      if (userRoles[subscription.user_id] === "rm_admin") {
        return false;
      }

      return true;
    });

    // Step 5: Paginate filtered subscriptions
    const paginatedSubscriptions = filteredSubscriptions.slice(offset, offset + limit);
    const total = filteredSubscriptions.length;

    // Step 6: Build response with user roles
    const clients = paginatedSubscriptions.map(subscription => ({
      id: subscription.user_id,
      email: subscription.email,
      fullName: subscription.full_name || subscription.email,
      phone: subscription.phone || "-",
      role: userRoles[subscription.user_id] || "member",
      subscriptionId: subscription.id,
      planType: subscription.plan_type,
      planAmount: subscription.plan_amount,
      billingCycle: subscription.billing_cycle,
      subscriptionStatus: subscription.status,
      startDate: subscription.subscription_start_date,
      endDate: subscription.subscription_end_date,
    }));

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
