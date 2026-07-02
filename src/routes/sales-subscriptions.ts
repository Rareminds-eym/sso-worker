import type { Env, SalesSubscription } from "../types";
import { db } from "../lib/db";

/**
 * GET /api/sales/subscriptions — fetch subscription data for sales dashboard
 * Query params: page, limit, planType, status, startDate, endDate, clientType, search
 */
export async function performGetSalesSubscriptions(
  env: Env,
  searchParams: URLSearchParams
) {
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
  const clientTypeParam = searchParams.get("clientType")?.trim() || null;
  const search = searchParams.get("search")?.trim() || null;

  // Validate clientType early - reject rm_admin before processing
  if (clientTypeParam === "rm_admin") {
    return { error: "rm_admin is not a valid client type for filtering", status: 400 };
  }
  const clientTypeList = clientTypeParam ? clientTypeParam.split(",").map(t => t.trim()).filter(Boolean) : [];

  // Validate date format (ISO 8601)
  const isValidISODate = (dateStr: string): boolean => {
    try {
      const d = new Date(dateStr);
      return !isNaN(d.getTime());
    } catch {
      return false;
    }
  };
  if (startDate && !isValidISODate(startDate)) return { error: "Invalid startDate format, use ISO 8601", status: 400 };
  if (endDate && !isValidISODate(endDate)) return { error: "Invalid endDate format, use ISO 8601", status: 400 };

  try {
    const database = db(env);

    // Step 1: Build subscription query with subscription-level filters only
    let subsQuery = "subscriptions?select=user_id,id,plan_type,status&order=created_at.desc";

    const subsFilters = [];
    if (planType) subsFilters.push(`plan_type=eq.${encodeURIComponent(planType)}`);
    if (status) subsFilters.push(`status=eq.${encodeURIComponent(status)}`);
    if (startDate) subsFilters.push(`subscription_start_date=gte.${encodeURIComponent(startDate)}`);
    if (endDate) subsFilters.push(`subscription_end_date=lte.${encodeURIComponent(endDate)}`);

    if (subsFilters.length > 0) {
      subsQuery += "&" + subsFilters.join("&");
    }

    // Fetch subscription user IDs (lightweight query for pagination)
    let subscriptions: Array<{ user_id: string; id: string; plan_type: string; status: string }>;
    try {
      subscriptions = await database.query<{ user_id: string; id: string; plan_type: string; status: string }>(subsQuery);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error("Error fetching subscriptions:", errorMessage);
      return { error: "Failed to fetch subscription data", status: 500 };
    }

    if (!subscriptions || subscriptions.length === 0) {
      return {
        data: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
      };
    }

    // Step 2: Get unique user IDs from subscription-level filtered results
    // Do NOT paginate yet - pagination must happen AFTER clientType/search filtering
    const uniqueUserIds = [...new Set(subscriptions.map(s => s.user_id))];

    // Step 3: Fetch full subscription details for ALL users
    // Necessary because clientType and search filtering happen next, requiring complete dataset
    const userIdList = uniqueUserIds.map(id => encodeURIComponent(id)).join(',');
    let allSubscriptions: SalesSubscription[] = [];

    if (userIdList) {
      try {
        allSubscriptions = await database.query<SalesSubscription>(
          `subscriptions?select=*&user_id=in.(${userIdList})&order=created_at.desc,id.desc`
        );
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        console.error("Error fetching subscription details:", errorMessage);
        return { error: "Failed to fetch subscription data", status: 500 };
      }
    }

    // Step 4: Build role map for ALL users
    const userRoles: Record<string, string> = {};
    uniqueUserIds.forEach(userId => {
      userRoles[userId] = "member";
    });

    try {
      if (userIdList) {
        const allMemberships = await database.query<{ user_id: string; id: string }>(
          `memberships?select=user_id,id&user_id=in.(${userIdList})`
        );

        if (allMemberships.length > 0) {
          const membershipIds = allMemberships.map(m => encodeURIComponent(m.id)).join(',');
          const allRoles = await database.query<{ membership_id: string; roles: { name: string } }>(
            `membership_roles?select=membership_id,roles(name)&membership_id=in.(${membershipIds})`
          );

          // Aggregate all memberships per user
          const membershipsByUserId = new Map<string, Array<{ user_id: string; id: string }>>();
          allMemberships.forEach(m => {
            const existing = membershipsByUserId.get(m.user_id) || [];
            existing.push(m);
            membershipsByUserId.set(m.user_id, existing);
          });

          // Aggregate all roles per membership
          const rolesByMembershipId = new Map<string, string[]>();
          allRoles.forEach(r => {
            const existing = rolesByMembershipId.get(r.membership_id) || [];
            existing.push(r.roles.name);
            rolesByMembershipId.set(r.membership_id, existing);
          });

          // Assign highest-priority role to each user
          const ROLE_PRIORITY: Record<string, number> = { rm_admin: 3, admin: 2, member: 1 };
          uniqueUserIds.forEach(userId => {
            const userMemberships = membershipsByUserId.get(userId) || [];
            const allUserRoles = userMemberships.flatMap(m => rolesByMembershipId.get(m.id) || []);
            const topRole = allUserRoles.sort((a, b) => (ROLE_PRIORITY[b] || 0) - (ROLE_PRIORITY[a] || 0))[0];
            userRoles[userId] = topRole || "member";
          });
        }
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error("Error fetching user roles:", errorMessage);
    }

    // Step 5: Filter subscriptions by ALL criteria (in memory, after role resolution)
    // This must happen BEFORE pagination to get accurate total count
    const filteredSubscriptions = allSubscriptions.filter(subscription => {
      // Always exclude rm_admin
      if (userRoles[subscription.user_id] === "rm_admin") {
        return false;
      }

      // Re-apply subscription-level filters (query 1 found users, but query 2 may have returned
      // additional subscriptions for those users that don't match the original filters)
      if (planType && subscription.plan_type !== planType) {
        return false;
      }
      if (status && subscription.status !== status) {
        return false;
      }
      if (startDate) {
        if (!subscription.subscription_start_date) return false;
        const subStart = new Date(subscription.subscription_start_date).getTime();
        const filterStart = new Date(startDate).getTime();
        if (!isNaN(subStart) && !isNaN(filterStart) && subStart < filterStart) {
          return false;
        }
      }
      if (endDate) {
        if (!subscription.subscription_end_date) return false;
        const subEnd = new Date(subscription.subscription_end_date).getTime();
        const filterEnd = new Date(endDate).getTime();
        if (!isNaN(subEnd) && !isNaN(filterEnd) && subEnd > filterEnd) {
          return false;
        }
      }

      // Filter by clientType if specified
      if (clientTypeList.length > 0) {
        const userRole = userRoles[subscription.user_id] || "member";
        if (!clientTypeList.includes(userRole)) {
          return false;
        }
      }

      // Filter by search (email or full_name from SSO database)
      if (search) {
        const searchLower = search.toLowerCase();
        const matchesEmail = subscription.email?.toLowerCase().includes(searchLower) || false;
        const matchesName = subscription.full_name?.toLowerCase().includes(searchLower) || false;
        if (!matchesEmail && !matchesName) {
          return false;
        }
      }

      return true;
    });

    // Step 6: Apply pagination AFTER filtering to get correct page boundaries
    const filteredTotal = filteredSubscriptions.length;
    const filteredTotalPages = Math.ceil(filteredTotal / limit);
    const paginatedSubscriptions = filteredSubscriptions.slice(offset, offset + limit);

    // Step 7: Build response with filtered count
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

    return {
      data: clients,
      pagination: {
        page,
        limit,
        total: filteredTotal,
        totalPages: filteredTotalPages,
      },
    };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error("Sales subscriptions error:", errorMessage);
    return { error: "Internal server error", status: 500 };
  }
}

// HTTP handler removed - all access via RPC method in index.ts:
// - getSalesSubscriptions() → env.SSO_SERVICE.getSalesSubscriptions()
