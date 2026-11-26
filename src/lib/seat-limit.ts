import type { DbClient } from "./db";
import { getLearnerRole } from "./learner-helpers";

export interface SeatAvailability {
	allowed: boolean;
	limited: boolean;
	used: number;
	limit: number | null;
	remaining: number | null;
	message?: string;
}

const ACTIVE_ORG_SUBSCRIPTION_STATUSES = "active,pending,grace_period";
const PAGE_SIZE = 1000;

/**
 * Check whether an organization has enough remaining learner seats under its
 * active organization subscription (`subscriptions.seat_count`).
 * Counts only active memberships holding the `learner` role — admins and
 * educators are excluded.
 */
export async function checkLearnerSeatAvailability(
	database: DbClient,
	organizationId: string,
	additionalSeats: number = 0,
): Promise<SeatAvailability> {
	const subs = await database.query<{
		id: string;
		seat_count: number | null;
		status: string;
	}>(
		`subscriptions?organization_id=eq.${encodeURIComponent(organizationId)}&is_organization_subscription=is.true&status=in.(${ACTIVE_ORG_SUBSCRIPTION_STATUSES})&order=created_at.desc&limit=5&select=id,seat_count,status`,
	);

	const activeSub =
		subs.find((s) => s.status === "active" && typeof s.seat_count === "number") ??
		subs.find((s) => typeof s.seat_count === "number");

	if (typeof activeSub?.seat_count !== "number") {
		return { allowed: true, limited: false, used: 0, limit: null, remaining: null };
	}

	const limit = activeSub.seat_count;
	const learnerRoleId = await getLearnerRole(database);
	if (!learnerRoleId) {
		return { allowed: false, limited: true, used: 0, limit, remaining: 0, message: "Learner role not found in database" };
	}

	let used = 0;
	for (let offset = 0; ; offset += PAGE_SIZE) {
		const page = await database.query<{ id: string }>(
			`memberships?org_id=eq.${encodeURIComponent(organizationId)}&status=eq.active&membership_roles.role_id=eq.${encodeURIComponent(learnerRoleId)}&select=id,membership_roles!inner(role_id)&order=id.asc&limit=${PAGE_SIZE}&offset=${offset}`,
		);
		used += page.length;
		if (page.length < PAGE_SIZE) break;
	}

	const remaining = Math.max(0, limit - used);
	const allowed = used + additionalSeats <= limit;
	const message =
		remaining <= 0
			? `Seat limit reached (${used}/${limit} seats used). Please upgrade or purchase additional seats.`
			: `Seat limit reached (${remaining} of ${limit} seats remaining). Please upgrade or purchase additional seats.`;

	return { allowed, limited: true, used, limit, remaining, ...(allowed ? {} : { message }) };
}
