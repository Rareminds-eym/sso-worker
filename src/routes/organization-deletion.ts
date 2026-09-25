import { db } from "../lib/db";
import { publishSyncEvent } from "../lib/sync-queue";
import type { Env } from "../types";

interface OrgDeletionSummary {
	organization_id: string;
	membership_count: number;
	deleted_user_count: number;
	subscription_count: number;
	had_active_subscription: boolean;
}

/**
 * Gathers what a delete would affect, without deleting anything. Both
 * soft and hard delete use this to decide whether to block on an active
 * subscription, and sp-dash uses the counts to warn the admin before they
 * confirm.
 */
async function inspectOrganization(
	env: Env,
	organizationId: string,
): Promise<{
	organization: { id: string; name: string; deleted_at?: string | null };
	memberships: Array<{ id: string; user_id: string }>;
	subscriptions: Array<{ id: string; status: string }>;
}> {
	const database = db(env);

	const organization = await database.queryOne<{ id: string; name: string; deleted_at?: string | null }>(
		`organizations?id=eq.${encodeURIComponent(organizationId)}&select=id,name,deleted_at`,
	);
	if (!organization) {
		throw new Error(`Organization ${organizationId} not found`);
	}

	const memberships = await database.query<{ id: string; user_id: string }>(
		`memberships?org_id=eq.${encodeURIComponent(organizationId)}&select=id,user_id`,
	);

	const subscriptions = await database.query<{ id: string; status: string }>(
		`subscriptions?organization_id=eq.${encodeURIComponent(organizationId)}&select=id,status`,
	);

	return { organization, memberships, subscriptions };
}

function hasActiveOrPendingSubscription(subscriptions: Array<{ status: string }>): boolean {
	return subscriptions.some((s) => s.status === "active" || s.status === "pending");
}

/**
 * Soft-delete: marks the organization deleted_at and deactivates its
 * memberships, but does not delete any rows. Reversible by an admin
 * clearing deleted_at directly in the DB (no "undelete" RPC yet — this is
 * intentionally minimal since soft delete's whole point is to be safe).
 *
 * Does NOT delete users, subscriptions, or transactions. Blocks if the org
 * has an active/pending subscription unless `force` is passed, since an
 * admin might soft-delete a live paying customer by mistake otherwise.
 */
export async function performSoftDeleteOrganization(
	env: Env,
	ctx: ExecutionContext,
	params: { organization_id: string; admin_user_id: string; force?: boolean },
): Promise<{ organization_id: string; deleted_at: string }> {
	if (!params.organization_id) throw new Error("organization_id is required");
	if (!params.admin_user_id) throw new Error("admin_user_id is required");

	const { organization, subscriptions } = await inspectOrganization(env, params.organization_id);
	if (organization.deleted_at) {
		throw new Error("Organization is already soft-deleted");
	}
	if (!params.force && hasActiveOrPendingSubscription(subscriptions)) {
		throw new Error(
			"Organization has an active or pending subscription. Pass force=true to soft-delete anyway.",
		);
	}

	const database = db(env);
	const deletedAt = new Date().toISOString();

	await database.update(
		"organizations",
		{ id: `eq.${encodeURIComponent(params.organization_id)}` },
		{ deleted_at: deletedAt },
	);

	// Deactivate memberships so members lose access, without deleting them —
	// keeps the soft-delete reversible.
	await database.update(
		"memberships",
		{ org_id: `eq.${encodeURIComponent(params.organization_id)}` },
		{ status: "inactive" },
	);

	if (env.SYNC_QUEUE) {
		publishSyncEvent(env.SYNC_QUEUE, ctx, "organization.deleted", {
			id: params.organization_id,
			hard: false,
			deleted_by: params.admin_user_id,
		});
	}

	return { organization_id: params.organization_id, deleted_at: deletedAt };
}

/**
 * Hard-delete: irreversibly removes the organization and everything scoped
 * to it — transactions, subscriptions, memberships, and any user who is
 * ONLY a member of this org (users who belong to other orgs too are kept,
 * just with this membership removed).
 *
 * Deletion order matters due to FK constraints:
 *   1. transactions for this org's subscriptions (transactions.subscription_id
 *      has no ON DELETE action — blocks subscription deletion otherwise)
 *   2. subscriptions for this org (subscriptions.organization_id has no FK
 *      at all — must be deleted explicitly, not caught by any cascade)
 *   3. the organization row itself — memberships/invites/organization_products/
 *      sessions all cascade automatically from organizations (ON DELETE CASCADE)
 *   4. users who have no remaining membership anywhere, from the membership
 *      list gathered BEFORE step 3 (their membership row is already gone by
 *      then via cascade, so we must capture user_ids first)
 *
 * Blocks if the org has an active/pending subscription unless `force` is
 * passed — hard-deleting a live paying customer by mistake is exactly the
 * kind of accident this guard exists to prevent.
 */
export async function performHardDeleteOrganization(
	env: Env,
	ctx: ExecutionContext,
	params: { organization_id: string; admin_user_id: string; force?: boolean },
): Promise<OrgDeletionSummary> {
	if (!params.organization_id) throw new Error("organization_id is required");
	if (!params.admin_user_id) throw new Error("admin_user_id is required");

	const { organization, memberships, subscriptions } = await inspectOrganization(env, params.organization_id);
	if (!params.force && hasActiveOrPendingSubscription(subscriptions)) {
		throw new Error(
			"Organization has an active or pending subscription. Pass force=true to hard-delete anyway.",
		);
	}

	const database = db(env);
	const memberUserIds = memberships.map((m) => m.user_id);

	// 1. Transactions for this org's subscriptions (must go before subscriptions).
	for (const sub of subscriptions) {
		await database.query(`transactions?subscription_id=eq.${encodeURIComponent(sub.id)}`, { method: "DELETE" });
	}

	// 2. Subscriptions for this org (no FK to organizations — explicit delete required).
	if (subscriptions.length > 0) {
		await database.query(`subscriptions?organization_id=eq.${encodeURIComponent(params.organization_id)}`, {
			method: "DELETE",
		});
	}

	// 3. The organization row — memberships/invites/organization_products/sessions cascade.
	await database.query(`organizations?id=eq.${encodeURIComponent(params.organization_id)}`, { method: "DELETE" });

	// 4. Delete users who now have zero remaining memberships (i.e. this was
	// their only org). Users who belong elsewhere keep their account.
	let deletedUserCount = 0;
	for (const userId of memberUserIds) {
		const remaining = await database.query<{ id: string }>(
			`memberships?user_id=eq.${encodeURIComponent(userId)}&select=id&limit=1`,
		);
		if (remaining.length === 0) {
			await database.query(`users?id=eq.${encodeURIComponent(userId)}`, { method: "DELETE" });
			deletedUserCount += 1;
			publishSyncEvent(env.SYNC_QUEUE, ctx, "user.deleted", { user_id: userId });
		}
	}

	if (env.SYNC_QUEUE) {
		publishSyncEvent(env.SYNC_QUEUE, ctx, "organization.deleted", {
			id: params.organization_id,
			hard: true,
			deleted_by: params.admin_user_id,
		});
	}

	return {
		organization_id: params.organization_id,
		membership_count: memberships.length,
		deleted_user_count: deletedUserCount,
		subscription_count: subscriptions.length,
		had_active_subscription: hasActiveOrPendingSubscription(subscriptions),
	};
}

/**
 * Read-only preview for the confirmation dialog in sp-dash — lets the admin
 * see how many members/subscriptions would be affected before choosing
 * soft or hard delete.
 */
export async function performInspectOrganizationForDeletion(
	env: Env,
	organizationId: string,
): Promise<{
	organization_id: string;
	organization_name: string;
	membership_count: number;
	subscription_count: number;
	has_active_subscription: boolean;
}> {
	const { organization, memberships, subscriptions } = await inspectOrganization(env, organizationId);
	return {
		organization_id: organization.id,
		organization_name: organization.name,
		membership_count: memberships.length,
		subscription_count: subscriptions.length,
		has_active_subscription: hasActiveOrPendingSubscription(subscriptions),
	};
}
