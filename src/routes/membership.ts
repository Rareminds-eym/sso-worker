import { db } from "../lib/db";
import { hashPassword } from "../lib/hash";
import type { Env } from "../types";

/**
 * Create member (admin-initiated user creation via RPC)
 * Calls the signup_member postgres function to create user, org, membership atomically
 */
export async function performCreateMember(
	env: Env,
	data: {
		email: string;
		password: string;
		role: string;
		org_id: string;
	},
): Promise<{ user_id: string; org_id: string; membership_id: string }> {
	if (!data.email || !data.password || !data.role || !data.org_id) {
		throw new Error("email, password, role, and org_id are required");
	}

	const email = data.email.toLowerCase().trim();
	const password_hash = await hashPassword(data.password);
	const database = db(env);

	let result: { user_id: string; org_id: string; membership_id: string };
	try {
		result = await database.rpc<{
			user_id: string;
			org_id: string;
			membership_id: string;
		}>("signup_member", {
			p_email: email,
			p_password_hash: password_hash,
			p_role: data.role,
			p_org_id: data.org_id,
		});
	} catch (err: unknown) {
		const errorMessage = err instanceof Error ? err.message : String(err);
		if (
			errorMessage.includes("duplicate") ||
			errorMessage.includes("23505")
		) {
			throw new Error(`A user with email ${email} already exists`);
		}
		throw err;
	}

	// Admin-created members are trusted — auto-verify their email so they can log
	// in immediately without an email-verification step.
	await database.update(
		"users",
		{ id: `eq.${encodeURIComponent(result.user_id)}` },
		{ is_email_verified: true },
	);

	// Emit sync events — await directly (RPC method, no ctx.waitUntil)
	if (!env.SYNC_QUEUE) {
		console.error("[SSO] SYNC_QUEUE not bound, member created but not synced");
	} else {
		const syncUserPayload = {
			type: "user.created" as const,
			payload: {
				id: result.user_id,
				email,
				user_metadata: {
					role: data.role,
				},
			},
			timestamp: new Date().toISOString(),
		};
		const syncMembershipPayload = {
			type: "membership.created" as const,
			payload: {
				user_id: result.user_id,
				organization_id: data.org_id,
				roles: [data.role],
				status: "active",
			},
			timestamp: new Date().toISOString(),
		};

		try {
			await env.SYNC_QUEUE.send(syncUserPayload);
		} catch (e) {
			console.error("[SSO] Failed to emit user.created sync event:", e);
		}
		try {
			await env.SYNC_QUEUE.send(syncMembershipPayload);
		} catch (e) {
			console.error("[SSO] Failed to emit membership.created sync event:", e);
		}
	}

	return result;
}

/**
 * Create membership record in SSO database
 */
export async function performCreateMembership(
	env: Env,
	data: {
		user_id: string;
		org_id: string;
		status: string;
	},
): Promise<{ id: string; status: string }> {
	if (!data.user_id || !data.org_id || !data.status) {
		throw new Error("user_id, org_id, and status are required");
	}
	const database = db(env);
	const membership = await database.mutate<{ id: string; status: string }>(
		"memberships",
		{
			user_id: data.user_id,
			org_id: data.org_id,
			status: data.status,
		},
	);
	return { id: membership.id, status: membership.status };
}

/**
 * Update membership status in SSO database
 */
export async function performUpdateMembershipStatus(
	env: Env,
	data: {
		membership_id: string;
		status: string;
	},
): Promise<{ success: boolean }> {
	if (!data.membership_id || !data.status) {
		throw new Error("membership_id and status are required");
	}
	const database = db(env);
	await database.update(
		"memberships",
		{ id: `eq.${encodeURIComponent(data.membership_id)}` },
		{ status: data.status },
	);

	try {
		const membership = await database.queryOne<{ user_id: string; org_id: string }>(
			`memberships?id=eq.${encodeURIComponent(data.membership_id)}&select=user_id,org_id`,
		);
		if (membership && env.SYNC_QUEUE) {
			await env.SYNC_QUEUE.send({
				type: 'membership.role_changed',
				payload: {
					user_id: membership.user_id,
					organization_id: membership.org_id,
					status: data.status,
				},
				timestamp: new Date().toISOString(),
			});
		}
	} catch (e) {
		console.error(`[SSO] Failed to publish sync event for membership ${data.membership_id}:`, e);
	}

	return { success: true };
}

/**
 * Assign role to membership (idempotent — skip if already assigned)
 */
export async function performAssignMembershipRole(
	env: Env,
	data: {
		membership_id: string;
		role_id: string;
	},
): Promise<{ success: boolean }> {
	if (!data.membership_id || !data.role_id) {
		throw new Error("membership_id and role_id are required");
	}
	const database = db(env);
	const existing = await database.query<{ id: string }>(
		`membership_roles?membership_id=eq.${encodeURIComponent(data.membership_id)}&role_id=eq.${encodeURIComponent(data.role_id)}&select=id`,
	);
	if (existing.length > 0) return { success: true };
	await database.mutate("membership_roles", {
		membership_id: data.membership_id,
		role_id: data.role_id,
	});

	try {
		const [membership, roleRow] = await Promise.all([
			database.queryOne<{ user_id: string; org_id: string }>(
				`memberships?id=eq.${encodeURIComponent(data.membership_id)}&select=user_id,org_id`,
			),
			database.queryOne<{ name: string }>(
				`roles?id=eq.${encodeURIComponent(data.role_id)}&select=name`,
			),
		]);
		if (membership && roleRow && env.SYNC_QUEUE) {
			await env.SYNC_QUEUE.send({
				type: 'membership.role_changed',
				payload: {
					user_id: membership.user_id,
					organization_id: membership.org_id,
					roles: [roleRow.name],
				},
				timestamp: new Date().toISOString(),
			});
		}
	} catch (e) {
		console.error(`[SSO] Failed to publish sync event for membership role ${data.membership_id}:`, e);
	}

	return { success: true };
}
