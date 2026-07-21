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
	} catch (err: any) {
		if (
			err?.message?.includes("duplicate") ||
			err?.message?.includes("23505")
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
		try {
			await env.SYNC_QUEUE.send({
				type: "user.created",
				payload: {
					id: result.user_id,
					email,
					user_metadata: {
						role: data.role, // Include role for Skillpassport sync
					},
				},
				timestamp: new Date().toISOString(),
			});
			await env.SYNC_QUEUE.send({
				type: "membership.created",
				payload: {
					user_id: result.user_id,
					organization_id: data.org_id,
					roles: [data.role],
					status: "active",
				},
				timestamp: new Date().toISOString(),
			});
		} catch (e) {
			console.error("[SSO] Failed to emit sync events:", e);
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
	return { success: true };
}
