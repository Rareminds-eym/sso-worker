import { db } from "../lib/db";
import { getErrorMessage } from "../lib/error-utils";
import type { Env } from "../types";

/**
 * Checks if a user exists in Skillpassport and only creates queue
 * messages if the user is missing.
 *
 * Use case: Called after successful login to ensure user data is synced
 */
export async function performQueueUserSync(
	env: Env,
	userId: string,
): Promise<{ queued: boolean; reason: string }> {
	if (!userId) {
		throw new Error("userId is required");
	}

	if (!env.SYNC_QUEUE) {
		console.error("[SSO] SYNC_QUEUE not bound");
		return { queued: false, reason: "SYNC_QUEUE not bound" };
	}

	const { checkUserExistsInSkillpassport } = await import(
		"../lib/skillpassport-check"
	);
	const exists = await checkUserExistsInSkillpassport(env, userId);

	if (exists) {
		console.log(
			`[SSO] queueUserSync: User ${userId} already exists in Skillpassport`,
		);
		return { queued: false, reason: "User already synced" };
	}

	// User doesn't exist, fetch their data from SSO DB and queue sync
	const database = db(env);

	let user;
	try {
		user = await database.queryOne<{
			id: string;
			email: string;
			user_metadata: Record<string, unknown>;
		}>(
			`users?id=eq.${encodeURIComponent(userId)}&select=id,email,user_metadata`,
		);
	} catch (dbError) {
		const errorMsg = getErrorMessage(dbError);
		console.error(
			`[SSO] queueUserSync: Database error fetching user ${userId}:`,
			errorMsg,
		);
		return { queued: false, reason: `Database error: ${errorMsg}` };
	}

	if (!user) {
		console.error(`[SSO] queueUserSync: User ${userId} not found in SSO DB`);
		return { queued: false, reason: "User not found in SSO database" };
	}

	// Fetch user's primary organization and its membership id (needed to look up roles)
	let membership;
	try {
		membership = await database.queryOne<{
			id: string;
			org_id: string;
		}>(
			`memberships?user_id=eq.${encodeURIComponent(userId)}&select=id,org_id&limit=1`,
		);
	} catch (dbError) {
		const errorMsg = getErrorMessage(dbError);
		console.error(
			`[SSO] queueUserSync: Database error fetching membership for ${userId}:`,
			errorMsg,
		);
		// Continue without membership - user sync can still proceed
	}

	try {
		// Queue user sync
		await env.SYNC_QUEUE.send({
			type: "user.created",
			payload: {
				id: user.id,
				email: user.email,
				user_metadata: user.user_metadata || {},
			},
			timestamp: new Date().toISOString(),
		});

		// If user has organization, queue that too
		if (membership) {
			let org;
			try {
				org = await database.queryOne<{
					id: string;
					name: string;
				}>(
					`organizations?id=eq.${encodeURIComponent(membership.org_id)}&select=id,name`,
				);
			} catch (dbError) {
				const errorMsg = getErrorMessage(dbError);
				console.error(
					`[SSO] queueUserSync: Database error fetching org ${membership.org_id}:`,
					errorMsg,
				);
				// Continue without org sync - user sync already completed
			}

			if (org) {
				// Fetch the user's actual roles for this membership — previously this
				// was hardcoded to ["learner"], which silently mis-synced admins
				// and instructors as learners to Skillpassport.
				let roles: string[] = [];
				try {
					const membershipRoles = await database.query<{
						roles: { name: string } | null;
					}>(
						`membership_roles?membership_id=eq.${encodeURIComponent(membership.id)}&select=roles(name)`,
					);
					roles = membershipRoles
						.map((mr) => mr.roles?.name)
						.filter((n): n is string => typeof n === "string");
				} catch (dbError) {
					const errorMsg = getErrorMessage(dbError);
					console.error(
						`[SSO] queueUserSync: Database error fetching roles for membership ${membership.id}:`,
						errorMsg,
					);
				}

				await env.SYNC_QUEUE.send({
					type: "organization.created",
					payload: {
						id: org.id,
						name: org.name,
					},
					timestamp: new Date().toISOString(),
				});

				await env.SYNC_QUEUE.send({
					type: "membership.created",
					payload: {
						user_id: user.id,
						organization_id: membership.org_id,
						roles: roles.length > 0 ? roles : ["learner"],
						status: "active",
					},
					timestamp: new Date().toISOString(),
				});
			}
		}

		console.log(`[SSO] queueUserSync: Queued sync for user ${userId}`);
		return { queued: true, reason: "User sync queued successfully" };
	} catch (queueError) {
		const errorMsg = getErrorMessage(queueError);
		console.error(
			`[SSO] queueUserSync: Failed to queue sync for user ${userId}:`,
			errorMsg,
		);
		return { queued: false, reason: `Queue error: ${errorMsg}` };
	}
}
