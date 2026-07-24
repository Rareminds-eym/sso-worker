import { createBatch } from "../lib/batch-kv";
import { db } from "../lib/db";
import { buildLearnerInvitationEmail } from "../lib/email-templates";
import { getErrorMessage } from "../lib/error-utils";
import { hashPassword } from "../lib/hash";
import {
	validateLearnerData,
	generateTempPassword,
	splitName,
	checkUserExists,
	getLearnerRole,
} from "../lib/learner-helpers";
import { ensureOrganizationExists } from "../lib/organization-sync";
import { isValidUUID } from "../lib/validate";
import type { Env } from "../types";

/**
 * Create learner user account (for bulk admission or manual entry)
 * Creates user in SSO DB, syncs to Skillpassport via queue, sends invitation email
 *
 * @param env Worker environment
 * @param data Learner user data
 * @returns { success, user_id, temp_password }
 */
export async function performCreateLearnerUser(
	env: Env,
	data: {
		email: string;
		name: string;
		organization_id: string;
		contact_number?: string;
		enrollment_number?: string;
		program_id?: string;
		metadata?: Record<string, unknown>;
	},
): Promise<{
	success: boolean;
	user_id?: string;
	temp_password?: string;
	error?: string;
	sync_warning?: string;
}> {
	// Validate input
	const validation = validateLearnerData(data);
	if (!validation.valid) {
		return { success: false, error: validation.error };
	}

	// Validate organization_id UUID format
	if (!isValidUUID(data.organization_id)) {
		return {
			success: false,
			error: "Invalid organization_id format (must be a valid UUID)",
		};
	}

	const database = db(env);
	const {
		name,
		organization_id,
		contact_number,
		enrollment_number,
		program_id,
		metadata,
	} = data;
	const email = data.email.toLowerCase().trim();

	try {
		// Check if user already exists
		const exists = await checkUserExists(database, email);
		if (exists) {
			return {
				success: false,
				error: `User with email ${email} already exists`,
			};
		}

		// Verify learner role exists before creating user (prevents orphaned users)
		const learnerRoleId = await getLearnerRole(database);
		if (!learnerRoleId) {
			return { success: false, error: "Learner role not found in database" };
		}

		// Generate temporary password for immediate login
		const tempPassword = generateTempPassword();
		const passwordHash = await hashPassword(tempPassword);

		// Split name
		const { first_name, last_name } = splitName(name);

		// Create user in SSO DB
		const user = await database.mutate<{ id: string; email: string }>("users", {
			email,
			password_hash: passwordHash,
			user_metadata: {
				first_name,
				last_name,
				contact_number,
				enrollment_number,
				program_id,
				role: "learner",
				...metadata,
			},
			is_email_verified: true, // Learners are auto-verified (admin-created accounts)
		});

		console.log(`[SSO] Created learner user ${user.id} for ${email}`);

		// CREATE MEMBERSHIP AND ROLE for learner in SSO DB
		let membershipCreated = false;
		try {
			// Race-safe org upsert — concurrent inserts both succeed, one returns existing row
			await ensureOrganizationExists(env, organization_id);

			// Upsert membership (race-safe: check-insert-catch-recheck)
			let membershipId: string | undefined;

			try {
				const membershipResult = await database.query<{ id: string }>(
					`memberships?user_id=eq.${encodeURIComponent(user.id)}&org_id=eq.${encodeURIComponent(organization_id)}&select=id`,
				);

				if (membershipResult.length > 0) {
					membershipId = membershipResult[0].id;
					console.log(`[SSO] Membership already exists: ${membershipId}`);
				} else {
					const membership = await database.mutate<{ id: string }>(
						"memberships",
						{
							user_id: user.id,
							org_id: organization_id,
							status: "active",
						},
					);
					membershipId = membership.id;
				}
			} catch (insertError) {
				// Duplicate key from concurrent request — re-check
				const error = insertError as Error & { code?: string | number };
				const errorMsg = (error?.message || String(insertError)).toLowerCase();

				const isDuplicateError =
					error?.code === "23505" ||
					errorMsg.includes("duplicate key") ||
					errorMsg.includes("unique constraint");

				if (isDuplicateError) {
					console.log(
						`[SSO] Membership inserted by concurrent request, re-fetching for user ${user.id}`,
					);
					const retryResult = await database.query<{ id: string }>(
						`memberships?user_id=eq.${encodeURIComponent(user.id)}&org_id=eq.${encodeURIComponent(organization_id)}&select=id`,
					);
					if (retryResult.length > 0) {
						membershipId = retryResult[0].id;
					} else {
						throw new Error("Membership lost after concurrent insert detected");
					}
				} else {
					throw insertError;
				}
			}

			if (!membershipId) {
				throw new Error("Failed to create or retrieve membership");
			}

			// Upsert membership_role (race-safe: check first)
			const roleResult = await database.query<{ id: string }>(
				`membership_roles?membership_id=eq.${encodeURIComponent(membershipId)}&role_id=eq.${encodeURIComponent(learnerRoleId)}&select=id`,
			);

			if (roleResult.length === 0) {
				try {
					await database.mutate("membership_roles", {
						membership_id: membershipId,
						role_id: learnerRoleId,
					});
				} catch (roleInsertError) {
					// Duplicate from concurrent request is OK
					const errorMsg =
						roleInsertError instanceof Error
							? roleInsertError.message
							: String(roleInsertError);
					if (
						!errorMsg.includes("duplicate") &&
						!errorMsg.includes("23505") &&
						!errorMsg.includes("unique")
					) {
						throw roleInsertError;
					}
				}
			}

			console.log(
				`[SSO] Membership setup complete for learner ${user.id} in org ${organization_id}`,
			);
			membershipCreated = true;
		} catch (membershipError) {
			console.error(
				`[SSO] Failed to create membership for learner ${user.id}:`,
				membershipError,
			);
			// Don't fail user creation, but track that membership failed
			membershipCreated = false;
		}

		// If membership creation failed, return error immediately
		if (!membershipCreated) {
			return {
				success: false,
				error: `User created in SSO but membership setup failed for organization ${organization_id}`,
				user_id: user.id,
			};
		}

		// Publish to auth-db-sync-queue and email queue (with error handling)
		if (!env.SYNC_QUEUE) {
			console.error(
				`[SSO] SYNC_QUEUE not bound, learner ${user.id} created but not synced`,
			);
			return {
				success: true,
				user_id: user.id,
				temp_password: tempPassword,
				sync_warning:
					"SYNC_QUEUE not bound - sync skipped, manual reconciliation needed",
			};
		}

		try {
			await env.SYNC_QUEUE.send({
				type: "user.created",
				payload: {
					id: user.id,
					email: user.email,
					is_email_verified: true,
					user_metadata: {
						first_name,
						last_name,
						contact_number,
						enrollment_number,
						program_id,
						role: "learner",
					},
				},
				timestamp: new Date().toISOString(),
			});

			console.log(
				`[SSO] Published user.created event for ${user.id} to sync queue`,
			);

			await env.SYNC_QUEUE.send({
				type: "membership.created",
				payload: {
					user_id: user.id,
					organization_id,
					roles: ["learner"],
					status: "active",
				},
				timestamp: new Date().toISOString(),
			});

			console.log(
				`[SSO] Published membership.created event for learner ${user.id} to sync queue`,
			);

			if (!env.EMAIL_QUEUE) {
				console.error(
					`[SSO] EMAIL_QUEUE not bound, cannot send invitation for ${user.id}`,
				);
				return {
					success: true,
					user_id: user.id,
					temp_password: tempPassword,
					sync_warning:
						"Email queue not bound - invitation not sent. Use temp_password or forgot password flow.",
				};
			}

			const loginUrl = `${env.SKILLPASSPORT_URL}/login`;
			const template = buildLearnerInvitationEmail(
				name,
				user.email,
				tempPassword,
				loginUrl,
			);

			await env.EMAIL_QUEUE.send({
				type: "send-email",
				to: user.email,
				subject: template.subject,
				html: template.html,
				text: template.text,
			});

			console.log(
				`[SSO] Published email invitation for ${user.id} to email queue`,
			);
		} catch (queueError) {
			const queueErrorMsg = getErrorMessage(queueError);
			console.error(
				`[SSO] Failed to queue sync events for ${user.id}:`,
				queueErrorMsg,
			);
			console.error(
				`[SSO] MANUAL ACTION REQUIRED: User ${user.id} (${email}) created but not synced to Skillpassport`,
			);
			return {
				success: true,
				user_id: user.id,
				temp_password: tempPassword,
				sync_warning: "User created but sync to Skillpassport failed",
			};
		}

		return {
			success: true,
			user_id: user.id,
			temp_password: tempPassword,
		};
	} catch (error) {
		const errorMsg = getErrorMessage(error);
		console.error(`[SSO] Error creating learner user for ${email}:`, errorMsg);
		return { success: false, error: errorMsg };
	}
}

/**
 * Queue bulk learner upload (RPC method)
 * Called by Skillpassport to initiate bulk CSV processing
 */
export async function performQueueBulkLearnerUpload(
	env: Env,
	data: {
		csv_data: string;
		organization_id: string;
		admin_id: string;
	},
): Promise<{ success: boolean; batch_id?: string; error?: string }> {
	if (!data.csv_data || !data.csv_data.trim() || !data.organization_id) {
		return {
			success: false,
			error: "csv_data and organization_id are required",
		};
	}

	try {
		// Generate batch ID
		const batchId = `BATCH-${new Date().toISOString().split("T")[0]}-${Date.now()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;

		console.log(
			`[SSO] Queueing bulk upload batch ${batchId} for org ${data.organization_id}`,
		);

		// Quick row count from CSV string (header is first line, data rows are the rest)
		const csvLines = data.csv_data.trim().split("\n");
		const estimatedRows = csvLines.length > 1 ? csvLines.length - 1 : 0;

		// Create batch in KV immediately so frontend can start polling
		await createBatch(
			env,
			batchId,
			data.admin_id || "system",
			data.organization_id,
			estimatedRows,
		).catch((err) => {
			console.error(`[SSO] Failed to create batch in KV: ${err}`);
		});

		if (!env.LEARNER_ADMISSION_QUEUE) {
			const errorMsg = "LEARNER_ADMISSION_QUEUE not bound";
			console.error(`[SSO] ${errorMsg}`);
			throw new Error(errorMsg);
		}

		try {
			await env.LEARNER_ADMISSION_QUEUE.send({
				type: "parse-csv",
				batch_id: batchId,
				csv_data: data.csv_data,
				organization_id: data.organization_id,
				admin_id: data.admin_id,
			});
		} catch (queueError) {
			const errorMsg = getErrorMessage(queueError);
			throw new Error(`Failed to queue bulk upload: ${errorMsg}`);
		}

		console.log(`[SSO] Queued parse-csv job for batch ${batchId}`);

		return {
			success: true,
			batch_id: batchId,
		};
	} catch (error) {
		const errorMsg = getErrorMessage(error);
		console.error(`[SSO] Error queueing bulk upload:`, errorMsg);
		return { success: false, error: errorMsg };
	}
}
