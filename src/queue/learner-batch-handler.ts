import { recordRowError, updateBatchProgress } from "../lib/batch-kv";
import { db } from "../lib/db";
import { buildLearnerInvitationEmail } from "../lib/email-templates";
import { getErrorMessage } from "../lib/error-utils";
import { splitName } from "../lib/learner-helpers";
import type { LearnerBatchItem } from "../lib/learner-types";
import { ensureOrganizationExists } from "../lib/organization-sync";
import { sendBatchToQueue } from "../lib/queue-utils";
import type { Env, QueueMessage } from "../types";
import { createUser } from "./handlers/create-user";

export interface LearnerBatchMessage {
	batch_id: string;
	batch_index: number;
	learners: LearnerBatchItem[];
	organization_id: string;
	retry_count?: number;
}

interface CreatedUser {
	id: string;
	email: string;
	user_metadata?: Record<string, unknown>;
}

interface UserToCreate {
	email: string;
	password_hash: string;
	user_metadata: {
		first_name: string;
		last_name: string;
		contact_number?: string;
		enrollment_number?: string;
		program_id?: string;
		role: string;
	};
	is_email_verified: boolean;
}

interface CreatedMembership {
	id: string;
	user_id: string;
	org_id: string;
	status: string;
}

/**
 * Handle create-learner-batch queue message
 * Processes a batch of learners, creating users, memberships, and roles in bulk
 */
export async function handleCreateLearnerBatch(
	env: Env,
	body: LearnerBatchMessage,
	message: QueueMessage<LearnerBatchMessage>,
): Promise<void> {
	const {
		batch_id,
		batch_index,
		learners,
		organization_id,
		retry_count = 0,
	} = body;

	try {
		console.log(
			`[SSO] Processing batch ${batch_index} with ${learners.length} learners, retry ${retry_count}`,
		);

		const database = db(env);

		// Ensure organization exists before creating memberships
		const org = await ensureOrganizationExists(env, organization_id);
		if (!org) {
			throw new Error(
				`Organization ${organization_id} not found in SSO DB and could not be synced`,
			);
		}

		// ponytail: Build email map once instead of 3x find() calls (issue F1)
		const learnersByEmail = new Map(learners.map((l) => [l.email, l]));

		// Prepare all learners for bulk insert
		const usersToCreate: UserToCreate[] = [];
		const emailSet = new Set<string>();
		const duplicateEmails: string[] = [];

		for (const learner of learners) {
			const { email, password_hash, learner_data } = learner;

			// Check for duplicates within this batch
			if (emailSet.has(email)) {
				duplicateEmails.push(email);
				continue;
			}
			emailSet.add(email);

			const { first_name, last_name } = splitName(learner_data.name);

			usersToCreate.push({
				email,
				password_hash,
				user_metadata: {
					first_name,
					last_name,
					contact_number: learner_data.contact_number,
					enrollment_number: learner_data.enrollment_number,
					program_id: learner_data.program_id,
					role: "learner",
					...learner_data.metadata,
				},
				is_email_verified: true, // Bulk imports are trusted
			});
		}

		// Bulk insert all users in ONE database call (FAST!)
		let createdUsers: CreatedUser[] = [];
		const failedLearners: Array<{
			rowNumber: number;
			email: string;
			error: string;
		}> = [];

		if (usersToCreate.length > 0) {
			try {
				// Use DbClient bulk insert (issue D1 - eliminates duplicate headers)
				console.log(
					`[SSO] Attempting bulk insert of ${usersToCreate.length} users`,
				);
				createdUsers = await database.bulkInsert<CreatedUser>(
					"users",
					usersToCreate,
				);
				console.log(
					`[SSO] Bulk inserted ${createdUsers.length} users in batch ${batch_index}`,
				);

				// Create memberships and roles for all created users (BULK)
				await createMembershipsForBatch(env, createdUsers, organization_id);
			} catch (bulkError) {
				const errorText = getErrorMessage(bulkError);

				// If bulk insert fails due to duplicates, fall back to individual inserts
				if (errorText.includes("duplicate") || errorText.includes("23505")) {
					console.warn(
						`[SSO] Bulk insert failed with duplicates, falling back to individual inserts`,
					);

					for (let i = 0; i < usersToCreate.length; i++) {
						const userData = usersToCreate[i];
						const learner = learnersByEmail.get(userData.email); // Using map from issue F1

						if (!learner) continue;

					try {
						const user = await createUser(env, {
							email: userData.email,
							password_hash: userData.password_hash,
							first_name: userData.user_metadata.first_name,
							last_name: userData.user_metadata.last_name,
							metadata: userData.user_metadata,
							is_email_verified: true,
						});
						createdUsers.push({ id: user.user_id, email: user.email });
					} catch (err) {
							const errorMsg = getErrorMessage(err);
							if (
								errorMsg.includes("already exists") ||
								errorMsg.includes("23505") ||
								errorMsg.includes("duplicate")
							) {
								failedLearners.push({
									rowNumber: learner.row_number,
									email: userData.email,
									error: `User already exists`,
								});
							} else {
								throw err; // Re-throw for retry
							}
						}
					}

					// Create memberships for individually created users
					if (createdUsers.length > 0) {
						await createMembershipsForBatch(env, createdUsers, organization_id);
					}
				} else {
					throw new Error(`Bulk insert failed: ${errorText}`);
				}
			}
		}

		// Record duplicates from within batch
		for (const email of duplicateEmails) {
			const learner = learnersByEmail.get(email); // Using map from issue F1
			if (learner) {
				failedLearners.push({
					rowNumber: learner.row_number,
					email,
					error: `Duplicate email in batch`,
				});
			}
		}

		// Publish sync events for all created users (fire-and-forget)
		await publishSyncEventsForBatch(
			env,
			createdUsers,
			learnersByEmail,
			organization_id,
			batch_id,
		);

		// Update batch progress
		await updateBatchProgress(env, batch_id, {
			processed_rows_increment: createdUsers.length + failedLearners.length,
			success_count_increment: createdUsers.length,
			failed_count_increment: failedLearners.length,
		});

		// Record errors for failed learners
		for (const failed of failedLearners) {
			await recordRowError(
				env,
				batch_id,
				failed.rowNumber,
				failed.email,
				failed.error,
			);
		}

		console.log(
			`[SSO] Batch ${batch_index}: Created ${createdUsers.length} learners, ${failedLearners.length} failed`,
		);
		message.ack();
	} catch (error) {
		const errorMsg = getErrorMessage(error);
		console.error(`[SSO] Error processing batch ${batch_index}:`, errorMsg);

		// Retry entire batch on transient errors
		if (retry_count >= 3) {
			console.error(
				`[SSO] Max retries reached for batch ${batch_index}, moving to DLQ`,
			);

			// Mark all learners in batch as failed
			for (const learner of learners) {
				await recordRowError(
					env,
					batch_id,
					learner.row_number,
					learner.email,
					`Batch failed: ${errorMsg}`,
				);
			}
			await updateBatchProgress(env, batch_id, {
				processed_rows_increment: learners.length,
				failed_count_increment: learners.length,
			});

			message.ack(); // Send to DLQ
		} else {
			body.retry_count = retry_count + 1;
			message.retry();
		}
	}
}

/**
 * Create memberships and roles for a batch of users
 * ponytail: Extracted to reduce duplication, now uses DbClient.bulkInsert (issue D1)
 */
async function createMembershipsForBatch(
	env: Env,
	users: Array<{ id: string; email: string }>,
	organization_id: string,
): Promise<void> {
	const database = db(env);

	// Get learner role ID — a missing role is a config error, not transient.
	const learnerRole = await database.queryOne<{ id: string }>(
		`roles?name=eq.learner&select=id`,
	);

	if (!learnerRole) {
		throw new Error(
			"Learner role not found in database — cannot create memberships without a role to assign",
		);
	}

	// Bulk create memberships. Let errors propagate so the caller can retry the
	// whole batch — silently swallowing here would orphan users (created in the
	// users table with no membership/role) and they'd be counted as successes.
	const memberships = users.map((user) => ({
		user_id: user.id,
		org_id: organization_id,
		status: "active",
	}));

	const createdMemberships = await database.bulkInsert<CreatedMembership>(
		"memberships",
		memberships,
	);

	// Bulk create membership_roles
	const membershipRoles = createdMemberships.map((m) => ({
		membership_id: m.id,
		role_id: learnerRole.id,
	}));

	await database.bulkInsert("membership_roles", membershipRoles);
	console.log(
		`[SSO] Created ${createdMemberships.length} memberships and roles`,
	);
}

/**
 * Publish sync events and queue email invitations for created users
 * ponytail: Uses sendBatchToQueue helper (issue C1) and email map (issue F1)
 */
async function publishSyncEventsForBatch(
	env: Env,
	users: Array<{ id: string; email: string }>,
	learnersByEmail: Map<string, LearnerBatchItem>,
	organization_id: string,
	batch_id: string,
): Promise<void> {
	const syncEvents: Array<{
		type: string;
		payload: Record<string, unknown>;
		timestamp: string;
	}> = [];
	const emailEvents: Array<{
		type: string;
		to: string;
		subject: string;
		html: string;
		text: string;
	}> = [];

	// Collect all events
	for (const user of users) {
		const learner = learnersByEmail.get(user.email); // Using map from issue F1
		if (!learner) continue;

		const { first_name, last_name } = splitName(learner.learner_data.name);

		// User creation event
		syncEvents.push({
			type: "user.created",
			payload: {
				id: user.id,
				email: user.email,
				is_email_verified: true,
				user_metadata: {
					first_name,
					last_name,
					contact_number: learner.learner_data.contact_number,
					enrollment_number: learner.learner_data.enrollment_number,
					program_id: learner.learner_data.program_id,
					role: "learner",
				},
			},
			timestamp: new Date().toISOString(),
		});

		// Membership creation event
		syncEvents.push({
			type: "membership.created",
			payload: {
				user_id: user.id,
				organization_id,
				roles: ["learner"],
				status: "active",
			},
			timestamp: new Date().toISOString(),
		});

		// Build email template and queue
		try {
			const loginUrl = `${env.SKILLPASSPORT_URL}/login`;
			const template = buildLearnerInvitationEmail(
				learner.learner_data.name,
				user.email,
				learner.temp_password,
				loginUrl,
			);

			emailEvents.push({
				type: "send-email",
				to: user.email,
				subject: template.subject,
				html: template.html,
				text: template.text,
			});
		} catch (err) {
			console.error(`[SSO] Failed to build template for ${user.email}:`, err);
		}
	}

	// Send sync events. sendBatchToQueue throws on failure (Cloudflare Queues
	// sendBatch rejects only when messages were NOT enqueued — no auto-retry),
	// so we catch here and record the loss against the batch rather than letting
	// it fail the whole handler (users were already created in the DB).
	let syncFailures = 0;
	try {
		await sendBatchToQueue(env.SYNC_QUEUE, syncEvents, "sync");
	} catch (err) {
		syncFailures = syncEvents.length;
		console.error(`[SSO] Sync events lost for batch ${batch_id}:`, err);
		await recordRowError(
			env,
			batch_id,
			0,
			"",
			`Sync events lost: ${getErrorMessage(err)}`,
		);
	}

	// Send email events. Same treatment — a lost invitation email means the
	// user can't get their temp password, so record it visibly.
	try {
		await sendBatchToQueue(env.EMAIL_QUEUE, emailEvents, "email");
	} catch (err) {
		console.error(`[SSO] Email invitations lost for batch ${batch_id}:`, err);
		await recordRowError(
			env,
			batch_id,
			0,
			"",
			`Email invitations lost: ${getErrorMessage(err)}`,
		);
	}

	console.log(
		`[SSO] Published ${syncEvents.length - syncFailures}/${syncEvents.length} sync events and queued ${emailEvents.length} email invitations`,
	);
}
