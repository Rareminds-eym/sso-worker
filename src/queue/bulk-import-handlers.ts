/**
 * Generic queue handlers for bulk CSV imports (learner / faculty).
 *
 * Two factories:
 *  - createCsvParseHandler: parse CSV → validate → pre-hash temp passwords →
 *    chunk into per-entity batches → enqueue create-* messages.
 *  - createBatchHandler: create users + memberships via lib/bulk-import's
 *    shared auth-db layer, then publish sync events + invitation emails.
 *
 * Entity-specific behavior (validation, mapping, user_metadata shape, sync
 * events, email template) lives in a BulkImportAdapter (see bulk-import-adapters).
 * The queue wire format is unchanged: items keep the learner_data/faculty_data
 * key and the learners/faculties array key, so in-flight messages stay valid.
 */

import { getBatch, markBatchFailed, recordRowError, saveBatch, updateBatchProgress } from "../lib/batch-kv";
import { createUsersAndMemberships, type CreatedUser, type UserToCreate } from "../lib/bulk-import";
import { parseCSV, type CSVRow } from "../lib/csv-parser";
import { getErrorMessage } from "../lib/error-utils";
import { hashPassword } from "../lib/hash";
import { generateTempPassword } from "../lib/learner-helpers";
import { ensureOrganizationExists } from "../lib/organization-sync";
import { sendBatchToQueue } from "../lib/queue-utils";
import type { Env, QueueMessage } from "../types";

export interface CsvParseMessage {
	batch_id: string;
	csv_data: string;
	organization_id: string;
	admin_id?: string;
}

export interface BatchCreateMessage {
	batch_id: string;
	batch_index: number;
	organization_id: string;
	[key: string]: unknown;
}

/** A row inside a create-* queue message. */
export interface BulkItem {
	row_number: number;
	email: string;
	password_hash: string;
	temp_password: string;
}

export interface SyncEventLike {
	type: string;
	payload: Record<string, unknown>;
	timestamp: string;
}

export interface EmailEventLike {
	subject: string;
	html: string;
	text: string;
}

/**
 * Per-entity configuration driving both queue handlers.
 */
export interface BulkImportAdapter<TData> {
	/** Key of the entity data object inside each item ("learner_data" | "faculty_data"). */
	itemDataKey: string;
	/** Key of the items array inside create-* messages ("learners" | "faculties"). */
	itemKey: string;
	/** Message type of the parse stage ("parse-csv" | "parse-faculty-csv"). */
	parseMessageType: string;
	/** Message type of the create stage ("create-learner-batch" | "create-faculty-batch"). */
	createMessageType: string;
	/** Prefix for job_id of enqueued create-* messages. */
	jobIdPrefix: string;
	/** Rows per create-* message. */
	batchSize?: number;
	/** CSV row validation for the parse stage. */
	validateRow(row: CSVRow, rowNumber: number): { valid: boolean; error?: string };
	/** CSV row → entity data mapping for the parse stage. */
	mapRow(row: CSVRow): TData;
	/** Membership role name to assign ("learner" | "college_educator"). */
	roleName: string;
	/** Item → SSO user payload for the bulk insert. */
	buildUser(item: BulkItem): UserToCreate;
	/** user_metadata subset published in the user.created sync event. */
	buildSyncUserMetadata(data: TData): Record<string, unknown>;
	/** Extra sync events beyond user.created + membership.created (e.g. faculty.created). */
	buildExtraSyncEvents?(item: BulkItem, user: CreatedUser, organizationId: string): SyncEventLike[];
	/** Invitation email template, or null to skip. */
	buildEmail(item: BulkItem, user: CreatedUser, loginUrl: string): EmailEventLike | null;
}

/**
 * Factory for the parse-CSV queue handler.
 * Replaces the duplicated learner/faculty CSV parser handlers.
 */
export function createCsvParseHandler<TData>(adapter: BulkImportAdapter<TData>) {
	return async function handleParseCsvQueue(
		env: Env,
		body: CsvParseMessage,
		message: QueueMessage<CsvParseMessage>,
	): Promise<void> {
		const { batch_id, csv_data, organization_id } = body;

		try {
			const { rows, errors: parseErrors } = parseCSV(csv_data);

			if (parseErrors.length > 0) {
				console.error(`[SSO] CSV parsing errors for batch ${batch_id}:`, parseErrors);
				await markBatchFailed(env, batch_id, `CSV parsing failed: ${parseErrors.join(", ")}`);
				message.ack();
				return;
			}

			console.log(`[SSO] Parsed ${rows.length} rows from CSV batch ${batch_id}`);

			const existing = await getBatch(env, batch_id);
			if (existing) {
				existing.total_rows = rows.length;
				existing.status = "processing";
				await saveBatch(env, existing);
				console.log(`[batch-kv] Updated batch ${batch_id} total_rows to ${rows.length}`);
			}

			let validCount = 0;
			let invalidCount = 0;
			const errorRecords: Array<{ rowNumber: number; email: string; error: string }> = [];

			type HashResult =
				| { rowNumber: number; error: string; email: string }
				| { rowNumber: number; email: string; passwordHash: string; tempPassword: string; data: TData };

			const hashPromises = rows.map(async (row, i) => {
				const rowNumber = i + 1;
				const validation = adapter.validateRow(row, rowNumber);
				if (!validation.valid) {
					return { rowNumber, error: validation.error || "Validation failed", email: row.email || "" };
				}
				const email = row.email.toLowerCase();
				const tempPassword = generateTempPassword();
				const passwordHash = await hashPassword(tempPassword);
				return { rowNumber, email, passwordHash, tempPassword, data: adapter.mapRow(row) };
			});

			const results: HashResult[] = await Promise.all(hashPromises);

			const batchSize = adapter.batchSize ?? 20;
			const itemBatches: Array<Record<string, unknown>[]> = [];
			let currentBatch: Record<string, unknown>[] = [];

			for (const result of results) {
				if ("error" in result) {
					errorRecords.push({ rowNumber: result.rowNumber, email: result.email || "", error: result.error });
					invalidCount++;
				} else {
					currentBatch.push({
						row_number: result.rowNumber,
						email: result.email,
						password_hash: result.passwordHash,
						temp_password: result.tempPassword,
						[adapter.itemDataKey]: result.data,
					});
					if (currentBatch.length >= batchSize) {
						itemBatches.push([...currentBatch]);
						currentBatch = [];
					}
					validCount++;
				}
			}

			if (currentBatch.length > 0) {
				itemBatches.push(currentBatch);
			}

			for (const record of errorRecords) {
				await recordRowError(env, batch_id, record.rowNumber, record.email, record.error);
			}

			for (let batchIndex = 0; batchIndex < itemBatches.length; batchIndex++) {
				await env.LEARNER_ADMISSION_QUEUE.send({
					type: adapter.createMessageType,
					job_id: `${adapter.jobIdPrefix}${batch_id}-${batchIndex}`,
					batch_id,
					batch_index: batchIndex,
					[adapter.itemKey]: itemBatches[batchIndex],
					organization_id,
				});
			}

			console.log(
				`[SSO] Batch ${batch_id}: Enqueued ${itemBatches.length} batches (${validCount} valid, passwords pre-hashed), ${invalidCount} invalid rows`,
			);
			message.ack();
		} catch (error) {
			const errorMsg = getErrorMessage(error);
			console.error(`[SSO] Error parsing CSV batch ${batch_id}:`, errorMsg);
			message.retry();
		}
	};
}

/**
 * Factory for the create-* queue handler.
 * Replaces the duplicated learner/faculty batch handlers.
 */
export function createBatchHandler<TData>(adapter: BulkImportAdapter<TData>) {
	return async function handleCreateBatch(
		env: Env,
		body: BatchCreateMessage,
		message: QueueMessage<BatchCreateMessage>,
	): Promise<void> {
		const { batch_id, batch_index, organization_id } = body;
		const items = (body[adapter.itemKey] as BulkItem[] | undefined) ?? [];

		try {
			console.log(`[SSO] Processing batch ${batch_index} with ${items.length} items`);

			const org = await ensureOrganizationExists(env, organization_id);
			if (!org) {
				throw new Error(`Organization ${organization_id} not found in SSO DB and could not be synced`);
			}

			const { createdUsers, rowErrors } = await createUsersAndMemberships(
				env,
				{ batch_id, batch_index, organization_id },
				items,
				adapter.buildUser,
				adapter.roleName,
			);

			const itemsByEmail = new Map(items.map((item) => [item.email, item]));
			await publishBatchSyncEvents(env, createdUsers, itemsByEmail, organization_id, batch_id, adapter);

			await updateBatchProgress(env, batch_id, {
				processed_rows_increment: createdUsers.length + rowErrors.length,
				success_count_increment: createdUsers.length,
				failed_count_increment: rowErrors.length,
			});

			for (const failed of rowErrors) {
				await recordRowError(env, batch_id, failed.rowNumber, failed.email, failed.error);
			}

			console.log(
				`[SSO] Batch ${batch_index}: Created ${createdUsers.length} users, ${rowErrors.length} failed`,
			);
			message.ack();
		} catch (error) {
			const errorMsg = getErrorMessage(error);
			console.error(`[SSO] Error processing batch ${batch_index}:`, errorMsg);
			message.retry();
		}
	};
}

/**
 * Publish user.created + membership.created (+ entity-specific events) to
 * SYNC_QUEUE and invitation emails to EMAIL_QUEUE for the created users.
 */
async function publishBatchSyncEvents<TData>(
	env: Env,
	users: CreatedUser[],
	itemsByEmail: Map<string, BulkItem>,
	organization_id: string,
	batch_id: string,
	adapter: BulkImportAdapter<TData>,
): Promise<void> {
	const syncEvents: SyncEventLike[] = [];
	const emailEvents: Array<EmailEventLike & { type: string; to: string }> = [];

	for (const user of users) {
		const item = itemsByEmail.get(user.email);
		if (!item) continue;

		const data = (item as unknown as Record<string, unknown>)[adapter.itemDataKey] as TData;
		const timestamp = new Date().toISOString();

		syncEvents.push({
			type: "user.created",
			payload: {
				id: user.id,
				email: user.email,
				is_email_verified: true,
				user_metadata: adapter.buildSyncUserMetadata(data),
			},
			timestamp,
		});
		syncEvents.push({
			type: "membership.created",
			payload: {
				user_id: user.id,
				organization_id,
				roles: [adapter.roleName],
				status: "active",
			},
			timestamp,
		});
		if (adapter.buildExtraSyncEvents) {
			syncEvents.push(...adapter.buildExtraSyncEvents(item, user, organization_id));
		}

		try {
			const loginUrl = `${env.SKILLPASSPORT_URL}/login`;
			const template = adapter.buildEmail(item, user, loginUrl);
			if (template) {
				emailEvents.push({
					type: "send-email",
					to: user.email,
					subject: template.subject,
					html: template.html,
					text: template.text,
				});
			}
		} catch (err) {
			console.error(`[SSO] Failed to build template for ${user.email}:`, err);
		}
	}

	let syncFailures = 0;
	try {
		await sendBatchToQueue(env.SYNC_QUEUE, syncEvents, "sync");
	} catch (err) {
		syncFailures = syncEvents.length;
		console.error(`[SSO] Sync events lost for batch ${batch_id}:`, err);
		await recordRowError(env, batch_id, 0, "", `Sync events lost: ${getErrorMessage(err)}`);
	}

	try {
		await sendBatchToQueue(env.EMAIL_QUEUE, emailEvents, "email");
	} catch (err) {
		console.error(`[SSO] Email invitations lost for batch ${batch_id}:`, err);
		await recordRowError(env, batch_id, 0, "", `Email invitations lost: ${getErrorMessage(err)}`);
	}

	console.log(
		`[SSO] Published ${syncEvents.length - syncFailures}/${syncEvents.length} sync events and queued ${emailEvents.length} email invitations`,
	);
}
