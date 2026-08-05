/**
 * Queue Message Router
 * Routes incoming queue messages to appropriate handlers
 * Keeps index.ts clean and focused on RPC methods
 */

import { markBatchFailed, recordRowError, updateBatchProgress } from "../lib/batch-kv";
import { db } from "../lib/db";
import { getErrorMessage } from "../lib/error-utils";
import type { Env, MessageBatch, QueueMessage } from "../types";
import {
	BULK_CREATE_MESSAGE_TYPES,
	BULK_PARSE_MESSAGE_TYPES,
	handleCreateFacultyBatch,
	handleCreateLearnerBatch,
	handleParseCsvQueue,
	handleParseFacultyCsvQueue,
	learnerBulkImport,
} from "./bulk-import-adapters";
import type { BatchCreateMessage, CsvParseMessage } from "./bulk-import-handlers";

interface QueueMessageBody {
	type?: string;
	event_type?: string;
	user_id?: string;
	[key: string]: unknown;
}

function isCsvParseMessage(
	body: QueueMessageBody,
): body is QueueMessageBody & CsvParseMessage {
	return (
		typeof body.batch_id === "string" &&
		typeof body.csv_data === "string" &&
		typeof body.organization_id === "string"
	);
}

function isBatchCreateMessage(
	body: QueueMessageBody,
	itemKey: string,
): body is QueueMessageBody & BatchCreateMessage {
	return (
		typeof body.batch_id === "string" &&
		typeof body.batch_index === "number" &&
		Array.isArray(body[itemKey]) &&
		typeof body.organization_id === "string"
	);
}

interface BulkImportRegistration {
	isMessage: (body: QueueMessageBody) => boolean;
	handle: (env: Env, body: QueueMessageBody, message: QueueMessage<QueueMessageBody>) => Promise<void>;
}

/**
 * Bulk import handlers, keyed by queue message type. Guards run before the
 * handler, so the casts below are safe (the guard established the shape).
 */
const BULK_IMPORT_HANDLERS: Record<string, BulkImportRegistration> = {
	[learnerBulkImport.parseMessageType]: {
		isMessage: isCsvParseMessage,
		handle: handleParseCsvQueue as unknown as BulkImportRegistration["handle"],
	},
	[learnerBulkImport.createMessageType]: {
		isMessage: (body) => isBatchCreateMessage(body, learnerBulkImport.itemKey),
		handle: handleCreateLearnerBatch as unknown as BulkImportRegistration["handle"],
	},
	"parse-faculty-csv": {
		isMessage: isCsvParseMessage,
		handle: handleParseFacultyCsvQueue as unknown as BulkImportRegistration["handle"],
	},
	"create-faculty-batch": {
		isMessage: (body) => isBatchCreateMessage(body, "faculties"),
		handle: handleCreateFacultyBatch as unknown as BulkImportRegistration["handle"],
	},
};

/**
 * Route queue messages to appropriate handlers
 * Returns true if message was handled, false otherwise
 */
export async function routeQueueMessage(
	env: Env,
	message: QueueMessage<QueueMessageBody>,
	body: QueueMessageBody,
): Promise<boolean> {
	// Validate message body structure
	if (!body || typeof body !== "object") {
		console.warn("[SSO] Invalid queue message body:", message);
		message.ack();
		return true;
	}

	// ═══════════════════════════════════════════════════════════
	// BULK IMPORT HANDLERS (Learner Admission Queue)
	// ═══════════════════════════════════════════════════════════

	if (typeof body.type === "string" && BULK_IMPORT_HANDLERS[body.type]) {
		const registration = BULK_IMPORT_HANDLERS[body.type];
		if (!registration.isMessage(body)) {
			console.warn(`[SSO] Invalid ${body.type} message body:`, body);
			message.ack();
			return true;
		}
		await registration.handle(env, body, message);
		return true;
	}

	// ═══════════════════════════════════════════════════════════
	// REVERSE SYNC HANDLERS (Skillpassport → SSO)
	// ═══════════════════════════════════════════════════════════

	// User metadata bidirectional sync
	if (body.event_type === "user_metadata.updated" && body.user_id) {
		await handleUserMetadataSync(env, body, message);
		return true;
	}

	// ═══════════════════════════════════════════════════════════
	// PAYMENT WEBHOOK HANDLERS
	// ═══════════════════════════════════════════════════════════

	// Payment events (Razorpay, etc.)
	if (body.event_id && body.event_type && body.payload) {
		await handlePaymentEvent(env, body, message);
		return true;
	}

	// Unknown message type
	console.warn("[SSO] Unknown queue message type:", body);
	message.ack();
	return true;
}

/**
 * Handle user metadata sync from Skillpassport
 */
async function handleUserMetadataSync(
	env: Env,
	body: QueueMessageBody,
	message: QueueMessage<QueueMessageBody>,
): Promise<void> {
	const payload =
		typeof body.payload === "object" && body.payload !== null
			? (body.payload as Record<string, unknown>)
			: {};
	const { first_name, last_name } = payload;

	if (first_name !== undefined || last_name !== undefined) {
		try {
			const database = db(env);
			const user = await database.queryOne<{
				user_metadata?: Record<string, unknown>;
			}>(
				`users?id=eq.${encodeURIComponent(body.user_id as string)}&select=user_metadata`,
			);
			const currentMetadata = user?.user_metadata || {};

			const newMetadata = { ...currentMetadata };
			if (first_name !== undefined) newMetadata.first_name = first_name;
			if (last_name !== undefined) newMetadata.last_name = last_name;

			await database.update(
				"users",
				{ id: `eq.${encodeURIComponent(body.user_id as string)}` },
				{ user_metadata: newMetadata },
			);
			console.log(
				`[SSO] Bidirectional sync complete: updated user_metadata for user ${body.user_id}`,
			);

			// Broadcast to forward consumers
			if (env.SYNC_QUEUE) {
				const userObj = await database.queryOne<{ id: string; email: string }>(
					`users?id=eq.${encodeURIComponent(body.user_id as string)}&select=id,email`,
				);
				if (userObj) {
					await env.SYNC_QUEUE.send({
						type: "user.updated",
						payload: {
							id: userObj.id,
							email: userObj.email,
							user_metadata: newMetadata,
						},
						timestamp: new Date().toISOString(),
					});
				}
			}
		} catch (updateErr) {
			console.error(
				`[SSO] Failed to update user_metadata for ${body.user_id}:`,
				updateErr,
			);
			message.retry();
			return;
		}
	}

	message.ack();
}

/**
 * Handle payment event from queue
 */
async function handlePaymentEvent(
	env: Env,
	body: QueueMessageBody,
	message: QueueMessage<QueueMessageBody>,
): Promise<void> {
	const database = db(env);

	const eventId = body.event_id as string;
	const eventType = body.event_type as string;

	// Idempotency check
	const existing = await database.queryOne(
		`events?event_id=eq.${encodeURIComponent(eventId)}`,
	);

	if (existing) {
		console.log(`[SSO] Event ${eventId} already processed`);
		message.ack();
		return;
	}

	// Store event for processing by scheduled worker
	await database.mutate("events", {
		event_id: eventId,
		event_type: eventType,
		status: "received",
		payload: body.payload || {},
		user_id: body.user_id || null,
		subscription_id: body.subscription_id || null,
		razorpay_payment_id: body.razorpay_payment_id || null,
	});

	message.ack();
}

/**
 * Main queue handler - processes message batches
 */
export async function handleQueueBatch(
	env: Env,
	batch: MessageBatch,
): Promise<void> {
	// Handle DLQ messages — mark affected batches as failed so the frontend sees the error
	if (batch.queue === "learner-admission-dlq") {
		for (const message of batch.messages) {
			try {
				const body = message.body as Record<string, unknown>;
				const batchId = body?.batch_id as string | undefined;
				const msgType = typeof body?.type === "string" ? body.type : undefined;
				const errorMsg = `Processing failed after retries exhausted`;

				if (msgType && batchId && BULK_PARSE_MESSAGE_TYPES.includes(msgType)) {
					await markBatchFailed(env, batchId, errorMsg);
				} else if (msgType && batchId && BULK_CREATE_MESSAGE_TYPES[msgType]) {
					const itemKey = BULK_CREATE_MESSAGE_TYPES[msgType];
					const items = body?.[itemKey] as Array<{ row_number?: number; email?: string }> | undefined;
					if (Array.isArray(items)) {
						for (const item of items) {
							await recordRowError(env, batchId, item.row_number ?? 0, item.email ?? "", errorMsg);
						}
						await updateBatchProgress(env, batchId, {
							processed_rows_increment: items.length,
							failed_count_increment: items.length,
						});
					}
				}

				console.error(`[DLQ] batch=${batchId} type=${msgType}: ${errorMsg}`);
				message.ack();
			} catch (error) {
				console.error(`[DLQ] Failed to process DLQ message: ${getErrorMessage(error)}`);
				message.retry();
			}
		}
		return;
	}

	// Route each message to appropriate handler
	for (const message of batch.messages as readonly QueueMessage<QueueMessageBody>[]) {
		try {
			await routeQueueMessage(env, message, message.body);
		} catch (err) {
			console.error("[SSO] Failed to process queue message:", err);
			message.retry();
		}
	}
}
