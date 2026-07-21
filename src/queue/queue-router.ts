/**
 * Queue Message Router
 * Routes incoming queue messages to appropriate handlers
 * Keeps index.ts clean and focused on RPC methods
 */

import { db } from "../lib/db";
import type { Env, MessageBatch, QueueMessage } from "../types";
import type { CsvParseMessage } from "./csv-parser-handler";
import { handleParseCsvQueue } from "./csv-parser-handler";
import type { LearnerBatchMessage } from "./learner-batch-handler";
import { handleCreateLearnerBatch } from "./learner-batch-handler";

interface QueueMessageBody {
	type?: string;
	event_type?: string;
	user_id?: string;
	[key: string]: unknown;
}

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

	// CSV Parsing Handler
	if (body.type === "parse-csv") {
		await handleParseCsvQueue(
			env,
			body as unknown as CsvParseMessage,
			message as unknown as QueueMessage<CsvParseMessage>,
		);
		return true;
	}

	// Batch Creation Handler (20 learners at once)
	if (body.type === "create-learner-batch") {
		await handleCreateLearnerBatch(
			env,
			body as unknown as LearnerBatchMessage,
			message as unknown as QueueMessage<LearnerBatchMessage>,
		);
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
	const { first_name, last_name } =
		(body.payload as Record<string, unknown>) || {};

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
	// Handle DLQ messages
	if (batch.queue === "learner-admission-dlq") {
		for (const message of batch.messages) {
			console.error(
				`[DLQ] Unrecoverable message from ${batch.queue}:`,
				JSON.stringify(message.body),
			);
			message.ack();
		}
		return;
	}

	// Route each message to appropriate handler
	for (const message of batch.messages) {
		try {
			await routeQueueMessage(env, message, message.body);
		} catch (err) {
			console.error("[SSO] Failed to process queue message:", err);
			message.retry();
		}
	}
}
