/**
 * Bulk upload RPC — queues a bulk CSV import (learner / faculty).
 * Shared by performQueueBulkLearnerUpload / performQueueBulkFacultyUpload.
 */

import { createBatch } from "../lib/batch-kv";
import { getErrorMessage } from "../lib/error-utils";
import { assertQueueBound } from "../lib/queue-utils";
import type { Env } from "../types";

export interface QueueBulkUploadData {
	csv_data: string;
	organization_id: string;
	admin_id: string;
}

export type BulkParseMessageType = "parse-csv" | "parse-faculty-csv";

/**
 * Validate the client sent a CSV and the required org, then create the batch in
 * KV (so the UI can start polling immediately) and enqueue a parse-* message
 * with the RAW csv_data — the queue consumer never trusts client-side validation.
 */
export async function performQueueBulkUpload(
	env: Env,
	data: QueueBulkUploadData,
	parseMessageType: BulkParseMessageType,
): Promise<{ success: boolean; batch_id?: string; error?: string }> {
	if (!data.csv_data || !data.csv_data.trim() || !data.organization_id) {
		return {
			success: false,
			error: "csv_data and organization_id are required",
		};
	}

	try {
		const batchId = `BATCH-${new Date().toISOString().split("T")[0]}-${Date.now()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;

		console.log(`[SSO] Queueing bulk upload batch ${batchId} for org ${data.organization_id}`);

		const csvLines = data.csv_data.trim().split("\n");
		const estimatedRows = csvLines.length > 1 ? csvLines.length - 1 : 0;

		await createBatch(env, batchId, data.admin_id || "system", data.organization_id, estimatedRows).catch((err) => {
			console.error(`[SSO] Failed to create batch in KV: ${err}`);
		});

		const queue = assertQueueBound(env.LEARNER_ADMISSION_QUEUE, "LEARNER_ADMISSION_QUEUE");

		try {
			await queue.send({
				type: parseMessageType,
				batch_id: batchId,
				csv_data: data.csv_data,
				organization_id: data.organization_id,
				admin_id: data.admin_id,
			});
		} catch (queueError) {
			const errorMsg = getErrorMessage(queueError);
			throw new Error(`Failed to queue bulk upload: ${errorMsg}`);
		}

		console.log(`[SSO] Queued ${parseMessageType} job for batch ${batchId}`);

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

export function performQueueBulkLearnerUpload(
	env: Env,
	data: QueueBulkUploadData,
): Promise<{ success: boolean; batch_id?: string; error?: string }> {
	return performQueueBulkUpload(env, data, "parse-csv");
}

export function performQueueBulkFacultyUpload(
	env: Env,
	data: QueueBulkUploadData,
): Promise<{ success: boolean; batch_id?: string; error?: string }> {
	return performQueueBulkUpload(env, data, "parse-faculty-csv");
}
