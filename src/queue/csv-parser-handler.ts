import { getBatch, markBatchFailed, saveBatch } from "../lib/batch-kv";
import {
	mapCSVRowToLearnerData,
	parseCSV,
	validateCSVRow,
} from "../lib/csv-parser";
import { getErrorMessage } from "../lib/error-utils";
import { hashPassword } from "../lib/hash";
import type { LearnerBatchItem } from "../lib/learner-types";
import type { Env, QueueMessage } from "../types";

interface CsvParseMessage {
	batch_id: string;
	csv_data: string;
	organization_id: string;
	admin_id?: string;
	retry_count?: number;
}

export async function handleParseCsvQueue(
	env: Env,
	body: CsvParseMessage,
	message: QueueMessage<CsvParseMessage>,
): Promise<void> {
	const { batch_id, csv_data, organization_id, retry_count = 0 } = body;

	try {
		console.log(
			`[SSO] Parsing CSV for batch ${batch_id}, retry ${retry_count}`,
		);

		// Parse CSV (fast, in-memory only)
		const { rows, errors: parseErrors } = parseCSV(csv_data);

		if (parseErrors.length > 0) {
			console.error(
				`[SSO] CSV parsing errors for batch ${batch_id}:`,
				parseErrors,
			);
			await markBatchFailed(
				env,
				batch_id,
				`CSV parsing failed: ${parseErrors.join(", ")}`,
			);
			message.ack();
			return;
		}

		console.log(`[SSO] Parsed ${rows.length} rows from CSV batch ${batch_id}`);

		// Update batch metadata in KV with actual row count
		const existing = await getBatch(env, batch_id);
		if (existing) {
			existing.total_rows = rows.length;
			existing.status = "processing";
			await saveBatch(env, existing);
			console.log(
				`[batch-kv] Updated batch ${batch_id} total_rows to ${rows.length}`,
			);
		}

		// Validate and collect valid rows (fast, no I/O)
		let validCount = 0;
		let invalidCount = 0;
		const errorRecords: Array<{
			rowNumber: number;
			email: string;
			error: string;
		}> = [];

		// PRE-HASH all passwords in parallel (do it ONCE here, not in each queue job!)
		const { generateTempPassword } = await import("../lib/learner-helpers");
		const hashPromises = rows.map(async (row, i) => {
			const rowNumber = i + 1;
			const validation = validateCSVRow(row, rowNumber);

			if (!validation.valid) {
				return {
					rowNumber,
					error: validation.error || "Validation failed",
					email: row.email || "",
				};
			}

			// Generate temp password once per user
			const email = row.email.toLowerCase();
			const tempPassword = generateTempPassword();
			const passwordHash = await hashPassword(tempPassword);

			return {
				rowNumber,
				email,
				passwordHash,
				tempPassword,
				learnerData: mapCSVRowToLearnerData(row),
			};
		});

		const results: any[] = await Promise.all(hashPromises);

		// Collect messages and errors
		const LEARNER_BATCH_SIZE = 20; // Process 20 learners per queue message
		const learnerBatches: LearnerBatchItem[][] = [];
		let currentBatch: LearnerBatchItem[] = [];

		for (const result of results) {
			if ("error" in result) {
				errorRecords.push({
					rowNumber: result.rowNumber,
					email: result.email || "",
					error: result.error,
				});
				invalidCount++;
			} else {
				currentBatch.push({
					row_number: result.rowNumber,
					email: result.email,
					password_hash: result.passwordHash,
					temp_password: result.tempPassword, // ✅ Pass temp password to batch handler
					learner_data: result.learnerData,
				});

				// When batch is full, save it and start new batch
				if (currentBatch.length >= LEARNER_BATCH_SIZE) {
					learnerBatches.push([...currentBatch]);
					currentBatch = [];
				}
				validCount++;
			}
		}

		// Add remaining learners as final batch
		if (currentBatch.length > 0) {
			learnerBatches.push(currentBatch);
		}

		// Send batched queue messages (one message per 20 learners)
		for (let batchIndex = 0; batchIndex < learnerBatches.length; batchIndex++) {
			await env.LEARNER_ADMISSION_QUEUE.send({
				type: "create-learner-batch",
				job_id: `batch-${batch_id}-${batchIndex}`,
				batch_id,
				batch_index: batchIndex,
				learners: learnerBatches[batchIndex], // 20 learners with pre-hashed passwords
				organization_id,
				retry_count: 0,
			});
		}

		console.log(
			`[SSO] Batch ${batch_id}: Enqueued ${learnerBatches.length} batches (${validCount} learners, passwords pre-hashed), ${invalidCount} invalid rows`,
		);
		message.ack();
	} catch (error) {
		const errorMsg = getErrorMessage(error);
		console.error(`[SSO] Error parsing CSV batch ${batch_id}:`, errorMsg);

		// Retry logic
		if (retry_count >= 2) {
			console.error(
				`[SSO] Max retries reached for parse-csv batch ${batch_id}, moving to DLQ`,
			);
			await markBatchFailed(
				env,
				batch_id,
				`Failed after ${retry_count + 1} attempts: ${errorMsg}`,
			);
			message.ack(); // Send to DLQ
		} else {
			message.retry();
		}
	}
}
