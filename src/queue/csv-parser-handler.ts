import { getBatch, markBatchFailed, recordRowError, saveBatch } from "../lib/batch-kv";
import {
	mapCSVRowToLearnerData,
	parseCSV,
	validateCSVRow,
} from "../lib/csv-parser";
import { getErrorMessage } from "../lib/error-utils";
import { hashPassword } from "../lib/hash";
import type { LearnerBatchItem } from "../lib/learner-types";
import { generateTempPassword } from "../lib/learner-helpers";
import type { Env, QueueMessage } from "../types";

export interface CsvParseMessage {
	batch_id: string;
	csv_data: string;
	organization_id: string;
	admin_id?: string;
}

export async function handleParseCsvQueue(
	env: Env,
	body: CsvParseMessage,
	message: QueueMessage<CsvParseMessage>,
): Promise<void> {
	const { batch_id, csv_data, organization_id } = body;

	try {
		console.log(`[SSO] Parsing CSV for batch ${batch_id}`);

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
			| {
					rowNumber: number;
					email: string;
					passwordHash: string;
					tempPassword: string;
					learnerData: {
						email: string;
						name: string;
						contact_number?: string;
						enrollment_number?: string;
						program_id?: string;
						metadata?: Record<string, unknown>;
					};
			  };

		const hashPromises = rows.map(async (row, i) => {
			const rowNumber = i + 1;
			const validation = validateCSVRow(row, rowNumber);
			if (!validation.valid) {
				return { rowNumber, error: validation.error || "Validation failed", email: row.email || "" };
			}
			const email = row.email.toLowerCase();
			const tempPassword = generateTempPassword();
			const passwordHash = await hashPassword(tempPassword);
			return { rowNumber, email, passwordHash, tempPassword, learnerData: mapCSVRowToLearnerData(row) };
		});

		const results: HashResult[] = await Promise.all(hashPromises);

		const LEARNER_BATCH_SIZE = 20;
		const learnerBatches: LearnerBatchItem[][] = [];
		let currentBatch: LearnerBatchItem[] = [];

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
					learner_data: result.learnerData,
				});
				if (currentBatch.length >= LEARNER_BATCH_SIZE) {
					learnerBatches.push([...currentBatch]);
					currentBatch = [];
				}
				validCount++;
			}
		}

		if (currentBatch.length > 0) {
			learnerBatches.push(currentBatch);
		}

		for (const record of errorRecords) {
			await recordRowError(env, batch_id, record.rowNumber, record.email, record.error);
		}

		for (let batchIndex = 0; batchIndex < learnerBatches.length; batchIndex++) {
			await env.LEARNER_ADMISSION_QUEUE.send({
				type: "create-learner-batch",
				job_id: `batch-${batch_id}-${batchIndex}`,
				batch_id,
				batch_index: batchIndex,
				learners: learnerBatches[batchIndex],
				organization_id,
			});
		}

		console.log(
			`[SSO] Batch ${batch_id}: Enqueued ${learnerBatches.length} batches (${validCount} learners, passwords pre-hashed), ${invalidCount} invalid rows`,
		);
		message.ack();
	} catch (error) {
		const errorMsg = getErrorMessage(error);
		console.error(`[SSO] Error parsing CSV batch ${batch_id}:`, errorMsg);
		message.retry();
	}
}
