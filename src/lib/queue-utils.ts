/**
 * Queue operation utilities
 * ponytail: Extracted to eliminate duplicate batch-send loops
 */

import { getErrorMessage } from "./error-utils";

/**
 * Send items to queue in batches
 * @param queue - Cloudflare Queue instance
 * @param items - Items to send
 * @param label - Label for logging (e.g., 'sync', 'email')
 * @param batchSize - Number of items per batch (default: 100)
 * @returns Number of items successfully enqueued
 * @throws Error if any batch fails — Cloudflare Queues `sendBatch` rejects only
 *   when messages were NOT enqueued (no auto-retry by the runtime), so swallowing
 *   the error would silently drop messages. Caller should handle by retrying the
 *   whole operation or recording the loss against the batch.
 */
export async function sendBatchToQueue<T>(
	queue: Queue<T>,
	items: T[],
	label: string,
	batchSize: number = 100,
): Promise<number> {
	if (items.length === 0) return 0;

	let enqueued = 0;
	for (let i = 0; i < items.length; i += batchSize) {
		const chunk = items.slice(i, i + batchSize);
		try {
			await queue.sendBatch(chunk.map((item) => ({ body: item })));
			enqueued += chunk.length;
		} catch (err) {
			console.error(
				`[SSO] Failed to queue ${label} batch (${chunk.length} items at offset ${i}):`,
				err,
			);
			throw new Error(
				`Failed to enqueue ${items.length - enqueued} of ${items.length} ${label} items (dropped at offset ${i}): ${getErrorMessage(err)}`,
			);
		}
	}
	return enqueued;
}

/**
 * Assert that a queue is properly bound
 * @param queue - Queue instance or undefined
 * @param queueName - Name of the queue for error messages
 * @returns The queue if bound
 * @throws Error if queue is not bound
 */
export function assertQueueBound<T>(
	queue: T | undefined,
	queueName: string,
): T {
	if (!queue) {
		throw new Error(`${queueName} not bound`);
	}
	return queue;
}
