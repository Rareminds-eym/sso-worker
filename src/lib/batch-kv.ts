/**
 * KV Helpers for Bulk Upload Batch Tracking
 * Stores batch metadata and progress in KV (7-day TTL)
 */

import type { Env } from '../types';

export interface BatchMetadata {
  batch_id: string;
  admin_id: string;
  organization_id: string;
  total_rows: number;
  processed_rows: number;
  success_count: number;
  failed_count: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  created_at: string;
  completed_at?: string;
  errors: Array<{
    row: number;
    email: string;
    error: string;
  }>;
}

const BATCH_KV_PREFIX = 'bulk-upload:';
const BATCH_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

/**
 * Create new batch metadata in KV
 */
export async function createBatch(
  env: Env,
  batchId: string,
  adminId: string,
  organizationId: string,
  totalRows: number
): Promise<void> {
  const metadata: BatchMetadata = {
    batch_id: batchId,
    admin_id: adminId,
    organization_id: organizationId,
    total_rows: totalRows,
    processed_rows: 0,
    success_count: 0,
    failed_count: 0,
    status: 'processing',
    created_at: new Date().toISOString(),
    errors: []
  };
  
  await saveBatch(env, metadata);
  
  console.log(`[batch-kv] Created batch ${batchId} with ${totalRows} rows`);
}

/**
 * Get batch metadata from KV
 */
export async function getBatch(
  env: Env,
  batchId: string
): Promise<BatchMetadata | null> {
  const data = await env.RATE_LIMIT_KV.get(`${BATCH_KV_PREFIX}${batchId}`);
  
  if (!data) {
    return null;
  }
  try {
    return JSON.parse(data) as BatchMetadata;
  } catch (err) {
    console.error(`[batch-kv] Failed to parse batch ${batchId}:`, err);
    return null;
  }
}

/**
 * Save batch metadata to KV (single source of truth for key prefix + TTL).
 * Use this instead of reaching into RATE_LIMIT_KV directly so the prefix and
 * TTL stay consistent with the rest of this module.
 */
export async function saveBatch(
  env: Env,
  metadata: BatchMetadata
): Promise<void> {
  await env.RATE_LIMIT_KV.put(
    `${BATCH_KV_PREFIX}${metadata.batch_id}`,
    JSON.stringify(metadata),
    { expirationTtl: BATCH_TTL_SECONDS }
  );
}

/**
 * Update batch progress (increment counters)
 */
export async function updateBatchProgress(
  env: Env,
  batchId: string,
  updates: {
    processed_rows_increment?: number;
    success_count_increment?: number;
    failed_count_increment?: number;
  }
): Promise<void> {
  const metadata = await getBatch(env, batchId);
  
  if (!metadata) {
    console.warn(`[batch-kv] Batch ${batchId} not found, skipping update`);
    return;
  }
  
  // Increment counters
  if (updates.processed_rows_increment !== undefined) {
    metadata.processed_rows += updates.processed_rows_increment;
  }
  if (updates.success_count_increment !== undefined) {
    metadata.success_count += updates.success_count_increment;
  }
  if (updates.failed_count_increment !== undefined) {
    metadata.failed_count += updates.failed_count_increment;
  }
  
	if (metadata.processed_rows >= metadata.total_rows) {
		metadata.status = 'completed';
		metadata.completed_at = new Date().toISOString();
	}

	await saveBatch(env, metadata);
}

/**
 * Record row error in batch
 */
export async function recordRowError(
  env: Env,
  batchId: string,
  rowNumber: number,
  email: string,
  errorMessage: string
): Promise<void> {
  const metadata = await getBatch(env, batchId);
  
  if (!metadata) {
    console.warn(`[batch-kv] Batch ${batchId} not found, cannot record error`);
    return;
  }
  
  metadata.errors.push({
    row: rowNumber,
    email,
    error: errorMessage
  });
  
  await saveBatch(env, metadata);
  
  console.log(`[batch-kv] Recorded error for batch ${batchId} row ${rowNumber}: ${errorMessage}`);
}

/**
 * Mark batch as failed
 */
export async function markBatchFailed(
  env: Env,
  batchId: string,
  errorMessage: string
): Promise<void> {
  const metadata = await getBatch(env, batchId);

  if (!metadata) {
    return;
  }

  metadata.status = 'failed';
  metadata.completed_at = new Date().toISOString();
  metadata.processed_rows = metadata.total_rows;
  metadata.failed_count = metadata.total_rows - metadata.success_count;
  metadata.errors.push({
    row: 0,
    email: '',
    error: errorMessage
  });

  await saveBatch(env, metadata);
}
