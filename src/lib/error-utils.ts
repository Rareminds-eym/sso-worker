/**
 * Error handling utilities
 * ponytail: Extracted to eliminate 20+ occurrences of error message extraction
 */

/**
 * Safely extract error message from unknown error type
 * @param error - Unknown error object
 * @returns String error message
 */
export function getErrorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
