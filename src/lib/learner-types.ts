/**
 * Shared types for learner admission flow
 * Used across CSV parser and batch handler
 */

export interface LearnerBatchItem {
	row_number: number;
	email: string;
	password_hash: string;
	temp_password: string; // Actual temp password for email
	learner_data: {
		email: string;
		name: string;
		contact_number?: string;
		enrollment_number?: string;
		program_id?: string;
		metadata?: Record<string, unknown>;
	};
}
