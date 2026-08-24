/**
 * Bulk-import adapters: per-entity configuration for the generic bulk import
 * queue handlers (src/queue/bulk-import-handlers.ts).
 *
 * Learner and faculty only differ in: CSV validation/mapping, the user_metadata
 * shape, the membership role name, extra sync events and the invitation email.
 * Everything else (parsing pipeline, hashing, chunking, user/membership
 * creation, progress/error bookkeeping) is shared.
 */

import type { CSVRow } from "../lib/csv-parser";
import { buildFacultyInvitationEmail, buildLearnerInvitationEmail } from "../lib/email-templates";
import { splitName } from "../lib/learner-helpers";
import { createBatchHandler, createCsvParseHandler, type BulkImportAdapter, type BulkItem } from "./bulk-import-handlers";

// ─── Entity data shapes ────────────────────────────────────────────

export interface LearnerData {
	email: string;
	name: string;
	contact_number?: string;
	enrollment_number?: string;
	program_id?: string;
	metadata?: Record<string, unknown>;
}

export interface FacultyData {
	email: string;
	first_name: string;
	last_name: string;
	phone?: string;
	employee_id?: string;
	department?: string;
	specialization?: string;
	qualification?: string;
	experience_years?: number;
	role?: string;
	metadata: Record<string, unknown>;
}

/** Wire items inside create-learner-batch messages. */
export interface LearnerBatchItem extends BulkItem {
	learner_data: LearnerData;
}

/** Wire items inside create-faculty-batch messages. */
export interface FacultyBatchItem extends BulkItem {
	faculty_data: FacultyData;
}

const EMAIL_REGEX = /^(?!.*\.\.)[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/;

// ─── Learner ───────────────────────────────────────────────────────

function validateLearnerRow(row: CSVRow, rowNumber: number): { valid: boolean; error?: string } {
	if (!row.email || !row.email.includes("@")) {
		return { valid: false, error: `Row ${rowNumber}: Invalid or missing email` };
	}

	if (!row.name || row.name.trim().length < 2) {
		return { valid: false, error: `Row ${rowNumber}: Invalid or missing name` };
	}

	if (!EMAIL_REGEX.test(row.email)) {
		return { valid: false, error: `Row ${rowNumber}: Invalid email format` };
	}

	return { valid: true };
}

function mapLearnerRow(row: CSVRow): LearnerData {
	return {
		email: row.email?.trim() || "",
		name: row.name?.trim() || "",
		contact_number: row.contact_number?.trim() || row.phone?.trim() || undefined,
		enrollment_number: row.enrollment_number?.trim() || row.roll_number?.trim() || undefined,
		program_id: row.program_id?.trim() || undefined,
		metadata: {
			...Object.fromEntries(
				Object.entries(row).filter(
					([key]) =>
						!["email", "name", "contact_number", "phone", "enrollment_number", "roll_number", "program_id"].includes(key),
				),
			),
		},
	};
}

export const learnerBulkImport: BulkImportAdapter<LearnerData> = {
	itemDataKey: "learner_data",
	itemKey: "learners",
	parseMessageType: "parse-csv",
	createMessageType: "create-learner-batch",
	jobIdPrefix: "batch-",
	validateRow: validateLearnerRow,
	mapRow: mapLearnerRow,
	roleName: "learner",
	buildUser(item) {
		const data = (item as LearnerBatchItem).learner_data;
		const { first_name, last_name } = splitName(data.name);
		return {
			email: item.email,
			password_hash: item.password_hash,
			user_metadata: {
				first_name,
				last_name,
				contact_number: data.contact_number,
				enrollment_number: data.enrollment_number,
				program_id: data.program_id,
				role: "learner",
				...data.metadata,
			},
			is_email_verified: true, // Bulk imports are trusted
		};
	},
	buildSyncUserMetadata(data) {
		const { first_name, last_name } = splitName(data.name);
		return {
			first_name,
			last_name,
			contact_number: data.contact_number,
			enrollment_number: data.enrollment_number,
			program_id: data.program_id,
			role: "learner",
		};
	},
	buildEmail(item, user, loginUrl) {
		return buildLearnerInvitationEmail((item as LearnerBatchItem).learner_data.name, user.email, item.temp_password, loginUrl);
	},
};

// ─── Faculty ───────────────────────────────────────────────────────

function validateFacultyRow(row: CSVRow, rowNumber: number): { valid: boolean; error?: string } {
	if (!row.email || !EMAIL_REGEX.test(row.email)) {
		return { valid: false, error: `Row ${rowNumber}: Invalid or missing email` };
	}

	const firstName =
		row.firstName?.trim() || row.first_name?.trim() || row.name?.trim()?.split(" ")[0] || "";
	const lastName =
		row.lastName?.trim() || row.last_name?.trim() || row.name?.trim()?.split(" ").slice(1).join(" ") || "";

	if (!firstName && !lastName) {
		return { valid: false, error: `Row ${rowNumber}: Missing name (firstName or name required)` };
	}

	if (row.experienceYears !== undefined && row.experienceYears !== "" && Number.isNaN(Number(row.experienceYears))) {
		return { valid: false, error: `Row ${rowNumber}: experienceYears must be a number` };
	}

	return { valid: true };
}

const FACULTY_METADATA_KEYS = [
	"email",
	"name",
	"firstName",
	"lastName",
	"first_name",
	"last_name",
	"phone",
	"contactNumber",
	"employeeId",
	"employee_id",
	"department",
	"department_id",
	"specialization",
	"qualification",
	"experienceYears",
	"role",
];

function mapFacultyRow(row: CSVRow): FacultyData {
	const name = row.name?.trim() || "";
	const firstName = row.firstName?.trim() || row.first_name?.trim() || name.split(" ")[0] || "";
	const lastName = row.lastName?.trim() || row.last_name?.trim() || name.split(" ").slice(1).join(" ") || "";
	const experienceYears =
		row.experienceYears && row.experienceYears !== "" ? Number(row.experienceYears) : undefined;

	return {
		email: row.email?.trim()?.toLowerCase() || "",
		first_name: firstName,
		last_name: lastName,
		phone: row.phone?.trim() || row.contactNumber?.trim() || undefined,
		employee_id: row.employeeId?.trim() || row.employee_id?.trim() || undefined,
		department: row.department?.trim() || row.department_id?.trim() || undefined,
		specialization: row.specialization?.trim() || undefined,
		qualification: row.qualification?.trim() || undefined,
		experience_years: experienceYears,
		role: row.role?.trim() || undefined,
		metadata: {
			// Store any additional columns in metadata
			...(Object.fromEntries(Object.entries(row).filter(([key]) => !FACULTY_METADATA_KEYS.includes(key)))),
		},
	};
}

export const facultyBulkImport: BulkImportAdapter<FacultyData> = {
	itemDataKey: "faculty_data",
	itemKey: "faculties",
	parseMessageType: "parse-faculty-csv",
	createMessageType: "create-faculty-batch",
	jobIdPrefix: "faculty-batch-",
	validateRow: validateFacultyRow,
	mapRow: mapFacultyRow,
	roleName: "college_educator",
	buildUser(item) {
		const data = (item as FacultyBatchItem).faculty_data;
		return {
			email: item.email,
			password_hash: item.password_hash,
			user_metadata: {
				first_name: data.first_name,
				last_name: data.last_name,
				phone: data.phone,
				employee_id: data.employee_id,
				department: data.department,
				specialization: data.specialization,
				qualification: data.qualification,
				experience_years: data.experience_years,
				role: "college_educator",
				staff_role: data.role,
				...data.metadata,
			},
			is_email_verified: true, // Bulk imports are trusted
		};
	},
	buildSyncUserMetadata(data) {
		return {
			first_name: data.first_name,
			last_name: data.last_name,
			role: "college_educator",
			phone: data.phone,
		};
	},
	buildExtraSyncEvents(item, user, organizationId) {
		const data = (item as FacultyBatchItem).faculty_data;
		return [
			{
				type: "faculty.created",
				payload: {
					user_id: user.id,
					email: user.email,
					college_id: organizationId,
					first_name: data.first_name,
					last_name: data.last_name,
					phone: data.phone,
					employee_id: data.employee_id,
					department: data.department,
					specialization: data.specialization,
					qualification: data.qualification,
					experience_years: data.experience_years,
					role: data.role,
					temp_password: item.temp_password,
				},
				timestamp: new Date().toISOString(),
			},
		];
	},
	buildEmail(item, user, loginUrl) {
		const data = (item as FacultyBatchItem).faculty_data;
		const name = [data.first_name, data.last_name].filter(Boolean).join(" ") || user.email;
		return buildFacultyInvitationEmail(name, user.email, item.temp_password, loginUrl);
	},
};

/** All create-* message types → their items array key (for the DLQ handler). */
export const BULK_CREATE_MESSAGE_TYPES: Record<string, string> = Object.fromEntries(
	[learnerBulkImport, facultyBulkImport].map((adapter) => [adapter.createMessageType, adapter.itemKey]),
);

/** All parse-* message types handled by the bulk import pipeline. */
export const BULK_PARSE_MESSAGE_TYPES: string[] = [learnerBulkImport, facultyBulkImport].map(
	(adapter) => adapter.parseMessageType,
);

// ─── Wired queue handlers ──────────────────────────────────────────
// Concrete handlers consumed by the queue router. Wiring lives here (not in
// bulk-import-handlers) to avoid a circular import between the factories and
// the adapters.

export const handleParseCsvQueue = createCsvParseHandler(learnerBulkImport);
export const handleCreateLearnerBatch = createBatchHandler(learnerBulkImport);
export const handleParseFacultyCsvQueue = createCsvParseHandler(facultyBulkImport);
export const handleCreateFacultyBatch = createBatchHandler(facultyBulkImport);
