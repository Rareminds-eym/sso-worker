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

/**
 * Canonical learner profile. Keys match the SkillPassport `learners` table
 * columns consumed by the learner Settings page (see
 * skillpassport/src/entities/learner/api/learnerSettingsService.js
 * `fieldMapping`), so bulk-imported rows render exactly like manually added
 * learners. `program_id` is only populated when the CSV value is a UUID
 * (the column is uuid-typed).
 */
export interface LearnerData {
	email: string;
	name: string;
	contactNumber?: string;
	alternate_number?: string;
	dateOfBirth?: string;
	gender?: string;
	enrollmentNumber?: string;
	registration_number?: string;
	roll_number?: string;
	admission_number?: string;
	category?: string;
	quota?: string;
	admission_academic_year?: string;
	bloodGroup?: string;
	district_name?: string;
	university?: string;
	profilePicture?: string;
	guardianName?: string;
	guardianPhone?: string;
	guardianEmail?: string;
	guardianRelation?: string;
	address?: string;
	city?: string;
	state?: string;
	country?: string;
	pincode?: string;
	program_id?: string;
	grade?: string;
	section?: string;
}

/**
 * Normalize a raw CSV row the same way the college-admin preview does
 * (Papa `transformHeader`: trim, lowercase, strip non-alphanumeric), so
 * `Email`, `Contact Number`, `contactNumber` and `contact_number` all map
 * to the same key. Without this, Excel-saved files pass the frontend
 * preview but fail/mis-map in this backend parser.
 */
export function normalizeCsvHeaders(row: CSVRow): CSVRow {
	const out: CSVRow = {};
	for (const [key, value] of Object.entries(row)) {
		out[key.trim().toLowerCase().replace(/[^a-z0-9]/g, "")] = value;
	}
	return out;
}

/** First non-empty trimmed value across candidate normalized keys. */
function pick(row: CSVRow, ...keys: string[]): string | undefined {
	for (const key of keys) {
		const value = row[key]?.trim();
		if (value) return value;
	}
	return undefined;
}

/**
 * Convert DD-MM-YYYY / DD/MM/YYYY / YYYY-MM-DD to YYYY-MM-DD (the
 * `learners.dateOfBirth` column is date-typed). Mirrors the college-admin
 * modal `convertDateFormat`. Returns undefined when unparseable so the
 * column stays NULL instead of failing the insert.
 */
function toISODate(value: string | undefined): string | undefined {
	if (!value) return undefined;
	const trimmed = value.trim();
	if (!trimmed) return undefined;
	if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return trimmed;
	const match = trimmed.match(/^(\d{1,2})[-\/](\d{1,2})[-\/](\d{4})$/);
	if (match) {
		const [, day, month, year] = match;
		const iso = `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
		const date = new Date(iso);
		if (
			date.getFullYear() === Number(year) &&
			date.getMonth() === Number(month) - 1 &&
			date.getDate() === Number(day)
		) {
			return iso;
		}
	}
	return undefined;
}

function isUUID(value: string | undefined): value is string {
	return !!value && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
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
	const email = row.email?.trim() || "";
	const name = row.name?.trim() || "";
	if (!email || !email.includes("@")) {
		return { valid: false, error: `Row ${rowNumber}: Invalid or missing email` };
	}

	if (name.length < 2) {
		return { valid: false, error: `Row ${rowNumber}: Invalid or missing name` };
	}

	if (!EMAIL_REGEX.test(email)) {
		return { valid: false, error: `Row ${rowNumber}: Invalid email format` };
	}

	return { valid: true };
}

function mapLearnerRow(row: CSVRow): LearnerData {
	const programId = pick(row, "programid");
	return {
		email: row.email?.trim() || "",
		name: row.name?.trim() || "",
		contactNumber: pick(row, "contactnumber", "phone"),
		alternate_number: pick(row, "alternatenumber"),
		dateOfBirth: toISODate(pick(row, "dateofbirth")),
		gender: pick(row, "gender"),
		enrollmentNumber: pick(row, "enrollmentnumber"),
		registration_number: pick(row, "registrationnumber"),
		roll_number: pick(row, "rollnumber"),
		admission_number: pick(row, "admissionnumber"),
		category: pick(row, "category"),
		quota: pick(row, "quota"),
		admission_academic_year: pick(row, "academicyear"),
		bloodGroup: pick(row, "bloodgroup"),
		district_name: pick(row, "district", "districtname"),
		university: pick(row, "university"),
		profilePicture: pick(row, "profilepicture"),
		guardianName: pick(row, "guardianname"),
		guardianPhone: pick(row, "guardianphone"),
		guardianEmail: pick(row, "guardianemail"),
		guardianRelation: pick(row, "guardianrelation"),
		address: pick(row, "address"),
		city: pick(row, "city"),
		state: pick(row, "state"),
		country: pick(row, "country"),
		pincode: pick(row, "pincode"),
		program_id: isUUID(programId) ? programId : undefined,
		grade: pick(row, "grade", "class"),
		section: pick(row, "section", "division"),
	};
}

/**
 * Learner profile keyed by SkillPassport `learners` column names — the same
 * reference the Settings page reads/writes
 * (learnerSettingsService.js `fieldMapping`). Sent inside the
 * `membership.created` sync event so the shadow `learners` row is created
 * with every displayed field, not just name/email.
 */
function buildLearnerProfile(data: LearnerData): Record<string, unknown> {
	const profile: Record<string, unknown> = {};
	const set = (key: string, value: unknown) => {
		if (value !== undefined && value !== null && value !== "") {
			profile[key] = value;
		}
	};
	set("contactNumber", data.contactNumber);
	set("alternate_number", data.alternate_number);
	set("dateOfBirth", data.dateOfBirth);
	set("gender", data.gender);
	set("enrollmentNumber", data.enrollmentNumber);
	set("registration_number", data.registration_number);
	set("roll_number", data.roll_number);
	set("admission_number", data.admission_number);
	set("category", data.category);
	set("quota", data.quota);
	set("admission_academic_year", data.admission_academic_year);
	set("bloodGroup", data.bloodGroup);
	set("district_name", data.district_name);
	set("university", data.university);
	set("profilePicture", data.profilePicture);
	set("guardianName", data.guardianName);
	set("guardianPhone", data.guardianPhone);
	set("guardianEmail", data.guardianEmail);
	set("guardianRelation", data.guardianRelation);
	set("address", data.address);
	set("city", data.city);
	set("state", data.state);
	set("country", data.country);
	set("pincode", data.pincode);
	set("program_id", data.program_id);
	set("grade", data.grade);
	set("section", data.section);
	return profile;
}

export const learnerBulkImport: BulkImportAdapter<LearnerData> = {
	itemDataKey: "learner_data",
	itemKey: "learners",
	parseMessageType: "parse-csv",
	createMessageType: "create-learner-batch",
	jobIdPrefix: "batch-",
	normalizeRow: normalizeCsvHeaders,
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
				// Snake-case aliases kept for syncUser (users.phone) compat.
				contact_number: data.contactNumber,
				enrollment_number: data.enrollmentNumber,
				program_id: data.program_id,
				role: "learner",
				// Canonical learners-column keys (Settings reference).
				...buildLearnerProfile(data),
			},
			is_email_verified: true, // Bulk imports are trusted
		};
	},
	buildSyncUserMetadata(data) {
		const { first_name, last_name } = splitName(data.name);
		return {
			first_name,
			last_name,
			contact_number: data.contactNumber,
			enrollment_number: data.enrollmentNumber,
			program_id: data.program_id,
			role: "learner",
			...buildLearnerProfile(data),
		};
	},
	buildLearnerProfile(data) {
		return buildLearnerProfile(data);
	},
	buildEmail(item, user, loginUrl) {
		return buildLearnerInvitationEmail((item as LearnerBatchItem).learner_data.name, user.email, item.temp_password, loginUrl);
	},
};

// ─── Faculty ───────────────────────────────────────────────────────

function validateFacultyRow(row: CSVRow, rowNumber: number): { valid: boolean; error?: string } {
	const email = row.email?.trim() || "";
	if (!email || !EMAIL_REGEX.test(email)) {
		return { valid: false, error: `Row ${rowNumber}: Invalid or missing email` };
	}

	const nameParts = (row.name?.trim() || "").split(" ").filter(Boolean);
	const firstName = row.firstname?.trim() || nameParts[0] || "";
	const lastName = row.lastname?.trim() || nameParts.slice(1).join(" ") || "";

	if (!firstName && !lastName) {
		return { valid: false, error: `Row ${rowNumber}: Missing name (firstName or name required)` };
	}

	if (row.experienceyears !== undefined && row.experienceyears !== "" && Number.isNaN(Number(row.experienceyears))) {
		return { valid: false, error: `Row ${rowNumber}: experienceYears must be a number` };
	}

	return { valid: true };
}

// Normalized (lowercased, non-alphanumeric stripped) header keys consumed above.
const FACULTY_METADATA_KEYS = [
	"email",
	"name",
	"firstname",
	"lastname",
	"phone",
	"contactnumber",
	"employeeid",
	"department",
	"departmentid",
	"specialization",
	"qualification",
	"experienceyears",
	"role",
];

function mapFacultyRow(row: CSVRow): FacultyData {
	const name = row.name?.trim() || "";
	const nameParts = name.split(" ").filter(Boolean);
	const firstName = row.firstname?.trim() || nameParts[0] || "";
	const lastName = row.lastname?.trim() || nameParts.slice(1).join(" ") || "";
	const experienceYears =
		row.experienceyears && row.experienceyears !== "" ? Number(row.experienceyears) : undefined;

	return {
		email: row.email?.trim()?.toLowerCase() || "",
		first_name: firstName,
		last_name: lastName,
		phone: row.phone?.trim() || row.contactnumber?.trim() || undefined,
		employee_id: row.employeeid?.trim() || undefined,
		department: row.department?.trim() || row.departmentid?.trim() || undefined,
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
	normalizeRow: normalizeCsvHeaders,
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
