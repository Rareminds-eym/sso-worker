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


export function buildLearnerProfile(data: LearnerData): Record<string, unknown> {
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

