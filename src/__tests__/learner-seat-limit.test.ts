import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	query: vi.fn(),
	queryOne: vi.fn(),
	mutate: vi.fn(),
	bulkInsert: vi.fn(),
	queueSend: vi.fn(),
	syncSend: vi.fn(),
	emailSend: vi.fn(),
	kvPut: vi.fn(),
	kvGet: vi.fn(),
}));

vi.mock("../lib/db", () => ({
	db: () => ({
		query: state.query,
		queryOne: state.queryOne,
		mutate: state.mutate,
		bulkInsert: state.bulkInsert,
	}),
}));

vi.mock("../lib/hash", () => ({
	hashPassword: async () => "hashed-password",
}));

vi.mock("../lib/organization-sync", () => ({
	ensureOrganizationExists: async () => ({ id: ORG_ID }),
}));

import { checkLearnerSeatAvailability } from "../lib/seat-limit";
import { performCreateLearnerUser } from "../routes/learner-admission";
import { performQueueBulkFacultyUpload, performQueueBulkLearnerUpload } from "../routes/bulk-upload";
import { handleCreateLearnerBatch, handleParseCsvQueue } from "../queue/bulk-import-adapters";

const ORG_ID = "10000000-0000-4000-8000-000000000001";
const LEARNER_ROLE_ID = "role-learner-uuid";

const env = {
	LEARNER_ADMISSION_QUEUE: { send: state.queueSend, sendBatch: state.queueSend },
	SYNC_QUEUE: { send: state.syncSend, sendBatch: state.syncSend },
	EMAIL_QUEUE: { send: state.emailSend, sendBatch: state.emailSend },
	RATE_LIMIT_KV: { put: state.kvPut, get: state.kvGet },
	SKILLPASSPORT_URL: "https://skillpassport.test",
} as never;

function mockSeatQueries(options: { seatCount: number | null; usedLearners: number }) {
	state.query.mockImplementation(async (path: string) => {
		if (path.startsWith("subscriptions?")) {
			return options.seatCount === null
				? []
				: [{ id: "sub-1", seat_count: options.seatCount, status: "active" }];
		}
		if (path.startsWith("roles?name=eq.learner")) {
			return [{ id: LEARNER_ROLE_ID }];
		}
		if (path.startsWith("memberships?") && path.includes("membership_roles!inner")) {
			expect(path).toContain(`membership_roles.role_id=eq.${LEARNER_ROLE_ID}`);
			expect(path).toContain("status=eq.active");
			return Array.from({ length: options.usedLearners }, (_, i) => ({ id: `m-${i + 1}` }));
		}
		return [];
	});
}

describe("learner seat limit enforcement", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		state.queueSend.mockResolvedValue(undefined);
		state.syncSend.mockResolvedValue(undefined);
		state.emailSend.mockResolvedValue(undefined);
		state.kvPut.mockResolvedValue(undefined);
		state.kvGet.mockResolvedValue(null);
		state.queryOne.mockResolvedValue({ id: LEARNER_ROLE_ID });
		state.mutate.mockImplementation(async (table: string) =>
			table === "users" ? { id: "new-user-id", email: "new@example.test" } : { id: "new-membership-id" },
		);
		state.bulkInsert.mockImplementation(async (table: string, rows: Array<{ email?: string; user_id?: string }>) =>
			table === "users"
				? rows.map((r, i) => ({ id: `bulk-u-${i + 1}`, email: r.email || "" }))
				: rows.map((r, i) => ({ id: `bulk-m-${i + 1}`, user_id: r.user_id || "" })),
		);
	});

	it("allows when used + additionalSeats <= seat_count and counts only learner memberships", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 8 });
		const res = await checkLearnerSeatAvailability({ query: state.query } as never, ORG_ID, 2);
		expect(res).toEqual({
			allowed: true,
			limited: true,
			used: 8,
			limit: 10,
			remaining: 2,
		});
	});

	it("blocks manual learner creation when 10/10 seats are used", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 10 });
		const res = await performCreateLearnerUser(env, {
			email: "student11@example.test",
			name: "Student Eleven",
			organization_id: ORG_ID,
		});
		expect(res).toMatchObject({
			success: false,
			errorCode: "SEAT_LIMIT_EXCEEDED",
		});
		expect(res.error).toContain("10/10 seats used");
		expect(state.mutate).not.toHaveBeenCalled();
		expect(state.syncSend).not.toHaveBeenCalled();
	});

	it("allows manual learner creation when 9/10 seats are used", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 9 });
		const res = await performCreateLearnerUser(env, {
			email: "student10@example.test",
			name: "Student Ten",
			organization_id: ORG_ID,
		});
		expect(res.success).toBe(true);
		expect(state.mutate).toHaveBeenCalled();
	});

	it("blocks bulk learner CSV upload when rows exceed remaining seats", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 8 });
		const csv = [
			"name,email",
			"A,a@example.test",
			"B,b@example.test",
			"C,c@example.test",
		].join("\n");

		const res = await performQueueBulkLearnerUpload(env, {
			csv_data: csv,
			organization_id: ORG_ID,
			admin_id: "admin-1",
		});

		expect(res).toMatchObject({
			success: false,
			errorCode: "SEAT_LIMIT_EXCEEDED",
		});
		expect(res.error).toBe("Seat limit reached (2 of 10 seats remaining). Please upgrade or purchase additional seats.");
		expect(state.queueSend).not.toHaveBeenCalled();
	});

	it("allows bulk learner CSV upload when rows fit within remaining seats", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 8 });
		const csv = ["name,email", "A,a@example.test", "B,b@example.test"].join("\n");

		const res = await performQueueBulkLearnerUpload(env, {
			csv_data: csv,
			organization_id: ORG_ID,
			admin_id: "admin-1",
		});

		expect(res.success).toBe(true);
		expect(state.queueSend).toHaveBeenCalledTimes(1);
	});

	it("does not block faculty bulk CSV upload when learner seats are full", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 10 });
		const csv = ["name,email", "Prof A,prof@example.test"].join("\n");

		const res = await performQueueBulkFacultyUpload(env, {
			csv_data: csv,
			organization_id: ORG_ID,
			admin_id: "admin-1",
		});

		expect(res.success).toBe(true);
		expect(state.queueSend).toHaveBeenCalledTimes(1);
	});

	it("marks batch failed in parse queue handler if seat limit is exceeded", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 9 });
		let storedBatch = JSON.stringify({
			batch_id: "BATCH-1",
			admin_id: "admin-1",
			organization_id: ORG_ID,
			total_rows: 2,
			processed_rows: 0,
			success_count: 0,
			failed_count: 0,
			status: "processing",
			created_at: new Date().toISOString(),
			errors: [],
		});
		state.kvGet.mockImplementation(async () => storedBatch);
		state.kvPut.mockImplementation(async (_k: string, v: string) => {
			storedBatch = v;
		});
		const ack = vi.fn();
		const retry = vi.fn();

		await handleParseCsvQueue(
			env,
			{
				batch_id: "BATCH-1",
				organization_id: ORG_ID,
				csv_data: "name,email\nLearner One,a@example.test\nLearner Two,b@example.test",
			},
			{ ack, retry } as never,
		);

		expect(ack).toHaveBeenCalledTimes(1);
		expect(state.queueSend).not.toHaveBeenCalled();
		const lastSaved = JSON.parse(storedBatch);
		expect(lastSaved.status).toBe("failed");
		expect(lastSaved.errors[0].error).toBe("Seat limit reached (1 of 10 seats remaining). Please upgrade or purchase additional seats.");
	});

	it("caps batch creation in queue worker when concurrent uploads leave fewer seats", async () => {
		mockSeatQueries({ seatCount: 10, usedLearners: 9 });
		let storedBatch = JSON.stringify({
			batch_id: "BATCH-2",
			admin_id: "admin-1",
			organization_id: ORG_ID,
			total_rows: 2,
			processed_rows: 0,
			success_count: 0,
			failed_count: 0,
			status: "processing",
			created_at: new Date().toISOString(),
			errors: [],
		});
		state.kvGet.mockImplementation(async () => storedBatch);
		state.kvPut.mockImplementation(async (_k: string, v: string) => {
			storedBatch = v;
		});
		const ack = vi.fn();

		await handleCreateLearnerBatch(
			env,
			{
				batch_id: "BATCH-2",
				batch_index: 0,
				organization_id: ORG_ID,
				learners: [
					{
						row_number: 1,
						email: "a@example.test",
						password_hash: "h1",
						temp_password: "p1",
						learner_data: { email: "a@example.test", name: "Learner A" },
					},
					{
						row_number: 2,
						email: "b@example.test",
						password_hash: "h2",
						temp_password: "p2",
						learner_data: { email: "b@example.test", name: "Learner B" },
					},
				],
			},
			{ ack, retry: vi.fn() } as never,
		);

		expect(ack).toHaveBeenCalledTimes(1);
		// Only 1 user inserted; 2nd row failed with seat-limit error
		const userInsertCall = state.bulkInsert.mock.calls.find(([table]) => table === "users");
		expect(userInsertCall?.[1]).toHaveLength(1);
		const lastSaved = JSON.parse(storedBatch);
		expect(lastSaved.success_count).toBe(1);
		expect(lastSaved.failed_count).toBe(1);
		expect(lastSaved.errors[0].email).toBe("b@example.test");
	});
});
