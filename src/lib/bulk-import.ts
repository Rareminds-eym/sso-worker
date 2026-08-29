import type { Env } from "../types";
import { db } from "./db";
import { getErrorMessage } from "./error-utils";

/**
 * Shared bulk-import auth-db layer.
 *
 * Single source of truth for the batch-creation flow used by both the faculty
 * and learner bulk import handlers:
 *   1. in-file dedup
 *   2. existence pre-check by email (one query)
 *   3. partition into new / existing
 *   4. bulk-insert ONLY new users
 *   5. membership creation skip-if-exists (retried once on a 23505 race, never
 *      thrown to the DLQ for a duplicate)
 *   6. per-row error classification for existing users (NO reuse)
 *
 * SSO auth-db is the single source of truth for users/memberships/membership_roles.
 * This layer never touches skillpassport tables (e.g. college_lecturers).
 */

export interface EmailRow {
  email: string;
}

export interface BulkBatchRow extends EmailRow {
  row_number: number;
}

export interface UserToCreate {
  email: string;
  password_hash: string;
  user_metadata: Record<string, unknown>;
  is_email_verified: boolean;
}

export interface CreatedUser {
  id: string;
  email: string;
}

export interface BatchContext {
  batch_id: string;
  batch_index: number;
  organization_id: string;
}

export interface BulkBatchResult {
  createdUsers: CreatedUser[];
  rowErrors: Array<{ rowNumber: number; email: string; error: string }>;
}

/**
 * Split rows into those needing user creation and those whose email already
 * maps to an existing SSO user.
 */
export function partitionByExistingEmail<T extends EmailRow>(
  rows: T[],
  existingEmails: ReadonlySet<string>,
): { newRows: T[]; existingRows: T[] } {
  const newRows: T[] = [];
  const existingRows: T[] = [];
  for (const row of rows) {
    if (existingEmails.has(row.email)) {
      existingRows.push(row);
    } else {
      newRows.push(row);
    }
  }
  return { newRows, existingRows };
}

/**
 * Per-row error for an email that already maps to an SSO user.
 */
export function existingUserError(hasMembershipInOrg: boolean): "User already exists" | "Already a member of this college" {
  return hasMembershipInOrg ? "Already a member of this college" : "User already exists";
}

/**
 * Create SSO users + memberships for a batch of rows, failing already-existing
 * emails per-row with clear errors (no reuse). `buildUser` maps a domain row
 * (faculty_data / learner_data) to the auth-db user payload; `roleName` is the
 * membership role to assign (college_educator | learner).
 */
export async function createUsersAndMemberships<T extends BulkBatchRow>(
  env: Env,
  ctx: BatchContext,
  rows: T[],
  buildUser: (row: T) => UserToCreate,
  roleName: string,
): Promise<BulkBatchResult> {
  const { batch_index, organization_id } = ctx;
  const database = db(env);

  const rowErrors: Array<{ rowNumber: number; email: string; error: string }> = [];

  // 1. Dedup within this batch — repeated emails fail, rest proceed.
  const emailSet = new Set<string>();
  const duplicateEmails: string[] = [];
  const uniqueRows: T[] = [];
  for (const row of rows) {
    if (emailSet.has(row.email)) {
      duplicateEmails.push(row.email);
      continue;
    }
    emailSet.add(row.email);
    uniqueRows.push(row);
  }

  // 2. Pre-check: one query to find which emails already exist as SSO users.
  const emails = uniqueRows.map((r) => r.email);
  const existingUsers = emails.length > 0
    ? await database.query<{ id: string; email: string }>(
        `users?email=in.(${emails.map((e) => encodeURIComponent(e)).join(",")})&select=id,email`,
      )
    : [];
  const existingByEmail = new Map(existingUsers.map((u) => [u.email, u]));

  // 3. Partition into new / existing.
  const { newRows, existingRows } = partitionByExistingEmail(
    uniqueRows,
    new Set(existingByEmail.keys()),
  );

  // 4. Bulk-insert ONLY new rows.
  const usersToCreate = newRows.map(buildUser);
  let createdUsers: CreatedUser[] = [];
  if (usersToCreate.length > 0) {
    console.log(`[SSO] Bulk inserting ${usersToCreate.length} new ${roleName} users`);
    createdUsers = await database.bulkInsert<CreatedUser>("users", usersToCreate);
    console.log(`[SSO] Bulk inserted ${createdUsers.length} users in batch ${batch_index}`);
  }

  // 5. Single membership query covering created AND pre-existing user ids —
  //    serves both the membership dedup and the per-row error classification.
  const allUserIds = [
    ...createdUsers.map((u) => u.id),
    ...existingRows.map((r) => existingByEmail.get(r.email)!.id),
  ];
  let existingMembershipUserIds = new Set<string>();
  if (allUserIds.length > 0) {
    const existingMemberships = await database.query<{ user_id: string }>(
      `memberships?user_id=in.(${allUserIds.join(",")})&org_id=eq.${organization_id}&select=user_id`,
    );
    existingMembershipUserIds = new Set(existingMemberships.map((m) => m.user_id));
  }

  if (createdUsers.length > 0) {
    await createMembershipsForBatch(
      env,
      createdUsers,
      organization_id,
      existingMembershipUserIds,
      roleName,
    );
  }

  // 6. Existing users never get reused — classify each with the right error.
  for (const row of existingRows) {
    const user = existingByEmail.get(row.email)!;
    rowErrors.push({
      rowNumber: row.row_number,
      email: row.email,
      error: existingUserError(existingMembershipUserIds.has(user.id)),
    });
  }
  for (const email of duplicateEmails) {
    const row = uniqueRows.find((r) => r.email === email);
    if (row) {
      rowErrors.push({
        rowNumber: row.row_number,
        email,
        error: `Duplicate email in file`,
      });
    }
  }

  return { createdUsers, rowErrors };
}

/**
 * Create memberships + role for a batch of SSO users.
 * Skip-if-exists: memberships already present for this org are not re-inserted.
 * If a 23505 race is hit (another retry created them), re-query and insert only
 * the still-missing ones — never throw the whole batch to the DLQ for it.
 */
async function createMembershipsForBatch(
  env: Env,
  users: CreatedUser[],
  organization_id: string,
  existingMembershipUserIds: Set<string>,
  roleName: string,
): Promise<void> {
  const database = db(env);

  const role = await database.queryOne<{ id: string }>(
    `roles?name=eq.${roleName}&select=id`,
  );

  if (!role) {
    throw new Error(
      `${roleName} role not found in database — cannot create memberships without a role to assign`,
    );
  }

  const missing = users
    .filter((user) => !existingMembershipUserIds.has(user.id))
    .map((user) => ({
      user_id: user.id,
      org_id: organization_id,
      status: "active",
    }));

  if (missing.length === 0) {
    console.log(`[SSO] All ${users.length} ${roleName} users already have memberships — nothing to create`);
    return;
  }

  let createdMemberships: Array<{ id: string; user_id: string }> = [];
  try {
    createdMemberships = await database.bulkInsert<{ id: string; user_id: string }>(
      "memberships",
      missing,
    );
  } catch (err) {
    if (getErrorMessage(err).includes("23505")) {
      console.warn(`[SSO] Membership insert hit a duplicate race — re-querying and inserting only missing`);
      const existing = await database.query<{ user_id: string }>(
        `memberships?user_id=in.(${missing.map((m) => m.user_id).join(",")})&org_id=eq.${organization_id}&select=user_id`,
      );
      const existingSet = new Set(existing.map((m) => m.user_id));
      const stillMissing = missing.filter((m) => !existingSet.has(m.user_id));
      if (stillMissing.length > 0) {
        createdMemberships = await database.bulkInsert<{ id: string; user_id: string }>(
          "memberships",
          stillMissing,
        );
      }
    } else {
      throw err;
    }
  }

  if (createdMemberships.length > 0) {
    const membershipRoles = createdMemberships.map((m) => ({
      membership_id: m.id,
      role_id: role.id,
    }));
    await database.bulkInsert("membership_roles", membershipRoles);
  }
  console.log(`[SSO] Created ${createdMemberships.length} ${roleName} memberships and roles`);
}