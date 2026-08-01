/**
 * User Creation Logic
 * Handles creating a single user in SSO DB
 */

import { db } from "../../lib/db";
import type { Env } from "../../types";

export interface CreateUserInput {
	email: string;
	password_hash: string;
	first_name: string;
	last_name: string;
	metadata: Record<string, unknown>;
	is_email_verified: boolean;
}

export interface CreateUserResult {
	user_id: string;
	email: string;
}

/**
 * Create a user in SSO database
 * Returns user ID and email on success
 * Throws error if user already exists or creation fails
 */
export async function createUser(
	env: Env,
	input: CreateUserInput,
): Promise<CreateUserResult> {
	const database = db(env);

	try {
		const user = await database.mutate<{ id: string; email: string }>("users", {
			email: input.email,
			password_hash: input.password_hash,
			user_metadata: {
				first_name: input.first_name,
				last_name: input.last_name,
				role: "learner",
				...input.metadata,
			},
			is_email_verified: input.is_email_verified,
		});

		return {
			user_id: user.id,
			email: user.email,
		};
	} catch (dbError) {
		// Check if it's a duplicate key error
		const errorMsg =
			dbError instanceof Error ? dbError.message : String(dbError);
		if (
			errorMsg.includes("duplicate") ||
			errorMsg.includes("23505") ||
			errorMsg.includes("already exists")
		) {
			throw new Error(`User with email ${input.email} already exists`);
		}
		throw dbError;
	}
}
