import { db } from "../lib/db";
import { getErrorMessage } from "../lib/error-utils";
import type { Env } from "../types";

/**
 * Create organization in SSO database (source of truth)
 * Called by Skillpassport when admin creates a new organization
 * Publishes to sync queue to create in Skillpassport
 */
export async function performCreateOrganization(
	env: Env,
	data: {
		name: string;
		slug: string;
		created_by: string;
		metadata?: Record<string, unknown>;
	},
): Promise<{ success: boolean; org_id?: string; error?: string }> {
	if (!data.name) {
		return { success: false, error: "name is required" };
	}
	if (!data.slug) {
		return { success: false, error: "slug is required" };
	}
	if (!data.created_by) {
		return { success: false, error: "created_by is required" };
	}

	try {
		const database = db(env);

		// Check SYNC_QUEUE binding before creating org in DB
		if (!env.SYNC_QUEUE) {
			console.error("[SSO] SYNC_QUEUE not bound");
			return { success: false, error: "SYNC_QUEUE not bound" };
		}

		// Create organization in SSO DB
		const org = await database.mutate<{ id: string }>("organizations", {
			name: data.name,
			slug: data.slug,
			created_by: data.created_by,
			metadata: data.metadata || {},
		});

		console.log(`[SSO] Created organization ${org.id}: "${data.name}"`);

		// Publish to sync queue to create in Skillpassport
		await env.SYNC_QUEUE.send({
			type: "organization.created",
			payload: {
				id: org.id,
				name: data.name,
				slug: data.slug,
				created_by: data.created_by,
				metadata: data.metadata || {},
			},
			timestamp: new Date().toISOString(),
		});

		console.log(
			`[SSO] Published organization.created event for ${org.id} to sync queue`,
		);

		return { success: true, org_id: org.id };
	} catch (error) {
		const errorMsg = getErrorMessage(error);
		console.error(`[SSO] Error creating organization:`, errorMsg);
		return { success: false, error: errorMsg };
	}
}

/**
 * Update organization name in SSO database (auth DB)
 * This is called by Skillpassport when org settings are updated
 * to keep the auth DB in sync with app DB
 */
export async function performUpdateOrganization(
	env: Env,
	data: {
		id: string;
		name: string;
	},
): Promise<{ success: boolean }> {
	if (!data.id) {
		throw new Error("id is required");
	}
	if (!data.name) {
		throw new Error("name is required");
	}

	const database = db(env);
	await database.update(
		"organizations",
		{ id: `eq.${encodeURIComponent(data.id)}` },
		{ name: data.name },
	);

	console.log(`[SSO] Updated organization ${data.id} name to "${data.name}"`);
	return { success: true };
}

/**
 * Update organization metadata in SSO database
 * Called by /organization-setup to add full details to signup-created org
 */
export async function performUpdateOrganizationDetails(
	env: Env,
	data: {
		id: string;
		metadata: Record<string, unknown>;
	},
): Promise<{ success: boolean; error?: string }> {
	if (!data.id) {
		return { success: false, error: "id is required" };
	}

	try {
		const database = db(env);

		// Check SYNC_QUEUE binding before updating org in DB
		if (!env.SYNC_QUEUE) {
			console.error(
				"[SSO] SYNC_QUEUE not bound, organization updated but not synced",
			);
			return { success: false, error: "SYNC_QUEUE not bound" };
		}

		// Fetch existing org to merge metadata
		const existing = await database.queryOne<{
			metadata: Record<string, unknown>;
		}>(`organizations?id=eq.${encodeURIComponent(data.id)}&select=metadata`);

		if (!existing) {
			return { success: false, error: `Organization ${data.id} not found` };
		}

		// Merge metadata
		const updatedMetadata = {
			...(existing.metadata || {}),
			...data.metadata,
		};

		// Update org
		await database.update(
			"organizations",
			{ id: `eq.${encodeURIComponent(data.id)}` },
			{ metadata: updatedMetadata },
		);

		console.log(`[SSO] Updated organization ${data.id} metadata`);

		// Publish organization.updated event to sync to Skillpassport
		await env.SYNC_QUEUE.send({
			type: "organization.updated",
			payload: {
				id: data.id,
				metadata: updatedMetadata,
			},
			timestamp: new Date().toISOString(),
		});

		console.log(`[SSO] Published organization.updated event for ${data.id}`);

		return { success: true };
	} catch (error) {
		const errorMsg = getErrorMessage(error);
		console.error(`[SSO] Error updating organization details:`, errorMsg);
		return { success: false, error: errorMsg };
	}
}
