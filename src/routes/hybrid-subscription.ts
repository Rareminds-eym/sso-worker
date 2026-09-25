import { addMonths, parseDurationMonths } from "../lib/date";
import { db, type DbClient } from "../lib/db";
import { hashPassword } from "../lib/hash";
import { publishSyncEvent } from "../lib/sync-queue";
import type { Env } from "../types";

const HYBRID_PLAN_CODE = "hybrid";
const VALID_HYBRID_ORG_TYPES = ["school", "college", "university"] as const;
type HybridOrgType = (typeof VALID_HYBRID_ORG_TYPES)[number];

interface HybridTerms {
	plan_amount: number;
	seat_count: number;
	billing_cycle?: string;
	features?: unknown[];
	notes?: string;
}

function validateHybridTerms(data: HybridTerms): void {
	if (typeof data.plan_amount !== "number" || !Number.isFinite(data.plan_amount) || data.plan_amount < 0) {
		throw new Error("plan_amount must be a non-negative number");
	}
	if (!Number.isInteger(data.seat_count) || data.seat_count < 1) {
		throw new Error("seat_count must be a positive integer");
	}
}

/**
 * Core Hybrid activation, shared by `performCreateHybridSubscription`
 * (existing org) and `performCreateHybridOrganization` (new org). Assumes
 * the organization row already exists and terms have been validated.
 */
async function activateHybridForOrganization(
	env: Env,
	ctx: ExecutionContext,
	database: DbClient,
	organization: { id: string; name: string; metadata?: Record<string, unknown> },
	terms: HybridTerms,
	adminUserId: string,
	contactEmail = "",
): Promise<Record<string, unknown>> {
	const hybridPlan = await database.queryOne<{ id: string; plan_code: string; name: string }>(
		`plans?plan_code=eq.${HYBRID_PLAN_CODE}&is_active=eq.true`,
	);
	if (!hybridPlan) {
		throw new Error("Hybrid plan not found in catalog. Apply seed_hybrid_sales_plan.sql first.");
	}

	// One org can hold only one active/pending Hybrid subscription at a time.
	const existing = await database.queryOne(
		`subscriptions?organization_id=eq.${encodeURIComponent(organization.id)}&plan_code=eq.${HYBRID_PLAN_CODE}&status=in.(active,pending)`,
	);
	if (existing) {
		throw new Error("This organization already has an active or pending Hybrid subscription");
	}

	const billingCycle = terms.billing_cycle || "annual";
	const now = new Date();
	const endDate = addMonths(now, parseDurationMonths(billingCycle));
	const organizationType = (organization.metadata?.organization_type as string) || null;

	const subscription = await database.mutate("subscriptions", {
		user_id: adminUserId,
		plan_id: hybridPlan.id,
		plan_code: hybridPlan.plan_code,
		plan_type: hybridPlan.name,
		plan_amount: terms.plan_amount,
		billing_cycle: billingCycle,
		features: terms.features || [],
		full_name: organization.name,
		email: contactEmail,
		status: "active",
		auto_renew: billingCycle !== "lifetime",
		subscription_start_date: now.toISOString(),
		subscription_end_date: billingCycle === "lifetime" ? null : endDate.toISOString(),
		organization_id: organization.id,
		organization_type: organizationType,
		seat_count: terms.seat_count,
		is_organization_subscription: true,
		is_bulk_purchase: true,
		purchased_by: adminUserId,
		metadata: {
			activation_source: "admin_grant",
			activated_by: adminUserId,
			notes: terms.notes || null,
		},
	});

	publishSyncEvent(env.SYNC_QUEUE, ctx, "subscription.created", {
		id: (subscription as { id: string }).id,
		user_id: adminUserId,
		organization_id: organization.id,
		organization_type: organizationType,
		plan_id: hybridPlan.id,
		plan_code: hybridPlan.plan_code,
		plan_type: hybridPlan.name,
		plan_amount: terms.plan_amount,
		billing_cycle: billingCycle,
		features: terms.features || [],
		status: "active",
		subscription_start_date: now.toISOString(),
		subscription_end_date: billingCycle === "lifetime" ? null : endDate.toISOString(),
		is_organization_subscription: true,
		seat_count: terms.seat_count,
		assigned_seats: 0,
		product_id: null,
		updated_at: now.toISOString(),
	});

	return subscription as Record<string, unknown>;
}

/**
 * Admin-provisioned Hybrid subscription activation for an EXISTING org.
 *
 * Hybrid is a "contact sales" catalog plan — self-serve checkout always
 * rejects it (see skillpassport's `requireSelfServePlan`/`isSalesOnlyPlan`).
 * This RPC is the one deliberate bypass: an internal admin who has already
 * negotiated terms out-of-band calls it to create the `subscriptions` row
 * directly. It is only reachable via the SSO_SERVICE binding — the caller
 * (sp-dash's admin API route) is responsible for verifying the requester
 * holds an admin role before invoking this method.
 */
export async function performCreateHybridSubscription(
	env: Env,
	ctx: ExecutionContext,
	data: HybridTerms & {
		organization_id: string;
		admin_user_id: string;
	},
): Promise<Record<string, unknown>> {
	if (!data.organization_id) {
		throw new Error("organization_id is required");
	}
	if (!data.admin_user_id) {
		throw new Error("admin_user_id is required");
	}
	validateHybridTerms(data);

	const database = db(env);

	const organization = await database.queryOne<{
		id: string;
		name: string;
		metadata?: Record<string, unknown>;
		created_by?: string;
	}>(`organizations?id=eq.${encodeURIComponent(data.organization_id)}`);
	if (!organization) {
		throw new Error(`Organization ${data.organization_id} not found`);
	}

	// Best-effort: use the org's existing owner/creator email as the contact
	// on the subscription row, so it shows up correctly in sales dashboards
	// that read subscriptions.email. Not required — falls back to blank.
	let contactEmail = "";
	if (organization.created_by) {
		try {
			const creator = await database.queryOne<{ email: string }>(
				`users?id=eq.${encodeURIComponent(organization.created_by)}`,
			);
			contactEmail = creator?.email || "";
		} catch {
			// non-fatal — leave blank
		}
	}

	return activateHybridForOrganization(env, ctx, database, organization, data, data.admin_user_id, contactEmail);
}

/**
 * Admin-provisioned creation of a brand-new organization, owner user, and
 * Hybrid subscription in one flow — for the "New Hybrid Organization" modal
 * in sp-dash, where sales has signed a new customer who doesn't have an
 * account yet.
 *
 * Creates the user + org atomically via the `signup_user` Postgres function
 * (same primitive normal signup uses), tags the org's `metadata.organization_type`,
 * auto-verifies the owner's email (admin-created accounts are trusted, same
 * convention as `performCreateMember`), then activates Hybrid on the new org.
 *
 * If subscription activation fails after the org/user were created, the org
 * and user are NOT rolled back — losing a newly-created org/user is worse
 * than leaving one temporarily without a subscription, since an admin can
 * retry activation via `createHybridSubscription` afterward. The error is
 * surfaced with the created org/user ids so the caller can show a clear
 * partial-success message and let the admin retry just the subscription step.
 */
export async function performCreateHybridOrganization(
	env: Env,
	ctx: ExecutionContext,
	data: HybridTerms & {
		org_name: string;
		org_type: HybridOrgType;
		owner_email: string;
		owner_password: string;
		owner_name?: string;
		admin_user_id: string;
	},
): Promise<Record<string, unknown>> {
	if (!data.org_name?.trim()) {
		throw new Error("org_name is required");
	}
	if (!VALID_HYBRID_ORG_TYPES.includes(data.org_type)) {
		throw new Error(`org_type must be one of: ${VALID_HYBRID_ORG_TYPES.join(", ")}`);
	}
	if (!data.owner_email) {
		throw new Error("owner_email is required");
	}
	if (!data.owner_password || data.owner_password.length < 8) {
		throw new Error("owner_password must be at least 8 characters");
	}
	if (!data.admin_user_id) {
		throw new Error("admin_user_id is required");
	}
	validateHybridTerms(data);

	const database = db(env);
	const email = data.owner_email.toLowerCase().trim();

	const existingUser = await database.queryOne(`users?email=eq.${encodeURIComponent(email)}`);
	if (existingUser) {
		throw new Error(`A user with email ${email} already exists`);
	}

	const orgName = data.org_name.trim();
	const slug = `${orgName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}-${crypto.randomUUID().split("-")[0]}`;
	const password_hash = await hashPassword(data.owner_password);

	// skillpassport's primary user.created sync consumer only reads
	// firstName/lastName (see functions/lib/sync-service.ts syncUser) — it
	// does not split full_name the way the cache-miss self-heal path does.
	// Split here so the owner's name reaches skillpassport on first sync.
	const ownerNameParts = (data.owner_name || "").trim().split(/\s+/).filter(Boolean);
	const ownerFirstName = ownerNameParts[0] || "";
	const ownerLastName = ownerNameParts.slice(1).join(" ") || "";

	let signupResult: { user_id: string; org_id: string; slug: string };
	try {
		signupResult = await database.rpc<{ user_id: string; org_id: string; slug: string }>("signup_user", {
			p_email: email,
			p_password_hash: password_hash,
			p_org_name: orgName,
			p_org_slug: slug,
			p_role: "owner",
			p_user_metadata: { firstName: ownerFirstName, lastName: ownerLastName },
		});
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		if (message.includes("duplicate") || message.includes("23505")) {
			throw new Error(`A user or organization with these details already exists`);
		}
		throw err;
	}

	// Admin-created owner is trusted — auto-verify, same as performCreateMember.
	await database.update(
		"users",
		{ id: `eq.${encodeURIComponent(signupResult.user_id)}` },
		{ is_email_verified: true },
	);

	const orgMetadata = { organization_type: data.org_type };
	await database.update(
		"organizations",
		{ id: `eq.${encodeURIComponent(signupResult.org_id)}` },
		{ metadata: orgMetadata },
	);

	if (env.SYNC_QUEUE) {
		publishSyncEvent(env.SYNC_QUEUE, ctx, "user.created", {
			id: signupResult.user_id,
			email,
			user_metadata: { firstName: ownerFirstName, lastName: ownerLastName, role: "owner" },
		});
		publishSyncEvent(env.SYNC_QUEUE, ctx, "organization.created", {
			id: signupResult.org_id,
			name: orgName,
			slug: signupResult.slug,
			created_by: signupResult.user_id,
			metadata: orgMetadata,
		});
		publishSyncEvent(env.SYNC_QUEUE, ctx, "membership.created", {
			user_id: signupResult.user_id,
			organization_id: signupResult.org_id,
			roles: ["owner"],
			status: "active",
		});
	} else {
		console.error("[SSO] SYNC_QUEUE not bound, org/owner created but not synced to skillpassport");
	}

	const organization = { id: signupResult.org_id, name: orgName, metadata: orgMetadata };

	try {
		const subscription = await activateHybridForOrganization(env, ctx, database, organization, data, data.admin_user_id, email);
		return {
			organization: { id: signupResult.org_id, name: orgName, slug: signupResult.slug, type: data.org_type },
			owner: { id: signupResult.user_id, email },
			subscription,
		};
	} catch (subscriptionError) {
		const message = subscriptionError instanceof Error ? subscriptionError.message : String(subscriptionError);
		throw new Error(
			`Organization "${orgName}" and owner account were created, but Hybrid activation failed: ${message}. ` +
			`Retry activation for organization_id=${signupResult.org_id} without re-creating the org.`,
		);
	}
}

/**
 * List organizations with their most recent subscription (any plan), for
 * the sp-dash "Activate Hybrid Plan" org table. Admin-only, read via the
 * SSO_SERVICE binding.
 */
export async function performListOrganizationsWithSubscriptions(
	env: Env,
	params: {
		search?: string;
		plan_code?: string;
		status?: string;
		page?: number;
		limit?: number;
	},
): Promise<{
	data: Array<{
		organization_id: string;
		organization_name: string;
		organization_type: string | null;
		subscription_id: string | null;
		plan_code: string | null;
		plan_type: string | null;
		plan_amount: number | null;
		billing_cycle: string | null;
		status: string | null;
		seat_count: number | null;
		subscription_start_date: string | null;
		subscription_end_date: string | null;
	}>;
	pagination: { page: number; limit: number; total: number; totalPages: number };
}> {
	const database = db(env);
	const page = Number.isInteger(params.page) && (params.page as number) > 0 ? (params.page as number) : 1;
	const limit = Number.isInteger(params.limit) && (params.limit as number) > 0 ? Math.min(params.limit as number, 100) : 20;
	const offset = (page - 1) * limit;

	// Filtering by plan_code/status happens in memory below, since that data
	// lives on a joined table (subscriptions) that PostgREST can't filter in
	// one request alongside organizations. This mirrors the same all-then-
	// filter-then-paginate pattern already used by getSalesSubscriptions.
	// Caveat: PostgREST's default row cap could silently truncate results
	// if the organization count grows very large — same caveat that applies
	// to sales-subscriptions.ts today. Revisit with a DB view/RPC if this
	// list needs to scale past a few thousand orgs.
	let orgQuery = "organizations?select=id,name,metadata,created_at&deleted_at=is.null&order=created_at.desc";
	if (params.search) {
		orgQuery += `&name=ilike.*${encodeURIComponent(params.search)}*`;
	}

	const organizations = await database.query<{
		id: string;
		name: string;
		metadata?: Record<string, unknown>;
		created_at: string;
	}>(orgQuery);

	if (organizations.length === 0) {
		return { data: [], pagination: { page, limit, total: 0, totalPages: 0 } };
	}

	const orgIds = organizations.map((o) => encodeURIComponent(o.id)).join(",");
	const subscriptions = await database.query<{
		id: string;
		organization_id: string;
		plan_code: string;
		plan_type: string;
		plan_amount: number;
		billing_cycle: string;
		status: string;
		seat_count: number;
		subscription_start_date: string;
		subscription_end_date: string | null;
		created_at: string;
	}>(
		`subscriptions?organization_id=in.(${orgIds})&is_organization_subscription=eq.true&order=created_at.desc`,
	);

	// Keep only the most recent subscription per org.
	const latestByOrg = new Map<string, (typeof subscriptions)[number]>();
	for (const sub of subscriptions) {
		if (!latestByOrg.has(sub.organization_id)) {
			latestByOrg.set(sub.organization_id, sub);
		}
	}

	let rows = organizations.map((org) => {
		const sub = latestByOrg.get(org.id);
		return {
			organization_id: org.id,
			organization_name: org.name,
			organization_type: (org.metadata?.organization_type as string) || null,
			subscription_id: sub?.id ?? null,
			plan_code: sub?.plan_code ?? null,
			plan_type: sub?.plan_type ?? null,
			plan_amount: sub?.plan_amount ?? null,
			billing_cycle: sub?.billing_cycle ?? null,
			status: sub?.status ?? null,
			seat_count: sub?.seat_count ?? null,
			subscription_start_date: sub?.subscription_start_date ?? null,
			subscription_end_date: sub?.subscription_end_date ?? null,
		};
	});

	if (params.plan_code === "none") {
		rows = rows.filter((r) => !r.plan_code);
	} else if (params.plan_code) {
		rows = rows.filter((r) => r.plan_code === params.plan_code);
	}
	if (params.status) {
		rows = rows.filter((r) => r.status === params.status);
	}

	const total = rows.length;
	const paginated = rows.slice(offset, offset + limit);

	return {
		data: paginated,
		pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
	};
}
