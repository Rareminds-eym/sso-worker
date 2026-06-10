import { db } from "../lib/db";
import { json, error } from "../lib/response";
import type { Env } from "../types";

/**
 * POST /api/memberships/create
 * Creates a membership for a user in an org.
 * Called by SkillPassport when accepting a recruitment invitation.
 */
export async function createMembership(req: Request, env: Env): Promise<Response> {
  let body: { user_id: string; org_id: string; status?: string };
  try {
    body = await req.json();
  } catch {
    return error("Invalid JSON body", 400);
  }

  const { user_id, org_id, status = "active" } = body;
  if (!user_id || !org_id) {
    return error("user_id and org_id are required", 400);
  }

  const database = db(env);

  const existing = await database.queryOne<{ id: string; status: string }>(
    `memberships?user_id=eq.${user_id}&org_id=eq.${org_id}&select=id,status`,
  );

  if (existing) {
    if (existing.status !== "active") {
      await database.update(
        "memberships",
        { id: `eq.${existing.id}` },
        { status: "active" },
      );
    }
    return json({ id: existing.id, status: "active" });
  }

  const membership = await database.mutate<{ id: string; status: string }>(
    "memberships",
    { user_id, org_id, status },
  );

  return json({ id: membership.id, status: membership.status });
}

/**
 * POST /api/memberships/assign-role
 * Assigns a role to a membership via the membership_roles join table.
 */
export async function assignMembershipRole(req: Request, env: Env): Promise<Response> {
  let body: { membership_id: string; role_id: string };
  try {
    body = await req.json();
  } catch {
    return error("Invalid JSON body", 400);
  }

  const { membership_id, role_id } = body;
  if (!membership_id || !role_id) {
    return error("membership_id and role_id are required", 400);
  }

  const database = db(env);

  const existing = await database.queryOne<{ id: string }>(
    `membership_roles?membership_id=eq.${membership_id}&role_id=eq.${role_id}&select=id`,
  );

  if (!existing) {
    await database.mutate("membership_roles", { membership_id, role_id });
  }

  return json({ success: true });
}

/**
 * PUT /api/memberships/update-status
 * Updates the status of an existing membership.
 */
export async function updateMembershipStatus(req: Request, env: Env): Promise<Response> {
  let body: { membership_id: string; status: string };
  try {
    body = await req.json();
  } catch {
    return error("Invalid JSON body", 400);
  }

  const { membership_id, status } = body;
  if (!membership_id || !status) {
    return error("membership_id and status are required", 400);
  }

  const database = db(env);

  await database.update(
    "memberships",
    { id: `eq.${membership_id}` },
    { status },
  );

  return json({ success: true });
}
