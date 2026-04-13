import type { Env, Membership, Organization, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { json } from "../lib/response";

export async function listOrgs(
  _req: Request,
  env: Env,
  _ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const payload = auth!;
  const database = db(env);

  // Only active memberships
  const memberships = await database.query<Membership>(
    `memberships?user_id=eq.${payload.sub}&status=eq.active&select=*&order=created_at.asc`,
  );

  const orgIds = memberships.map((m) => m.org_id);
  const orgs = orgIds.length
    ? await database.query<Organization>(
        `organizations?id=in.(${orgIds.join(",")})&select=*`,
      )
    : [];

  const orgMap = new Map(orgs.map((o) => [o.id, o]));

  // Fetch roles for each membership via join table
  const membershipIds = memberships.map((m) => m.id);
  const roleRows = membershipIds.length
    ? await database.query<{ membership_id: string; name: string }>(
        `membership_roles?membership_id=in.(${membershipIds.join(",")})&select=membership_id,role_id(name)`,
      )
    : [];

  // PostgREST returns nested objects for FK selects — flatten
  const roleMap = new Map<string, string[]>();
  for (const row of roleRows) {
    const mid = row.membership_id;
    const roleName = (row as any).role_id?.name ?? (row as any).name;
    if (!roleMap.has(mid)) roleMap.set(mid, []);
    if (roleName) roleMap.get(mid)!.push(roleName);
  }

  return json({
    organizations: memberships.map((m) => ({
      org_id: m.org_id,
      roles: roleMap.get(m.id) ?? [],
      name: orgMap.get(m.org_id)?.name ?? null,
      slug: orgMap.get(m.org_id)?.slug ?? null,
      is_active: m.org_id === payload.org_id,
    })),
  });
}
