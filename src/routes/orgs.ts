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

  return json({
    organizations: memberships.map((m) => ({
      org_id: m.org_id,
      role: m.role,
      name: orgMap.get(m.org_id)?.name ?? null,
      slug: orgMap.get(m.org_id)?.slug ?? null,
      is_active: m.org_id === payload.org_id,
    })),
  });
}
