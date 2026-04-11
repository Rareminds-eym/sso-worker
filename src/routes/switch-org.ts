import type { Env, SwitchOrgBody, Membership, AccessTokenPayload } from "../types";
import { db } from "../lib/db";
import { signAccessToken } from "../lib/jwt";
import { hashToken, generateRefreshToken } from "../lib/hash";
import { getCookie, setAuthCookies } from "../lib/cookies";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";

export async function switchOrg(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const currentPayload = auth!;
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");

  let body: SwitchOrgBody;
  try {
    body = await req.json() as SwitchOrgBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.org_id) {
    return error("org_id is required");
  }

  const database = db(env);

  // Verify ACTIVE membership in target org
  const membership = await database.queryOne<Membership>(
    `memberships?user_id=eq.${currentPayload.sub}&org_id=eq.${body.org_id}&status=eq.active&select=*`,
  );

  if (!membership) {
    return error("You are not an active member of this organization", 403);
  }

  const oldRefresh = getCookie(req, "refresh_token");
  if (oldRefresh) {
    const oldHash = await hashToken(oldRefresh);
    await database.update(
      "sessions",
      { refresh_token_hash: `eq.${oldHash}` },
      { revoked: true },
    ).catch((err) => {
      console.warn("[SSO] Old session revocation failed on switch-org:", err);
    });
  }

  const refreshToken = generateRefreshToken();
  const refreshHash = await hashToken(refreshToken);

  await database.mutate("sessions", {
    user_id: currentPayload.sub,
    org_id: body.org_id,
    refresh_token_hash: refreshHash,
    user_agent: ua,
    ip_address: ip,
    revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
  });

  const accessToken = await signAccessToken(
    {
      sub: currentPayload.sub,
      email: currentPayload.email,
      org_id: body.org_id,
      role: membership.role,
    },
    env,
  );

  const response = json({ success: true, org_id: body.org_id, role: membership.role });
  setAuthCookies(response, accessToken, refreshToken);

  audit(ctx, env, "switch_org", {
    user_id: currentPayload.sub,
    org_id: body.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { from_org: currentPayload.org_id, to_org: body.org_id },
  });

  return response;
}
