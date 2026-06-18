import { audit } from "../lib/audit";
import { SESSION_TTL_MS } from "../lib/constants";
import { getCookie, setAuthCookies } from "../lib/cookies";
import { db } from "../lib/db";
import { generateRefreshToken, hashToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { endpointRateLimit } from "../lib/rate-limit";
import { error, json } from "../lib/response";
import type { AccessTokenPayload, Env, JwtClaims, Membership, SwitchOrgBody } from "../types";

export async function switchOrg(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const currentPayload = auth!;
  const rateLimited = await endpointRateLimit(env, `switch-org:user:${currentPayload.sub}`, 30, 60);
  if (rateLimited) return rateLimited;

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

  // Get RBAC claims for the target org
  const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
    p_user_id: currentPayload.sub,
    p_org_id: body.org_id,
  });

  if (!claims) {
    return error("Failed to resolve membership claims", 500);
  }

  const refreshToken = generateRefreshToken();
  const refreshHash = await hashToken(refreshToken);
  const sessionId = crypto.randomUUID();

  await database.mutate("sessions", {
    id: sessionId,
    user_id: currentPayload.sub,
    org_id: body.org_id,
    refresh_token_hash: refreshHash,
    user_agent: ua,
    ip_address: ip,
    revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    family_id: sessionId,
    family_created_at: new Date().toISOString(),
  });

  const accessToken = await signAccessToken(
    {
      sub: currentPayload.sub,
      email: currentPayload.email,
      org_id: body.org_id,
      roles: claims.roles,
      products: claims.products,
      membership_status: claims.membership_status,
      is_email_verified: currentPayload.is_email_verified,
      user_metadata: currentPayload.user_metadata ?? {},
    },
    env,
  );

  const response = json({
    access_token: accessToken,
    org_id: body.org_id,
    roles: claims.roles,
  });
  setAuthCookies(response, accessToken, refreshToken, env);

  audit(ctx, env, "switch_org", {
    user_id: currentPayload.sub,
    org_id: body.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { from_org: currentPayload.org_id, to_org: body.org_id },
  });

  return response;
}
