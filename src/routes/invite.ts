import type { Env, InviteBody, AcceptInviteBody, Invite, User, Membership, AccessTokenPayload, JwtClaims } from "../types";
import { db } from "../lib/db";
import { signAccessToken } from "../lib/jwt";
import { hashPassword, hashToken, generateRefreshToken } from "../lib/hash";
import { setAuthCookies } from "../lib/cookies";
import { validateEmail, validatePassword } from "../lib/validate";
import { json, error } from "../lib/response";
import { audit } from "../lib/audit";
import { SESSION_TTL_MS, INVITE_TTL_MS } from "../lib/constants";

const ALLOWED_INVITE_ROLES = ["admin", "member"] as const;

export async function createInvite(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  auth?: AccessTokenPayload,
): Promise<Response> {
  const caller = auth!;
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");

  // Only owners and admins can create invites
  if (!caller.roles.includes("owner") && !caller.roles.includes("admin")) {
    return error("Only owners and admins can create invites", 403);
  }

  let body: InviteBody;
  try {
    body = await req.json() as InviteBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.email || !body.org_id || !body.role?.length) {
    return error("email, org_id, and role are required");
  }

  const emailErr = validateEmail(body.email);
  if (emailErr) return emailErr;

  // Validate all roles in the array
  const invalidRoles = body.role.filter(
    (r) => !ALLOWED_INVITE_ROLES.includes(r as any),
  );
  if (invalidRoles.length) {
    return error(`Invalid roles: ${invalidRoles.join(", ")}. Allowed: ${ALLOWED_INVITE_ROLES.join(", ")}`);
  }

  if (body.org_id !== caller.org_id) {
    return error("You can only invite to your active organization", 403);
  }

  const database = db(env);
  const inviteEmail = body.email.toLowerCase().trim();

  const existingUser = await database.queryOne<User>(
    `users?email=eq.${encodeURIComponent(inviteEmail)}&select=id`,
  );
  if (existingUser) {
    const existingMembership = await database.queryOne<Membership>(
      `memberships?user_id=eq.${existingUser.id}&org_id=eq.${body.org_id}&status=eq.active&select=id`,
    );
    if (existingMembership) {
      return error("This user is already an active member of the organization", 409);
    }
  }

  const existing = await database.queryOne<Invite>(
    `invites?email=eq.${encodeURIComponent(inviteEmail)}&org_id=eq.${body.org_id}&accepted=eq.false&select=id`,
  );
  if (existing) {
    return error("An invite for this email already exists", 409);
  }

  const inviteToken = crypto.randomUUID();

  const invite = await database.mutate<Invite>("invites", {
    email: inviteEmail,
    org_id: body.org_id,
    role: body.role,
    token: inviteToken,
    invited_by: caller.sub,
    expires_at: new Date(Date.now() + INVITE_TTL_MS).toISOString(),
    accepted: false,
  });

  audit(ctx, env, "invite_created", {
    user_id: caller.sub,
    org_id: body.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { invited_email: inviteEmail, roles: body.role },
  });

  return json(
    {
      invite_id: invite.id,
      token: inviteToken,
      email: inviteEmail,
      expires_at: invite.expires_at,
    },
    201,
  );
}

export async function acceptInvite(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let body: AcceptInviteBody;
  try {
    body = await req.json() as AcceptInviteBody;
  } catch {
    return error("Invalid JSON body");
  }

  if (!body.token) {
    return error("token is required");
  }

  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");
  const database = db(env);

  const invite = await database.queryOne<Invite>(
    `invites?token=eq.${encodeURIComponent(body.token)}&select=*`,
  );

  if (!invite) return error("Invalid invite token", 404);
  if (invite.accepted) return error("Invite has already been accepted", 410);
  if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
    return error("Invite has expired", 410);
  }

  let user = await database.queryOne<User>(
    `users?email=eq.${encodeURIComponent(invite.email)}&select=*`,
  );

  if (!user) {
    const passErr = validatePassword(body.password);
    if (passErr) return passErr;

    const password_hash = await hashPassword(body.password!);
    user = await database.mutate<User>("users", {
      email: invite.email,
      password_hash,
      is_email_verified: false,
    });
  }

  const existingMembership = await database.queryOne<Membership>(
    `memberships?user_id=eq.${user.id}&org_id=eq.${invite.org_id}&select=id,status`,
  );

  let membershipId: string;

  if (existingMembership) {
    membershipId = existingMembership.id;
    // Reactivate if deactivated
    if (existingMembership.status !== "active") {
      await database.update(
        "memberships",
        { id: `eq.${existingMembership.id}` },
        { status: "active" },
      );
    }
  } else {
    const newMembership = await database.mutate<Membership>("memberships", {
      user_id: user.id,
      org_id: invite.org_id,
      status: "active",
    });
    membershipId = newMembership.id;
  }

  // Assign roles from invite via join table
  const inviteRoles = invite.role?.length ? invite.role : ["member"];
  // Fetch role IDs
  const roleRows = await database.query<{ id: string; name: string }>(
    `roles?name=in.(${inviteRoles.join(",")})&select=id,name`,
  );

  for (const role of roleRows) {
    try {
      await database.mutate("membership_roles", {
        membership_id: membershipId,
        role_id: role.id,
      });
    } catch (err: any) {
      // Ignore duplicate — role already assigned (e.g. reactivated membership)
      if (!err?.message?.includes("23505") && !err?.message?.includes("duplicate")) {
        throw err;
      }
    }
  }

  // Mark invite as accepted
  await database.update("invites", { id: `eq.${invite.id}` }, {
    accepted: true,
    accepted_at: new Date().toISOString(),
  });

  // Get RBAC claims for the new membership
  const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
    p_user_id: user.id,
    p_org_id: invite.org_id,
  });

  const refreshToken = generateRefreshToken();
  const refreshHash = await hashToken(refreshToken);

  await database.mutate("sessions", {
    user_id: user.id,
    org_id: invite.org_id,
    refresh_token_hash: refreshHash,
    user_agent: ua,
    ip_address: ip,
    revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
  });

  const accessToken = await signAccessToken(
    {
      sub: user.id,
      email: user.email,
      org_id: invite.org_id,
      roles: claims?.roles ?? inviteRoles,
      products: claims?.products ?? [],
      membership_status: claims?.membership_status ?? "active",
      is_email_verified: user.is_email_verified,
    },
    env,
  );

  const response = json({
    access_token: accessToken,
    user: { id: user.id, email: user.email },
    org_id: invite.org_id,
  });

  setAuthCookies(response, accessToken, refreshToken);

  audit(ctx, env, "invite_accepted", {
    user_id: user.id,
    org_id: invite.org_id,
    ip_address: ip,
    user_agent: ua,
    metadata: { invite_id: invite.id },
  });

  return response;
}
