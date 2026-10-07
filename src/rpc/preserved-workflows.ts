import { audit } from "../lib/audit";
import { INVITE_TTL_MS, PLATFORM_ORG_ID, SESSION_TTL_MS } from "../lib/constants";
import type { DbClient } from "../lib/db";
import { inviteEmail, logEmailFailure, sendEmailWithStatus, type EmailStatus } from "../lib/email";
import { checkEmailThrottle } from "../lib/email-throttle";
import { generateRefreshToken, hashPassword, hashToken } from "../lib/hash";
import { signAccessToken, verifyAccessToken } from "../lib/jwt";
import { resolveEffectiveRoles } from "../lib/roles";
import { publishSyncEvent } from "../lib/sync-queue";
import { resolveAppUrl, validateEmail, validatePassword } from "../lib/validate";
import { performForgotPassword, performResetPassword } from "../routes/password-reset";
import { performRequestVerification, performVerifyEmail } from "../routes/verify-email";
import type { AccessTokenPayload, Env, Invite, JwtClaims, Membership, Organization } from "../types";
import type {
    AcceptInviteRpcInput, AcceptInviteRpcOutcome,
    CancelInviteRpcInput, CancelInviteRpcOutcome,
    ChangeOrganizationRpcInput,
    ChangeOrganizationRpcOutcome, Correlated, CreateInviteRpcInput, CreateInviteRpcOutcome,
    ForgotPasswordRpcInput, ForgotPasswordRpcOutcome,
    GetIdentityRpcInput, IdentityRpcOutcome, ListInvitesRpcInput, ListInvitesRpcOutcome,
    ListOrganizationsRpcInput, OrganizationListRpcOutcome, PendingInviteData,
    RequestVerificationRpcInput, RequestVerificationRpcOutcome, ResendInviteRpcInput,
    ResendInviteRpcOutcome, ResetPasswordRpcInput, ResetPasswordRpcOutcome, RpcIdentity, RpcSession,
    VerifyEmailRpcInput, VerifyEmailRpcOutcome, WorkflowRejectionCode,
} from "./contracts";

export interface PreservedWorkflowDependencies {
    readonly hash: typeof hashToken;
    readonly hashPassword: typeof hashPassword;
    readonly generateRefreshToken: typeof generateRefreshToken;
    readonly signAccessToken: typeof signAccessToken;
    readonly verifyAccessToken: typeof verifyAccessToken;
    readonly now: () => number;
}

export const defaultPreservedWorkflowDependencies: PreservedWorkflowDependencies = {
    hash: hashToken, hashPassword, generateRefreshToken, signAccessToken, verifyAccessToken, now: Date.now,
};

type PreservedMethods = Pick<import("./contracts").SsoServiceBinding,
    "changeOrganization" | "listOrganizations" | "createInvite" | "acceptInvite" |
    "cancelInvite" | "resendInvite" | "listInvites" | "requestVerification" | "verifyEmail" |
    "forgotPassword" | "resetPassword" | "getIdentity">;

export function createPreservedWorkflowAuthority(
    env: Env,
    ctx: ExecutionContext,
    database: DbClient,
    dependencies: PreservedWorkflowDependencies = defaultPreservedWorkflowDependencies,
): PreservedMethods {
    return {
        changeOrganization: (input) => changeOrganization(env, input, database, dependencies),
        listOrganizations: (input) => listOrganizations(env, input, database, dependencies),
        createInvite: (input) => createInvite(env, ctx, input, database, dependencies),
        acceptInvite: (input) => acceptInvite(env, ctx, input, database, dependencies),
        cancelInvite: (input) => cancelInvite(env, ctx, input, database, dependencies),
        resendInvite: (input) => resendInvite(env, ctx, input, database, dependencies),
        listInvites: (input) => listInvites(env, input, database, dependencies),
        requestVerification: (input) => requestVerification(env, ctx, input, database, dependencies),
        verifyEmail: (input) => verifyEmail(env, ctx, input, database, dependencies),
        forgotPassword: (input) => forgotPassword(env, ctx, input),
        resetPassword: (input) => resetPassword(env, ctx, input, database, dependencies),
        getIdentity: (input) => getIdentity(env, input, database, dependencies),
    };
}

class WorkflowError extends Error {
    constructor(readonly code: WorkflowRejectionCode) { super(code); }
}

async function authenticated(
    env: Env,
    accessToken: string,
    dependencies: PreservedWorkflowDependencies,
): Promise<AccessTokenPayload> {
    if (!accessToken) throw new WorkflowError("authorization_denied");
    try { return await dependencies.verifyAccessToken(accessToken, env); }
    catch { throw new WorkflowError("authorization_denied"); }
}

function rejected(input: Correlated, code: WorkflowRejectionCode) {
    return { kind: "rejected" as const, correlationId: input.correlationId, code };
}

function workflowFailure(input: Correlated, error: unknown) {
    return error instanceof WorkflowError
        ? rejected(input, error.code)
        : { kind: isTimeout(error) ? "timeout" as const : "unavailable" as const, correlationId: input.correlationId };
}

function isTimeout(error: unknown): boolean {
    return error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
}

async function activeSession(
    database: DbClient,
    token: string | undefined,
    dependencies: PreservedWorkflowDependencies,
): Promise<SessionRow | null> {
    if (!token) return null;
    const tokenHash = await dependencies.hash(token);
    return database.queryOne<SessionRow>(
        `sessions?refresh_token_hash=eq.${encodeURIComponent(tokenHash)}&revoked=eq.false&select=id,user_id,org_id,expires_at,revoked`,
    );
}

interface SessionRow { id: string; user_id: string; org_id: string | null; expires_at: string; revoked: boolean }

async function issueSession(
    env: Env,
    database: DbClient,
    userId: string,
    orgId: string,
    dependencies: PreservedWorkflowDependencies,
): Promise<RpcSession> {
    const user = await database.queryOne<UserRow>(
        `users?id=eq.${encodeURIComponent(userId)}&select=id,email,is_email_verified,user_metadata,is_blocked`,
    );
    if (!user || user.is_blocked) throw new WorkflowError("account_blocked");
    const identity = await loadIdentity(database, user, orgId);
    const refreshToken = dependencies.generateRefreshToken();
    const refreshHash = await dependencies.hash(refreshToken);
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(dependencies.now() + SESSION_TTL_MS).toISOString();
    const accessToken = await dependencies.signAccessToken(toAccessPayload(identity), env);
    await database.mutate("sessions", {
        id: sessionId, user_id: userId, org_id: orgId, refresh_token_hash: refreshHash,
        user_agent: null, ip_address: null, revoked: false, expires_at: expiresAt,
        family_id: sessionId, family_created_at: new Date(dependencies.now()).toISOString(),
    });
    return { accessToken, refreshToken, remainingLifetimeSeconds: SESSION_TTL_MS / 1000, identity };
}

interface UserRow {
    id: string; email: string; is_email_verified: boolean; is_blocked?: boolean;
    user_metadata?: Record<string, unknown> | null;
}

async function loadIdentity(database: DbClient, user: UserRow, orgId: string): Promise<RpcIdentity> {
    const claims = (orgId ? await database.rpc<JwtClaims>("get_jwt_claims", { p_user_id: user.id, p_org_id: orgId }) : null)
        ?? { roles: [], products: [], membership_status: "active" as const };
    if (!Array.isArray(claims.roles) || !Array.isArray(claims.products)) {
        throw new Error("Invalid authoritative claims");
    }
    const roles = resolveEffectiveRoles({
        claims,
        userMetadata: user.user_metadata,
        fallbackRole: "learner",
    });

    return {
        subject: user.id, email: user.email, organizationId: (orgId && orgId.length > 0) ? orgId : PLATFORM_ORG_ID,
        roles, products: claims.products, membershipStatus: claims.membership_status,
        emailVerified: user.is_email_verified,
        userMetadata: (user.user_metadata ?? {}) as RpcIdentity["userMetadata"],
    };
}

function toAccessPayload(identity: RpcIdentity): AccessTokenPayload {
    return {
        sub: identity.subject, email: identity.email, org_id: identity.organizationId,
        roles: [...identity.roles], products: [...identity.products],
        membership_status: identity.membershipStatus, is_email_verified: identity.emailVerified,
        user_metadata: identity.userMetadata ? { ...identity.userMetadata } : {},
    };
}

async function revokeSession(database: DbClient, sessionId: string): Promise<void> {
    await database.update("sessions", { id: `eq.${encodeURIComponent(sessionId)}` }, { revoked: true });
}

async function changeOrganization(
    env: Env, input: ChangeOrganizationRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<ChangeOrganizationRpcOutcome> {
    try {
        const prior = await activeSession(database, input.refreshToken, dependencies);
        if (!prior || prior.revoked || Date.parse(prior.expires_at) <= dependencies.now()) {
            return { kind: "rejected", code: "absent", correlationId: input.correlationId };
        }
        const membership = await database.queryOne<Membership>(
            `memberships?user_id=eq.${encodeURIComponent(prior.user_id)}&org_id=eq.${encodeURIComponent(input.organizationId)}&status=eq.active&select=id`,
        );
        if (!membership) return { kind: "rejected", code: "blocked", correlationId: input.correlationId };
        const session = await issueSession(env, database, prior.user_id, input.organizationId, dependencies);
        if (session.refreshToken === input.refreshToken) throw new Error("Replacement credential was reused");
        await revokeSession(database, prior.id);
        return { kind: "rotated", correlationId: input.correlationId, session };
    } catch (error) {
        return { kind: isTimeout(error) ? "timeout" : "unavailable", correlationId: input.correlationId };
    }
}

async function listOrganizations(
    env: Env, input: ListOrganizationsRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<OrganizationListRpcOutcome> {
    try {
        const caller = await authenticated(env, input.accessToken, dependencies);
        const memberships = await database.query<Membership>(
            `memberships?user_id=eq.${encodeURIComponent(caller.sub)}&status=eq.active&select=*&order=created_at.asc`,
        );
        const orgIds = memberships.map(({ org_id }) => org_id);
        const orgs = orgIds.length ? await database.query<Organization>(
            `organizations?id=in.(${orgIds.map(encodeURIComponent).join(",")})&select=*`,
        ) : [];
        const membershipIds = memberships.map(({ id }) => id);
        const roleRows = membershipIds.length ? await database.query<RoleJoin>(
            `membership_roles?membership_id=in.(${membershipIds.map(encodeURIComponent).join(",")})&select=membership_id,role_id(name)`,
        ) : [];
        const roleMap = new Map<string, string[]>();
        for (const row of roleRows) {
            if (!row.role_id) continue;
            roleMap.set(row.membership_id, [...(roleMap.get(row.membership_id) ?? []), row.role_id.name]);
        }
        const orgMap = new Map(orgs.map((org) => [org.id, org]));
        return {
            kind: "succeeded", correlationId: input.correlationId,
            data: {
                organizations: memberships.map((membership) => ({
                    organizationId: membership.org_id,
                    name: orgMap.get(membership.org_id)?.name ?? null,
                    slug: orgMap.get(membership.org_id)?.slug ?? null,
                    roles: roleMap.get(membership.id) ?? [], active: membership.org_id === caller.org_id,
                }))
            },
        };
    } catch (error) { return workflowFailure(input, error); }
}

interface RoleJoin { membership_id: string; role_id: { name: string } | null }

async function getIdentity(
    env: Env, input: GetIdentityRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<IdentityRpcOutcome> {
    try {
        const caller = await authenticated(env, input.accessToken, dependencies);
        const user = await database.queryOne<UserRow>(
            `users?id=eq.${encodeURIComponent(caller.sub)}&select=id,email,is_email_verified,user_metadata,is_blocked`,
        );
        if (!user) throw new WorkflowError("not_found");
        const data = await loadIdentity(database, user, caller.org_id);
        return { kind: "succeeded", correlationId: input.correlationId, data };
    } catch (error) { return workflowFailure(input, error); }
}

/** Invites carrying these roles may only be created by an organization administrator. */
const GATED_INVITE_ROLES: ReadonlySet<string> = new Set(["college_educator", "school_educator"]);
const INVITER_ROLES: ReadonlySet<string> = new Set(["owner", "admin", "super_admin", "college_admin", "school_admin"]);

function isAdminTierRole(name: string): boolean {
    return name === "owner" || name === "admin" || name === "super_admin" || name.endsWith("_admin");
}

async function createInvite(
    env: Env, ctx: ExecutionContext, input: CreateInviteRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<CreateInviteRpcOutcome> {
    try {
        const caller = await authenticated(env, input.accessToken, dependencies);
        const emailError = validateEmail(input.email);
        if (emailError || !input.organizationId || input.roles.length === 0) throw new WorkflowError("invalid_request");
        if (caller.org_id !== input.organizationId) throw new WorkflowError("authorization_denied");
        if (input.roles.some((role) => GATED_INVITE_ROLES.has(role))) {
            await requireInviterRole(database, caller, input.organizationId);
        }
        const email = input.email.toLowerCase().trim();
        const existing = await database.queryOne<{ id: string }>(
            `invites?email=eq.${encodeURIComponent(email)}&org_id=eq.${encodeURIComponent(input.organizationId)}&accepted=eq.false&select=id`,
        );
        if (existing) throw new WorkflowError("conflict");
        if (await checkEmailThrottle(env, "invite", input.organizationId)) {
            return { kind: "rate_limited", correlationId: input.correlationId };
        }
        const token = crypto.randomUUID();
        const expiresAt = new Date(dependencies.now() + INVITE_TTL_MS).toISOString();
        const invite = await database.mutate<Invite>("invites", {
            email, org_id: input.organizationId, role: [...input.roles],
            token_hash: await dependencies.hash(token), invited_by: caller.sub,
            expires_at: expiresAt, accepted: false,
        });
        const emailStatus = await deliverInviteEmail(
            env, ctx, database, caller, invite.id, email, input.organizationId, token,
        );
        audit(ctx, env, "invite_created", {
            user_id: caller.sub, org_id: input.organizationId,
            metadata: { invite_id: invite.id, email_status: emailStatus }
        });
        return {
            kind: "succeeded", correlationId: input.correlationId,
            data: {
                inviteId: invite.id, email, expiresAt,
                ...(input.includeEmailStatus === true ? { emailStatus } : {}),
            }
        };
    } catch (error) { return workflowFailure(input, error); }
}

/**
 * Roles come from the database, never from the token (token roles can originate from client metadata).
 * A get_jwt_claims transport error propagates (fail closed).
 */
async function requireInviterRole(
    database: DbClient, caller: AccessTokenPayload, organizationId: string,
): Promise<void> {
    const claims = await database.rpc<JwtClaims | null>("get_jwt_claims", {
        p_user_id: caller.sub, p_org_id: organizationId,
    });
    if (claims?.membership_status !== "active" || !claims.roles?.some((role) => INVITER_ROLES.has(role))) {
        throw new WorkflowError("authorization_denied");
    }
}

/**
 * Send the invite email and report the result. Never throws: an organization lookup failure is
 * reported as "failed" (the invite row is already stored). The token only ever goes into the
 * email body; it is never logged or returned.
 */
async function deliverInviteEmail(
    env: Env, ctx: ExecutionContext, database: DbClient, caller: AccessTokenPayload,
    inviteId: string, email: string, organizationId: string, token: string,
): Promise<EmailStatus> {
    let message: ReturnType<typeof inviteEmail>;
    try {
        const organization = await database.queryOne<{ name: string }>(
            `organizations?id=eq.${encodeURIComponent(organizationId)}&select=name`,
        );
        const acceptUrl = `${resolveAppUrl(undefined, env)}/invite/accept?token=${token}`;
        message = inviteEmail(caller.email, organization?.name ?? "an organization", acceptUrl);
    } catch (error) {
        logEmailFailure(inviteId, "lookup_failed", { errorName: (error as { name?: unknown } | null)?.name });
        return "failed";
    }
    return sendEmailWithStatus(env, { to: email, ...message }, ctx, { inviteId });
}

async function acceptInvite(
    env: Env, ctx: ExecutionContext, input: AcceptInviteRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<AcceptInviteRpcOutcome> {
    try {
        if (!input.invitationToken) return sessionRejected(input, "invalid_invitation");
        const invite = await database.queryOne<Invite>(
            `invites?token_hash=eq.${encodeURIComponent(await dependencies.hash(input.invitationToken))}&select=*`,
        );
        if (!invite) return sessionRejected(input, "invalid_invitation");
        if (invite.accepted) return sessionRejected(input, "invalid_invitation");
        if (invite.expires_at && Date.parse(invite.expires_at) <= dependencies.now()) {
            return sessionRejected(input, "invitation_expired");
        }
        const prior = await activeSession(database, input.currentRefreshToken, dependencies);
        const { user, created } = await resolveInviteUser(invite, input.password, database, dependencies);
        if (created) {
            // user.created must precede membership.created so the SkillPassport users row exists first.
            const role = invite.role[0];
            publishSyncEvent(env.SYNC_QUEUE, ctx, "user.created", {
                id: user.id, email: user.email, is_email_verified: user.is_email_verified,
                user_metadata: role ? { role } : {},
            });
        }
        const membershipId = await ensureMembership(database, user.id, invite.org_id);
        await assignInviteRoles(database, membershipId, invite.role);
        await database.update("invites", { id: `eq.${encodeURIComponent(invite.id)}` },
            { accepted: true, accepted_at: new Date(dependencies.now()).toISOString() });
        const session = await issueSession(env, database, user.id, invite.org_id, dependencies);
        if (session.refreshToken === input.currentRefreshToken) throw new Error("Replacement credential was reused");
        if (prior) await revokeSession(database, prior.id);
        publishSyncEvent(env.SYNC_QUEUE, ctx, "membership.created", {
            user_id: user.id, organization_id: invite.org_id, roles: invite.role, status: "active",
            source: "invite",
        });
        return {
            kind: "issued", correlationId: input.correlationId,
            data: { inviteId: invite.id, organizationId: invite.org_id }, session
        };
    } catch (error) {
        if (error instanceof WorkflowError) return sessionRejected(input, "membership_rejected");
        return { kind: isTimeout(error) ? "timeout" : "unavailable", correlationId: input.correlationId };
    }
}

function sessionRejected(input: Correlated, code: "invalid_invitation" | "invitation_expired" | "membership_rejected") {
    return { kind: "rejected" as const, correlationId: input.correlationId, code };
}

async function resolveInviteUser(
    invite: Invite, password: string | undefined, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<{ user: UserRow; created: boolean }> {
    const existing = await database.queryOne<UserRow>(
        `users?email=eq.${encodeURIComponent(invite.email)}&select=id,email,is_email_verified,user_metadata,is_blocked`,
    );
    // Existing users are never modified (including is_email_verified).
    if (existing) return { user: existing, created: false };
    if (!password || validatePassword(password)) throw new WorkflowError("invalid_request");
    // The token was delivered only to this address; verify new users unless the invite grants an admin-tier role.
    const user = await database.mutate<UserRow>("users", {
        email: invite.email, password_hash: await dependencies.hashPassword(password),
        is_email_verified: !invite.role.some(isAdminTierRole),
    });
    return { user, created: true };
}

async function ensureMembership(database: DbClient, userId: string, organizationId: string): Promise<string> {
    const existing = await database.queryOne<{ id: string; status: string }>(
        `memberships?user_id=eq.${encodeURIComponent(userId)}&org_id=eq.${encodeURIComponent(organizationId)}&select=id,status`,
    );
    if (existing) {
        if (existing.status !== "active") await database.update("memberships",
            { id: `eq.${encodeURIComponent(existing.id)}` }, { status: "active" });
        return existing.id;
    }
    const created = await database.mutate<{ id: string }>("memberships",
        { user_id: userId, org_id: organizationId, status: "active" });
    return created.id;
}

async function assignInviteRoles(database: DbClient, membershipId: string, names: readonly string[]): Promise<void> {
    const effectiveNames = names.length ? names : ["member"];
    const roles = await database.query<{ id: string }>(
        `roles?name=in.(${effectiveNames.map(encodeURIComponent).join(",")})&select=id,name`,
    );
    for (const role of roles) {
        try { await database.mutate("membership_roles", { membership_id: membershipId, role_id: role.id }); }
        catch (error) {
            const message = error instanceof Error ? error.message : "";
            if (!message.includes("23505") && !message.includes("duplicate")) throw error;
        }
    }
}

async function cancelInvite(
    env: Env, ctx: ExecutionContext, input: CancelInviteRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<CancelInviteRpcOutcome> {
    try {
        const caller = await authenticated(env, input.accessToken, dependencies);
        const invite = await database.queryOne<Invite>(`invites?id=eq.${encodeURIComponent(input.inviteId)}&select=*`);
        if (!invite) throw new WorkflowError("not_found");
        if (invite.accepted) throw new WorkflowError("already_used");
        const privileged = caller.roles.includes("owner") || caller.roles.includes("admin");
        if (invite.org_id !== caller.org_id || (!privileged && invite.invited_by !== caller.sub)) {
            throw new WorkflowError("authorization_denied");
        }
        await database.query(`invites?id=eq.${encodeURIComponent(input.inviteId)}`, { method: "DELETE" });
        audit(ctx, env, "invite_cancelled", {
            user_id: caller.sub, org_id: caller.org_id,
            metadata: { invite_id: input.inviteId }
        });
        return {
            kind: "succeeded", correlationId: input.correlationId,
            data: { inviteId: input.inviteId, cancelled: true }
        };
    } catch (error) { return workflowFailure(input, error); }
}

const INVITE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LIST_INVITES_CAP = 100;
const MAX_ORGANIZATION_ID_LENGTH = 64;

async function resendInvite(
    env: Env, ctx: ExecutionContext, input: ResendInviteRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<ResendInviteRpcOutcome> {
    try {
        const caller = await authenticated(env, input.accessToken, dependencies);
        // Pure format check before any DB call: invites.id is a uuid, so a malformed id would
        // otherwise surface as a PostgREST 400 and be reported as an outage.
        if (typeof input.inviteId !== "string" || !INVITE_ID_PATTERN.test(input.inviteId)) {
            throw new WorkflowError("invalid_request");
        }
        await requireInviterRole(database, caller, caller.org_id);
        const invite = await database.queryOne<Pick<Invite, "id" | "email" | "org_id" | "accepted">>(
            `invites?id=eq.${encodeURIComponent(input.inviteId)}&select=id,email,org_id,accepted`,
        );
        // Another org's invite is indistinguishable from a missing one.
        if (!invite || invite.org_id !== caller.org_id) throw new WorkflowError("not_found");
        if (invite.accepted === true) throw new WorkflowError("already_used");
        if (await checkEmailThrottle(env, "invite", caller.org_id)) {
            return { kind: "rate_limited", correlationId: input.correlationId };
        }
        const token = crypto.randomUUID();
        const expiresAt = new Date(dependencies.now() + INVITE_TTL_MS).toISOString();
        await database.update("invites", {
            id: `eq.${encodeURIComponent(invite.id)}`,
            accepted: "not.is.true",
            org_id: `eq.${encodeURIComponent(caller.org_id)}`,
        }, { token_hash: await dependencies.hash(token), expires_at: expiresAt });
        const emailStatus = await deliverInviteEmail(
            env, ctx, database, caller, invite.id, invite.email, caller.org_id, token,
        );
        audit(ctx, env, "invite_resent", {
            user_id: caller.sub, org_id: caller.org_id,
            metadata: { invite_id: invite.id, email_status: emailStatus }
        });
        return {
            kind: "succeeded", correlationId: input.correlationId,
            data: {
                inviteId: invite.id, email: invite.email, expiresAt,
                ...(input.includeEmailStatus === true ? { emailStatus } : {}),
            }
        };
    } catch (error) { return workflowFailure(input, error); }
}

interface PendingInviteRow {
    id: string; email: string; role: unknown; created_at: string | null; expires_at: string | null;
}

async function listInvites(
    env: Env, input: ListInvitesRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<ListInvitesRpcOutcome> {
    try {
        const caller = await authenticated(env, input.accessToken, dependencies);
        if (typeof input.organizationId !== "string" || input.organizationId.length === 0 ||
            input.organizationId.length > MAX_ORGANIZATION_ID_LENGTH) {
            throw new WorkflowError("invalid_request");
        }
        // Always the caller's active organization; no code path queries another one.
        if (input.organizationId !== caller.org_id) throw new WorkflowError("authorization_denied");
        await requireInviterRole(database, caller, caller.org_id);
        // Explicit column list: token_hash is never read.
        const rows = await database.query<PendingInviteRow>(
            `invites?org_id=eq.${encodeURIComponent(caller.org_id)}&accepted=not.is.true` +
            `&select=id,email,role,created_at,expires_at&order=created_at.desc.nullslast,id.desc` +
            `&limit=${LIST_INVITES_CAP + 1}`,
        );
        const now = dependencies.now();
        const invites: PendingInviteData[] = rows.slice(0, LIST_INVITES_CAP).map((row) => ({
            inviteId: row.id,
            email: row.email,
            roles: Array.isArray(row.role) ? row.role.filter((role): role is string => typeof role === "string") : [],
            createdAt: row.created_at ?? null,
            expiresAt: row.expires_at ?? null,
            status: row.expires_at && Date.parse(row.expires_at) <= now ? "expired" : "pending",
        }));
        return {
            kind: "succeeded", correlationId: input.correlationId,
            data: { invites, truncated: rows.length > LIST_INVITES_CAP },
        };
    } catch (error) { return workflowFailure(input, error); }
}

async function requestVerification(
    env: Env, ctx: ExecutionContext, input: RequestVerificationRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<RequestVerificationRpcOutcome> {
    try {
        const caller = await authenticated(env, input.accessToken, dependencies);
        const result = await performRequestVerification(env, ctx, {
            user_id: caller.sub, email: caller.email, org_id: caller.org_id,
        });
        if (result.error) return mapWorkflowStatus(input, result.status);
        return {
            kind: "succeeded", correlationId: input.correlationId,
            data: { accepted: true, alreadyVerified: result.already_verified === true }
        };
    } catch (error) { return workflowFailure(input, error); }
}

interface OneTimeRecord { id: string; user_id: string; used: boolean; expires_at: string }

async function verifyEmail(
    env: Env, ctx: ExecutionContext, input: VerifyEmailRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<VerifyEmailRpcOutcome> {
    try {
        const record = await database.queryOne<OneTimeRecord>(
            `email_verifications?token_hash=eq.${encodeURIComponent(await dependencies.hash(input.verificationToken))}&select=*`,
        );
        const prior = await activeSession(database, input.currentRefreshToken, dependencies);
        const before = record && prior && prior.user_id === record.user_id
            ? await privilegeFingerprint(database, record.user_id, prior.org_id) : null;
        const result = await performVerifyEmail(env, ctx, { token: input.verificationToken }, null, null);
        if (result.error) return mapWorkflowStatus(input, result.status);
        const data = { verified: true as const };
        if (!record || !prior || prior.user_id !== record.user_id || !prior.org_id) {
            return { kind: "succeeded", correlationId: input.correlationId, data };
        }
        const after = await privilegeFingerprint(database, record.user_id, prior.org_id);
        if (before === after) return { kind: "succeeded", correlationId: input.correlationId, data };
        const session = await issueSession(env, database, prior.user_id, prior.org_id, dependencies);
        if (session.refreshToken === input.currentRefreshToken) throw new Error("Replacement credential was reused");
        await revokeSession(database, prior.id);
        return { kind: "rotated", correlationId: input.correlationId, data, session };
    } catch (error) { return workflowFailure(input, error); }
}

async function privilegeFingerprint(database: DbClient, userId: string, orgId: string | null): Promise<string> {
    if (!orgId) return "";
    const claims = await database.rpc<JwtClaims>("get_jwt_claims", { p_user_id: userId, p_org_id: orgId });
    return JSON.stringify({ roles: claims.roles, products: claims.products, membershipStatus: claims.membership_status });
}

async function forgotPassword(
    env: Env, ctx: ExecutionContext, input: ForgotPasswordRpcInput,
): Promise<ForgotPasswordRpcOutcome> {
    try {
        const result = await performForgotPassword(env, ctx, { email: input.email, redirect_url: input.redirectUrl },
            `rpc:${input.correlationId}`, null);
        if (result.error) return mapWorkflowStatus(input, result.status);
        return { kind: "succeeded", correlationId: input.correlationId, data: { accepted: true } };
    } catch (error) { return workflowFailure(input, error); }
}

async function resetPassword(
    env: Env, ctx: ExecutionContext, input: ResetPasswordRpcInput, database: DbClient,
    dependencies: PreservedWorkflowDependencies,
): Promise<ResetPasswordRpcOutcome> {
    try {
        const resetRecord = await database.queryOne<OneTimeRecord>(
            `password_resets?token_hash=eq.${encodeURIComponent(await dependencies.hash(input.resetToken))}&select=*`,
        );
        const prior = await activeSession(database, input.currentRefreshToken, dependencies);
        const result = await performResetPassword(env, ctx,
            { token: input.resetToken, password: input.password }, null, null);
        if (result.error) return mapWorkflowStatus(input, result.status);
        const data = { reset: true as const };
        if (!resetRecord || !prior || prior.user_id !== resetRecord.user_id || !prior.org_id) {
            return { kind: "succeeded", correlationId: input.correlationId, data };
        }
        const session = await issueSession(env, database, prior.user_id, prior.org_id, dependencies);
        if (session.refreshToken === input.currentRefreshToken) throw new Error("Replacement credential was reused");
        return { kind: "issued", correlationId: input.correlationId, data, session };
    } catch (error) { return workflowFailure(input, error); }
}

function mapWorkflowStatus(input: Correlated, status = 400) {
    if (status === 429) return { kind: "rate_limited" as const, correlationId: input.correlationId };
    if (status >= 500) return { kind: "unavailable" as const, correlationId: input.correlationId };
    const code: WorkflowRejectionCode = status === 404 ? "not_found"
        : status === 409 ? "conflict" : status === 410 ? "expired" : "invalid_request";
    return rejected(input, code);
}
